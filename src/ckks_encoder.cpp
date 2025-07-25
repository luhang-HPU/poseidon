#include "ckks_encoder.h"
#include "util/exception.h"

namespace poseidon
{
using namespace util;
CKKSEncoder::CKKSEncoder(const PoseidonContext &context) : context_(context)
{
    // Verify parameters
    if (context_.parameters_literal() == nullptr)
    {
        POSEIDON_THROW(invalid_argument_error, "encryption parameters are not set correctly");
    }

    auto params = context_.parameters_literal();
    if (params->scheme() != CKKS)
    {
        POSEIDON_THROW(invalid_argument_error, "unsupported scheme");
    }

    size_t coeff_count = params->degree();
    slots_ = coeff_count >> 1;
    int logn = params->log_n();
    uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
    matrix_reps_index_map_ = allocate<size_t>(coeff_count, pool_);

    // Copy from the matrix to the value vectors
    uint64_t gen = 5;
    uint64_t pos = 1;

    for (size_t i = 0; i < slots_; i++)
    {
        // Position in normal bit order
        uint64_t index1 = (pos - 1) >> 1;
        uint64_t index2 = (m - pos - 1) >> 1;

        // Set the bit-reversed locations
        matrix_reps_index_map_[i] = safe_cast<size_t>(reverse_bits(index1, logn));
        matrix_reps_index_map_[slots_ | i] = safe_cast<size_t>(reverse_bits(index2, logn));

        // Next primitive root
        pos *= gen;
        pos &= (m - 1);
    }

    // We need 1~(n-1)-th powers of the primitive 2n-th root, m = 2n
    root_powers_ = allocate<complex<double>>(coeff_count, pool_);
    inv_root_powers_ = allocate<complex<double>>(coeff_count, pool_);
    // Powers of the primitive 2n-th root have 4-fold symmetry
    if (m >= 8)
    {
        complex_roots_ =
            make_shared<util::ComplexRoots>(util::ComplexRoots(static_cast<size_t>(m), pool_));
        for (size_t i = 1; i < coeff_count; i++)
        {
            root_powers_[i] = complex_roots_->get_root(reverse_bits(i, logn));
            inv_root_powers_[i] = conj(complex_roots_->get_root(reverse_bits(i - 1, logn) + 1));
        }
    }
    else if (m == 4)
    {
        root_powers_[1] = {0, 1};
        inv_root_powers_[1] = {0, -1};
    }

    complex_arith_ = ComplexArith();
    fft_handler_ = FFTHandler(complex_arith_);
}

void CKKSEncoder::encode_internal(double value, parms_id_type parms_id, double scale,
                                  Plaintext &destination, MemoryPoolHandle pool) const
{
    // Verify parameters.
    auto context_data_ptr = context_.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    // Quick sanity check
    if (!product_fits_in(coeff_modulus_size, coeff_count))
    {
        throw logic_error("invalid parameters");
    }

    // Check that scale is positive and not too large
    if (scale <= 0 ||
        (static_cast<int>(log2(scale)) >= context_data.total_coeff_modulus_bit_count()))
    {
        throw invalid_argument("scale out of bounds");
    }

    // Compute the scaled value
    value *= scale;
    auto coeff_bit_count = static_cast<uint32_t>(log2(fabs(value))) + 2;
    if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count())
    {
        POSEIDON_THROW(invalid_argument_error, "encoded value is too large");
    }

    double two_pow_64 = pow(2.0, 64);
    destination.resize(context_, parms_id, util::mul_safe(coeff_count, coeff_modulus_size));

    double coeffd = round(value);
    bool is_negative = signbit(coeffd);
    coeffd = fabs(coeffd);

    // Use faster decomposition methods when possible
    if (coeff_bit_count <= 64)
    {
        uint64_t coeffu = static_cast<uint64_t>(fabs(coeffd));

        if (is_negative)
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(
                    destination.data() + (j * coeff_count), coeff_count,
                    negate_uint_mod(barrett_reduce_64(coeffu, coeff_modulus[j]), coeff_modulus[j]));
            }
        }
        else
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(destination.data() + (j * coeff_count), coeff_count,
                       barrett_reduce_64(coeffu, coeff_modulus[j]));
            }
        }
    }
    else if (coeff_bit_count <= 128)
    {
        uint64_t coeffu[2]{static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                           static_cast<uint64_t>(coeffd / two_pow_64)};

        if (is_negative)
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(destination.data() + (j * coeff_count), coeff_count,
                       negate_uint_mod(barrett_reduce_128(coeffu, coeff_modulus[j]),
                                       coeff_modulus[j]));
            }
        }
        else
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(destination.data() + (j * coeff_count), coeff_count,
                       barrett_reduce_128(coeffu, coeff_modulus[j]));
            }
        }
    }
    else
    {
        // Slow case
        auto coeffu(allocate_uint(coeff_modulus_size, pool));

        // We are at this point guaranteed to fit in the allocated space
        set_zero_uint(coeff_modulus_size, coeffu.get());
        auto coeffu_ptr = coeffu.get();
        while (coeffd >= 1)
        {
            *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
            coeffd /= two_pow_64;
        }

        // Next decompose this coefficient
        context_data.rns_tool()->base_q()->decompose(coeffu.get(), pool);

        // Finally replace the sign if necessary
        if (is_negative)
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(destination.data() + (j * coeff_count), coeff_count,
                       negate_uint_mod(coeffu[j], coeff_modulus[j]));
            }
        }
        else
        {
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                fill_n(destination.data() + (j * coeff_count), coeff_count, coeffu[j]);
            }
        }
    }

    destination.scale() = scale;
}

void CKKSEncoder::encode_internal(int64_t value, parms_id_type parms_id,
                                  Plaintext &destination) const
{
    // Verify parameters.
    auto context_data_ptr = context_.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }

    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    // Quick sanity check
    if (!product_fits_in(coeff_modulus_size, coeff_count))
    {
        throw logic_error("invalid parameters");
    }

    int coeff_bit_count = get_significant_bit_count(static_cast<uint64_t>(llabs(value))) + 2;
    if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count())
    {
        POSEIDON_THROW(invalid_argument_error, "encoded value is too large");
    }

    destination.resize(context_, parms_id, util::mul_safe(coeff_count, coeff_modulus_size));
    if (value < 0)
    {
        for (size_t j = 0; j < coeff_modulus_size; j++)
        {
            uint64_t tmp = static_cast<uint64_t>(value);
            tmp += coeff_modulus[j].value();
            tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
            fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
        }
    }
    else
    {
        for (size_t j = 0; j < coeff_modulus_size; j++)
        {
            uint64_t tmp = static_cast<uint64_t>(value);
            tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
            fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
        }
    }

    destination.scale() = 1.0;
}
}  // namespace poseidon
