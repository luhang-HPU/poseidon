#pragma once

#include "basics/util/uintarithsmallmod.h"
#include "basics/util/uintcore.h"
#include "plaintext.h"
#include "poseidon_context.h"
#include "util/fft.h"
#include <cmath>
#include <complex>
#include <limits>
#include <type_traits>
#include <vector>

#undef POSEIDON_USE_MSGSL
#ifdef POSEIDON_USE_MSGSL
#include "gsl/span"
#endif

namespace poseidon
{

/**
Provides functionality for encoding vectors of complex or real numbers into
plaintext polynomials to be encrypted and computed on using the ckks scheme.
If the polynomial modulus degree is N, then CKKSEncoder converts vectors of
N/2 complex numbers into plaintext elements. Homomorphic operations performed
on such encrypted vectors are applied coefficient (slot-)wise, enabling
powerful SIMD functionality for computations that are vectorizable. This
functionality is often called "batching" in the homomorphic encryption
literature.

@par Mathematical Background
Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of
two, the CKKSEncoder implements an approximation of the canonical embedding
of the ring of integers Z[X]/(X^N+1) into C^(N/2), where C denotes the complex
numbers. The Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2)
whose action on the primitive roots of unity modulo coeff_modulus is easy to
describe. Since the batching slots correspond 1-to-1 to the primitive roots
of unity, applying Galois automorphisms on the plaintext acts by permuting
the slots. By applying generators of the two cyclic subgroups of the Galois
group, we can effectively enable cyclic rotations and complex conjugations
of the encrypted complex vectors.
*/
class CKKSEncoder
{
    using ComplexArith = util::Arithmetic<std::complex<double>, std::complex<double>, double>;
    using FFTHandler = util::DWTHandler<std::complex<double>, std::complex<double>, double>;

public:
    /**
    Creates a CKKSEncoder instance initialized with the specified PoseidonContext.

    @param[in] context The PoseidonContext
    @throws std::invalid_argument if the encryption parameters are not valid
    @throws std::invalid_argument if scheme is not scheme_type::ckks
    */
    CKKSEncoder(const PoseidonContext &context);

    /**
    Encodes a vector of double-precision floating-point real or complex numbers
    into a plaintext polynomial. Append zeros if vector size is less than N/2.
    Dynamic memory allocations in the process are allocated from the memory
    pool pointed to by the given MemoryPoolHandle.

    @tparam T Vector value type (double or std::complex<double>)
    @param[in] values The vector of double-precision floating-point numbers
    (of type T) to encode
    @param[in] parms_id parms_id determining the encryption parameters to
    be used by the result plaintext
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if values has invalid size
    @throws std::invalid_argument if parms_id is not valid for the encryption
    parameters
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(const std::vector<T> &values, parms_id_type parms_id, double scale,
                       Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode_internal(values.data(), values.size(), parms_id, scale, destination,
                        std::move(pool));
    }

    /**
    Encodes a vector of double-precision floating-point real or complex numbers
    into a plaintext polynomial. Append zeros if vector size is less than N/2.
    The encryption parameters used are the top level parameters for the given
    context. Dynamic memory allocations in the process are allocated from the
    memory pool pointed to by the given MemoryPoolHandle.

    @tparam T Vector value type (double or std::complex<double>)
    @param[in] values The vector of double-precision floating-point numbers
    (of type T) to encode
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if values has invalid size
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(const std::vector<T> &values, double scale, Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode(values, context_.crt_context()->first_parms_id(), scale, destination,
               std::move(pool));
    }

#ifdef POSEIDON_USE_MSGSL
    /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @tparam T Array value type (double or std::complex<double>)
        @param[in] values The array of double-precision floating-point numbers
        (of type T) to encode
        @param[in] parms_id parms_id determining the encryption parameters to
        be used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(gsl::span<const T> values, parms_id_type parms_id, double scale,
                       Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode_internal(values.data(), static_cast<std::size_t>(values.size()), parms_id, scale,
                        destination, std::move(pool));
    }

    /**
    Encodes a vector of double-precision floating-point real or complex numbers
    into a plaintext polynomial. Append zeros if vector size is less than N/2.
    The encryption parameters used are the top level parameters for the given
    context. Dynamic memory allocations in the process are allocated from the
    memory pool pointed to by the given MemoryPoolHandle.

    @tparam T Array value type (double or std::complex<double>)
    @param[in] values The array of double-precision floating-point numbers
    (of type T) to encode
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if values has invalid size
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(gsl::span<const T> values, double scale, Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode(values, context_.crt_context()->first_parms_id(), scale, destination,
               std::move(pool));
    }
#endif

    /**
    Encodes a double-precision floating-point real number into a plaintext
    polynomial. The number repeats for N/2 times to fill all slots. Dynamic
    memory allocations in the process are allocated from the memory pool
    pointed to by the given MemoryPoolHandle.

    @param[in] value The double-precision floating-point number to encode
    @param[in] parms_id parms_id determining the encryption parameters to be
    used by the result plaintext
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if parms_id is not valid for the encryption
    parameters
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    inline void encode(double value, parms_id_type parms_id, double scale, Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode_internal(value, parms_id, scale, destination, std::move(pool));
    }

    /**
    Encodes a double-precision floating-point real number into a plaintext
    polynomial. The number repeats for N/2 times to fill all slots. The
    encryption parameters used are the top level parameters for the given
    context. Dynamic memory allocations in the process are allocated from
    the memory pool pointed to by the given MemoryPoolHandle.

    @param[in] value The double-precision floating-point number to encode
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    inline void encode(double value, double scale, Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode(value, context_.crt_context()->first_parms_id(), scale, destination,
               std::move(pool));
    }

    /**
    Encodes a double-precision complex number into a plaintext polynomial.
    Append zeros to fill all slots. Dynamic memory allocations in the process
    are allocated from the memory pool pointed to by the given MemoryPoolHandle.

    @param[in] value The double-precision complex number to encode
    @param[in] parms_id parms_id determining the encryption parameters to be
    used by the result plaintext
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if parms_id is not valid for the encryption
    parameters
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    inline void encode(std::complex<double> value, parms_id_type parms_id, double scale,
                       Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode_internal(value, parms_id, scale, destination, std::move(pool));
    }

    /**
    Encodes a double-precision complex number into a plaintext polynomial.
    Append zeros to fill all slots. The encryption parameters used are the
    top level parameters for the given context. Dynamic memory allocations
    in the process are allocated from the memory pool pointed to by the
    given MemoryPoolHandle.

    @param[in] value The double-precision complex number to encode
    @param[in] scale Scaling parameter defining encoding precision
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if scale is not strictly positive
    @throws std::invalid_argument if encoding is too large for the encryption
    parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    inline void encode(std::complex<double> value, double scale, Plaintext &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        encode(value, context_.crt_context()->first_parms_id(), scale, destination,
               std::move(pool));
    }

    /**
    Encodes an integer number into a plaintext polynomial without any scaling.
    The number repeats for N/2 times to fill all slots.
    @param[in] value The integer number to encode
    @param[in] parms_id parms_id determining the encryption parameters to be
    used by the result plaintext
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    @throws std::invalid_argument if parms_id is not valid for the encryption
    parameters
    */
    inline void encode(std::int64_t value, parms_id_type parms_id, Plaintext &destination) const
    {
        encode_internal(value, parms_id, destination);
    }

    /**
    Encodes an integer number into a plaintext polynomial without any scaling.
    The number repeats for N/2 times to fill all slots. The encryption
    parameters used are the top level parameters for the given context.

    @param[in] value The integer number to encode
    @param[out] destination The plaintext polynomial to overwrite with the
    result
    */
    inline void encode(std::int64_t value, Plaintext &destination) const
    {
        encode(value, context_.crt_context()->first_parms_id(), destination);
    }

    /**
    Decodes a plaintext polynomial into double-precision floating-point
    real or complex numbers. Dynamic memory allocations in the process are
    allocated from the memory pool pointed to by the given MemoryPoolHandle.

    @tparam T Vector value type (double or std::complex<double>)
    @param[in] plain The plaintext to decode
    @param[out] destination The vector to be overwritten with the values in
    the slots
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if plain is not in NTT form or is invalid
    for the encryption parameters
    @throws std::invalid_argument if pool is uninitialized
    */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void decode(const Plaintext &plain, std::vector<T> &destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        destination.resize(slots_);
        decode_internal(plain, destination.data(), std::move(pool));
    }
#ifdef POSEIDON_USE_MSGSL
    /**
        Decodes a plaintext polynomial into double-precision floating-point
        real or complex numbers. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Array value type (double or std::complex<double>)
        @param[in] plain The plaintext to decode
        @param[out] destination The array to be overwritten with the values in
        the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not in NTT form or is invalid
        for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void decode(const Plaintext &plain, gsl::span<T> destination,
                       MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        if (destination.size() != slots_)
        {
            throw std::invalid_argument("destination has invalid size");
        }
        decode_internal(plain, destination.data(), std::move(pool));
    }
#endif

    /**
    Returns the number of complex numbers encoded.
    */
    POSEIDON_NODISCARD inline std::size_t slot_count() const noexcept { return slots_; }

    POSEIDON_NODISCARD inline const PoseidonContext &context() const { return context_; }

private:
    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    void encode_internal(const T *values, std::size_t values_size, parms_id_type parms_id,
                         double scale, Plaintext &destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto params = this->context_.parameters_literal();
        auto crt_context = context_.crt_context();
        if (params == nullptr)
        {
            throw std::invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!values && values_size > 0)
        {
            throw std::invalid_argument("values cannot be null");
        }
        if (values_size > slots_)
        {
            throw std::invalid_argument("values_size is too large");
        }
        if (!pool)
        {
            throw std::invalid_argument("pool is uninitialized");
        }

        auto global_context_data = context_.crt_context();
        auto &context_data = *context_.crt_context()->get_context_data(parms_id);
        auto &parms = context_data.parms();
        auto &coeff_modulus = context_data.coeff_modulus();
        std::size_t coeff_modulus_size = context_data.coeff_modulus().size();
        std::size_t coeff_count = parms.degree();
        std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);
        auto level = coeff_modulus_size - 1;
        int logn = static_cast<int>(parms.log_n());
        auto ntt_tables = global_context_data->small_ntt_tables();

        // Quick sanity check
        if (!util::product_fits_in(coeff_modulus_size, coeff_count))
        {
            throw std::logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 ||
            (static_cast<int>(log2(scale)) + 1 >= context_data.total_coeff_modulus_bit_count()))
        {
            POSEIDON_THROW(invalid_argument_error, "scale out of bounds");
        }

        // values_size is guaranteed to be no bigger than slots_
        std::size_t n = util::mul_safe(slots_, std::size_t(2));

        auto conj_values = util::allocate<std::complex<double>>(n, pool, 0);
        for (std::size_t i = 0; i < values_size; i++)
        {
            conj_values[matrix_reps_index_map_[i]] = values[i];
            // TODO: if values are real, the following values should be set to zero, and multiply
            // results by 2.
            conj_values[matrix_reps_index_map_[i + slots_]] = std::conj(values[i]);
        }
        double fix = scale / static_cast<double>(n);
        fft_handler_.transform_from_rev(conj_values.get(), util::get_power_of_two(n),
                                        inv_root_powers_.get(), &fix);

        double max_coeff = 0;
        for (std::size_t i = 0; i < n; i++)
        {
            max_coeff = std::max<>(max_coeff, std::fabs(conj_values[i].real()));
        }
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        int max_coeff_bit_count =
            static_cast<int>(std::ceil(std::log2(std::max<>(max_coeff, 1.0)))) + 1;
        if (max_coeff_bit_count >= context_data.total_coeff_modulus_bit_count())
        {
            throw std::invalid_argument("encoded values are too large");
        }

        double two_pow_64 = std::pow(2.0, 64);

        destination.parms_id() = parms_id;
        destination.resize(context_, parms_id, util::mul_safe(coeff_count, coeff_modulus_size));

        // Use faster decomposition methods when possible
        if (max_coeff_bit_count <= 64)
        {
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);

                std::uint64_t coeffu = static_cast<std::uint64_t>(std::fabs(coeffd));

                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::negate_uint_mod(
                            util::barrett_reduce_64(coeffu, coeff_modulus[j]), coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] =
                            util::barrett_reduce_64(coeffu, coeff_modulus[j]);
                    }
                }
            }
        }
        else if (max_coeff_bit_count <= 128)
        {
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);
                coeffd = std::fabs(coeffd);

                std::uint64_t coeffu[2]{static_cast<std::uint64_t>(std::fmod(coeffd, two_pow_64)),
                                        static_cast<std::uint64_t>(coeffd / two_pow_64)};

                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = util::negate_uint_mod(
                            util::barrett_reduce_128(coeffu, coeff_modulus[j]), coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] =
                            util::barrett_reduce_128(coeffu, coeff_modulus[j]);
                    }
                }
            }
        }
        else
        {
            // Slow case
            auto coeffu(util::allocate_uint(coeff_modulus_size, pool));
            for (std::size_t i = 0; i < n; i++)
            {
                double coeffd = std::round(conj_values[i].real());
                bool is_negative = std::signbit(coeffd);
                coeffd = std::fabs(coeffd);

                // We are at this point guaranteed to fit in the allocated space
                util::set_zero_uint(coeff_modulus_size, coeffu.get());
                auto coeffu_ptr = coeffu.get();
                while (coeffd >= 1)
                {
                    *coeffu_ptr++ = static_cast<std::uint64_t>(std::fmod(coeffd, two_pow_64));
                    coeffd /= two_pow_64;
                }

                // Next decompose this coefficient
                context_data.rns_tool()->base_q()->decompose(coeffu.get(), pool);

                // Finally replace the sign if necessary
                if (is_negative)
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] =
                            util::negate_uint_mod(coeffu[j], coeff_modulus[j]);
                    }
                }
                else
                {
                    for (std::size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + (j * coeff_count)] = coeffu[j];
                    }
                }
            }
        }

        destination.is_ntt_form() = true;

        destination.poly().coeff_to_dot();
        destination.scale() = scale;
    }

    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    void decode_internal(const Plaintext &plain, T *destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!plain.is_valid(context_))
        {
            throw std::invalid_argument("plain is not valid for encryption parameters");
        }
        if (!plain.is_ntt_form())
        {
            throw std::invalid_argument("plain is not in NTT form");
        }
        if (!destination)
        {
            throw std::invalid_argument("destination cannot be null");
        }
        if (!pool)
        {
            throw std::invalid_argument("pool is uninitialized");
        }

        auto global_context_data = context_.crt_context();
        auto &context_data = *context_.crt_context()->get_context_data(plain.parms_id());
        auto &parms = context_data.parms();
        std::size_t coeff_modulus_size = context_data.coeff_modulus().size();
        std::size_t coeff_count = parms.degree();
        std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);
        int logn = static_cast<int>(parms.log_n());
        auto ntt_tables = global_context_data->small_ntt_tables();

        // Check that scale is positive and not too large
        if (plain.scale() <= 0 ||
            (static_cast<int>(log2(plain.scale())) >= context_data.total_coeff_modulus_bit_count()))
        {
            POSEIDON_THROW(invalid_argument_error, "scale out of bounds");
        }

        auto decryption_modulus = context_data.total_coeff_modulus();
        auto upper_half_threshold = context_data.upper_half_threshold();

        // Quick sanity check
        if ((logn < 0) || (coeff_count < POSEIDON_POLY_MOD_DEGREE_MIN) ||
            (coeff_count > POSEIDON_POLY_MOD_DEGREE_MAX))
        {
            throw std::logic_error("invalid parameters");
        }

        double inv_scale = double(1.0) / plain.scale();

        // Create mutable copy of input
        auto plain_copy(util::allocate_uint(rns_poly_uint64_count, pool));
        util::set_uint(plain.data(), rns_poly_uint64_count, plain_copy.get());

        for (std::size_t i = 0; i < coeff_modulus_size; i++)
        {
            util::inverse_ntt_negacyclic_harvey(plain_copy.get() + (i * coeff_count),
                                                ntt_tables[i]);
        }

        // CRT-compose the polynomial
        context_data.rns_tool()->base_q()->compose_array(plain_copy.get(), coeff_count, pool);

        // Create floating-point representations of the multi-precision integer coefficients
        double two_pow_64 = std::pow(2.0, 64);
        auto res(util::allocate<std::complex<double>>(coeff_count, pool));
        for (std::size_t i = 0; i < coeff_count; i++)
        {
            res[i] = 0.0;
            if (util::is_greater_than_or_equal_uint(plain_copy.get() + (i * coeff_modulus_size),
                                                    upper_half_threshold, coeff_modulus_size))
            {
                double scaled_two_pow_64 = inv_scale;
                for (std::size_t j = 0; j < coeff_modulus_size;
                     j++, scaled_two_pow_64 *= two_pow_64)
                {
                    if (plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j])
                    {
                        auto diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                        res[i] += diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                    }
                    else
                    {
                        auto diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                        res[i] -= diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                    }
                }
            }
            else
            {
                double scaled_two_pow_64 = inv_scale;
                for (std::size_t j = 0; j < coeff_modulus_size;
                     j++, scaled_two_pow_64 *= two_pow_64)
                {
                    auto curr_coeff = plain_copy[i * coeff_modulus_size + j];
                    res[i] +=
                        curr_coeff ? static_cast<double>(curr_coeff) * scaled_two_pow_64 : 0.0;
                }
            }

            // Scaling instead incorporated above; this can help in cases
            // where otherwise pow(two_pow_64, j) would overflow due to very
            // large coeff_modulus_size and very large scale
            // res[i] = res_accum * inv_scale;
        }

        fft_handler_.transform_to_rev(res.get(), logn, root_powers_.get());

        for (std::size_t i = 0; i < slots_; i++)
        {
            destination[i] =
                from_complex<T>(res[static_cast<std::size_t>(matrix_reps_index_map_[i])]);
        }
    }

    void encode_internal(double value, parms_id_type parms_id, double scale, Plaintext &destination,
                         MemoryPoolHandle pool) const;

    inline void encode_internal(std::complex<double> value, parms_id_type parms_id, double scale,
                                Plaintext &destination, MemoryPoolHandle pool) const
    {
        auto input = util::allocate<std::complex<double>>(slots_, pool_, value);
        encode_internal(input.get(), slots_, parms_id, scale, destination, std::move(pool));
    }

    void encode_internal(std::int64_t value, parms_id_type parms_id, Plaintext &destination) const;

    MemoryPoolHandle pool_ = MemoryManager::GetPool();

    PoseidonContext context_;

    std::size_t slots_;

    std::shared_ptr<util::ComplexRoots> complex_roots_;

    // Holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
    util::Pointer<std::complex<double>> root_powers_;

    // Holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
    util::Pointer<std::complex<double>> inv_root_powers_;

    util::Pointer<std::size_t> matrix_reps_index_map_;

    ComplexArith complex_arith_;

    FFTHandler fft_handler_;
};
}  // namespace poseidon
