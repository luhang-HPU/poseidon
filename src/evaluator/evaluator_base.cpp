#include "evaluator_base.h"

namespace poseidon
{

EvaluatorBase::EvaluatorBase(const PoseidonContext &context, MemoryPoolHandle pool)
    : context_(context), pool_(std::move(pool))
{
}

void EvaluatorBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result, uint32_t level) const
{
    auto parms_id = context_.crt_context()->parms_id_map().at(level);
    drop_modulus(ciph, result, parms_id);
}

void EvaluatorBase::drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const
{
    auto level = ciph.level();
    auto parms_id = context_.crt_context()->parms_id_map().at(level - 1);
    drop_modulus(ciph, result, parms_id);
}

void EvaluatorBase::ntt_fwd_b(const Plaintext &plain, Plaintext &result)
{
    if (!plain.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ntt_fwd : Plaintext is empty!");
    }
    result = plain;
    result.poly().coeff_to_dot();
    result.is_ntt_form() = true;
}

void EvaluatorBase::ntt_fwd_b(const Ciphertext &ciph, Ciphertext &result)
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ntt_fwd : Ciphertext is empty!");
    }
    result = ciph;
    for (auto &p : result.polys())
    {
        p.coeff_to_dot();
    }
    result.is_ntt_form() = true;
}

void EvaluatorBase::ntt_inv_b(const Plaintext &plain, Plaintext &result)
{
    if (!plain.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ntt_inv : Plaintext is empty!");
    }
    result = plain;
    result.poly().dot_to_coeff();
}

void EvaluatorBase::ntt_inv_b(const Ciphertext &ciph, Ciphertext &result)
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ntt_inv : Ciphertext is empty!");
    }
    result = ciph;
    for (auto &p : result.polys())
    {
        p.dot_to_coeff();
    }
    result.is_ntt_form() = false;
}

void EvaluatorBase::transform_to_ntt_inplace(Plaintext &plain,
                                             parms_id_type parms_id, MemoryPoolHandle pool) const
{
    // Verify parameters.
    auto context_data_ptr = context_.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for the current context");
    }
    if (plain.is_ntt_form())
    {
        return;
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    // Extract encryption parameters.
    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t plain_coeff_count = plain.coeff_count();

    uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    auto plain_upper_half_increment = context_data.plain_upper_half_increment();

    auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    // Resize to fit the entire NTT transformed (ciph size) polynomial
    // Note that the new coefficients are automatically set to 0
    plain.resize(context_, parms_id, coeff_count * coeff_modulus_size);
    RNSIter plain_iter(plain.data(), coeff_count);

    if (!context_data.using_fast_plain_lift())
    {
        // Allocate temporary space for an entire RNS polynomial
        // Slight semantic misuse of RNSIter here, but this works well
        POSEIDON_ALLOCATE_ZERO_GET_RNS_ITER(temp, coeff_modulus_size, coeff_count, pool);

        POSEIDON_ITERATE(iter(plain.data(), temp), plain_coeff_count,
                         [&](auto I)
                         {
                             auto plain_value = get<0>(I);
                             if (plain_value >= plain_upper_half_threshold)
                             {
                                 add_uint(plain_upper_half_increment, coeff_modulus_size,
                                          plain_value, get<1>(I));
                             }
                             else
                             {
                                 *get<1>(I) = plain_value;
                             }
                         });

        context_data.rns_tool()->base_q()->decompose_array(temp, coeff_count, pool);

        // Copy data back to plain
        set_poly(temp, coeff_count, coeff_modulus_size, plain.data());
    }
    else
    {
        // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the
        // coeff_modulus primes.
        // Create a "reversed" helper iterator that iterates in the reverse order both plain RNS
        // components and the plain_upper_half_increment values.
        auto helper_iter = reverse_iter(plain_iter, plain_upper_half_increment);
        advance(helper_iter, -safe_cast<ptrdiff_t>(coeff_modulus_size - 1));

        POSEIDON_ITERATE(helper_iter, coeff_modulus_size,
                         [&](auto I)
                         {
                             POSEIDON_ITERATE(iter(*plain_iter, get<0>(I)), plain_coeff_count,
                                              [&](auto J)
                                              {
                                                  get<1>(J) = POSEIDON_COND_SELECT(
                                                      get<0>(J) >= plain_upper_half_threshold,
                                                      get<0>(J) + get<1>(I), get<0>(J));
                                              });
                         });
    }

    // Transform to NTT domain
    ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables);

    plain.parms_id() = parms_id;
    plain.is_ntt_form() = true;
}

void EvaluatorBase::transform_to_ntt_inplace(Ciphertext &ciph) const
{

    auto context_data_ptr = context_.crt_context()->get_context_data(ciph.parms_id());
    if (!context_data_ptr)
    {
        throw invalid_argument("ciph is not valid for encryption parameters");
    }
    if (ciph.is_ntt_form())
    {
        return;
    }

    // Extract encryption parameters.
    auto &context_data = *context_data_ptr;
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // size_t encrypted_ntt_size = ciph.size();

    auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());
    RNSIter ciph_iter(ciph.data(), coeff_count);
    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    // Transform each polynomial from NTT domain
    inverse_ntt_negacyclic_harvey(ciph_iter, coeff_modulus_size, ntt_tables);

    // Finally change the is_ntt_transformed flag
    ciph.is_ntt_form() = true;
}
}  // namespace poseidon
