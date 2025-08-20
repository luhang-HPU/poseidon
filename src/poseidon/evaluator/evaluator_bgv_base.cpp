#include "evaluator_bgv_base.h"
#include "poseidon/basics/util/scalingvariant.h"

namespace poseidon
{

EvaluatorBgvBase::EvaluatorBgvBase(const PoseidonContext &context) : Base(context)
{
    if (context_.key_switch_variant() == BV)
    {
        kswitch_ = make_shared<KSwitchBV>(context);
    }
    else if (context_.key_switch_variant() == GHS)
    {
        kswitch_ = make_shared<KSwitchGHS>(context);
    }
    else if (context_.key_switch_variant() == HYBRID)
    {
        kswitch_ = make_shared<KSwitchHybrid>(context);
    }
}

void EvaluatorBgvBase::rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                              const GaloisKeys &galois_keys) const
{
    POSEIDON_THROW(invalid_argument_error,
                   "BGV rotate : software don't support, just support rotate_col and rotate_row");
}

void EvaluatorBgvBase::square_inplace(Ciphertext &ciph, MemoryPoolHandle pool) const
{
    if (!ciph.is_ntt_form())
    {
        throw invalid_argument("ciph must be in NTT form");
    }

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = parms.coeff_modulus().size();
    size_t encrypted_size = ciph.size();

    // Optimization implemented currently only for size 2 ciphertexts
    if (encrypted_size != 2)
    {
        multiply_inplace(ciph, ciph, move(pool));
        return;
    }

    // Determine destination.size()
    // Default is 3 (c_0, c_1, c_2)
    size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

    // Size check
    if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    // Set up iterator for the base
    auto coff = parms.coeff_modulus();
    auto coeff_modulus = iter(coff);

    // Prepare destination
    ciph.resize(context_, context_data.parms_id(), dest_size);

    // Set up iterators for input ciphertext
    auto ciph_iter = iter(ciph);

    // Allocate temporary space for the result
    POSEIDON_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

    // Compute c1^2
    dyadic_product_coeffmod(ciph_iter[1], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                            ciph_iter[2]);

    // Compute 2*c0*c1
    dyadic_product_coeffmod(ciph_iter[0], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                            ciph_iter[1]);
    add_poly_coeffmod(ciph_iter[1], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                      ciph_iter[1]);

    // Compute c0^2
    dyadic_product_coeffmod(ciph_iter[0], ciph_iter[0], coeff_modulus_size, coeff_modulus,
                            ciph_iter[0]);

    // Set the correction factor
    ciph.correction_factor() = multiply_uint_mod(ciph.correction_factor(), ciph.correction_factor(),
                                                 parms.plain_modulus());
}

void EvaluatorBgvBase::multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                      Ciphertext &result, const RelinKeys &relin_keys) const
{
    multiply(ciph1, ciph2, result);
    relinearize(result, result, relin_keys);
}

void EvaluatorBgvBase::ntt_fwd(const Plaintext &plain, Plaintext &result, parms_id_type id) const
{
    if (id == parms_id_zero && plain.parms_id() != parms_id_zero)
    {
        ntt_fwd_b(plain, result);
    }
    else if (id != parms_id_zero)
    {
        result = plain;
        transform_to_ntt_inplace(result, id, pool_);
    }
    else
    {
        POSEIDON_THROW(invalid_argument_error, "ntt_fwd : parms_id error");
    }
}

void EvaluatorBgvBase::ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const
{
    ntt_fwd_b(ciph, result);
}

void EvaluatorBgvBase::ntt_inv(const Ciphertext &ciph, Ciphertext &result) const
{
    ntt_inv_b(ciph, result);
}

void EvaluatorBgvBase::rescale(Ciphertext &ciph) const
{
    MemoryPoolHandle pool = MemoryManager::GetPool();
    auto ciphertext = ciph;
    auto &result = ciph;

    if (!ciphertext.is_valid())
        POSEIDON_THROW(invalid_argument_error, "rescale_inplace : ciph is empty");

    if (!ciphertext.is_ntt_form())
        POSEIDON_THROW(invalid_argument_error, "rescale_inplace : ckks ciph must be in NTT form");

    auto context_data_ptr = context_.crt_context()->get_context_data(ciphertext.parms_id());
    auto &context_data = *context_data_ptr;
    auto &next_context_data = *context_data.next_context_data();
    auto &next_parms = next_context_data.parms();
    auto rns_tool = context_data.rns_tool();
    auto ntt_table = context_.crt_context()->small_ntt_tables();

    size_t ciphertext_size = ciphertext.size();
    size_t coeff_count = next_parms.degree();
    size_t next_coeff_modulus_size = next_context_data.coeff_modulus().size();

    Ciphertext ciphertext_copy(pool);
    ciphertext_copy = ciphertext;

    POSEIDON_ITERATE(iter(ciphertext_copy), ciphertext_size, [&](auto I)
                     { rns_tool->mod_t_and_divide_q_last_ntt_inplace(I, ntt_table, pool); });

    result.resize(context_, next_context_data.parms().parms_id(), ciphertext_size);
    POSEIDON_ITERATE(iter(ciphertext_copy, result), ciphertext_size, [&](auto I)
                     { set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I)); });

    // Set other attributes
    result.is_ntt_form() = ciphertext.is_ntt_form();
    result.correction_factor() = multiply_uint_mod(
        ciphertext.correction_factor(), rns_tool->inv_q_last_mod_t(), next_parms.plain_modulus());
}

void EvaluatorBgvBase::apply_galois(const Ciphertext &ciph, Ciphertext &destination,
                                    std::uint32_t galois_elt, const GaloisKeys &galois_keys,
                                    MemoryPoolHandle pool) const
{
    destination = ciph;
    dynamic_cast<KSwitchBV *>(kswitch_.get())
        ->apply_galois_inplace(destination, galois_elt, galois_keys, std::move(pool));
}

void EvaluatorBgvBase::add(const Ciphertext &ciph1, const Ciphertext &ciph2,
                           Ciphertext &result) const
{
    if (&result == &ciph1)
    {
        add_inplace(result, ciph2);
    }
    else
    {
        result = ciph2;
        add_inplace(result, ciph1);
    }
}

void EvaluatorBgvBase::sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                           Ciphertext &result) const
{
    if (&ciph2 != &result)
    {
        result = ciph1;
    }

    if (!ciph1.is_valid() || !ciph2.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() != ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : NTT form mismatch");
    }
    if (!util::are_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
        POSEIDON_THROW(invalid_argument_error, "sub : scale mismatch");
    }

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph1.size();
    size_t max_count = max(ciph1_size, ciph2_size);
    size_t min_count = min(ciph1_size, ciph2_size);

    // Size check
    if (!product_fits_in(max_count, coeff_count))
    {
        throw logic_error("invalid parameters");
    }

    // Prepare result
    result.resize(context_, ciph1.parms_id(), ciph1.size());
    result.is_ntt_form() = ciph1.is_ntt_form();
    for (auto i = 0; i < min_count; i++)
    {
        ciph1[i].sub(ciph2[i], result[i]);
    }
    // Copy the remainding polys of the array with larger count into ciph1
    if (ciph1_size < ciph2_size)
    {
        for (auto i = min_count; i < max_count; ++i)
        {
            result[i].copy(ciph2[i]);
        }
    }
}

void EvaluatorBgvBase::add_plain(const Ciphertext &ciph, const Plaintext &plain,
                                 Ciphertext &result) const
{
    result = ciph;
    add_plain_inplace(result, plain);
}

void EvaluatorBgvBase::sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                                 Ciphertext &result) const
{
    result = ciph;
    sub_plain_inplace(result, plain);
}

void EvaluatorBgvBase::multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result) const
{
    if (&ciph2 == &result)
    {
        multiply_inplace(result, ciph1);
    }
    else
    {
        result = ciph1;
        multiply_inplace(result, ciph2);
    }
}

void EvaluatorBgvBase::relinearize(const Ciphertext &ciph1, Ciphertext &result,
                                   const RelinKeys &relin_keys) const
{
    kswitch_->relinearize(ciph1, result, relin_keys);
}

void EvaluatorBgvBase::rotate_row(const Ciphertext &ciph, Ciphertext &result, int rot_step,
                                  const GaloisKeys &galois_keys) const
{
    result = ciph;
    kswitch_->rotate_internal(result, rot_step, galois_keys, pool_);
}

void EvaluatorBgvBase::rotate_col(const Ciphertext &ciph, Ciphertext &result,
                                  const GaloisKeys &galois_keys) const
{
    result = ciph;
    kswitch_->conjugate_internal(result, galois_keys, pool_);
}

void EvaluatorBgvBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                                    parms_id_type parms_id) const
{
    result = ciph;

    auto context_data_ptr = context_.crt_context()->get_context_data(ciph.parms_id());
    auto target_context_data_ptr = context_.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        throw invalid_argument("encrypted is not valid for encryption parameters");
    }
    if (!target_context_data_ptr)
    {
        throw invalid_argument("parms_id is not valid for encryption parameters");
    }
    if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
    {
        throw invalid_argument("cannot switch to higher level modulus");
    }

    while (ciph.parms_id() != parms_id)
    {
        drop_modulus_to_next(result, result);
    }

}

void EvaluatorBgvBase::add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "add_plain_inplace : Ciphertext is empty!");
    }
    // Verify parameters.
    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV ciph must be NTT form");
    }
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV plain must not be NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    Plaintext plain_copy = plain;
    multiply_poly_scalar_coeffmod(plain.data(), plain.coeff_count(), ciph.correction_factor(),
                                  parms.plain_modulus(), plain_copy.data());
    transform_to_ntt_inplace(plain_copy, ciph.parms_id(), move(pool_));
    RNSIter ciph_iter(ciph.data(), coeff_count);
    ConstRNSIter plain_iter(plain_copy.data(), coeff_count);
    add_poly_coeffmod(ciph_iter, plain_iter, coeff_modulus_size, coeff_modulus, ciph_iter);
}

void EvaluatorBgvBase::sub_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "sub_plain_inplace : Ciphertext is empty!");
    }
    // Verify parameters.
    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV ciph must be NTT form");
    }
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV plain must not be NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    multiply_sub_plain_with_scaling_variant(plain, context_data, *iter(ciph));
}

void EvaluatorBgvBase::add_inplace(Ciphertext &ciph1, const Ciphertext &ciph2) const
{
    // Verify parameters.
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "add_inplace : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() != ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "NTT form mismatch");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();
    size_t max_count = max(ciph1_size, ciph2_size);
    size_t min_count = min(ciph1_size, ciph2_size);

    // Size check
    if (!product_fits_in(max_count, coeff_count))
    {
        throw logic_error("invalid parameters");
    }
    // Prepare result
    ciph1.resize(context_, context_data.parms().parms_id(), max_count);
    // Add ciphs
    for (auto i = 0; i < min_count; i++)
    {
        ciph1[i].add(ciph2[i], ciph1[i]);
    }

    // Copy the remainding polys of the array with larger count into ciph1
    if (ciph1_size < ciph2_size)
    {
        for (auto i = min_count; i < max_count; ++i)
        {
            ciph1[i].copy(ciph2[i]);
        }
    }
}

void EvaluatorBgvBase::bgv_multiply(Ciphertext &ciph1, const Ciphertext &ciph2,
                                    MemoryPoolHandle pool) const
{
    if (!ciph1.is_ntt_form() || !ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph1 or ciph2 must be in NTT form");
    }
    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = context_data.coeff_modulus().size();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();

    // Determine destination.size()
    // Default is 3 (c_0, c_1, c_2)
    size_t dest_size = sub_safe(add_safe(ciph1_size, ciph2_size), size_t(1));

    // Set up iterator for the base
    auto coeff_modulus = iter(context_data.coeff_modulus());

    // Prepare destination
    ciph1.resize(context_, context_data.parms().parms_id(), dest_size);

    // Convert c0 and c1 to ntt
    // Set up iterators for input ciphs
    PolyIter ciph1_iter = iter(ciph1);
    ConstPolyIter ciph2_iter = iter(ciph2);

    if (dest_size == 3)
    {
        // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
        // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67 coefficients
        // per polynomial, we should keep the tile size at 682 or below. The tile size must divide
        // coeff_count, i.e. be a power of two. Some testing shows similar performance with tile
        // size 256 and 512, and worse performance on smaller tiles. We pick the smaller of the two
        // to prevent L1 cache misses on processors with < 32 KiB L1 cache.
        size_t tile_size = min<size_t>(coeff_count, size_t(256));
        size_t num_tiles = coeff_count / tile_size;
#ifdef POSEIDON_DEBUG
        if (coeff_count % tile_size != 0)
        {
            POSEIDON_THROW(invalid_argument_error, "tile_size does not divide coeff_count");
        }
#endif

        // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor in
        // sequence
        ConstRNSIter ciph2_0_iter(*ciph2_iter[0], tile_size);
        ConstRNSIter ciph2_1_iter(*ciph2_iter[1], tile_size);
        RNSIter ciph1_0_iter(*ciph1_iter[0], tile_size);
        RNSIter ciph1_1_iter(*ciph1_iter[1], tile_size);
        RNSIter ciph1_2_iter(*ciph1_iter[2], tile_size);

        // Temporary buffer to store intermediate results
        POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

        // Computes the output tile_size coefficients at a time
        // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
        // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
        // with appropriate modular reduction
        POSEIDON_ITERATE(coeff_modulus, coeff_modulus_size,
                         [&](auto I)
                         {
                             POSEIDON_ITERATE(
                                 iter(size_t(0)), num_tiles,
                                 [&](POSEIDON_MAYBE_UNUSED auto J)
                                 {
                                     // Compute third output polynomial, overwriting input
                                     // x[2] = x[1] * y[1]
                                     dyadic_product_coeffmod(ciph1_1_iter[0], ciph2_1_iter[0],
                                                             tile_size, I, ciph1_2_iter[0]);

                                     // Compute second output polynomial, overwriting input
                                     // temp = x[1] * y[0]
                                     dyadic_product_coeffmod(ciph1_1_iter[0], ciph2_0_iter[0],
                                                             tile_size, I, temp);
                                     // x[1] = x[0] * y[1]
                                     dyadic_product_coeffmod(ciph1_0_iter[0], ciph2_1_iter[0],
                                                             tile_size, I, ciph1_1_iter[0]);
                                     // x[1] += temp
                                     add_poly_coeffmod(ciph1_1_iter[0], temp, tile_size, I,
                                                       ciph1_1_iter[0]);

                                     // Compute first output polynomial, overwriting input
                                     // x[0] = x[0] * y[0]
                                     dyadic_product_coeffmod(ciph1_0_iter[0], ciph2_0_iter[0],
                                                             tile_size, I, ciph1_0_iter[0]);

                                     // Manually increment iterators
                                     ciph1_0_iter++;
                                     ciph1_1_iter++;
                                     ciph1_2_iter++;
                                     ciph2_0_iter++;
                                     ciph2_1_iter++;
                                 });
                         });
    }
    else
    {
        // Allocate temporary space for the result
        POSEIDON_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size,
                                             pool);

        POSEIDON_ITERATE(
            iter(size_t(0)), dest_size,
            [&](auto I)
            {
                // We iterate over relevant components of ciph1 and ciph2 in increasing
                // order for ciph1 and reversed (decreasing) order for ciph2. The bounds
                // for the indices of the relevant terms are obtained as follows.
                size_t curr_ciph1_last = min<size_t>(I, ciph1_size - 1);
                size_t curr_ciph2_first = min<size_t>(I, ciph2_size - 1);
                size_t curr_ciph1_first = I - curr_ciph2_first;
                // size_t curr_ciph2_last = secret_power_index - curr_ciph1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_ciph1_last - curr_ciph1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_ciph1_iter = ciph1_iter + curr_ciph1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_ciph2_iter = reverse_iter(ciph2_iter + curr_ciph2_first);

                POSEIDON_ITERATE(iter(shifted_ciph1_iter, shifted_reversed_ciph2_iter), steps,
                                 [&](auto J)
                                 {
                                     // Extra care needed here:
                                     // temp_iter must be dereferenced once to produce an
                                     // appropriate RNSIter
                                     POSEIDON_ITERATE(
                                         iter(J, coeff_modulus, temp[I]), coeff_modulus_size,
                                         [&](auto K)
                                         {
                                             POSEIDON_ALLOCATE_GET_COEFF_ITER(prod, coeff_count,
                                                                              pool);
                                             dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K),
                                                                     coeff_count, get<1>(K), prod);
                                             add_poly_coeffmod(prod, get<2>(K), coeff_count,
                                                               get<1>(K), get<2>(K));
                                         });
                                 });
            });

        // Set the final result
        set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, ciph1.data());
    }

    // Set the correction factor
    ciph1.correction_factor() = multiply_uint_mod(ciph1.correction_factor(),
                                                  ciph2.correction_factor(), parms.plain_modulus());
}

void EvaluatorBgvBase::multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                                        MemoryPoolHandle pool) const
{
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "multiply_inplace : ciph1 and ciph2 parameter mismatch");
    }
    bgv_multiply(ciph1, ciph2, std::move(pool));
}

void EvaluatorBgvBase::multiply_plain_inplace(Ciphertext &ciph, const Plaintext &plain,
                                              MemoryPoolHandle pool) const
{
    // Verify parameters.
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph is empty");
    }
    if (!pool)
    {
        throw invalid_argument("pool is uninitialized");
    }

    if (ciph.is_ntt_form() && plain.is_ntt_form())
    {
        multiply_plain_ntt(ciph, plain);
    }
    else if (!ciph.is_ntt_form() && !plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph is empty");
        // multiply_plain_normal(ciph, plain, move(pool));
    }
    else if (ciph.is_ntt_form() && !plain.is_ntt_form())
    {
        Plaintext plain_copy = plain;
        transform_to_ntt_inplace(plain_copy, ciph.parms_id(), move(pool));
        multiply_plain_ntt(ciph, plain_copy);
    }
    else
    {
        transform_to_ntt_inplace(ciph);
        multiply_plain_ntt(ciph, plain);
        transform_from_ntt_inplace(ciph);
    }

#ifdef POSEIDON_THROW_ON_TRANSPARENT_CIPHERTEXT
    // Transparent ciph output is not allowed.
    if (ciph.is_transparent())
    {
        throw logic_error("result ciph is transparent");
    }
#endif
}

void EvaluatorBgvBase::multiply_plain_ntt(Ciphertext &ciph_ntt, const Plaintext &plain_ntt) const
{
    // Verify parameters.
    if (!plain_ntt.is_ntt_form())
    {
        throw invalid_argument("plain_ntt is not in NTT form");
    }
    if (ciph_ntt.parms_id() != plain_ntt.parms_id())
    {
        throw invalid_argument("ciph_ntt and plain_ntt parameter mismatch");
    }

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph_ntt.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t encrypted_ntt_size = ciph_ntt.size();

    // Size check
    if (!product_fits_in(encrypted_ntt_size, coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    ConstRNSIter plain_ntt_iter(plain_ntt.data(), coeff_count);
    POSEIDON_ITERATE(
        iter(ciph_ntt), encrypted_ntt_size, [&](auto I)
        { dyadic_product_coeffmod(I, plain_ntt_iter, coeff_modulus_size, coeff_modulus, I); });

    // Set the scale
    ciph_ntt.scale() *= plain_ntt.scale();
}

// void EvaluatorBgvBase::multiply_plain_normal(Ciphertext &ciph, const Plaintext &plain,
//                                            MemoryPoolHandle pool) const
// {
//     // Extract encryption parameters.
//     auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
//     auto &parms = context_data.parms();
//     auto &coeff_modulus = context_data.coeff_modulus();
//     size_t coeff_count = parms.degree();
//     size_t coeff_modulus_size = coeff_modulus.size();

//     uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
//     auto plain_upper_half_increment = context_data.plain_upper_half_increment();
//     auto ntt_tables = context_.crt_context()->small_ntt_tables();
//     // auto ntt_tables = iter(context_data.small_ntt_tables());

//     size_t encrypted_size = ciph.size();
//     size_t plain_coeff_count = plain.coeff_count();
//     size_t plain_nonzero_coeff_count = plain.nonzero_coeff_count();

//     // Size check
//     if (!product_fits_in(encrypted_size, coeff_count, coeff_modulus_size))
//     {
//         throw logic_error("invalid parameters");
//     }

//     /*
//     Optimizations for constant / monomial multiplication can lead to the presence of a timing
//     side-channel in use-cases where the plaintext data should also be kept private.
//     */
//     if (plain_nonzero_coeff_count == 1)
//     {
//         // Multiplying by a monomial?
//         size_t mono_exponent = plain.significant_coeff_count() - 1;

//         if (plain[mono_exponent] >= plain_upper_half_threshold)
//         {
//             if (!context_data.qualifiers().using_fast_plain_lift)
//             {
//                 // Allocate temporary space for a single RNS coefficient
//                 POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_modulus_size, pool);

//                 // We need to adjust the monomial modulo each coeff_modulus prime separately when
//                 // the coeff_modulus primes may be larger than the plain_modulus. We add
//                 // plain_upper_half_increment (i.e., q-t) to the monomial to ensure it is smaller
//                 // than coeff_modulus and then do an RNS multiplication. Note that in this case
//                 // plain_upper_half_increment contains a multi-precision integer, so after the
//                 // addition we decompose the multi-precision integer into RNS components, and
//                 then
//                 // multiply.
//                 add_uint(plain_upper_half_increment, coeff_modulus_size, plain[mono_exponent],
//                          temp);
//                 context_data.rns_tool()->base_q()->decompose(temp, pool);
//                 negacyclic_multiply_poly_mono_coeffmod(
//                     ciph, encrypted_size, temp, mono_exponent, coeff_modulus, ciph, pool);
//             }
//             else
//             {
//                 // Every coeff_modulus prime is larger than plain_modulus, so there is no need to
//                 // adjust the monomial. Instead, just do an RNS multiplication.
//                 negacyclic_multiply_poly_mono_coeffmod(ciph, encrypted_size,
//                                                        plain[mono_exponent], mono_exponent,
//                                                        coeff_modulus, ciph, pool);
//             }
//         }
//         else
//         {
//             // The monomial represents a positive number, so no RNS multiplication is needed.
//             negacyclic_multiply_poly_mono_coeffmod(ciph, encrypted_size, plain[mono_exponent],
//                                                    mono_exponent, coeff_modulus, ciph, pool);
//         }
//         return;
//     }

//     // Generic case: any plaintext polynomial
//     // Allocate temporary space for an entire RNS polynomial
//     auto temp(allocate_zero_poly(coeff_count, coeff_modulus_size, pool));

//     if (!context_data.qualifiers().using_fast_plain_lift)
//     {
//         StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

//         POSEIDON_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count,
//                      [&](auto I)
//                      {
//                          auto plain_value = get<0>(I);
//                          if (plain_value >= plain_upper_half_threshold)
//                          {
//                              add_uint(plain_upper_half_increment, coeff_modulus_size,
//                              plain_value,
//                                       get<1>(I));
//                          }
//                          else
//                          {
//                              *get<1>(I) = plain_value;
//                          }
//                      });

//         context_data.rns_tool()->base_q()->decompose_array(temp_iter, coeff_count, pool);
//     }
//     else
//     {
//         // Note that in this case plain_upper_half_increment holds its value in RNS form modulo
//         the
//         // coeff_modulus primes.
//         RNSIter temp_iter(temp.get(), coeff_count);
//         POSEIDON_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size,
//                          [&](auto I)
//                          {
//                              POSEIDON_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count,
//                                               [&](auto J)
//                                               {
//                                                   get<0>(J) = SEAL_COND_SELECT(
//                                                       get<1>(J) >= plain_upper_half_threshold,
//                                                       get<1>(J) + get<1>(I), get<1>(J));
//                                               });
//                          });
//     }

//     // Need to multiply each component in ciph with temp; first step is to transform to NTT
//     // form
//     RNSIter temp_iter(temp.get(), coeff_count);
//     ntt_negacyclic_harvey(temp_iter, coeff_modulus_size, ntt_tables);

//     POSEIDON_ITERATE(iter(ciph), encrypted_size,
//                      [&](auto I)
//                      {
//                          POSEIDON_ITERATE(
//                              iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size,
//                              [&](auto J)
//                              {
//                                  // Lazy reduction
//                                  ntt_negacyclic_harvey_lazy(get<0>(J), get<3>(J));
//                                  dyadic_product_coeffmod(get<0>(J), get<1>(J), coeff_count,
//                                                          get<2>(J), get<0>(J));
//                                  inverse_ntt_negacyclic_harvey(get<0>(J), get<3>(J));
//                              });
//                      });

// }

void EvaluatorBgvBase::multiply_by_diag_matrix_bsgs(const Ciphertext &ciph,
                                                    const MatrixPlain &plain_mat,
                                                    Ciphertext &result,
                                                    const GaloisKeys &rot_key) const
{
}

void EvaluatorBgvBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                                    uint32_t level) const
{
    auto parms_id = context_.crt_context()->parms_id_map().at(level);
    drop_modulus(ciph, result, parms_id);
}

void EvaluatorBgvBase::drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph is empty");
    }

    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(config_error, "BGV ciph must be in NTT form");
    }
    auto context_data_ptr = context_.crt_context()->get_context_data(ciph.parms_id());
    auto &context_data = *context_data_ptr;
    auto &next_context_data = *context_data.next_context_data();
    auto &next_parms = next_context_data.parms();
    auto rns_tool = context_data.rns_tool();

    size_t ciph_size = ciph.size();
    size_t coeff_count = next_parms.degree();
    size_t next_coeff_modulus_size = next_context_data.coeff_modulus().size();

    Ciphertext ciph_copy(pool_);
    ciph_copy = ciph;
    POSEIDON_ITERATE(iter(ciph_copy), ciph_size,
                     [&](auto I)
                     {
                         rns_tool->mod_t_and_divide_q_last_ntt_inplace(
                             I, context_.crt_context()->small_ntt_tables(), pool_);
                     });
    result.resize(context_, next_context_data.parms().parms_id(), ciph_size);
    POSEIDON_ITERATE(iter(ciph_copy, result), ciph_size, [&](auto I)
                     { set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I)); });

    // Set other attributes
    result.is_ntt_form() = ciph.is_ntt_form();
    result.correction_factor() = multiply_uint_mod(
        ciph.correction_factor(), rns_tool->inv_q_last_mod_t(), next_parms.plain_modulus());
}

}  // namespace poseidon
