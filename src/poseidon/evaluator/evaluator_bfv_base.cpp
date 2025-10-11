#include "evaluator_bfv_base.h"
#include "poseidon/basics/util/scalingvariant.h"
#include "poseidon/util/debug.h"

namespace poseidon
{

namespace
{
POSEIDON_NODISCARD inline bool
is_scale_within_bounds(double scale, const CrtContext::ContextData &context_data) noexcept
{
    int scale_bit_count_bound = 0;
    scale_bit_count_bound = context_data.parms().plain_modulus().bit_count();
    return !(scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
}
}  // namespace

EvaluatorBfvBase::EvaluatorBfvBase(const PoseidonContext &context) : Base(context)
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

void EvaluatorBfvBase::ntt_fwd(const Plaintext &plain, Plaintext &result, parms_id_type id) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("NTT");
#endif
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

void EvaluatorBfvBase::ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("NTT");
#endif
    ntt_fwd_b(ciph, result);
}

void EvaluatorBfvBase::ntt_inv(const Ciphertext &ciph, Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("INTT");
#endif
    ntt_inv_b(ciph, result);
}

void EvaluatorBfvBase::add(const Ciphertext &ciph1, const Ciphertext &ciph2,
                           Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("ADD");
#endif
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

void EvaluatorBfvBase::add_plain(const Ciphertext &ciph, const Plaintext &plain,
                                 Ciphertext &result) const
{
    result = ciph;
    add_plain_inplace(result, plain);
}

void EvaluatorBfvBase::sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                           Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("SUB");
#endif
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

void EvaluatorBfvBase::sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                                 Ciphertext &result) const
{
    result = ciph;
    sub_plain_inplace(result, plain);
}

void EvaluatorBfvBase::add_inplace(Ciphertext &ciph1, const Ciphertext &ciph2) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("ADD INPLACE");
#endif
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

void EvaluatorBfvBase::add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("ADD PLAIN");
#endif
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "add_plain_inplace : Ciphertext is empty!");
    }
    // Verify parameters.
    if (ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV ciph must not be  NTT form");
    }
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV plain must not be NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    multiply_add_plain_with_scaling_variant(plain, context_data, *iter(ciph));
}

void EvaluatorBfvBase::sub_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("SUB PLAIN");
#endif
    // Verify parameters.
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "sub_plain_inplace : Ciphertext is empty!");
    }
    if (ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV ciph must not be  NTT form");
    }
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV plain must not be NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    multiply_sub_plain_with_scaling_variant(plain, context_data, *iter(ciph));
}

void EvaluatorBfvBase::multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("MULTIPLY");
#endif
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

void EvaluatorBfvBase::square_inplace(Ciphertext &ciph,
                                      MemoryPoolHandle pool) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("SQUARE");
#endif
    multiply_inplace(ciph, ciph);
}

void EvaluatorBfvBase::relinearize(const Ciphertext &ciph, Ciphertext &result,
                                   const RelinKeys &relin_keys) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("RELINEARIZE");
#endif
    kswitch_->relinearize(ciph, result, relin_keys);
}

void EvaluatorBfvBase::multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                      Ciphertext &result, const RelinKeys &relin_keys) const
{
    multiply(ciph1, ciph2, result);
    relinearize(result, result, relin_keys);
}

void EvaluatorBfvBase::rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                              const GaloisKeys &galois_keys) const
{
    POSEIDON_THROW(invalid_argument_error, "BFV rotate : software don't support");
}

void EvaluatorBfvBase::rotate_row(const Ciphertext &ciph, Ciphertext &result, int step,
                                  const GaloisKeys &galois_keys) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("ROTATE_ROW");
#endif
    result = ciph;
    kswitch_->rotate_internal(result, step, galois_keys, pool_);
}

void EvaluatorBfvBase::rotate_col(const Ciphertext &ciph, Ciphertext &result,
                                  const GaloisKeys &galois_keys) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("ROTATE_COL");
#endif
    result = ciph;
    kswitch_->conjugate_internal(result, galois_keys, pool_);
}

void EvaluatorBfvBase::drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("DROP MODULUS");
#endif
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "drop_modulus : Ciphertext is empty!");
    }

    if (ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "rescale_inplace : BFV ciph must not be in NTT form");
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
                     [&](auto I) { rns_tool->divide_and_round_q_last_inplace(I, pool_); });
    result.resize(context_, next_context_data.parms().parms_id(), ciph_size);
    POSEIDON_ITERATE(iter(ciph_copy, result), ciph_size,
                     [&](auto I)
                     { set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I)); });

    // Set other attributes
    result.is_ntt_form() = ciph.is_ntt_form();
}

void EvaluatorBfvBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                                    parms_id_type parms_id) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("DROP MODULUS");
#endif
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

void EvaluatorBfvBase::apply_galois(const Ciphertext &ciph, Ciphertext &destination,
                                    std::uint32_t galois_elt, const GaloisKeys &galois_keys,
                                    MemoryPoolHandle pool) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("APPLY GALOIS");
#endif
    destination = ciph;
    dynamic_cast<KSwitchBV *>(kswitch_.get())
        ->apply_galois_inplace(destination, galois_elt, galois_keys, std::move(pool));
}

/////////////////////////////   private method   //////////////////////////////////////
void EvaluatorBfvBase::multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                                        MemoryPoolHandle pool) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("MULTIPLY INPLACE");
#endif
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "multiply_inplace : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() || ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph1 or ciph2 cannot be in NTT form");
    }

    bool is_square = false;
    if (&ciph1 == &ciph2)
    {
        is_square = true;
    }
    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t base_q_size = context_data.coeff_modulus().size();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();
    uint64_t plain_modulus = parms.plain_modulus().value();

    auto rns_tool = context_data.rns_tool();
    size_t base_bsk_size = rns_tool->base_bsk()->size();
    size_t base_bsk_m_tilde_size = rns_tool->base_bsk_m_tilde()->size();

    // Determine destination.size()
    size_t dest_size = sub_safe(add_safe(ciph1_size, ciph2_size), size_t(1));

    // Size check
    if (!product_fits_in(dest_size, coeff_count, base_bsk_m_tilde_size))
    {
        throw logic_error("invalid parameters");
    }

    // Set up iterators for bases
    auto base_q = iter(context_data.coeff_modulus());
    auto base_bsk = iter(rns_tool->base_bsk()->base());

    // Set up iterators for NTT tables
    auto base_q_ntt_tables = iter(context_.crt_context()->small_ntt_tables());
    auto base_bsk_ntt_tables = iter(rns_tool->base_bsk_ntt_tables());

    // Poseidon uses BEHZ-style RNS multiplication. This process is somewhat complex and
    // consists of the following steps:
    //
    // (1) Lift ciph1 and ciph2 (initially in base q) to an extended base q U Bsk U
    // {m_tilde} (2) Remove extra multiples of q from the results with Montgomery reduction,
    // switching base to q U Bsk (3) Transform the data to NTT form (4) Compute the ciph
    // polynomial product using dyadic multiplication (5) Transform the data back from NTT form (6)
    // Multiply the result by t (plain_modulus) (7) Scale the result by q using a divide-and-floor
    // algorithm, switching base to Bsk (8) Use Shenoy-Kumaresan method to convert the result to
    // base q

    // Resize ciph1 to destination size
    ciph1.resize(context_, context_data.parms().parms_id(), dest_size);

    // This lambda function takes as input an IterTuple with three components:
    //
    // 1. (Const)RNSIter to read an input polynomial from
    // 2. RNSIter for the output in base q
    // 3. RNSIter for the output in base Bsk
    //
    // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input
    // polynomial (given as an RNSIter or ConstRNSIter) and writes the results in base q and base
    // Bsk to the given output iterators.
   
    auto behz_extend_base_convert_to_ntt = [&](auto I)
    {
        // Make copy of input polynomial (in base q) and convert to NTT form
        // Lazy reduction
        set_poly(get<0>(I), coeff_count, base_q_size, get<1>(I));
        ntt_negacyclic_harvey(get<1>(I), base_q_size, base_q_ntt_tables);

        // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
        POSEIDON_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_bsk_m_tilde_size, pool);

        // (1) Convert from base q to base Bsk U {m_tilde}
        rns_tool->fastbconv_m_tilde(get<0>(I), temp, pool);

        // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
        rns_tool->sm_mrq(temp, get<2>(I), pool);

        // Transform to NTT form in base Bsk
        // Lazy reduction
        ntt_negacyclic_harvey(get<2>(I), base_bsk_size, base_bsk_ntt_tables);
    };
    // Allocate space for a base q output of behz_extend_base_convert_to_ntt for ciph1
    POSEIDON_ALLOCATE_GET_POLY_ITER(ciph1_q, ciph1_size, coeff_count, base_q_size, pool);

    // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for ciph1
    POSEIDON_ALLOCATE_GET_POLY_ITER(ciph1_bsk, ciph1_size, coeff_count, base_bsk_size, pool);

    // Perform BEHZ steps (1)-(3) for ciph1
    POSEIDON_ITERATE(iter(ciph1, ciph1_q, ciph1_bsk), ciph1_size, behz_extend_base_convert_to_ntt);

    // Repeat for ciph2
    POSEIDON_ALLOCATE_GET_POLY_ITER(ciph2_q, ciph2_size, coeff_count, base_q_size, pool);
    POSEIDON_ALLOCATE_GET_POLY_ITER(ciph2_bsk, ciph2_size, coeff_count, base_bsk_size, pool);

    POSEIDON_ITERATE(iter(ciph2, ciph2_q, ciph2_bsk), ciph2_size, behz_extend_base_convert_to_ntt);

    // Allocate temporary space for the output of step (4)
    // We allocate space separately for the base q and the base Bsk components
    POSEIDON_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
    POSEIDON_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_bsk, dest_size, coeff_count, base_bsk_size,
                                         pool);
    if (is_square)
    {
        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphs
        POSEIDON_ITERATE(
            iter(size_t(0)), dest_size,
            [&](auto I)
            {
                // We iterate over relevant components of ciph1 and ciph2 in increasing order
                // for ciph1 and reversed (decreasing) order for ciph2. The bounds for the
                // indices of the relevant terms are obtained as follows.
                size_t curr_ciph1_last = min<size_t>(I, ciph1_size - 1);
                size_t curr_ciph2_first = min<size_t>(I, ciph2_size - 1);
                size_t curr_ciph1_first = I - curr_ciph2_first;
                // size_t curr_ciph2_last = I - curr_ciph1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_ciph1_last - curr_ciph1_first + 1;

                // This lambda function computes the ciph product for BFV multiplication.
                // Since we use the BEHZ approach, the multiplication of individual polynomials is
                // done using a dyadic product where the inputs are already in NTT form. The
                // arguments of the lambda function are expected to be as follows:
                //
                // 1. a ConstPolyIter pointing to the beginning of the first input ciph (in
                // NTT form)
                // 2. a ConstPolyIter pointing to the beginning of the second input ciph (in
                // NTT form)
                // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
                // 4. the size of the base
                // 5. a PolyIter pointing to the beginning of the output ciph
                auto behz_ciph_square = [&](ConstPolyIter in_iter, ConstModulusIter base_iter,
                                            size_t base_size, PolyIter out_iter)
                {
                    // Compute c0^2
                    dyadic_product_coeffmod(in_iter[0], in_iter[0], base_size, base_iter,
                                            out_iter[0]);

                    // Compute 2*c0*c1
                    dyadic_product_coeffmod(in_iter[0], in_iter[1], base_size, base_iter,
                                            out_iter[1]);
                    add_poly_coeffmod(out_iter[1], out_iter[1], base_size, base_iter, out_iter[1]);

                    // Compute c1^2
                    dyadic_product_coeffmod(in_iter[1], in_iter[1], base_size, base_iter,
                                            out_iter[2]);
                };

                // Perform the BEHZ ciph square both for base q and base Bsk
                behz_ciph_square(ciph1_q, base_q, base_q_size, temp_dest_q);
                behz_ciph_square(ciph1_bsk, base_bsk, base_bsk_size, temp_dest_bsk);
            });
    }
    else
    {
        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphs
        POSEIDON_ITERATE(
            iter(size_t(0)), dest_size,
            [&](auto I)
            {
                // We iterate over relevant components of ciph1 and ciph2 in increasing order
                // for ciph1 and reversed (decreasing) order for ciph2. The bounds for the
                // indices of the relevant terms are obtained as follows.
                size_t curr_ciph1_last = min<size_t>(I, ciph1_size - 1);
                size_t curr_ciph2_first = min<size_t>(I, ciph2_size - 1);
                size_t curr_ciph1_first = I - curr_ciph2_first;
                // size_t curr_ciph2_last = I - curr_ciph1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_ciph1_last - curr_ciph1_first + 1;

                // This lambda function computes the ciph product for BFV multiplication.
                // Since we use the BEHZ approach, the multiplication of individual polynomials is
                // done using a dyadic product where the inputs are already in NTT form. The
                // arguments of the lambda function are expected to be as follows:
                //
                // 1. a ConstPolyIter pointing to the beginning of the first input ciph (in
                // NTT form)
                // 2. a ConstPolyIter pointing to the beginning of the second input ciph (in
                // NTT form)
                // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
                // 4. the size of the base
                // 5. a PolyIter pointing to the beginning of the output ciph
                auto behz_ciph_product = [&](ConstPolyIter in1_iter, ConstPolyIter in2_iter,
                                             ConstModulusIter base_iter, size_t base_size,
                                             PolyIter out_iter)
                {
                    // Create a shifted iterator for the first input
                    auto shifted_in1_iter = in1_iter + curr_ciph1_first;

                    // Create a shifted reverse iterator for the second input
                    auto shifted_reversed_in2_iter = reverse_iter(in2_iter + curr_ciph2_first);

                    // Create a shifted iterator for the output
                    auto shifted_out_iter = out_iter[I];

                    POSEIDON_ITERATE(
                        iter(shifted_in1_iter, shifted_reversed_in2_iter), steps,
                        [&](auto J)
                        {
                            POSEIDON_ITERATE(
                                iter(J, base_iter, shifted_out_iter), base_size,
                                [&](auto K)
                                {
                                    POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool);
                                    dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count,
                                                            get<1>(K), temp);
                                    add_poly_coeffmod(temp, get<2>(K), coeff_count, get<1>(K),
                                                      get<2>(K));
                                });
                        });
                };

                // Perform the BEHZ ciph product both for base q and base Bsk
                behz_ciph_product(ciph1_q, ciph2_q, base_q, base_q_size, temp_dest_q);
                behz_ciph_product(ciph1_bsk, ciph2_bsk, base_bsk, base_bsk_size, temp_dest_bsk);
            });
    }

    // Perform BEHZ step (5): transform data from NTT form
    // Lazy reduction here. The following multiply_poly_scalar_coeffmod will correct the value back
    // to [0, p)
    inverse_ntt_negacyclic_harvey_lazy(temp_dest_q, dest_size, base_q_ntt_tables);
    inverse_ntt_negacyclic_harvey_lazy(temp_dest_bsk, dest_size, base_bsk_ntt_tables);

    // Perform BEHZ steps (6)-(8)
    POSEIDON_ITERATE(iter(temp_dest_q, temp_dest_bsk, ciph1), dest_size,
                     [&](auto I)
                     {
                         // Bring together the base q and base Bsk components into a single
                         // allocation
                         POSEIDON_ALLOCATE_GET_RNS_ITER(temp_q_bsk, coeff_count,
                                                        base_q_size + base_bsk_size, pool);

                         // Step (6): multiply base q components by t (plain_modulus)
                         multiply_poly_scalar_coeffmod(get<0>(I), base_q_size, plain_modulus,
                                                       base_q, temp_q_bsk);

                         multiply_poly_scalar_coeffmod(get<1>(I), base_bsk_size, plain_modulus,
                                                       base_bsk, temp_q_bsk + base_q_size);

                         // Allocate yet another temporary for fast divide-and-floor result in base
                         // Bsk
                         POSEIDON_ALLOCATE_GET_RNS_ITER(temp_bsk, coeff_count, base_bsk_size, pool);

                         // Step (7): divide by q and floor, producing a result in base Bsk
                         rns_tool->fast_floor(temp_q_bsk, temp_bsk, pool);

                         // Step (8): use Shenoy-Kumaresan method to convert the result to base q
                         // and write to ciph1
                         rns_tool->fastbconv_sk(temp_bsk, get<2>(I), pool);
                     });
}

void EvaluatorBfvBase::multiply_plain_inplace(Ciphertext &ciph, const Plaintext &plain,
                                              MemoryPoolHandle pool) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph is empty");
    }

    // Verify parameters.
    if (ciph.is_ntt_form() && !plain.is_ntt_form())
    {
        Plaintext plain_copy = plain;
        transform_to_ntt_inplace(plain_copy, ciph.parms_id(), pool);
        multiply_plain_ntt(ciph, plain_copy);
    }
    else if (ciph.is_ntt_form())
    {
        multiply_plain_ntt(ciph, plain);
    }
    else
    {
        multiply_plain_normal(ciph, plain);
        // static int hardware_cnt = 0;
        // hardware_cnt++;
        // printf("hardware_cnt = %d\r\n", hardware_cnt);
    }

#ifdef POSEIDON_THROW_ON_TRANSPARENT_CIPHERTEXT
    // Transparent ciph output is not allowed.
    if (ciph.is_transparent())
    {
        throw logic_error("result ciph is transparent");
    }
#endif
}

void EvaluatorBfvBase::multiply_plain_ntt(Ciphertext &ciph_ntt, const Plaintext &plain_ntt) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("MULTIPLY PLAIN");
#endif
    // Verify parameters.
    if (!plain_ntt.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "plain_ntt is not in NTT form");
    }
    if (ciph_ntt.parms_id() != plain_ntt.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph_ntt and plain_ntt parameter mismatch");
    }

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph_ntt.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t ciph_ntt_size = ciph_ntt.size();

    // Size check
    if (!product_fits_in(ciph_ntt_size, coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    ConstRNSIter plain_ntt_iter(plain_ntt.data(), coeff_count);
    POSEIDON_ITERATE(
        iter(ciph_ntt), ciph_ntt_size,
        [&](auto I)
        { dyadic_product_coeffmod(I, plain_ntt_iter, coeff_modulus_size, coeff_modulus, I); });

    // Set the scale
    ciph_ntt.scale() *= plain_ntt.scale();
    if (!is_scale_within_bounds(ciph_ntt.scale(), context_data))
    {
        POSEIDON_THROW(invalid_argument_error, "scale out of bounds");
    }
}

void EvaluatorBfvBase::multiply_plain_normal(Ciphertext &ciph, const Plaintext &plain,
                                             MemoryPoolHandle pool) const
{
#ifdef DEBUG
    poseidon::util::LocalTimer timer("MULTIPLY PLAIN");
#endif
    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    auto plain_upper_half_increment = context_data.plain_upper_half_increment();
    auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());

    size_t ciph_size = ciph.size();
    size_t plain_coeff_count = plain.coeff_count();
    size_t plain_nonzero_coeff_count = plain.nonzero_coeff_count();

    // Size check
    if (!product_fits_in(ciph_size, coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    /*
    Optimizations for constant / monomial multiplication can lead to the presence of a timing
    side-channel in use-cases where the plaintext data should also be kept private.
    */
    if (plain_nonzero_coeff_count == 1)
    {
        // Multiplying by a monomial?
        size_t mono_exponent = plain.significant_coeff_count() - 1;

        if (plain[mono_exponent] >= plain_upper_half_threshold)
        {
            if (!context_data.using_fast_plain_lift())
            {
                // Allocate temporary space for a single RNS coefficient
                POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_modulus_size, pool_);

                // We need to adjust the monomial modulo each coeff_modulus prime separately when
                // the coeff_modulus primes may be larger than the plain_modulus. We add
                // plain_upper_half_increment (i.e., q-t) to the monomial to ensure it is smaller
                // than coeff_modulus and then do an RNS multiplication. Note that in this case
                // plain_upper_half_increment contains a multi-precision integer, so after the
                // addition we decompose the multi-precision integer into RNS components, and then
                // multiply.
                add_uint(plain_upper_half_increment, coeff_modulus_size, plain[mono_exponent],
                         temp);
                context_data.rns_tool()->base_q()->decompose(temp, pool_);
                negacyclic_multiply_poly_mono_coeffmod(ciph, ciph_size, temp, mono_exponent,
                                                       coeff_modulus, ciph, pool_);
            }
            else
            {
                // Every coeff_modulus prime is larger than plain_modulus, so there is no need to
                // adjust the monomial. Instead, just do an RNS multiplication.
                negacyclic_multiply_poly_mono_coeffmod(ciph, ciph_size, plain[mono_exponent],
                                                       mono_exponent, coeff_modulus, ciph, pool_);
            }
        }
        else
        {
            // The monomial represents a positive number, so no RNS multiplication is needed.
            negacyclic_multiply_poly_mono_coeffmod(ciph, ciph_size, plain[mono_exponent],
                                                   mono_exponent, coeff_modulus, ciph, pool_);
        }
        return;
    }

    // Generic case: any plaintext polynomial
    // Allocate temporary space for an entire RNS polynomial
    auto temp(allocate_zero_poly(coeff_count, coeff_modulus_size, pool_));

    if (!context_data.using_fast_plain_lift())
    {
        StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

        POSEIDON_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count,
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

        context_data.rns_tool()->base_q()->decompose_array(temp_iter, coeff_count, pool_);
    }
    else
    {
        // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the
        // coeff_modulus primes.
        RNSIter temp_iter(temp.get(), coeff_count);
        POSEIDON_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size,
                         [&](auto I)
                         {
                             POSEIDON_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count,
                                              [&](auto J)
                                              {
                                                  get<0>(J) = POSEIDON_COND_SELECT(
                                                      get<1>(J) >= plain_upper_half_threshold,
                                                      get<1>(J) + get<1>(I), get<1>(J));
                                              });
                         });
    }

    // Need to multiply each component in ciph with temp; first step is to transform to NTT
    // form
    RNSIter temp_iter(temp.get(), coeff_count);
    ntt_negacyclic_harvey(temp_iter, coeff_modulus_size, ntt_tables);

    POSEIDON_ITERATE(iter(ciph), ciph_size,
                     [&](auto I)
                     {
                         POSEIDON_ITERATE(
                             iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size,
                             [&](auto J)
                             {
                                 // Lazy reduction
                                 ntt_negacyclic_harvey_lazy(get<0>(J), get<3>(J));
                                 dyadic_product_coeffmod(get<0>(J), get<1>(J), coeff_count,
                                                         get<2>(J), get<0>(J));
                                 inverse_ntt_negacyclic_harvey(get<0>(J), get<3>(J));
                             });
                     });
}

void EvaluatorBfvBase::multiply_by_diag_matrix_bsgs(const Ciphertext &ciph,
                                                    const MatrixPlain &plain_mat,
                                                    Ciphertext &result,
                                                    const GaloisKeys &rot_key) const
{
    auto poly_modulus_degree = ciph.poly_modulus_degree();
    auto poly_modulus_degree_div2 = poly_modulus_degree >> 1;
    auto [index, _, rot_n2] =
        bsgs_index(plain_mat.plain_vec, 1 << plain_mat.log_slots, plain_mat.n1);
    map<int, Ciphertext> rot_ciph;
    Ciphertext ciph_inner_sum, ciph_inner, ciph_inner_tmp;
    Ciphertext ciph_rrr;
    int z = 0;
    for (auto j : rot_n2)
    {
        if (j != 0)
        {
            rotate_row(ciph, rot_ciph[j], j, rot_key);
        }
    }

    int cnt0 = 0;
    for (const auto &j : index)
    {
        int cnt1 = 0;
        for (auto i : index[j.first])
        {
            if (i == 0)
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(ciph, plain_mat.plain_vec.at(j.first), result);
                    }
                    else
                    {
                        multiply_plain(ciph, plain_mat.plain_vec.at(j.first), ciph_inner_sum);
                    }
                }
                else
                {
                    multiply_plain(ciph, plain_mat.plain_vec.at(j.first), ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result, ciph_inner, result);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            else
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first), result);
                    }
                    else
                    {
                        multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first),
                                       ciph_inner_sum);
                    }
                }
                else
                {

                    multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first), ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result, ciph_inner, result);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            cnt1++;
        }
        if (cnt0 != 0)
        {
            auto step_src = j.first;
            if (j.first == (poly_modulus_degree_div2))
            {
                rotate_col(ciph_inner_sum, ciph_inner, rot_key);
            }
            else if (j.first > poly_modulus_degree_div2)
            {
                rotate_col(ciph_inner_sum, ciph_inner_tmp, rot_key);
                auto step = j.first - poly_modulus_degree_div2;
                rotate_row(ciph_inner_tmp, ciph_inner, step, rot_key);
            }
            else
            {
                rotate_row(ciph_inner_sum, ciph_inner, step_src, rot_key);
            }
            add(result, ciph_inner, result);
        }
        cnt0++;
    }
}

}  // namespace poseidon