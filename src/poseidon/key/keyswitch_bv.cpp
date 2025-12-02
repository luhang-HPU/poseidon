#include "keyswitch_bv.h"

using namespace poseidon::util;

namespace poseidon
{
void KSwitchGenBV::generate_one_kswitch_key(const SecretKey &prev_secret_key, ConstRNSIter new_key,
                                            vector<PublicKey> &destination) const
{
    auto global_context_data = context_.crt_context();
    size_t coeff_count = global_context_data->key_context_data()->parms().degree();
    size_t decomp_mod_count = global_context_data->first_context_data()->coeff_modulus().size();
    auto &key_context_data = *global_context_data->key_context_data();
    auto &key_modulus = key_context_data.coeff_modulus();

    // Size check
    if (!product_fits_in(coeff_count, decomp_mod_count))
    {
        throw logic_error("invalid parameters");
    }

    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    destination.resize(decomp_mod_count);

    POSEIDON_ITERATE(
        iter(new_key, key_modulus, destination, size_t(0)), decomp_mod_count,
        [&](auto I)
        {
            POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool_);
            encrypt_zero_symmetric(prev_secret_key, context_, key_context_data.parms().parms_id(),
                                   true, false, get<2>(I).data());
            uint64_t factor = barrett_reduce_64(key_modulus.back().value(), get<1>(I));
            multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, factor, get<1>(I), temp);

            // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination
            // polynomial.
            CoeffIter destination_iter = (*iter(get<2>(I).data()))[get<3>(I)];
            add_poly_coeffmod(destination_iter, temp, coeff_count, get<1>(I), destination_iter);
        });
}

void KSwitchBV::relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
                                     size_t destination_size, MemoryPoolHandle pool) const
{
    // Verify parameters.
    auto context_data_ptr = context_.crt_context()->get_context_data(encrypted.parms_id());
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted is not valid for encryption parameters");
    }
    if (relin_keys.parms_id() != context_.crt_context()->key_parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "relin_keys is not valid for encryption parameters");
    }

    size_t encrypted_size = encrypted.size();

    // Verify parameters.
    if (destination_size < 2 || destination_size > encrypted_size)
    {
        POSEIDON_THROW(
            invalid_argument_error,
            "destination_size must be at least 2 and less than or equal to current count");
    }
    if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
    {
        POSEIDON_THROW(invalid_argument_error, "not enough relinearization keys");
    }

    // If encrypted is already at the desired level, return
    if (destination_size == encrypted_size)
    {
        return;
    }

    // Calculate number of relinearize_one_step calls needed
    size_t relins_needed = encrypted_size - destination_size;

    // Iterator pointing to the last component of encrypted
    auto encrypted_iter = iter(encrypted);
    encrypted_iter += encrypted_size - 1;

    POSEIDON_ITERATE(iter(size_t(0)), relins_needed,
                     [&](auto I)
                     {
                         this->switch_key_inplace(encrypted, *encrypted_iter,
                                                  static_cast<const KSwitchKeys &>(relin_keys),
                                                  RelinKeys::get_index(encrypted_size - 1 - I),
                                                  pool);
                     });

    // Put the output of final relinearization into destination.
    // Prepare destination only at this point because we are resizing down
    encrypted.resize(context_, context_data_ptr->parms().parms_id(), destination_size);
}

void KSwitchBV::apply_galois_inplace(Ciphertext &encrypted, uint32_t galois_elt,
                                     const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
{
    // Don't validate all of galois_keys but just check the parms_id.
    if (galois_keys.parms_id() != context_.crt_context()->key_parms_id())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "galois_keys is not valid for encryption parameters");
    }

    auto &context_data = *context_.crt_context()->get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t encrypted_size = encrypted.size();
    // Use key_context_data where permutation tables exist since previous runs.
    auto galois_tool = context_.crt_context()->galois_tool();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    // Check if Galois key is generated or not.
    if (!galois_keys.has_key(galois_elt))
    {
        POSEIDON_THROW(invalid_argument_error, "Galois key not present");
    }

    uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));

    // Verify parameters
    if (!(galois_elt & 1) || unsigned_geq(galois_elt, m))
    {
        POSEIDON_THROW(invalid_argument_error, "Galois element is not valid");
    }
    if (encrypted_size > 2)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted size must be 2");
    }

    POSEIDON_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);

    // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
    // BEGIN: Apply Galois for each ciphertext
    // Execution order is sensitive, since apply_galois is not inplace!
    if (parms.scheme() == BFV)
    {
        // !!! DO NOT CHANGE EXECUTION ORDER!!!

        // First transform encrypted.data(0)
        auto encrypted_iter = iter(encrypted);
        galois_tool->apply_galois(encrypted_iter[0], coeff_modulus_size, galois_elt, coeff_modulus,
                                  temp);

        // Copy result to encrypted.data(0)
        set_poly(temp, coeff_count, coeff_modulus_size, encrypted.data(0));

        // Next transform encrypted.data(1)
        galois_tool->apply_galois(encrypted_iter[1], coeff_modulus_size, galois_elt, coeff_modulus,
                                  temp);
    }
    else if (parms.scheme() == CKKS || parms.scheme() == BGV)
    {
        // !!! DO NOT CHANGE EXECUTION ORDER!!!

        // First transform encrypted.data(0)
        auto encrypted_iter = iter(encrypted);
        galois_tool->apply_galois_ntt(encrypted_iter[0], coeff_modulus_size, galois_elt, temp);

        // Copy result to encrypted.data(0)
        set_poly(temp, coeff_count, coeff_modulus_size, encrypted.data(0));

        // Next transform encrypted.data(1)
        galois_tool->apply_galois_ntt(encrypted_iter[1], coeff_modulus_size, galois_elt, temp);
    }
    else
    {
        throw logic_error("scheme not implemented");
    }

    // Wipe encrypted.data(1)
    set_zero_poly(coeff_count, coeff_modulus_size, encrypted.data(1));

    // END: Apply Galois for each ciphertext
    // REORDERING IS SAFE NOW

    // Calculate (temp * galois_keys[0], temp * galois_keys[1]) + (ct[0], 0)
    switch_key_inplace(encrypted, temp, static_cast<const KSwitchKeys &>(galois_keys),
                       GaloisKeys::get_index(galois_elt), pool_);
#ifdef POSEIDON_THROW_ON_TRANSPARENT_CIPHERTEXT
    // Transparent ciphertext output is not allowed.
    if (encrypted.is_transparent())
    {
        throw logic_error("result ciphertext is transparent");
    }
#endif
}

void KSwitchBV::switch_key_inplace(Ciphertext &encrypted, ConstRNSIter target_iter,
                                   const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
                                   MemoryPoolHandle pool) const
{

    auto parms_id = encrypted.parms_id();
    auto &context_data = *context_.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &key_context_data = *context_.crt_context()->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto scheme = parms.scheme();

    // Don't validate all of kswitch_keys but just check the parms_id.
    if (kswitch_keys.parms_id() != context_.crt_context()->key_parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "parameter mismatch");
    }

    if (kswitch_keys_index >= kswitch_keys.data().size())
    {
        throw out_of_range("kswitch_keys_index");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }
    if (scheme == BFV && encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV encrypted cannot be in NTT form");
    }
    if (scheme == CKKS && !encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks encrypted must be in NTT form");
    }
    if (scheme == BGV && !encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV encrypted must be in NTT form");
    }

    // Extract encryption parameters.
    size_t coeff_count = parms.degree();
    size_t decomp_modulus_size = context_data.coeff_modulus().size();
    auto &key_modulus = key_context_data.coeff_modulus();
    size_t key_modulus_size = key_modulus.size();
    size_t rns_modulus_size = decomp_modulus_size + 1;
    auto key_ntt_tables = iter(context_.crt_context()->small_ntt_tables());
    auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

    // Size check
    if (!product_fits_in(coeff_count, rns_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }

    // Prepare input
    auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
    size_t key_component_count = key_vector[0].data().size();

    // Create a copy of target_iter
    POSEIDON_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
    set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

    // In ckks or BGV, t_target is in NTT form; switch back to normal form
    if (scheme == CKKS || scheme == BGV)
    {
        inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);
    }

    // Temporary result
    auto t_poly_prod(
        allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

    POSEIDON_ITERATE(
        iter(size_t(0)), rns_modulus_size,
        [&](auto I)
        {
            size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them
            // without reduction.
            size_t lazy_reduction_summand_bound = size_t(POSEIDON_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            auto t_poly_lazy(allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS
            // factor
            PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

            // Multiply with keys and perform lazy reduction on product's coefficients
            POSEIDON_ITERATE(
                iter(size_t(0)), decomp_modulus_size,
                [&](auto J)
                {
                    POSEIDON_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                    ConstCoeffIter t_operand;

                    // RNS-NTT form exists in input
                    if ((scheme == CKKS || scheme == BGV) && (I == J))
                    {
                        t_operand = target_iter[J];
                    }
                    // Perform RNS-NTT conversion
                    else
                    {
                        // No need to perform RNS conversion (modular reduction)
                        if (key_modulus[J] <= key_modulus[key_index])
                        {
                            set_uint(t_target[J], coeff_count, t_ntt);
                        }
                        // Perform RNS conversion (modular reduction)
                        else
                        {
                            modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index],
                                               t_ntt);
                        }
                        // NTT conversion lazy outputs in [0, 4q)
                        ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                        t_operand = t_ntt;
                    }

                    // Multiply with keys and modular accumulate products in a lazy fashion
                    POSEIDON_ITERATE(
                        iter(key_vector[J].data(), accumulator_iter), key_component_count,
                        [&](auto K)
                        {
                            if (!lazy_reduction_counter)
                            {
                                POSEIDON_ITERATE(
                                    iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count,
                                    [&](auto L)
                                    {
                                        unsigned long long qword[2]{0, 0};
                                        multiply_uint64(get<0>(L), get<1>(L), qword);

                                        // Accumulate product of t_operand and t_key_acc to
                                        // t_poly_lazy and reduce
                                        add_uint128(qword, get<2>(L).ptr(), qword);
                                        get<2>(L)[0] =
                                            barrett_reduce_128(qword, key_modulus[key_index]);
                                        get<2>(L)[1] = 0;
                                    });
                            }
                            else
                            {
                                // Same as above but no reduction
                                POSEIDON_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)),
                                                 coeff_count,
                                                 [&](auto L)
                                                 {
                                                     unsigned long long qword[2]{0, 0};
                                                     multiply_uint64(get<0>(L), get<1>(L), qword);
                                                     add_uint128(qword, get<2>(L).ptr(), qword);
                                                     get<2>(L)[0] = qword[0];
                                                     get<2>(L)[1] = qword[1];
                                                 });
                            }
                        });

                    if (!--lazy_reduction_counter)
                    {
                        lazy_reduction_counter = lazy_reduction_summand_bound;
                    }
                });

            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count,
                                      rns_modulus_size);

            // Final modular reduction
            POSEIDON_ITERATE(
                iter(accumulator_iter, t_poly_prod_iter), key_component_count,
                [&](auto K)
                {
                    if (lazy_reduction_counter == lazy_reduction_summand_bound)
                    {
                        POSEIDON_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count,
                                         [&](auto L)
                                         { get<1>(L) = static_cast<uint64_t>(*get<0>(L)); });
                    }
                    else
                    {
                        // Same as above except need to still do reduction
                        POSEIDON_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count,
                                         [&](auto L) {
                                             get<1>(L) = barrett_reduce_128(get<0>(L).ptr(),
                                                                            key_modulus[key_index]);
                                         });
                    }
                });
        });
    // Accumulated products are now stored in t_poly_prod

    // Perform modulus switching with scaling
    PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
    POSEIDON_ITERATE(
        iter(encrypted, t_poly_prod_iter), key_component_count,
        [&](auto I)
        {
            if (scheme == BGV)
            {
                const Modulus &plain_modulus = parms.plain_modulus();
                // qk is the special prime
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_inv_qp =
                    context_.crt_context()->key_context_data()->rns_tool()->inv_q_last_mod_t();

                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey(t_last, key_ntt_tables[key_modulus_size - 1]);

                POSEIDON_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
                modulo_poly_coeffs(t_last, coeff_count, plain_modulus, k);
                negate_poly_coeffmod(k, coeff_count, plain_modulus, k);
                if (qk_inv_qp != 1)
                {
                    multiply_poly_scalar_coeffmod(k, coeff_count, qk_inv_qp, plain_modulus, k);
                }

                POSEIDON_ALLOCATE_ZERO_GET_COEFF_ITER(delta, coeff_count, pool);
                POSEIDON_ALLOCATE_ZERO_GET_COEFF_ITER(c_mod_qi, coeff_count, pool);
                POSEIDON_ITERATE(
                    iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size,
                    [&](auto J)
                    {
                        // delta = k mod q_i
                        modulo_poly_coeffs(k, coeff_count, get<1>(J), delta);
                        // delta = k * q_k mod q_i
                        multiply_poly_scalar_coeffmod(delta, coeff_count, qk, get<1>(J), delta);

                        // c mod q_i
                        modulo_poly_coeffs(t_last, coeff_count, get<1>(J), c_mod_qi);
                        // delta = c + k * q_k mod q_i
                        // c_{i} = c_{i} - delta mod q_i
                        POSEIDON_ITERATE(iter(delta, c_mod_qi), coeff_count,
                                         [&](auto K) {
                                             get<0>(K) =
                                                 add_uint_mod(get<0>(K), get<1>(K), get<1>(J));
                                         });
                        ntt_negacyclic_harvey(delta, get<3>(J));
                        POSEIDON_ITERATE(iter(delta, get<0, 1>(J)), coeff_count,
                                         [&](auto K) {
                                             get<1>(K) =
                                                 sub_uint_mod(get<1>(K), get<0>(K), get<1>(J));
                                         });

                        multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<2>(J),
                                                      get<1>(J), get<0, 1>(J));

                        add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J),
                                          get<0, 0>(J));
                    });
            }
            else
            {
                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

                // Add (p-1)/2 to change from flooring to rounding.
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_half = qk >> 1;
                POSEIDON_ITERATE(
                    t_last, coeff_count,
                    [&](auto &J)
                    { J = barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]); });

                POSEIDON_ITERATE(
                    iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size,
                    [&](auto J)
                    {
                        POSEIDON_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                        // (ct mod 4qk) mod qi
                        uint64_t qi = get<1>(J).value();
                        if (qk > qi)
                        {
                            // This cannot be spared. NTT only tolerates input that is less
                            // than 4*modulus (i.e. qk <=4*qi).
                            modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                        }
                        else
                        {
                            set_uint(t_last, coeff_count, t_ntt);
                        }

                        // Lazy substraction, results in [0, 2*qi), since fix is in [0,
                        // qi].
                        uint64_t fix = qi - barrett_reduce_64(qk_half, get<1>(J));
                        POSEIDON_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                        uint64_t qi_lazy = qi << 1;  // some multiples of qi
                        if (scheme == CKKS)
                        {
                            // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                            ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if POSEIDON_USER_MOD_BIT_COUNT_MAX > 60
                            // Reduce from [0, 4qi) to [0, 2qi)
                            POSEIDON_ITERATE(t_ntt, coeff_count,
                                             [&](auto &K) {
                                                 K -=
                                                     POSEIDON_COND_SELECT(K >= qi_lazy, qi_lazy, 0);
                                             });
#else
                            // Since poseidon uses at most 60bit moduli, 8*qi < 2^63.
                            qi_lazy = qi << 2;
#endif
                        }
                        else if (scheme == BFV)
                        {
                            inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));
                        }

                        // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 *
                        // qi_lazy)
                        POSEIDON_ITERATE(iter(get<0, 1>(J), t_ntt), coeff_count,
                                         [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                        // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                        multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J),
                                                      get<1>(J), get<0, 1>(J));
                        add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J),
                                          get<0, 0>(J));
                    });
            }
        });
}

void KSwitchBV::switch_key_internal(Ciphertext &encrypted, const KSwitchKeys &switch_keys, 
                                    MemoryPoolHandle pool) const {
    Ciphertext copy = encrypted;
    auto ct_in_iter = util::iter(copy);
    ct_in_iter += encrypted.size() - 1;
    poseidon::util::set_zero_poly(encrypted.poly_modulus_degree(), 1, encrypted.data(1)); 
    switch_key_inplace(encrypted, *ct_in_iter, static_cast<const KSwitchKeys &>(switch_keys), 0);
}

}  // namespace poseidon