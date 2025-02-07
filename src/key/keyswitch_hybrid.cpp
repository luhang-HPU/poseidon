#include "keyswitch_hybrid.h"
#include "src/util/debug.h"

using namespace poseidon::util;

namespace poseidon
{
void KSwitchGenHybrid::generate_one_kswitch_key(const SecretKey &prev_secret_key,
                                                ConstRNSIter new_key,
                                                vector<PublicKey> &destination) const
{
    auto global_context_data = context_.crt_context();
    size_t coeff_count = global_context_data->key_context_data()->parms().degree();
    auto &key_context_data = *global_context_data->key_context_data();
    auto &key_modulus = key_context_data.coeff_modulus();
    auto key_rns_qp = key_context_data.qp_rns_tool();
    auto base_q = key_rns_qp->base_q();
    auto base_q_size = key_rns_qp->base_q()->size();
    auto base_p_size = key_rns_qp->base_p()->size();
    auto p_mod_qi = key_context_data.qp_rns_tool()->p_mod_qi();
    auto decomp_count = ceil(static_cast<double>(base_q_size) / static_cast<double>(base_p_size));

    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    destination.resize(decomp_count);
    POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool_);
    for (size_t i = 0; i < decomp_count; ++i)
    {
        auto &ct = destination[i];
        encrypt_zero_symmetric(prev_secret_key, context_, key_context_data.parms().parms_id(), true,
                               false, ct.data());
        for (size_t k = 0; k < base_p_size; ++k)
        {
            auto idx = i * base_p_size + k;
            if (idx >= base_q_size)
            {
                break;
            }
            multiply_poly_scalar_coeffmod(new_key[idx], coeff_count, p_mod_qi[idx].operand,
                                          base_q->base()[idx], temp);
            add_poly_coeffmod(ct[0][idx].begin(), temp, coeff_count, base_q->base()[idx],
                              ct[0][idx].begin());
        }
    }
}

void KSwitchHybrid::apply_galois_inplace(Ciphertext &encrypted, uint32_t galois_elt,
                                         const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
{
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

    RNSPoly temp_poly(context_, encrypted.parms_id());
    auto temp = temp_poly[0];
    // POSEIDON_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);

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
    switch_key_inplace(encrypted, temp_poly, static_cast<const KSwitchKeys &>(galois_keys),
                       GaloisKeys::get_index(galois_elt), pool_);
}

void KSwitchHybrid::relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
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

    for (auto i = 0; i < relins_needed; ++i)
    {
        this->switch_key_inplace(encrypted, encrypted[encrypted_size - 1 - i],
                                 static_cast<const KSwitchKeys &>(relin_keys),
                                 RelinKeys::get_index(encrypted_size - 1 - i), pool);
    }
    encrypted.resize(context_, context_data_ptr->parms().parms_id(), destination_size);
}

void KSwitchHybrid::switch_key_inplace(Ciphertext &encrypted, RNSPoly &poly,
                                       const KSwitchKeys &kswitch_keys, std::size_t key_index,
                                       MemoryPoolHandle pool) const
{
    auto parms_id = encrypted.parms_id();
    auto &context_data = *context_.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto scheme = parms.scheme();
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

    auto &key_context_data = *context_.crt_context()->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto &key_modulus = key_context_data.coeff_modulus();
    auto coeff_count = context_data.parms().degree();
    auto ntt_table = context_.crt_context()->small_ntt_tables();
    auto encrypted_size = encrypted.size();
    auto rns_qp = context_data.qp_rns_tool();
    auto base_q = rns_qp->base_q();
    auto base_p = rns_qp->base_p();
    auto base_q_size = base_q->size();
    auto base_p_size = base_p->size();
    auto rns_p_offset = key_context_data.parms().q().size();
    auto decomp_count = ceil(static_cast<double>(base_q_size) / static_cast<double>(base_p_size));
    auto &modulus_p = key_parms.p();

    RNSPoly c2_intt(context_, parms_id);
    RNSPoly c2_ntt(context_, parms_id);

    if (scheme == CKKS || scheme == BGV)
    {
        c2_ntt.copy(poly);
        c2_intt.copy(poly);
        c2_intt.dot_to_coeff();
    }
    else if (scheme == BFV)
    {
        c2_ntt.copy(poly);
        c2_intt.copy(poly);
        c2_ntt.coeff_to_dot();
    }

    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp1, coeff_count, base_p_size, pool);
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp2, coeff_count, base_p_size, pool);
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp3, coeff_count, base_p_size, pool);
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp4, coeff_count, base_p_size, pool);
    auto t_poly_prod(allocate_zero_poly_array(decomp_count, coeff_count, base_q_size, pool));
    auto t_poly_prod_p(allocate_zero_poly_array(decomp_count, coeff_count, base_p_size, pool));

    PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, base_q_size);
    PolyIter t_poly_prod_p_iter(t_poly_prod_p.get(), coeff_count, base_p_size);

    vector<Ciphertext> ciph(decomp_count);
    for (size_t i = 0; i < decomp_count; ++i)
    {
        ciph[i].resize(context_, parms_id, 2);
        auto decomp_state =
            base_q_size > (base_p_size * (i + 1)) ? base_p_size : base_q_size % base_p_size;
        if (decomp_state == 1)
        {  // only one rns in Qi, copy to other rns
            rns_qp->mod_up_copy_q(c2_intt.const_poly_iter()[0], i, t_poly_prod_iter[i], pool);
            rns_qp->mod_up_from_one_base_q(t_poly_prod_iter[i], i, pool);
            rns_qp->mod_up_from_one_base_p(t_poly_prod_iter[i], i, t_poly_prod_p_iter[i], pool);
        }
        else
        {
            rns_qp->mod_up_copy_q(c2_intt.const_poly_iter()[0], i, t_poly_prod_iter[i], pool);
            rns_qp->mod_up_base_q(t_poly_prod_iter[i], i, pool);
            rns_qp->mod_up_base_p(t_poly_prod_iter[i], i, t_poly_prod_p_iter[i], pool);
        }
    }

    Ciphertext ciph_tmp, ciph_tmp2;
    ciph_tmp.resize(context_, parms_id, 2);
    ciph_tmp2.resize(context_, parms_id, 2);
    for (auto i = 0; i < decomp_count; ++i)
    {
        auto &keys = kswitch_keys.data()[key_index][i];
        RNSPoly poly_tmp(context_, *t_poly_prod_iter[i], parms_id);

        poly_tmp.coeff_to_dot();
        if (i == 0)
        {
            poly_tmp.multiply(keys[0], ciph_tmp[0]);
            poly_tmp.multiply(keys[1], ciph_tmp[1]);
        }
        else
        {
            // rns_q
            poly_tmp.multiply(keys[0], ciph_tmp2[0]);
            poly_tmp.multiply(keys[1], ciph_tmp2[1]);
            ciph_tmp[0].add(ciph_tmp2[0], ciph_tmp[0]);
            ciph_tmp[1].add(ciph_tmp2[1], ciph_tmp[1]);
        }

        // rns_p
        for (auto j = 0; j < base_p_size; j++)
        {
            ntt_negacyclic_harvey(t_poly_prod_p_iter[i][j], ntt_table[j + rns_p_offset]);
        }
        if (i == 0)
        {
            for (auto j = 0; j < base_p_size; j++)
            {
                dyadic_product_coeffmod(t_poly_prod_p_iter[i][j],
                                        keys[0].const_poly_iter()[0][j + rns_p_offset], coeff_count,
                                        modulus_p[j], tmp1[j]);
                dyadic_product_coeffmod(t_poly_prod_p_iter[i][j],
                                        keys[1].const_poly_iter()[0][j + rns_p_offset], coeff_count,
                                        modulus_p[j], tmp2[j]);
            }
        }
        else
        {
            for (auto j = 0; j < base_p_size; j++)
            {
                dyadic_product_coeffmod(t_poly_prod_p_iter[i][j],
                                        keys[0].const_poly_iter()[0][j + rns_p_offset], coeff_count,
                                        modulus_p[j], tmp3[j]);
                dyadic_product_coeffmod(t_poly_prod_p_iter[i][j],
                                        keys[1].const_poly_iter()[0][j + rns_p_offset], coeff_count,
                                        modulus_p[j], tmp4[j]);
                add_poly_coeffmod(tmp1[j], tmp3[j], coeff_count, modulus_p[j], tmp1[j]);
                add_poly_coeffmod(tmp2[j], tmp4[j], coeff_count, modulus_p[j], tmp2[j]);
            }
        }
    }

    ciph_tmp[0].dot_to_coeff();
    ciph_tmp[1].dot_to_coeff();
    for (auto i = 0; i < base_p_size; i++)
    {
        inverse_ntt_negacyclic_harvey(tmp1[i], ntt_table[i + rns_p_offset]);
        inverse_ntt_negacyclic_harvey(tmp2[i], ntt_table[i + rns_p_offset]);
    }

    rns_qp->mod_down(ciph_tmp[0][0], tmp1, ciph_tmp[0][0], pool);
    rns_qp->mod_down(ciph_tmp[1][0], tmp2, ciph_tmp[1][0], pool);

    if (scheme == CKKS || scheme == BGV)
    {
        ciph_tmp[0].coeff_to_dot();
        ciph_tmp[1].coeff_to_dot();
    }

    encrypted[0].add(ciph_tmp[0], encrypted[0]);
    if (encrypted_size > 2)
    {
        encrypted[1].add(ciph_tmp[1], encrypted[1]);
    }
    else
    {
        encrypted[1].copy(ciph_tmp[1]);
    }
}
}  // namespace poseidon