#include "keyswitch_ghs.h"
// #include "poseidon/util/debug.h"

namespace poseidon
{
void KSwitchGenGHS::generate_one_kswitch_key(const SecretKey &prev_secret_key, ConstRNSIter new_key,
                                             vector<PublicKey> &destination) const
{
    auto global_context_data = context_.crt_context();
    size_t coeff_count = global_context_data->key_context_data()->parms().degree();
    size_t decomp_mod_count = 1;
    auto &key_context_data = *global_context_data->key_context_data();
    auto &key_modulus_q = key_context_data.parms().q();
    auto &key_modulus_p = key_context_data.parms().p();

    // Size check
    if (!product_fits_in(coeff_count, decomp_mod_count))
    {
        throw logic_error("invalid parameters");
    }
    auto p_mod_qi = key_context_data.qp_rns_tool()->p_mod_qi();
    auto base_q = key_context_data.qp_rns_tool()->base_q();
    auto base_q_size = base_q->size();
    // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
    destination.resize(1);
    auto &ct = destination[0].data();
    encrypt_zero_symmetric(prev_secret_key, context_, key_context_data.parms().parms_id(), true,
                           false, ct);
    for (auto i = 0; i < base_q_size; i++)
    {
        POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool_);
        multiply_poly_scalar_coeffmod(new_key[i], coeff_count, p_mod_qi[i].operand,
                                      base_q->base()[i], temp);
        add_poly_coeffmod(ct[0][i].begin(), temp, coeff_count, base_q->base()[i], ct[0][i].begin());
    }
}

void KSwitchGHS::relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
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

void KSwitchGHS::switch_key_inplace(Ciphertext &encrypted, RNSPoly &poly,
                                    const KSwitchKeys &kswitch_keys, std::size_t key_index,
                                    MemoryPoolHandle pool) const
{

    auto parms_id = encrypted.parms_id();
    auto &context_data = *context_.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &key_context_data = *context_.crt_context()->key_context_data();
    auto &key_parms = key_context_data.parms();
    auto scheme = parms.scheme();
    auto coeff_count = context_data.parms().degree();
    auto rns_qp = context_data.qp_rns_tool();
    auto ntt_table = context_.crt_context()->small_ntt_tables();
    auto encrypted_size = encrypted.size();
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

    auto rns_p_offset = key_context_data.parms().q().size();
    auto base_q_size = rns_qp->base_q()->size();
    auto base_p_size = rns_qp->base_p()->size();
    // cout << "tmp : " <<  key_index << endl;

    auto coeff_modulus_size = rns_qp->base_qp()->size();
    auto &keys = kswitch_keys.data()[key_index][0];
    auto &modulus_p = key_parms.p();
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp, coeff_count, base_p_size, pool);
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp1, coeff_count, base_p_size, pool);
    POSEIDON_ALLOCATE_GET_RNS_ITER(tmp2, coeff_count, base_p_size, pool);

    Ciphertext ciph_tmp;
    ciph_tmp.resize(context_, parms_id, 2);
    ciph_tmp.is_ntt_form() = true;

    if (scheme == CKKS || scheme == BGV)
    {
        RNSPoly poly_copy(context_, parms_id);
        poly_copy.copy(poly);
        poly_copy.dot_to_coeff();
        rns_qp->mod_up(poly_copy.const_poly_iter()[0], tmp, pool);
    }
    else if (scheme == BFV)
    {
        rns_qp->mod_up(poly.const_poly_iter()[0], tmp, pool);
        poly.coeff_to_dot();
    }

    for (auto i = 0; i < base_p_size; i++)
    {
        ntt_negacyclic_harvey(tmp[i], ntt_table[i + rns_p_offset]);
    }
    // key[j] * c2
    poly.multiply(keys[0], ciph_tmp[0]);
    poly.multiply(keys[1], ciph_tmp[1]);

    for (auto i = 0; i < base_p_size; i++)
    {
        dyadic_product_coeffmod(tmp[i], keys[0].const_poly_iter()[0][i + rns_p_offset], coeff_count,
                                modulus_p[i], tmp1[i]);
        dyadic_product_coeffmod(tmp[i], keys[1].const_poly_iter()[0][i + rns_p_offset], coeff_count,
                                modulus_p[i], tmp2[i]);
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

void KSwitchGHS::apply_galois_inplace(Ciphertext &encrypted, uint32_t galois_elt,
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
}  // namespace poseidon