#include "keyswitch_base.h"
#include "src/factory/poseidon_factory.h"
#include "src/util/thread_pool.h"
#ifdef USING_HARDWARE
#include "poseidon_hardware/hardware_drive/ckks_hardware_api.h"
#endif

namespace poseidon
{
secret_key_array_type KSwitchGenBase::compute_secret_key_array(const SecretKey &init_secret_key,
                                                               size_t max_power) const
{
    if (max_power < 1)
    {
        POSEIDON_THROW(invalid_argument_error, "max_power must be at least 1");
    }

    // Extract encryption parameters.
    auto gloabal_context_data = context_.crt_context().get();

    auto &parms = gloabal_context_data->key_context_data()->parms();
    auto &coeff_modulus = gloabal_context_data->key_context_data()->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size, max_power))
    {
        throw logic_error("invalid parameters");
    }

    ReaderLock reader_lock(secret_key_array_locker_.acquire_read());

    size_t old_size = 1;
    size_t new_size = max(max_power, old_size);

    auto secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
    set_poly(init_secret_key.data().data(), coeff_count, coeff_modulus_size,
             secret_key_array_.get());
    size_t secret_key_array_size_ = 1;

    if (old_size == new_size)
    {
        return secret_key_array_;
    }

    reader_lock.unlock();

    // Need to extend the array
    // Compute powers of secret key until max_power
    auto secret_key_array(allocate_poly_array(new_size, coeff_count, coeff_modulus_size, pool_));
    set_poly_array(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size,
                   secret_key_array.get());
    RNSIter secret_key(secret_key_array.get(), coeff_count);

    PolyIter secret_key_power(secret_key_array.get(), coeff_count, coeff_modulus_size);
    secret_key_power += (old_size - 1);
    auto next_secret_key_power = secret_key_power + 1;

    // Since all of the key powers in secret_key_array_ are already NTT transformed, to get the next
    // one we simply need to compute a dyadic product of the last one with the first one [which is
    // equal to NTT(secret_key_)].
    POSEIDON_ITERATE(iter(secret_key_power, next_secret_key_power), new_size - old_size,
                     [&](auto I)
                     {
                         dyadic_product_coeffmod(get<0>(I), secret_key, coeff_modulus_size,
                                                 coeff_modulus, get<1>(I));
                     });

    // Take writer lock to update array
    WriterLock writer_lock(secret_key_array_locker_.acquire_write());

    // Do we still need to update size?
    old_size = secret_key_array_size_;
    new_size = max(max_power, secret_key_array_size_);

    if (old_size == new_size)
    {
        return secret_key_array_;
    }

    // Acquire new array
    secret_key_array_.acquire(secret_key_array);
    return secret_key_array_;
}

// encrypt prev_secret_key with new_secret_key
KSwitchKeys KSwitchGenBase::create_switch_key(const SecretKey &prev_secret_key,
                                              const SecretKey &new_secret_key) const
{
    if (!prev_secret_key.data().is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "prev_secret_key is not ntt form!");
    }

    if (!new_secret_key.data().is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "new_secret_key is not ntt form!");
    }

    auto prev_poly_degree = prev_secret_key.data().coeff_count();
    auto new_poly_degree = new_secret_key.data().coeff_count();
    if (prev_poly_degree != new_poly_degree)
    {
        POSEIDON_THROW(invalid_argument_error, "Different degree switch key is not supported!");
    }

    auto global_context_data = context_.crt_context();
    auto key_context_data = global_context_data->key_context_data();
    auto degree = key_context_data->parms().degree();
    auto coeff_modulus_size = key_context_data->coeff_modulus().size();
    size_t num_keys = 1;
    KSwitchKeys destination;

    generate_kswitch_keys(new_secret_key, prev_secret_key.poly().const_poly_iter(), 1, destination);
    destination.parms_id() = key_context_data->parms().parms_id();

    return destination;
}

KSwitchKeys KSwitchGenBase::create_switch_key(const SecretKey &prev_key,
                                              const PublicKey &new_key) const
{
    return {};
}

// encrypt power new_keys with prev_secret_key
RelinKeys KSwitchGenBase::create_relin_keys(std::size_t count,
                                            const SecretKey &prev_secret_key) const
{

    // Extract encryption parameters.
    auto global_context_data = context_.crt_context().get();
    auto &context_data = *global_context_data->key_context_data();
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = context_data.coeff_modulus().size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    // Make sure we have enough secret keys computed
    auto secret_key_array_ = compute_secret_key_array(prev_secret_key, count + 1);

    // Create the RelinKeys object to return
    RelinKeys relin_keys;

    // Assume the secret key is already transformed into NTT form.
    ConstPolyIter secret_key(secret_key_array_.get(), coeff_count, coeff_modulus_size);
    generate_kswitch_keys(prev_secret_key, secret_key + 1, count,
                          static_cast<KSwitchKeys &>(relin_keys));
    // Set the parms_id
    relin_keys.parms_id() = context_data.parms().parms_id();

#ifdef USING_HARDWARE
    if (PoseidonFactory::get_instance()->get_device_type() == DEVICE_TYPE::DEVICE_HARDWARE)
    {
        auto literal = context_.parameters_literal();
        auto degree = literal->degree();
        auto rns_max = literal->q().size() + literal->p().size();
        HardwareApi::relin_key_config(relin_keys, rns_max, degree);
    }
#endif
    return relin_keys;
}

RelinKeys KSwitchGenBase::create_relin_keys(const SecretKey &prev_secret_key) const
{
    return create_relin_keys(1, prev_secret_key);
}
GaloisKeys KSwitchGenBase::create_galois_keys(const std::vector<int> &steps,
                                              const SecretKey &prev_secret_key) const
{
    auto GaloisKeys = create_galois_keys(
        context_.crt_context()->galois_tool()->get_elts_from_steps(steps), prev_secret_key);
    return GaloisKeys;
}
GaloisKeys KSwitchGenBase::create_galois_keys(const std::vector<uint32_t> &galois_elts,
                                              const SecretKey &prev_secret_key) const
{
    // Check to see if secret key and public key have been generated

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    auto galois_tool = context_.crt_context()->galois_tool();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }

    // Create the GaloisKeys object to return
    GaloisKeys galois_keys;

    // The max number of keys is equal to number of coefficients
    galois_keys.data().resize(coeff_count);

    for (auto galois_elt : galois_elts)
    {
        // Verify coprime conditions.
        if (!(galois_elt & 1) || (galois_elt >= coeff_count << 1))
        {
            POSEIDON_THROW(invalid_argument_error, "Galois element is not valid");
        }

        // Do we already have the key?
        if (galois_keys.has_key(galois_elt))
        {
            continue;
        }

        // Rotate secret key for each coeff_modulus
        POSEIDON_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count, coeff_modulus_size, pool_);
        ConstRNSIter secret_key(prev_secret_key.data().data(), coeff_count);
        galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, galois_elt,
                                      rotated_secret_key);

        // Initialize Galois key
        // This is the location in the galois_keys vector
        size_t index = GaloisKeys::get_index(galois_elt);

        // Create Galois keys.
        generate_one_kswitch_key(prev_secret_key, rotated_secret_key, galois_keys.data()[index]);
        // Set the parms_id
        galois_keys.parms_id() = context_data.parms().parms_id();

        return galois_keys;
    }

GaloisKeys KSwitchGenBase::create_galois_keys_mt(const std::vector<uint32_t> &galois_elts,
                                              const SecretKey &prev_secret_key) const
{
    // Check to see if secret key and public key have been generated

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    auto galois_tool = context_.crt_context()->galois_tool();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }

    // Create the GaloisKeys object to return
    GaloisKeys galois_keys;

    // The max number of keys is equal to number of coefficients
    galois_keys.data().resize(coeff_count);

    int num_threads = 8;
    ThreadPool thread_pool(num_threads);
    std::mutex mtx;  // 如果需要保护共享资源才用

    const int work_load = (galois_elts.size() + num_threads - 1) / num_threads;

    for (int t = 0; t < num_threads; ++t)
    {
        int s = t * work_load;
        int e = std::min<int>(galois_elts.size(), s + work_load);

        thread_pool.enqueue(
            [&, s, e]()
            {
                for (int i = s; i < e; ++i)
                {
                    auto galois_elt = galois_elts[i];

                    // Verify coprime conditions.
                    if (!(galois_elt & 1) || (galois_elt >= (coeff_count << 1)))
                    {
                        POSEIDON_THROW(invalid_argument_error, "Galois element is not valid");
                    }

                    // Do we already have the key?
                    if (galois_keys.has_key(galois_elt))
                    {
                        continue;
                    }

                    // Rotate secret key for each coeff_modulus
                    POSEIDON_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count,
                                                   coeff_modulus_size, pool_);
                    ConstRNSIter secret_key(prev_secret_key.data().data(), coeff_count);
                    galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, galois_elt,
                                                  rotated_secret_key);

                    // Initialize Galois key
                    size_t index = GaloisKeys::get_index(galois_elt);

                    // 如果每个 index 都是唯一的，可以不用锁
                    generate_one_kswitch_key(prev_secret_key, rotated_secret_key,
                                             galois_keys.data()[index]);
                }
            });
    }

    // Set the parms_id
    galois_keys.parms_id() = context_data.parms().parms_id();

    return galois_keys;
}

void KSwitchGenBase::generate_kswitch_keys(const SecretKey &prev_secret_key, ConstPolyIter new_keys,
                                           size_t num_keys, KSwitchKeys &destination) const
{
    size_t coeff_count = context_.crt_context()->key_context_data()->parms().degree();
    auto &key_context_data = *context_.crt_context()->key_context_data();
    auto &key_parms = key_context_data.parms();
    size_t coeff_modulus_size = key_context_data.coeff_modulus().size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size, num_keys))
    {
        throw logic_error("invalid parameters");
    }

    destination.data().resize(num_keys);
    POSEIDON_ITERATE(iter(new_keys, destination.data()), num_keys, [&](auto I)
                     { this->generate_one_kswitch_key(prev_secret_key, get<0>(I), get<1>(I)); });
}

void KSwitchBase::switch_key(const Ciphertext &encrypted, const KSwitchKeys &switch_keys,
                             Ciphertext &destination) const
{
}

void KSwitchBase::rotate(const Ciphertext &encrypted, Ciphertext &destination, int steps,
                         const GaloisKeys &galois_keys) const
{
    destination = encrypted;
    rotate_internal(destination, steps, galois_keys);
}
void KSwitchBase::conjugate(const Ciphertext &encrypted, const GaloisKeys &galois_keys,
                            Ciphertext &destination) const
{
    if (context_.crt_context()->key_context_data()->parms().scheme() != CKKS)
    {
        throw std::logic_error("unsupported scheme");
    }
    destination = encrypted;
    conjugate_internal(destination, galois_keys);
}
void KSwitchBase::relinearize(const Ciphertext &encrypted, Ciphertext &destination,
                              const RelinKeys &relin_keys) const
{
    destination = encrypted;
    relinearize_inplace(destination, relin_keys, pool_);
}

void KSwitchBase::conjugate_internal(Ciphertext &encrypted, const GaloisKeys &galois_keys,
                                     MemoryPoolHandle pool) const
{
    // Verify parameters.
    auto context_data_ptr = context_.crt_context()->get_context_data(encrypted.parms_id());
    if (!context_data_ptr)
    {
        throw std::invalid_argument("encrypted is not valid for encryption parameters");
    }

    // Extract encryption parameters.
    auto &context_data = *context_data_ptr;
    auto galois_tool = context_.crt_context()->galois_tool();

    // Perform rotation and key switching
    apply_galois_inplace(encrypted, galois_tool->get_elt_from_step(0), galois_keys,
                         std::move(pool));
}

void KSwitchBase::rotate_internal(Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys,
                                  MemoryPoolHandle pool) const
{
    auto context_data_ptr = context_.crt_context()->get_context_data(encrypted.parms_id());
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted is not valid for encryption parameters");
    }

    if (galois_keys.parms_id() != context_.crt_context()->key_parms_id())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "galois_keys is not valid for encryption parameters");
    }

    // Is there anything to do?
    if (steps == 0)
    {
        return;
    }

    size_t coeff_count = context_data_ptr->parms().degree();
    auto galois_tool = context_.crt_context()->galois_tool();

    // Check if Galois key is generated or not.
    if (galois_keys.has_key(galois_tool->get_elt_from_step(steps)))
    {
        // Perform rotation and key switching
        apply_galois_inplace(encrypted, galois_tool->get_elt_from_step(steps), galois_keys,
                             move(pool));
    }
    else
    {
        // Convert the steps to NAF: guarantees using smallest HW
        vector<int> naf_steps = naf(steps);

        // If naf_steps contains only one element, then this is a power-of-two
        // rotation and we would have expected not to get to this part of the
        // if-statement.
        if (naf_steps.size() == 1)
        {
            POSEIDON_THROW(invalid_argument_error, "Galois key not present");
        }

        POSEIDON_ITERATE(naf_steps.cbegin(), naf_steps.size(),
                         [&](auto step)
                         {
                             // We might have a NAF-term of size coeff_count / 2; this corresponds
                             // to no rotation so we skip it. Otherwise call rotate_internal.
                             if (safe_cast<size_t>(abs(step)) != (coeff_count >> 1))
                             {
                                 // Apply rotation for this step
                                 this->rotate_internal(encrypted, step, galois_keys, pool);
                             }
                         });
    }
}

}  // namespace poseidon