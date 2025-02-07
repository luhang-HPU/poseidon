#pragma once

#include "keys.h"
#include "kswitchkeys.h"
#include "src/basics/util/polyarithsmallmod.h"
#include <algorithm>

namespace poseidon
{
using secret_key_array_type = util::Pointer<std::uint64_t>;

class KSwitchGenBase
{
public:
    inline explicit KSwitchGenBase(const PoseidonContext &context,
                                   MemoryPoolHandle pool = MemoryManager::GetPool())
        : context_(context), pool_(std::move(pool))
    {
    }
    ~KSwitchGenBase() = default;

public:
    KSwitchKeys create_switch_key(const SecretKey &prev_secret_key,
                                  const SecretKey &new_secret_key) const;
    KSwitchKeys create_switch_key(const SecretKey &prev_key, const PublicKey &new_key) const;
    RelinKeys create_relin_keys(std::size_t count, const SecretKey &prev_secret_key) const;
    RelinKeys create_relin_keys(const SecretKey &prev_secret_key) const;
    GaloisKeys create_galois_keys(const std::vector<int> &steps,
                                  const SecretKey &prev_secret_key) const;
    GaloisKeys create_galois_keys(const std::vector<uint32_t> &galois_elts,
                                  const SecretKey &prev_secret_key) const;
    void generate_kswitch_keys(const SecretKey &prev_secret_key, ConstPolyIter new_keys,
                               size_t num_keys, KSwitchKeys &destination) const;
    secret_key_array_type compute_secret_key_array(const SecretKey &init_secret_key,
                                                   size_t max_power) const;

protected:
    virtual void generate_one_kswitch_key(const SecretKey &prev_secret_key, ConstRNSIter new_key,
                                          vector<PublicKey> &destination) const = 0;

protected:
    PoseidonContext context_;
    MemoryPoolHandle pool_;
    mutable util::ReaderWriterLocker secret_key_array_locker_;
};

class KSwitchBase
{
public:
    inline explicit KSwitchBase(const PoseidonContext &context,
                                MemoryPoolHandle pool = MemoryManager::GetPool())
        : context_(context), pool_(std::move(pool))
    {
    }
    ~KSwitchBase() = default;

public:
    void switch_key(const Ciphertext &encrypted, const KSwitchKeys &switch_keys,
                    Ciphertext &destination) const;
    void rotate(const Ciphertext &encrypted, Ciphertext &destination, int steps,
                const GaloisKeys &galois_keys) const;
    void conjugate(const Ciphertext &encrypted, const GaloisKeys &galois_keys,
                   Ciphertext &destination) const;
    void relinearize(const Ciphertext &encrypted, Ciphertext &destination,
                     const RelinKeys &relin_keys) const;
    void rotate_internal(Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys,
                         MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    void conjugate_internal(Ciphertext &encrypted, const GaloisKeys &galois_keys,
                            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

protected:
    virtual void relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
                                      size_t destination_size, MemoryPoolHandle pool) const = 0;
    virtual void apply_galois_inplace(Ciphertext &encrypted, uint32_t galois_elt,
                                      const GaloisKeys &galois_keys,
                                      MemoryPoolHandle pool) const = 0;

    PoseidonContext context_;
    MemoryPoolHandle pool_;

private:
    inline void relinearize_inplace(Ciphertext &encrypted, const RelinKeys &relin_keys,
                                    MemoryPoolHandle pool = MemoryManager::GetPool()) const
    {
        relinearize_internal(encrypted, relin_keys, 2, std::move(pool));
    }
};

}  // namespace poseidon
