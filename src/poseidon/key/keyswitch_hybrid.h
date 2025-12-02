#pragma once

#include "keyswitch_base.h"
#include "kswitchkeys.h"
#include "poseidon/basics/util/rlwe.h"

namespace poseidon
{
class KSwitchGenHybrid : public KSwitchGenBase
{
public:
    explicit KSwitchGenHybrid(const PoseidonContext &context) : KSwitchGenBase(context)
    {
        auto key_context_data = context_.crt_context()->key_context_data();
        auto len_modulus_p = key_context_data->parms().p().size();
        auto len_modulus_q = key_context_data->parms().q().size();

        if (len_modulus_p == 1)
        {
            POSEIDON_THROW(invalid_argument_error, "KSwitchGenHybrid :size of modulus P is not 1!");
        }

        if (len_modulus_p == len_modulus_q)
        {
            POSEIDON_THROW(invalid_argument_error,
                           "KSwitchGenHybrid :size of modulus P is equal to size of modulus q!");
        }
    }

protected:
    void generate_one_kswitch_key(const SecretKey &prev_secret_key, ConstRNSIter new_key,
                                  vector<PublicKey> &destination) const override;
};

class KSwitchHybrid : public KSwitchBase
{
public:
    explicit KSwitchHybrid(const PoseidonContext &context) : KSwitchBase(context) {}
    void apply_galois_inplace(Ciphertext &encrypted, uint32_t galois_elt,
                              const GaloisKeys &galois_keys, MemoryPoolHandle pool) const override;
    void relinearize_internal(Ciphertext &encrypted, const RelinKeys &relin_keys,
                              size_t destination_size, MemoryPoolHandle pool) const override;
    void switch_key_internal(Ciphertext &encrypted, const KSwitchKeys &switch_keys, 
                              MemoryPoolHandle pool) const override;
    
private:
    void switch_key_inplace(Ciphertext &encrypted, RNSPoly &poly, const KSwitchKeys &kswitch_keys,
                            std::size_t key_index,
                            MemoryPoolHandle pool = MemoryManager::GetPool()) const;
};

}  // namespace poseidon
