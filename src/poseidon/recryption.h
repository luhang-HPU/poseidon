#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_base.h"
#include "poseidon/key/kswitchkeys.h"
#include "poseidon/poseidon_context.h"
#include <cstdint>

namespace poseidon
{

struct RecryptionParameters
{
    uint32_t e = 0;
    uint32_t e_prime = 0;
    uint32_t r = 1;
    uint64_t p_power_r = 0;
    uint64_t p_power_e_prime = 0;
    uint64_t bootstrap_modulus = 0;
};

class RecryptionData
{
public:
    explicit RecryptionData(const PoseidonContext &context);

    void set_auxiliary_exponents(uint32_t e, uint32_t e_prime);

    POSEIDON_NODISCARD inline const RecryptionParameters &parameters() const noexcept
    {
        return parameters_;
    }

private:
    void validate_context() const;
    void recompute_derived_parameters();
    static uint64_t checked_power(uint64_t base, uint32_t exponent);

    const PoseidonContext &context_;
    RecryptionParameters parameters_;
};

class Recryptor
{
public:
    Recryptor(const PoseidonContext &context, EvaluatorBase &evaluator,
              const RecryptionData &data);
    Recryptor(const PoseidonContext &context, EvaluatorBase &evaluator,
              const RecryptionData &data, const Encryptor &refresh_encryptor,
              Decryptor &refresh_decryptor);

    void recrypt(const Ciphertext &ciph, Ciphertext &result,
                 const KSwitchKeys &recryption_key) const;
    void thin_recrypt(const Ciphertext &ciph, Ciphertext &result,
                      const KSwitchKeys &recryption_key) const;

private:
    void validate_context() const;
    void ensure_ciphertext_can_bootstrap(const Ciphertext &ciph) const;
    void secret_key_refresh(const Ciphertext &ciph, Ciphertext &result) const;
    [[noreturn]] void throw_public_bootstrap_not_implemented() const;

    const PoseidonContext &context_;
    EvaluatorBase &evaluator_;
    const RecryptionData &data_;
    const Encryptor *refresh_encryptor_ = nullptr;
    Decryptor *refresh_decryptor_ = nullptr;
};

}  // namespace poseidon
