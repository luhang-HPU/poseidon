#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_base.h"
#include "poseidon/key/galoiskeys.h"
#include "poseidon/key/kswitchkeys.h"
#include "poseidon/key/publickey.h"
#include "poseidon/key/relinkeys.h"
#include "poseidon/key/secretkey.h"
#include "poseidon/poseidon_context.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace poseidon
{

struct RecryptionParameters
{
    uint64_t plain_base = 0;
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

    void set_plain_base(uint64_t plain_base, uint32_t r = 1);
    void set_auxiliary_exponents(uint32_t e, uint32_t e_prime);

    POSEIDON_NODISCARD inline const RecryptionParameters &parameters() const noexcept
    {
        return parameters_;
    }

    void set_linear_maps(const LinearMatrixGroup &first_map,
                         const LinearMatrixGroup &second_map);
    POSEIDON_NODISCARD inline bool has_linear_maps() const noexcept
    {
        return first_map_ != nullptr && second_map_ != nullptr;
    }
    POSEIDON_NODISCARD inline const LinearMatrixGroup &first_map() const
    {
        return *first_map_;
    }
    POSEIDON_NODISCARD inline const LinearMatrixGroup &second_map() const
    {
        return *second_map_;
    }

private:
    void validate_context() const;
    void recompute_derived_parameters();
    static uint64_t checked_power(uint64_t base, uint32_t exponent);

    const PoseidonContext &context_;
    RecryptionParameters parameters_;
    std::shared_ptr<LinearMatrixGroup> first_map_;
    std::shared_ptr<LinearMatrixGroup> second_map_;
};

struct RecryptionRawPart
{
    std::vector<std::int64_t> coeffs;
};

struct RecryptionPreprocessResult
{
    std::vector<RecryptionRawPart> raw_parts;
    std::vector<RecryptionRawPart> divisible_parts;
    std::vector<RecryptionRawPart> divided_parts;
};

struct RecryptionKey
{
    KSwitchKeys bootstrap_switch_key;
    Ciphertext encrypted_bootstrap_secret;
    GaloisKeys linear_map_galois_keys;
    RelinKeys relin_keys;

    POSEIDON_NODISCARD inline bool has_encrypted_bootstrap_secret() const noexcept
    {
        return encrypted_bootstrap_secret.is_valid();
    }
    POSEIDON_NODISCARD inline bool has_linear_map_galois_keys() const noexcept
    {
        return linear_map_galois_keys.size() != 0;
    }
    POSEIDON_NODISCARD inline bool has_relin_keys() const noexcept
    {
        return relin_keys.size() != 0;
    }
};

POSEIDON_NODISCARD RecryptionKey
create_recryption_key(const PoseidonContext &context, const SecretKey &original_secret_key,
                      const PublicKey &original_public_key,
                      const SecretKey &bootstrap_secret_key,
                      const PublicKey &bootstrap_public_key);
POSEIDON_NODISCARD RecryptionKey
create_recryption_key(const PoseidonContext &context, const SecretKey &original_secret_key,
                      const PublicKey &original_public_key,
                      const SecretKey &bootstrap_secret_key,
                      const PublicKey &bootstrap_public_key,
                      const GaloisKeys &linear_map_galois_keys);
POSEIDON_NODISCARD RecryptionKey
create_recryption_key(const PoseidonContext &context, const SecretKey &original_secret_key,
                      const PublicKey &original_public_key,
                      const SecretKey &bootstrap_secret_key,
                      const PublicKey &bootstrap_public_key,
                      const GaloisKeys &linear_map_galois_keys,
                      const RelinKeys &relin_keys);

POSEIDON_NODISCARD std::vector<int>
bgv_recryption_required_galois_steps(const RecryptionData &data);
void bgv_build_thin_recryption_maps(const PoseidonContext &context, const BatchEncoder &encoder,
                                    std::uint32_t level, LinearMatrixGroup &coeff_to_slot,
                                    LinearMatrixGroup &slot_to_coeff,
                                    std::uint32_t log_bsgs_ratio = 1);

void bgv_initialize_plaintext_space(const PoseidonContext &context, Ciphertext &ciph);
void bgv_initialize_plaintext_space(const PoseidonContext &context, Ciphertext &ciph,
                                    std::uint64_t plain_base);
void bgv_reduce_plaintext_space(Ciphertext &ciph, std::uint64_t new_plaintext_space);
void bgv_divide_by_plain_base(const PoseidonContext &context, Ciphertext &ciph);
void bgv_divide_by_plain_base(const PoseidonContext &context, Ciphertext &ciph,
                              std::uint64_t plain_base);
void bgv_multiply_by_plain_base(const PoseidonContext &context, EvaluatorBase &evaluator,
                                Ciphertext &ciph, std::uint32_t exponent = 1);
void bgv_multiply_by_plain_base(const PoseidonContext &context, EvaluatorBase &evaluator,
                                Ciphertext &ciph, std::uint64_t plain_base,
                                std::uint32_t exponent = 1);
POSEIDON_NODISCARD std::uint32_t bgv_effective_plain_exponent(const PoseidonContext &context,
                                                              const Ciphertext &ciph);
POSEIDON_NODISCARD std::uint32_t bgv_effective_plain_exponent(const PoseidonContext &context,
                                                              const Ciphertext &ciph,
                                                              std::uint64_t plain_base);
void bgv_extract_digits_thin_basic(const PoseidonContext &context, EvaluatorBase &evaluator,
                                   const Ciphertext &ciph, std::vector<Ciphertext> &digits,
                                   std::uint32_t digit_count);
void bgv_extract_digits_thin_basic(const PoseidonContext &context, EvaluatorBase &evaluator,
                                   const Ciphertext &ciph, std::uint64_t plain_base,
                                   std::vector<Ciphertext> &digits, std::uint32_t digit_count);

class Recryptor
{
public:
    Recryptor(const PoseidonContext &context, EvaluatorBase &evaluator,
              const RecryptionData &data);

    void recrypt(const Ciphertext &ciph, Ciphertext &result,
                 const KSwitchKeys &recryption_key) const;
    void recrypt(const Ciphertext &ciph, Ciphertext &result,
                 const RecryptionKey &recryption_key) const;
    void thin_recrypt(const Ciphertext &ciph, Ciphertext &result,
                      const KSwitchKeys &recryption_key) const;
    void thin_recrypt(const Ciphertext &ciph, Ciphertext &result,
                      const RecryptionKey &recryption_key) const;

    POSEIDON_NODISCARD RecryptionPreprocessResult
    preprocess(const Ciphertext &ciph, const KSwitchKeys &recryption_key) const;
    void preprocess_and_compose(const Ciphertext &ciph, const RecryptionKey &recryption_key,
                                Ciphertext &result) const;
    void thin_digit_extract_after_compose(const Ciphertext &composed,
                                          Ciphertext &result) const;
    void apply_linear_map_for_bgv_recryption(const Ciphertext &ciph,
                                             const LinearMatrixGroup &map,
                                             const GaloisKeys &galois_keys,
                                             Ciphertext &result) const;

private:
    void validate_context() const;
    void ensure_ciphertext_can_bootstrap(const Ciphertext &ciph) const;
    void raw_mod_switch(const Ciphertext &ciph, std::uint64_t q,
                        std::vector<RecryptionRawPart> &destination) const;
    void make_divisible(std::vector<RecryptionRawPart> &parts,
                        std::vector<RecryptionRawPart> &v_parts) const;
    void divide_by_p_power_e_prime(std::vector<RecryptionRawPart> &parts) const;
    void apply_linear_map(const Ciphertext &ciph, const LinearMatrixGroup &map,
                          const GaloisKeys &galois_keys, Ciphertext &result) const;
    void bgv_modulus_raise_to_top(const Ciphertext &ciph, Ciphertext &result) const;
    void thin_digit_extract_after_compose(const Ciphertext &composed,
                                          const RelinKeys &relin_keys,
                                          Ciphertext &result) const;
    [[noreturn]] void throw_public_bootstrap_not_implemented() const;

    const PoseidonContext &context_;
    EvaluatorBase &evaluator_;
    const RecryptionData &data_;
};

}  // namespace poseidon
