#pragma once

#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/ciphertext.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/galoiskeys.h"
#include "poseidon/key/relinkeys.h"
#include "poseidon/poseidon_context.h"
#include <cstdint>
#include <vector>

namespace poseidon
{

struct RecryptionConfig
{
    SineType sine_type = CosDiscrete;
    double scaling_factor = 0.0;
    uint32_t level_start = 1;
    uint32_t log_message_ratio = 9;
    uint32_t double_angle = 3;
    uint32_t k = 16;
    uint32_t arcsine_degree = 0;
    uint32_t sine_degree = 30;
    std::vector<uint32_t> coeff_to_slot_levels = std::vector<uint32_t>(3, 1);
    std::vector<uint32_t> slot_to_coeff_levels = std::vector<uint32_t>(3, 1);
    uint32_t coeff_to_slot_step = 2;
    uint32_t slot_to_coeff_step = 1;
    uint32_t log_bsgs_ratio = 1;
    bool repack_imag_to_real = true;
    bool bit_reversed = false;
};

class RecryptionData
{
public:
    RecryptionData(const PoseidonContext &context, RecryptionConfig config = {});

    POSEIDON_NODISCARD inline EvalModPoly &eval_mod_poly() noexcept { return eval_mod_poly_; }
    POSEIDON_NODISCARD inline const EvalModPoly &eval_mod_poly() const noexcept
    {
        return eval_mod_poly_;
    }

    POSEIDON_NODISCARD inline LinearMatrixGroup &coeff_to_slot_matrix() noexcept
    {
        return coeff_to_slot_matrix_;
    }

    POSEIDON_NODISCARD inline const LinearMatrixGroup &coeff_to_slot_matrix() const noexcept
    {
        return coeff_to_slot_matrix_;
    }

    POSEIDON_NODISCARD inline LinearMatrixGroup &slot_to_coeff_matrix() noexcept
    {
        return slot_to_coeff_matrix_;
    }

    POSEIDON_NODISCARD inline const LinearMatrixGroup &slot_to_coeff_matrix() const noexcept
    {
        return slot_to_coeff_matrix_;
    }

    POSEIDON_NODISCARD inline const RecryptionConfig &config() const noexcept { return config_; }

    void ensure_coeff_to_slot_matrix(const PoseidonContext &context, const CKKSEncoder &encoder,
                                     uint32_t level);
    void ensure_slot_to_coeff_matrix(const PoseidonContext &context, const CKKSEncoder &encoder,
                                     uint32_t level);
    void clear_matrices();

private:
    RecryptionConfig config_;
    EvalModPoly eval_mod_poly_;
    LinearMatrixGroup coeff_to_slot_matrix_;
    LinearMatrixGroup slot_to_coeff_matrix_;
    uint32_t coeff_to_slot_level_ = UINT32_MAX;
    uint32_t slot_to_coeff_level_ = UINT32_MAX;
};

class Recryptor
{
public:
    Recryptor(const PoseidonContext &context, EvaluatorCkksBase &evaluator,
              const CKKSEncoder &encoder);

    void coeff_to_slot(const Ciphertext &ciph, Ciphertext &real_part, Ciphertext &imag_part,
                       RecryptionData &data, const GaloisKeys &galois_keys) const;

    void eval_mod(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                  const RelinKeys &relin_keys) const;

    void slot_to_coeff(const Ciphertext &real_part, const Ciphertext &imag_part,
                       Ciphertext &result, RecryptionData &data,
                       const GaloisKeys &galois_keys) const;

    void recrypt(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                 const RelinKeys &relin_keys, const GaloisKeys &galois_keys) const;

    void thin_recrypt(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                      const RelinKeys &relin_keys, const GaloisKeys &galois_keys) const;

private:
    void validate_ckks_context() const;

    const PoseidonContext &context_;
    EvaluatorCkksBase &evaluator_;
    const CKKSEncoder &encoder_;
};

}  // namespace poseidon
