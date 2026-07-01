#include "poseidon/recryption.h"
#include "poseidon/basics/util/common.h"
#include "poseidon/util/exception.h"
#include "poseidon/util/pke_params_defines.h"
#include <cmath>
#include <utility>

namespace poseidon
{

namespace
{
double default_scaling_factor(const PoseidonContext &context)
{
    return context.parameters_literal()->scale();
}

uint32_t top_level(const PoseidonContext &context)
{
    auto &q = context.parameters_literal()->q();
    if (q.empty())
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires a non-empty q chain");
    }
    return static_cast<uint32_t>(q.size() - 1);
}

double coeff_to_slot_scaling(const EvalModPoly &eval_mod_poly)
{
    return eval_mod_poly.q_div() /
           (eval_mod_poly.k() * eval_mod_poly.sc_fac() * eval_mod_poly.q_diff());
}

double slot_to_coeff_scaling(const PoseidonContext &context, const EvalModPoly &eval_mod_poly)
{
    return context.parameters_literal()->scale() /
           (eval_mod_poly.scaling_factor() / eval_mod_poly.message_ratio());
}

void create_dft_matrix(const PoseidonContext &context, const CKKSEncoder &encoder,
                       LinearType type, uint32_t level, const std::vector<uint32_t> &levels,
                       bool repack_imag_to_real, double scaling, bool bit_reversed,
                       uint32_t log_bsgs_ratio, uint32_t step, LinearMatrixGroup &matrix)
{
    HomomorphicDFTMatrixLiteral literal(
        type, context.parameters_literal()->log_n(), context.parameters_literal()->log_slots(),
        level, levels, repack_imag_to_real, scaling, bit_reversed, log_bsgs_ratio);
    literal.create(matrix, const_cast<CKKSEncoder &>(encoder), step);
}
}  // namespace

RecryptionData::RecryptionData(const PoseidonContext &context, RecryptionConfig config)
    : config_(std::move(config)),
      eval_mod_poly_(context, config_.sine_type,
                     config_.scaling_factor > 0.0 ? config_.scaling_factor
                                                  : default_scaling_factor(context),
                     config_.level_start, config_.log_message_ratio, config_.double_angle,
                     config_.k, config_.arcsine_degree, config_.sine_degree)
{
}

void RecryptionData::ensure_coeff_to_slot_matrix(const PoseidonContext &context,
                                                 const CKKSEncoder &encoder, uint32_t level)
{
    if (coeff_to_slot_level_ == level && !coeff_to_slot_matrix_.data().empty())
    {
        return;
    }

    coeff_to_slot_matrix_ = LinearMatrixGroup();
    create_dft_matrix(context, encoder, encode, level, config_.coeff_to_slot_levels,
                      config_.repack_imag_to_real, coeff_to_slot_scaling(eval_mod_poly_),
                      config_.bit_reversed, config_.log_bsgs_ratio, config_.coeff_to_slot_step,
                      coeff_to_slot_matrix_);
    coeff_to_slot_level_ = level;
}

void RecryptionData::ensure_slot_to_coeff_matrix(const PoseidonContext &context,
                                                 const CKKSEncoder &encoder, uint32_t level)
{
    if (slot_to_coeff_level_ == level && !slot_to_coeff_matrix_.data().empty())
    {
        return;
    }

    slot_to_coeff_matrix_ = LinearMatrixGroup();
    create_dft_matrix(context, encoder, decode, level, config_.slot_to_coeff_levels,
                      config_.repack_imag_to_real, slot_to_coeff_scaling(context, eval_mod_poly_),
                      config_.bit_reversed, config_.log_bsgs_ratio, config_.slot_to_coeff_step,
                      slot_to_coeff_matrix_);
    slot_to_coeff_level_ = level;
}

void RecryptionData::clear_matrices()
{
    coeff_to_slot_matrix_ = LinearMatrixGroup();
    slot_to_coeff_matrix_ = LinearMatrixGroup();
    coeff_to_slot_level_ = UINT32_MAX;
    slot_to_coeff_level_ = UINT32_MAX;
}

Recryptor::Recryptor(const PoseidonContext &context, EvaluatorCkksBase &evaluator,
                     const CKKSEncoder &encoder)
    : context_(context), evaluator_(evaluator), encoder_(encoder)
{
    validate_ckks_context();
}

void Recryptor::coeff_to_slot(const Ciphertext &ciph, Ciphertext &real_part,
                              Ciphertext &imag_part, RecryptionData &data,
                              const GaloisKeys &galois_keys) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "coeff_to_slot: ciph is empty");
    }

    const auto level = top_level(context_);
    data.ensure_coeff_to_slot_matrix(context_, encoder_, level);
    evaluator_.coeff_to_slot(ciph, data.coeff_to_slot_matrix(), real_part, imag_part, galois_keys,
                             encoder_);
}

void Recryptor::eval_mod(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                         const RelinKeys &relin_keys) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "eval_mod: ciph is empty");
    }

    data.eval_mod_poly().set_level_start(static_cast<uint32_t>(ciph.level()));
    evaluator_.eval_mod(ciph, result, data.eval_mod_poly(), relin_keys, encoder_);
}

void Recryptor::slot_to_coeff(const Ciphertext &real_part, const Ciphertext &imag_part,
                              Ciphertext &result, RecryptionData &data,
                              const GaloisKeys &galois_keys) const
{
    if (!real_part.is_valid() || !imag_part.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "slot_to_coeff: input ciphertext is empty");
    }

    const auto level = static_cast<uint32_t>(real_part.level());
    data.ensure_slot_to_coeff_matrix(context_, encoder_, level);
    evaluator_.slot_to_coeff(real_part, imag_part, data.slot_to_coeff_matrix(), result,
                             galois_keys, encoder_);
}

void Recryptor::recrypt(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                        const RelinKeys &relin_keys, const GaloisKeys &galois_keys) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "recrypt: ciph is empty");
    }

    evaluator_.bootstrap(ciph, result, relin_keys, galois_keys, encoder_, data.eval_mod_poly());
}

void Recryptor::thin_recrypt(const Ciphertext &ciph, Ciphertext &result, RecryptionData &data,
                             const RelinKeys &relin_keys, const GaloisKeys &galois_keys) const
{
    recrypt(ciph, result, data, relin_keys, galois_keys);
}

void Recryptor::validate_ckks_context() const
{
    if (context_.parameters_literal()->scheme() != CKKS)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires CKKS parameters");
    }

    (void)top_level(context_);
}

}  // namespace poseidon
