#include "poseidon/evaluator/software/evaluator_bgv_software.h"

namespace poseidon
{

EvaluatorBgvSoftware::EvaluatorBgvSoftware(PoseidonContext &context) : EvaluatorBgvBase(context) {}

void EvaluatorBgvSoftware::read(Plaintext &plain) const {}

void EvaluatorBgvSoftware::read(Ciphertext &ciph) const {}

}  // namespace poseidon