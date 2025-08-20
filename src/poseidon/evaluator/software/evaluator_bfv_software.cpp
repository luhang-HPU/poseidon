#include "evaluator_bfv_software.h"

namespace poseidon
{

EvaluatorBfvSoftware::EvaluatorBfvSoftware(PoseidonContext &context) : Base(context) {}

void EvaluatorBfvSoftware::read(Plaintext &plain) const {}

void EvaluatorBfvSoftware::read(Ciphertext &ciph) const {}

}  // namespace poseidon
