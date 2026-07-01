#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/bgv_recryption_data.h"
#include "poseidon/evaluator/evaluator_base.h"
#include "poseidon/key/bootstrapping_key.h"
#include "poseidon/key/relinkeys.h"
#include <vector>

namespace poseidon
{

void extractDigits(EvaluatorBase &evaluator, std::vector<Ciphertext> &digits,
                   const Ciphertext &c, uint64_t r, uint64_t p,
                   const RelinKeys &relin_keys);

void extractDigitsThin(EvaluatorBase &evaluator, Ciphertext &ctxt, long botHigh, long r,
                       long ePrime, uint64_t p, const RelinKeys &relin_keys);

}  // namespace poseidon
