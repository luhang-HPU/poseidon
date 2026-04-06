#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/relinkeys.h"

using namespace poseidon;

Ciphertext square_diff(EvaluatorCkksBase &eva, const Ciphertext &lhs, const Ciphertext &rhs, const RelinKeys &rk)
{
    Ciphertext tmp;
    Ciphertext out;
    eva.sub(lhs, rhs, tmp);
    eva.multiply_relin(tmp, tmp, out, rk);
    return out;
}

void helper_demo(EvaluatorCkksBase &eva, const Ciphertext &lhs, const Ciphertext &rhs, const RelinKeys &rk, Ciphertext &result)
{
    result = square_diff(eva, lhs, rhs, rk);
}
