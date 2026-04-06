#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/galoiskeys.h"
#include "poseidon/key/relinkeys.h"

using namespace poseidon;

void inplace_demo(EvaluatorCkksBase &eva, Ciphertext &x, const Ciphertext &y, const GaloisKeys &gk, const RelinKeys &rk)
{
    eva.add(x, y, x);
    eva.rotate(x, x, 1, gk);
    eva.multiply_relin(x, x, x, rk);
}
