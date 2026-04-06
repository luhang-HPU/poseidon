#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"

#include <vector>

using namespace poseidon;

void control_flow_demo(EvaluatorCkksBase &eva, Ciphertext &x, const Ciphertext &y, int rounds, std::vector<Ciphertext> &data)
{
    if (rounds > 0)
    {
        eva.add(x, y, x);
    }

    for (int i = 0; i < rounds; ++i)
    {
        eva.sub(data[i], y, data[i]);
    }
}
