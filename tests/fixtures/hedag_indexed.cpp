#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"

#include <vector>

using namespace poseidon;

void indexed_demo(EvaluatorCkksBase &eva, std::vector<Ciphertext> &data, const std::vector<Ciphertext> &query)
{
    for (int i = 0; i < 2; ++i)
    {
        eva.sub(data[i], query[i], data[i]);
    }
}
