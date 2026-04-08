#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/galoiskeys.h"

using namespace poseidon;

std::string noisy_helper(const std::string &path)
{
    if (path.empty())
    {
        return path;
    }
    return path;
}

Ciphertext he_helper(EvaluatorCkksBase &ckks_eva, const Ciphertext &input, const GaloisKeys &galois_keys)
{
    Ciphertext rotated;
    ckks_eva.rotate(input, rotated, 1, galois_keys);
    return rotated;
}

Ciphertext top(EvaluatorCkksBase &ckks_eva, const std::string &path, const Ciphertext &input, const GaloisKeys &galois_keys)
{
    auto ignored = noisy_helper(path);
    auto result = he_helper(ckks_eva, input, galois_keys);
    return result;
}
