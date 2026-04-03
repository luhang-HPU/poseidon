#include "poseidon/ciphertext.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/galoiskeys.h"

using namespace poseidon;

void knn_ckks_demo(EvaluatorCkksBase &ckks_eva, const Ciphertext &query, const Ciphertext &train0,
                   const Ciphertext &train1, const GaloisKeys &galois_keys,
                   Ciphertext &distance_sum)
{
    Ciphertext diff0, diff1, sq0, sq1, rot0, total;

    ckks_eva.sub(query, train0, diff0);
    ckks_eva.sub(query, train1, diff1);
    ckks_eva.multiply(diff0, diff0, sq0);
    ckks_eva.multiply(diff1, diff1, sq1);
    ckks_eva.rotate(sq0, rot0, 1, galois_keys);
    ckks_eva.add(rot0, sq1, total);
    distance_sum = total;
}

