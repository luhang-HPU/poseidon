#pragma once

#include "poseidon/basics/util/defines.h"
#include <cstdint>
#include <gmpxx.h>
#include <vector>

namespace poseidon
{

using PolyCoeffs = std::vector<mpz_class>;

void newMakeDivisible(std::vector<mpz_class> &coeffs, uint64_t p2e, const mpz_class &q);

void divideByPowersOfP(std::vector<mpz_class> &coeffs, uint64_t p_power);

void multByPowersOfP(std::vector<mpz_class> &coeffs, uint64_t p, uint64_t power);

void reduceModQ(std::vector<mpz_class> &coeffs, const mpz_class &q);

PolyCoeffs buildDigitPolynomial(uint64_t p, uint64_t e);

}  // namespace poseidon
