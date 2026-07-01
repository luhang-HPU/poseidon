#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/poseidon_context.h"
#include <cstdint>
#include <gmpxx.h>
#include <vector>

namespace poseidon
{

void rawModSwitch(const Ciphertext &ciph, const PoseidonContext &context, uint64_t q,
                  std::vector<std::vector<mpz_class>> &zzParts);

}  // namespace poseidon
