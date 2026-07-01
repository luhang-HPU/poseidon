#pragma once

#include "poseidon/basics/util/defines.h"
#include <cstdint>
#include <vector>

namespace poseidon
{

struct BgvRecryptionData
{
    uint64_t e = 0;
    uint64_t e_prime = 0;
    uint64_t p = 0;
    uint64_t p2e_prime = 0;
    uint64_t al_mod = 0;
    uint64_t p_inv_mod_al_mod = 0;
    long m = 0;
    long r = 0;

    // Precomputed table: al_mods[i] = p^i mod al_mod (used in digit extraction)
    std::vector<uint64_t> al_mods;

    // Precomputed table: ea[i] = p^{i+1} / al_mod (for extractDigits)
    std::vector<uint64_t> ea;

    BgvRecryptionData() = default;

    void init(uint64_t plaintext_prime, long r_val, long m_val,
              double noise_bound, double coeff_bound);

    static void set_ae(long &e_out, long &e_prime_out, uint64_t p, long r,
                       double coeff_bound, long e_bnd);

    static double compute_fudge(uint64_t p2e_prime_val, uint64_t p2e);

private:
    void compute_al_mods();
    void compute_digit_extraction_constants();
};

} // namespace poseidon
