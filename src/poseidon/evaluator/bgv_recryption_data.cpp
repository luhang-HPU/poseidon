#include "bgv_recryption_data.h"
#include "poseidon/basics/util/common.h"
#include <gmpxx.h>
#include <cmath>
#include <stdexcept>

namespace poseidon
{

namespace
{
// GMP-based power: returns p^e as mpz_class
mpz_class power_mod_p(long p, long e)
{
    mpz_class result;
    mpz_pow_ui(result.get_mpz_t(), mpz_class(p).get_mpz_t(), static_cast<unsigned long>(e));
    return result;
}

// GMP-based power: returns p^e as unsigned long (must fit)
unsigned long power_long(long p, long e)
{
    mpz_class val = power_mod_p(p, e);
    return val.get_ui();
}

// GMP-based modular inverse
unsigned long inv_mod_ul(unsigned long a, unsigned long m)
{
    mpz_class result;
    mpz_invert(result.get_mpz_t(), mpz_class(a).get_mpz_t(), mpz_class(m).get_mpz_t());
    return result.get_ui();
}
} // anonymous namespace

double BgvRecryptionData::compute_fudge(uint64_t p2e_prime_val, uint64_t p2e)
{
    double eps = 0;

    if (p2e_prime_val > 1)
    {
        if (p2e_prime_val % 2 == 0)
        {
            eps = 1.0 / static_cast<double>(p2e_prime_val * p2e_prime_val);
        }
        else
        {
            eps = 1.0 / static_cast<double>(p2e);
        }
    }

    return 1.0 + eps;
}

void BgvRecryptionData::set_ae(long &e_out, long &e_prime_out, uint64_t p, long r,
                               double coeff_bound, long e_bnd)
{
    long p2r = static_cast<long>(power_long(p, r));
    long first_term = 2 * p2r + 2;

    long e = r + 1;
    while (e <= e_bnd && static_cast<double>(power_long(p, e)) < first_term * coeff_bound * 2)
    {
        e++;
    }

    if (e > e_bnd)
    {
        throw std::runtime_error("set_ae: cannot find suitable e");
    }

    long e_prime = 1;

    long e_prime_try = 1;
    while (e_prime_try <= e_bnd)
    {
        long p2e_prime_try = static_cast<long>(power_long(p, e_prime_try));
        long e_try = std::max(r + 1, e_prime_try + 1);
        while (e_try <= e_bnd && e_try - e_prime_try < e - e_prime)
        {
            long p2e_try = static_cast<long>(power_long(p, e_try));
            double fudge = compute_fudge(p2e_prime_try, p2e_try);
            if (static_cast<double>(p2e_try) >=
                (static_cast<double>(p2e_prime_try) * fudge + first_term) * coeff_bound * 2)
            {
                break;
            }
            e_try++;
        }

        if (e_try <= e_bnd && e_try - e_prime_try < e - e_prime)
        {
            e = e_try;
            e_prime = e_prime_try;
        }

        e_prime_try++;
    }

    e_out = e;
    e_prime_out = e_prime;
}

void BgvRecryptionData::init(uint64_t plaintext_prime, long r_val, long m_val,
                             double noise_bound, double coeff_bound)
{
    p = plaintext_prime;
    r = r_val;
    m = m_val;

    long e_bnd = 0;
    long p2e_bnd = 1;
    while (p2e_bnd <= ((1L << 30) - 2) / static_cast<long>(p))
    {
        e_bnd++;
        p2e_bnd *= static_cast<long>(p);
    }

    long e_long, e_prime_long;
    set_ae(e_long, e_prime_long, p, r, coeff_bound, e_bnd);

    e = static_cast<uint64_t>(e_long);
    e_prime = static_cast<uint64_t>(e_prime_long);

    al_mod = power_long(p, e_long) + 1;
    p2e_prime = power_long(p, e_prime_long);

    p_inv_mod_al_mod = inv_mod_ul(p, al_mod);

    compute_al_mods();
    compute_digit_extraction_constants();
}

void BgvRecryptionData::compute_al_mods()
{
    uint64_t digit_range = (e - e_prime) + r;
    al_mods.resize(digit_range, 0);

    uint64_t val = 1;
    for (size_t i = 0; i < digit_range; i++)
    {
        al_mods[i] = val;
        val = (val * p) % al_mod;
    }
}

void BgvRecryptionData::compute_digit_extraction_constants()
{
    long top_high = static_cast<long>(e - e_prime) + r - 1;
    ea.resize(top_high + 1, 0);

    mpz_class p_pow = 1;
    mpz_class al_mod_mpz = mpz_class(al_mod);

    for (long i = 0; i <= top_high; i++)
    {
        ea[i] = mpz_class(p_pow / al_mod_mpz).get_ui();
        p_pow *= p;
    }
}

} // namespace poseidon
