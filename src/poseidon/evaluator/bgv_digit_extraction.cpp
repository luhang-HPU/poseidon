#include "bgv_digit_extraction.h"
#include <gmpxx.h>
#include <stdexcept>

namespace poseidon
{

void newMakeDivisible(std::vector<mpz_class> &coeffs, uint64_t p2e, const mpz_class &q)
{
    if (p2e == 1)
    {
        return;
    }

    if (mpz_class(q % p2e) != 1)
    {
        throw std::invalid_argument("newMakeDivisible: q must equal 1 modulo p2e");
    }

    for (auto &z : coeffs)
    {
        long z_mod = mpz_class(z % p2e).get_si();
        long v;
        if (z_mod > static_cast<long>(p2e) / 2)
        {
            v = static_cast<long>(p2e) - z_mod;
        }
        else
        {
            v = -z_mod;
        }
        z += q * v;
    }
}

void divideByPowersOfP(std::vector<mpz_class> &coeffs, uint64_t p_power)
{
    mpz_class divisor(p_power);
    for (auto &c : coeffs)
    {
        c /= divisor;
    }
}

void multByPowersOfP(std::vector<mpz_class> &coeffs, uint64_t p, uint64_t power)
{
    mpz_class p_mpz(p);
    mpz_class factor(1);
    for (uint64_t i = 0; i < power; i++)
    {
        factor *= p_mpz;
    }
    for (auto &c : coeffs)
    {
        c *= factor;
    }
}

void reduceModQ(std::vector<mpz_class> &coeffs, const mpz_class &q)
{
    for (auto &c : coeffs)
    {
        c %= q;
    }
}

// ---- Polynomial arithmetic modulo a modulus ----

namespace
{

// Evaluate polynomial poly at x modulo mod
mpz_class poly_eval_mod(const PolyCoeffs &poly, const mpz_class &x, const mpz_class &mod)
{
    if (poly.empty())
    {
        return mpz_class(0);
    }
    mpz_class result = poly.back() % mod;
    for (long i = static_cast<long>(poly.size()) - 2; i >= 0; i--)
    {
        result = (result * x + poly[i]) % mod;
    }
    return result;
}

// Add two polynomials mod mod
PolyCoeffs poly_add_mod(const PolyCoeffs &a, const PolyCoeffs &b, const mpz_class &mod)
{
    size_t n = std::max(a.size(), b.size());
    PolyCoeffs result(n);
    for (size_t i = 0; i < n; i++)
    {
        mpz_class ai = (i < a.size()) ? a[i] : mpz_class(0);
        mpz_class bi = (i < b.size()) ? b[i] : mpz_class(0);
        result[i] = (ai + bi) % mod;
    }
    return result;
}

// Multiply polynomial by scalar mod mod
PolyCoeffs poly_mul_scalar_mod(const PolyCoeffs &poly, const mpz_class &scalar, const mpz_class &mod)
{
    PolyCoeffs result(poly.size());
    for (size_t i = 0; i < poly.size(); i++)
    {
        result[i] = (poly[i] * scalar) % mod;
    }
    return result;
}

// Multiply polynomial by (X - c) mod mod
PolyCoeffs poly_mul_linear_mod(const PolyCoeffs &poly, const mpz_class &c, const mpz_class &mod)
{
    PolyCoeffs result(poly.size() + 1, mpz_class(0));
    for (size_t i = 0; i < poly.size(); i++)
    {
        result[i + 1] = (result[i + 1] + poly[i]) % mod;
        mpz_class term = (poly[i] * (-c)) % mod;
        if (term < 0)
            term += mod;
        result[i] = (result[i] + term) % mod;
    }
    return result;
}

// Multiply two polynomials mod mod
PolyCoeffs poly_mul_mod(const PolyCoeffs &a, const PolyCoeffs &b, const mpz_class &mod)
{
    PolyCoeffs result(a.size() + b.size() - 1, mpz_class(0));
    for (size_t i = 0; i < a.size(); i++)
    {
        for (size_t j = 0; j < b.size(); j++)
        {
            result[i + j] = (result[i + j] + a[i] * b[j]) % mod;
        }
    }
    return result;
}

// Compute modular inverse of a mod mod (a and mod must be coprime)
mpz_class mod_inv(const mpz_class &a, const mpz_class &mod)
{
    mpz_class result;
    mpz_invert(result.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
    return result;
}

// Trim trailing zero coefficients
void poly_trim(PolyCoeffs &poly)
{
    while (!poly.empty() && poly.back() == 0)
    {
        poly.pop_back();
    }
}

}  // anonymous namespace

PolyCoeffs buildDigitPolynomial(uint64_t p, uint64_t e)
{
    if (p < 2 || e <= 1)
    {
        return PolyCoeffs{};
    }

    mpz_class p2e(1);
    for (uint64_t i = 0; i < e; i++)
    {
        p2e *= p;
    }

    // Compute x - x^p (mod p^e) for x in [-(p/2), p/2)
    std::vector<mpz_class> xs(p);
    std::vector<mpz_class> ys(p);
    long bottom = -static_cast<long>(p) / 2;

    for (size_t j = 0; j < p; j++)
    {
        long z_val = bottom + static_cast<long>(j);
        mpz_class z(z_val);
        mpz_class z_mod = (z_val < 0) ? z + p2e : z;

        // Compute z^p mod p^e
        mpz_class z_pow;
        mpz_powm_ui(z_pow.get_mpz_t(), z_mod.get_mpz_t(), p, p2e.get_mpz_t());

        mpz_class y = (z_mod - z_pow) % p2e;

        // Balance to [-p^e/2, p^e/2]
        mpz_class half = p2e / 2;
        if (y > half)
            y -= p2e;
        else if (y < -half)
            y += p2e;

        xs[j] = mpz_class(z_val);
        ys[j] = y;
    }

    // Lagrange interpolation over Z_{p^e}
    PolyCoeffs poly_prime{mpz_class(0)};
    for (size_t i = 0; i < p; i++)
    {
        // Compute L_i(X) = Π_{j≠i} (X - x_j) / (x_i - x_j)
        PolyCoeffs L{mpz_class(1)};  // degree 0: constant 1
        mpz_class denom(1);
        for (size_t j = 0; j < p; j++)
        {
            if (i == j)
                continue;
            L = poly_mul_linear_mod(L, xs[j], p2e);
            denom = (denom * (xs[i] - xs[j])) % p2e;
        }
        mpz_class denom_inv = mod_inv(denom, p2e);
        L = poly_mul_scalar_mod(L, denom_inv, p2e);
        L = poly_mul_scalar_mod(L, ys[i], p2e);
        poly_prime = poly_add_mod(poly_prime, L, p2e);
    }

    poly_trim(poly_prime);

    // result = x^p + poly'(x)
    PolyCoeffs result(p + 1, mpz_class(0));
    result[p] = mpz_class(1);
    for (size_t i = 0; i < poly_prime.size(); i++)
    {
        result[i] = (result[i] + poly_prime[i]) % p2e;
    }
    poly_trim(result);

    return result;
}

}  // namespace poseidon
