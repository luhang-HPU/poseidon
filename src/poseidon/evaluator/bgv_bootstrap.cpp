#include "bgv_bootstrap.h"
#include "bgv_digit_extraction.h"
#include "bgv_raw_mod_switch.h"
#include "evaluator_bgv_base.h"
#include "evaluator_bfv_base.h"
#include "poseidon/crt_context.h"
#include "poseidon/plaintext.h"
#include <gmpxx.h>
#include <stdexcept>

namespace poseidon
{

namespace
{

mpz_class pow_p(uint64_t p, uint64_t exp)
{
    mpz_class result(1);
    mpz_class p_mpz(p);
    for (uint64_t i = 0; i < exp; i++)
    {
        result *= p_mpz;
    }
    return result;
}

Plaintext coeffsToPlaintext(const std::vector<mpz_class> &coeffs, const mpz_class &modulus,
                            MemoryPoolHandle pool = MemoryManager::GetPool())
{
    Plaintext plain(coeffs.size(), pool);
    for (size_t i = 0; i < coeffs.size(); i++)
    {
        plain[i] = mpz_class(coeffs[i] % modulus).get_ui();
    }
    return plain;
}

// Horner polynomial evaluation on ciphertext.
// Computes poly(x) where x is the ciphertext and poly has integer coefficients modulo ptxt_modulus.
void polyEvalCiphertext(EvaluatorBase &evaluator, Ciphertext &x, const PolyCoeffs &poly,
                        const mpz_class &ptxt_modulus, const RelinKeys &relin_keys)
{
    if (poly.empty())
    {
        // Result is 0
        Plaintext zero(x.poly_modulus_degree());
        zero.parms_id() = x.parms_id();
        evaluator.multiply_plain_inplace(x, zero);
        return;
    }

    // Start from the highest-degree coefficient
    long deg = static_cast<long>(poly.size()) - 1;
    while (deg >= 0 && poly[deg] == 0)
        deg--;
    if (deg < 0)
    {
        Plaintext zero(x.poly_modulus_degree());
        zero.parms_id() = x.parms_id();
        evaluator.multiply_plain_inplace(x, zero);
        return;
    }

    // Create result as constant ciphertext = poly[deg]
    Ciphertext result = x;
    Plaintext const_plain(x.poly_modulus_degree());
    const_plain.parms_id() = x.parms_id();
    for (size_t k = 0; k < x.poly_modulus_degree(); k++)
    {
        const_plain[k] = mpz_class(poly[deg] % ptxt_modulus).get_ui();
    }
    evaluator.multiply_plain_inplace(result, const_plain);

    // Horner: result = result * x + poly[i] for i = deg-1 down to 0
    Ciphertext orig_x = x;
    for (long i = deg - 1; i >= 0; i--)
    {
        evaluator.multiply_relin(result, orig_x, result, relin_keys);

        Plaintext term_plain(x.poly_modulus_degree());
        term_plain.parms_id() = result.parms_id();
        for (size_t k = 0; k < x.poly_modulus_degree(); k++)
        {
            term_plain[k] = mpz_class(poly[i] % ptxt_modulus).get_ui();
        }
        evaluator.add_plain(result, term_plain, result);
    }

    x = result;
}

}  // anonymous namespace

void extractDigits(EvaluatorBase &evaluator, std::vector<Ciphertext> &digits,
                   const Ciphertext &c, uint64_t r, uint64_t p,
                   const RelinKeys &relin_keys)
{
    if (r == 0)
        return;

    mpz_class ptxt_modulus = pow_p(p, r);

    // Compute p^{-1} mod p^r for divideByP
    mpz_class p_inv;
    mpz_invert(p_inv.get_mpz_t(), mpz_class(p).get_mpz_t(), ptxt_modulus.get_mpz_t());

    // Build digit extraction polynomial for p > 3
    PolyCoeffs digit_poly;
    if (p > 3)
    {
        digit_poly = buildDigitPolynomial(p, r);
    }

    Ciphertext tmp = c;
    digits.resize(r, tmp);

    for (uint64_t i = 0; i < r; i++)
    {
        tmp = c;
        for (uint64_t j = 0; j < i; j++)
        {
            // digits[j] = digits[j]^p (homomorphically)
            if (p == 2)
            {
                evaluator.square_inplace(digits[j]);
            }
            else if (p == 3)
            {
                Ciphertext squared = digits[j];
                evaluator.square_inplace(squared);
                evaluator.multiply_relin(squared, digits[j], digits[j], relin_keys);
            }
            else
            {
                // Evaluate the digit polynomial: digits[j] = poly(digits[j])
                polyEvalCiphertext(evaluator, digits[j], digit_poly, ptxt_modulus, relin_keys);
            }

            // tmp -= digits[j]
            evaluator.sub(tmp, digits[j], tmp);

            // tmp.divideByP(): multiply by p^{-1} mod p^r
            Plaintext p_inv_plain(tmp.poly_modulus_degree());
            p_inv_plain.parms_id() = tmp.parms_id();
            for (size_t k = 0; k < tmp.poly_modulus_degree(); k++)
            {
                p_inv_plain[k] = p_inv.get_ui();
            }
            evaluator.multiply_plain_inplace(tmp, p_inv_plain);
        }
        digits[i] = tmp;
    }
}

void extractDigitsThin(EvaluatorBase &evaluator, Ciphertext &ctxt, long botHigh, long r,
                       long ePrime, uint64_t p, const RelinKeys &relin_keys)
{
    Ciphertext unpacked = ctxt;
    std::vector<Ciphertext> scratch;
    long topHigh = botHigh + r - 1;

    mpz_class ptxt_modulus = pow_p(p, r);

    // Use basic digit extraction
    extractDigits(evaluator, scratch, unpacked, static_cast<uint64_t>(topHigh + 1), p, relin_keys);

    if (topHigh >= static_cast<long>(scratch.size()))
    {
        topHigh = static_cast<long>(scratch.size()) - 1;
    }

    // unpacked = -\sum_{j=botHigh}^{topHigh} scratch[j] * p^{j-botHigh}
    unpacked = scratch[topHigh];
    for (long j = topHigh - 1; j >= botHigh; --j)
    {
        // unpacked.multByP()
        Plaintext p_plain(unpacked.poly_modulus_degree());
        p_plain.parms_id() = unpacked.parms_id();
        for (size_t k = 0; k < unpacked.poly_modulus_degree(); k++)
        {
            p_plain[k] = p;
        }
        evaluator.multiply_plain_inplace(unpacked, p_plain);
        evaluator.add(unpacked, scratch[j], unpacked);
    }

    if (p == 2 && botHigh > 0)
    {
        evaluator.add(unpacked, scratch[botHigh - 1], unpacked);
    }

    // Negate: multiply by (p^r - 1) mod p^r ≡ -1
    mpz_class neg_one = ptxt_modulus - 1;
    Plaintext neg_plain(unpacked.poly_modulus_degree());
    neg_plain.parms_id() = unpacked.parms_id();
    for (size_t k = 0; k < unpacked.poly_modulus_degree(); k++)
    {
        neg_plain[k] = neg_one.get_ui();
    }
    evaluator.multiply_plain_inplace(unpacked, neg_plain);

    if (r > ePrime)
    {
        // Add bottom part: sum_{j=0}^{r-1-ePrime} scratch[j] * p^{j+ePrime}
        long topLow = r - 1 - ePrime;
        Ciphertext tmp = scratch[topLow];
        for (long j = topLow - 1; j >= 0; --j)
        {
            Plaintext p_plain2(tmp.poly_modulus_degree());
            p_plain2.parms_id() = tmp.parms_id();
            for (size_t k = 0; k < tmp.poly_modulus_degree(); k++)
            {
                p_plain2[k] = p;
            }
            evaluator.multiply_plain_inplace(tmp, p_plain2);
            evaluator.add(tmp, scratch[j], tmp);
        }
        if (ePrime > 0)
        {
            for (long ep = 0; ep < ePrime; ep++)
            {
                Plaintext p_plain3(tmp.poly_modulus_degree());
                p_plain3.parms_id() = tmp.parms_id();
                for (size_t k = 0; k < tmp.poly_modulus_degree(); k++)
                {
                    p_plain3[k] = p;
                }
                evaluator.multiply_plain_inplace(tmp, p_plain3);
            }
        }
        evaluator.add(unpacked, tmp, unpacked);
    }

    ctxt = unpacked;
}

void EvaluatorBgvBase::thin_bootstrap(const Ciphertext &ct, Ciphertext &result,
                                       const BgvRecryptionData &recrypt_data,
                                       const BootstrappingKey &boot_key,
                                       const RelinKeys &relin_keys)
{
    uint64_t p = recrypt_data.p;
    long r = recrypt_data.r;
    uint64_t e = recrypt_data.e;
    uint64_t e_prime = recrypt_data.e_prime;
    uint64_t p2e_prime = recrypt_data.p2e_prime;
    mpz_class q = mpz_class(recrypt_data.al_mod);

    // 1. Ensure canonical form
    Ciphertext tmp = ct;
    if (tmp.size() > 2)
    {
        relinearize(ct, tmp, relin_keys);
    }

    // 2. Drop modulus to minimal primes (keep 3 for bootstrapping)
    while (tmp.coeff_modulus_size() > 3)
    {
        Ciphertext dropped;
        drop_modulus_to_next(tmp, dropped);
        tmp = dropped;
    }

    // 3. Key-switch to bootstrapping key (switch from data key to boot key)
    const auto &swk = boot_key.switch_key();
    if (swk.data().size() > 0 && kswitch_)
    {
        kswitch_->switch_key(tmp, swk, tmp);
    }

    // 4. rawModSwitch to q = p^e + 1
    std::vector<std::vector<mpz_class>> zzParts;
    rawModSwitch(tmp, context_, q.get_ui(), zzParts);

    if (zzParts.size() < 2)
    {
        throw std::runtime_error("thin_bootstrap: rawModSwitch returned fewer than 2 parts");
    }

    // 5. newMakeDivisible + divide by p^e'
    for (auto &part : zzParts)
    {
        newMakeDivisible(part, p2e_prime, q);
        divideByPowersOfP(part, p2e_prime);
    }

    // 6. Homomorphic decryption: result = recryptEkey * zzParts[1] + zzParts[0]
    result = boot_key.recrypt_ekey();

    size_t poly_degree = result.poly_modulus_degree();
    mpz_class ptxt_modulus = pow_p(p, r);

    // Multiply by zzParts[1]
    Plaintext p1 = coeffsToPlaintext(zzParts[1], ptxt_modulus);
    p1.parms_id() = result.parms_id();
    multiply_plain_inplace(result, p1);

    // Add zzParts[0]
    Plaintext p0 = coeffsToPlaintext(zzParts[0], ptxt_modulus);
    p0.parms_id() = result.parms_id();
    add_plain_inplace(result, p0);

    // 7. Extract digits
    extractDigitsThin(*this, result, static_cast<long>(e - e_prime), r,
                      static_cast<long>(e_prime), p, relin_keys);
}

void EvaluatorBfvBase::thin_bootstrap(const Ciphertext &ct, Ciphertext &result,
                                       const BgvRecryptionData &recrypt_data,
                                       const BootstrappingKey &boot_key,
                                       const RelinKeys &relin_keys)
{
    uint64_t p = recrypt_data.p;
    long r = recrypt_data.r;
    uint64_t e = recrypt_data.e;
    uint64_t e_prime = recrypt_data.e_prime;
    uint64_t p2e_prime = recrypt_data.p2e_prime;
    mpz_class q = mpz_class(recrypt_data.al_mod);

    // 1. Ensure canonical form
    Ciphertext tmp = ct;
    if (tmp.size() > 2)
    {
        relinearize(ct, tmp, relin_keys);
    }

    // 2. For BFV, use drop_modulus with explicit parms_id to reduce to 3 primes
    auto crt_context = context_.crt_context();
    auto parms_map = crt_context->parms_id_map();
    size_t target_primes = 3;
    while (tmp.coeff_modulus_size() > target_primes)
    {
        Ciphertext dropped;
        drop_modulus_to_next(tmp, dropped);
        tmp = dropped;
    }

    // 3. Key-switch to bootstrapping key
    const auto &swk = boot_key.switch_key();
    if (swk.data().size() > 0 && kswitch_)
    {
        kswitch_->switch_key(tmp, swk, tmp);
    }

    // 4. rawModSwitch to q = p^e + 1
    std::vector<std::vector<mpz_class>> zzParts;
    rawModSwitch(tmp, context_, q.get_ui(), zzParts);

    if (zzParts.size() < 2)
    {
        throw std::runtime_error("thin_bootstrap: rawModSwitch returned fewer than 2 parts");
    }

    // 5. newMakeDivisible + divide by p^e'
    for (auto &part : zzParts)
    {
        newMakeDivisible(part, p2e_prime, q);
        divideByPowersOfP(part, p2e_prime);
    }

    // 6. Homomorphic decryption: result = recryptEkey * zzParts[1] + zzParts[0]
    result = boot_key.recrypt_ekey();

    size_t poly_degree = result.poly_modulus_degree();
    mpz_class ptxt_modulus = pow_p(p, r);

    Plaintext p1 = coeffsToPlaintext(zzParts[1], ptxt_modulus);
    p1.parms_id() = result.parms_id();
    multiply_plain_inplace(result, p1);

    Plaintext p0 = coeffsToPlaintext(zzParts[0], ptxt_modulus);
    p0.parms_id() = result.parms_id();
    add_plain_inplace(result, p0);

    // 7. Extract digits
    extractDigitsThin(*this, result, static_cast<long>(e - e_prime), r,
                      static_cast<long>(e_prime), p, relin_keys);
}

}  // namespace poseidon
