#include "bgv_raw_mod_switch.h"
#include "poseidon/crt_context.h"
#include <gmpxx.h>
#include <stdexcept>

namespace poseidon
{

void rawModSwitch(const Ciphertext &ciph, const PoseidonContext &context, uint64_t q,
                  std::vector<std::vector<mpz_class>> &zzParts)
{
    auto crt_context = context.crt_context();
    auto context_data = crt_context->get_context_data(ciph.parms_id());
    if (!context_data)
    {
        throw std::invalid_argument("rawModSwitch: invalid parms_id in ciphertext");
    }

    const auto &modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = ciph.coeff_modulus_size();
    size_t poly_degree = ciph.poly_modulus_degree();
    size_t num_parts = ciph.size();

    if (coeff_modulus_size > modulus.size())
    {
        throw std::invalid_argument("rawModSwitch: ciphertext has more primes than context");
    }

    mpz_class target_q(q);

    // Compute Q = product of the active ciphertext primes
    mpz_class Q(1);
    std::vector<mpz_class> primes;
    primes.reserve(coeff_modulus_size);
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        uint64_t prime_val = modulus[i].value();
        primes.emplace_back(prime_val);
        Q *= prime_val;
    }

    // Precompute Q_i = Q / q_i and inv_i = (Q_i)^{-1} mod q_i for CRT
    std::vector<mpz_class> Q_i(coeff_modulus_size);
    std::vector<mpz_class> inv_i(coeff_modulus_size);
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        Q_i[i] = Q / primes[i];
        mpz_class inv;
        mpz_invert(inv.get_mpz_t(), Q_i[i].get_mpz_t(), primes[i].get_mpz_t());
        inv_i[i] = inv;
    }

    mpz_class Q_half = Q / 2;

    // Output: one vector per ciphertext part
    zzParts.resize(num_parts, std::vector<mpz_class>(poly_degree));

    for (size_t part = 0; part < num_parts; part++)
    {
        const uint64_t *part_data = ciph.data(part);

        for (size_t coeff = 0; coeff < poly_degree; coeff++)
        {
            // CRT reconstruct coefficient from RNS residues.
            // Layout: part_data[k * poly_degree + coeff] is the residue for prime k.
            mpz_class x(0);
            for (size_t k = 0; k < coeff_modulus_size; k++)
            {
                uint64_t residue = part_data[k * poly_degree + coeff];
                mpz_class term(residue);
                term = (term * Q_i[k] * inv_i[k]) % Q;
                x += term;
            }
            x %= Q;

            // Scale: round(x * q / Q) = floor((x * q + Q/2) / Q)
            mpz_class scaled = (x * target_q + Q_half) / Q;
            zzParts[part][coeff] = scaled;
        }
    }
}

}  // namespace poseidon
