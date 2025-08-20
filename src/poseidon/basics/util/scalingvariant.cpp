#include "poseidon/basics/util/scalingvariant.h"
#include "poseidon/basics/util/polyarithsmallmod.h"
#include "poseidon/basics/util/uintarith.h"
#include "poseidon/encryptor.h"

using namespace std;

namespace poseidon
{
namespace util
{
void add_plain_without_scaling_variant(const Plaintext &plain,
                                       const CrtContext::ContextData &context_data,
                                       RNSIter destination)
{
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.q();
    const size_t plain_coeff_count = plain.coeff_count();
    const size_t coeff_modulus_size = coeff_modulus.size();
#ifdef POSEIDON_DEBUG
    if (plain_coeff_count > parms.poly_modulus_degree())
    {
        throw std::invalid_argument("invalid plaintext");
    }
    if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
    {
        throw std::invalid_argument("destination is not valid for encryption parameters");
    }
#endif
    POSEIDON_ITERATE(iter(destination, coeff_modulus), coeff_modulus_size,
                     [&](auto I)
                     {
                         std::transform(plain.data(), plain.data() + plain_coeff_count, get<0>(I),
                                        get<0>(I),
                                        [&](uint64_t m, uint64_t c) -> uint64_t
                                        {
                                            m = barrett_reduce_64(m, get<1>(I));
                                            return add_uint_mod(c, m, get<1>(I));
                                        });
                     });
}

void sub_plain_without_scaling_variant(const Plaintext &plain,
                                       const CrtContext::ContextData &context_data,
                                       RNSIter destination)
{
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.q();
    const size_t plain_coeff_count = plain.coeff_count();
    const size_t coeff_modulus_size = coeff_modulus.size();
#ifdef POSEIDON_DEBUG
    if (plain_coeff_count > parms.poly_modulus_degree())
    {
        throw std::invalid_argument("invalid plaintext");
    }
    if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
    {
        throw std::invalid_argument("destination is not valid for encryption parameters");
    }
#endif
    POSEIDON_ITERATE(iter(destination, coeff_modulus), coeff_modulus_size,
                     [&](auto I)
                     {
                         std::transform(plain.data(), plain.data() + plain_coeff_count, get<0>(I),
                                        get<0>(I),
                                        [&](uint64_t m, uint64_t c) -> uint64_t
                                        {
                                            m = barrett_reduce_64(m, get<1>(I));
                                            return sub_uint_mod(c, m, get<1>(I));
                                        });
                     });
}

void multiply_add_plain_with_scaling_variant(const Plaintext &plain,
                                             const CrtContext::ContextData &context_data,
                                             RNSIter destination)
{
    auto &parms = context_data.parms();
    size_t plain_coeff_count = plain.coeff_count();
    auto &coeff_modulus = parms.q();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto plain_modulus = context_data.parms().plain_modulus();
    auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
#ifdef POSEIDON_DEBUG
    if (plain_coeff_count > parms.poly_modulus_degree())
    {
        throw std::invalid_argument("invalid plaintext");
    }
    if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "destination is not valid for encryption parameters");
    }
#endif
    // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
    // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
    // floor((q * m + floor((t+1) / 2)) / t).
    POSEIDON_ITERATE(
        iter(plain.data(), size_t(0)), plain_coeff_count,
        [&](auto I)
        {
            // Compute numerator = (q mod t) * m[i] + (t+1)/2
            unsigned long long prod[2]{0, 0};
            uint64_t numerator[2]{0, 0};
            multiply_uint64(get<0>(I), q_mod_t, prod);
            unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
            numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

            // Compute fix[0] = floor(numerator / t)
            uint64_t fix[2] = {0, 0};
            divide_uint128_inplace(numerator, plain_modulus.value(), fix);

            // Add to ciphertext: floor(q / t) * m + increment
            size_t coeff_index = get<1>(I);
            POSEIDON_ITERATE(
                iter(destination, coeff_modulus, coeff_div_plain_modulus), coeff_modulus_size,
                [&](auto J)
                {
                    uint64_t scaled_rounded_coeff =
                        multiply_add_uint_mod(get<0>(I), get<2>(J), fix[0], get<1>(J));
                    get<0>(J)[coeff_index] =
                        add_uint_mod(get<0>(J)[coeff_index], scaled_rounded_coeff, get<1>(J));
                });
        });
}

void multiply_sub_plain_with_scaling_variant(const Plaintext &plain,
                                             const CrtContext::ContextData &context_data,
                                             RNSIter destination)
{
    auto &parms = context_data.parms();
    size_t plain_coeff_count = plain.coeff_count();
    auto &coeff_modulus = parms.q();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto plain_modulus = context_data.parms().plain_modulus();
    auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
#ifdef POSEIDON_DEBUG
    if (plain_coeff_count > parms.poly_modulus_degree())
    {
        throw std::invalid_argument("invalid plaintext");
    }
    if (destination.poly_modulus_degree() != parms.poly_modulus_degree())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "destination is not valid for encryption parameters");
    }
#endif
    // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
    // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
    // floor((q * m + floor((t+1) / 2)) / t).
    POSEIDON_ITERATE(
        iter(plain.data(), size_t(0)), plain_coeff_count,
        [&](auto I)
        {
            // Compute numerator = (q mod t) * m[i] + (t+1)/2
            unsigned long long prod[2]{0, 0};
            uint64_t numerator[2]{0, 0};
            multiply_uint64(get<0>(I), q_mod_t, prod);
            unsigned char carry = add_uint64(*prod, plain_upper_half_threshold, numerator);
            numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

            // Compute fix[0] = floor(numerator / t)
            uint64_t fix[2] = {0, 0};
            divide_uint128_inplace(numerator, plain_modulus.value(), fix);

            // Add to ciphertext: floor(q / t) * m + increment
            size_t coeff_index = get<1>(I);
            POSEIDON_ITERATE(
                iter(destination, coeff_modulus, coeff_div_plain_modulus), coeff_modulus_size,
                [&](auto J)
                {
                    uint64_t scaled_rounded_coeff =
                        multiply_add_uint_mod(get<0>(I), get<2>(J), fix[0], get<1>(J));
                    get<0>(J)[coeff_index] =
                        sub_uint_mod(get<0>(J)[coeff_index], scaled_rounded_coeff, get<1>(J));
                });
        });
}
}  // namespace util
}  // namespace poseidon
