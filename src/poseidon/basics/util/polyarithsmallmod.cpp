#include "poseidon/basics/util/polyarithsmallmod.h"
#include "poseidon/basics/util/uintarith.h"
#include "poseidon/basics/util/uintcore.h"

#ifdef POSEIDON_USE_INTEL_HEXL
#include "hexl/hexl.hpp"
#endif

using namespace std;

namespace poseidon
{
namespace util
{
void modulo_poly_coeffs(ConstCoeffIter poly, std::size_t coeff_count, const Modulus &modulus,
                        CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!poly && coeff_count > 0)
    {
        throw std::invalid_argument("poly");
    }
    if (!result && coeff_count > 0)
    {
        throw std::invalid_argument("result");
    }
    if (modulus.is_zero())
    {
        throw std::invalid_argument("modulus");
    }
#endif

#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseReduceMod(result, poly, coeff_count, modulus.value(), modulus.value(), 1);
#else
    POSEIDON_ITERATE(iter(poly, result), coeff_count,
                     [&](auto I) { get<1>(I) = barrett_reduce_64(get<0>(I), modulus); });
#endif
}

void add_poly_coeffmod(ConstCoeffIter operand1, ConstCoeffIter operand2, std::size_t coeff_count,
                       const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!operand1 && coeff_count > 0)
    {
        throw std::invalid_argument("operand1");
    }
    if (!operand2 && coeff_count > 0)
    {
        throw std::invalid_argument("operand2");
    }
    if (modulus.is_zero())
    {
        throw std::invalid_argument("modulus");
    }
    if (!result && coeff_count > 0)
    {
        throw std::invalid_argument("result");
    }
#endif
    const uint64_t modulus_value = modulus.value();

#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseAddMod(&result[0], &operand1[0], &operand2[0], coeff_count, modulus_value);
#else

    POSEIDON_ITERATE(iter(operand1, operand2, result), coeff_count,
                     [&](auto I)
                     {
#ifdef POSEIDON_DEBUG
                         if (get<0>(I) >= modulus_value)
                         {
                             throw std::invalid_argument("operand1");
                         }
                         if (get<1>(I) >= modulus_value)
                         {
                             throw std::invalid_argument("operand2");
                         }
#endif
                         auto aa = get<0>(I);
                         auto bb = get<1>(I);
                         std::uint64_t sum = get<0>(I) + get<1>(I);
                         get<2>(I) =
                             POSEIDON_COND_SELECT(sum >= modulus_value, sum - modulus_value, sum);
                     });
#endif
}

void sub_poly_coeffmod(ConstCoeffIter operand1, ConstCoeffIter operand2, std::size_t coeff_count,
                       const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!operand1 && coeff_count > 0)
    {
        throw std::invalid_argument("operand1");
    }
    if (!operand2 && coeff_count > 0)
    {
        throw std::invalid_argument("operand2");
    }
    if (modulus.is_zero())
    {
        throw std::invalid_argument("modulus");
    }
    if (!result && coeff_count > 0)
    {
        throw std::invalid_argument("result");
    }
#endif

    const uint64_t modulus_value = modulus.value();
#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseSubMod(result, operand1, operand2, coeff_count, modulus_value);
#else
    POSEIDON_ITERATE(iter(operand1, operand2, result), coeff_count,
                     [&](auto I)
                     {
#ifdef POSEIDON_DEBUG
                         if (get<0>(I) >= modulus_value)
                         {
                             throw std::invalid_argument("operand1");
                         }
                         if (get<1>(I) >= modulus_value)
                         {
                             throw std::invalid_argument("operand2");
                         }
#endif
                         unsigned long long temp_result;
                         std::int64_t borrow = sub_uint64(get<0>(I), get<1>(I), &temp_result);
                         get<2>(I) =
                             temp_result + (modulus_value & static_cast<std::uint64_t>(-borrow));
                     });
#endif
}

void add_poly_scalar_coeffmod(ConstCoeffIter poly, size_t coeff_count, uint64_t scalar,
                              const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!poly && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "poly");
    }
    if (!result && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "result");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
    if (scalar >= modulus.value())
    {
        POSEIDON_THROW(invalid_argument_error, "scalar");
    }
#endif

#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseAddMod(result, poly, scalar, coeff_count, modulus.value());
#else
    POSEIDON_ITERATE(iter(poly, result), coeff_count,
                     [&](auto I)
                     {
                         const uint64_t x = get<0>(I);
                         get<1>(I) = add_uint_mod(x, scalar, modulus);
                     });
#endif
}

void sub_poly_scalar_coeffmod(ConstCoeffIter poly, size_t coeff_count, uint64_t scalar,
                              const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!poly && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "poly");
    }
    if (!result && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "result");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
    if (scalar >= modulus.value())
    {
        POSEIDON_THROW(invalid_argument_error, "scalar");
    }
#endif

#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseSubMod(result, poly, scalar, coeff_count, modulus.value());
#else
    POSEIDON_ITERATE(iter(poly, result), coeff_count,
                     [&](auto I)
                     {
                         const uint64_t x = get<0>(I);
                         get<1>(I) = sub_uint_mod(x, scalar, modulus);
                     });
#endif
}

void multiply_poly_scalar_coeffmod(ConstCoeffIter poly, size_t coeff_count,
                                   MultiplyUIntModOperand scalar, const Modulus &modulus,
                                   CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!poly && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "poly");
    }
    if (!result && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "result");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
#endif

#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseFMAMod(&result[0], &poly[0], scalar.operand, nullptr, coeff_count,
                               modulus.value(), 8);
#else
    POSEIDON_ITERATE(iter(poly, result), coeff_count,
                     [&](auto I)
                     {
                         const uint64_t x = get<0>(I);
                         get<1>(I) = multiply_uint_mod(x, scalar, modulus);
                     });
#endif
}

void dyadic_product_coeffmod(ConstCoeffIter operand1, ConstCoeffIter operand2, size_t coeff_count,
                             const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!operand1)
    {
        POSEIDON_THROW(invalid_argument_error, "operand1");
    }
    if (!operand2)
    {
        POSEIDON_THROW(invalid_argument_error, "operand2");
    }
    if (!result)
    {
        POSEIDON_THROW(invalid_argument_error, "result");
    }
    if (coeff_count == 0)
    {
        POSEIDON_THROW(invalid_argument_error, "coeff_count");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
#endif
#ifdef POSEIDON_USE_INTEL_HEXL
    intel::hexl::EltwiseMultMod(&result[0], &operand1[0], &operand2[0], coeff_count,
                                modulus.value(), 4);
#else
    const uint64_t modulus_value = modulus.value();
    const uint64_t const_ratio_0 = modulus.const_ratio()[0];
    const uint64_t const_ratio_1 = modulus.const_ratio()[1];

    POSEIDON_ITERATE(iter(operand1, operand2, result), coeff_count,
                     [&](auto I)
                     {
                         // Reduces z using base 2^64 Barrett reduction
                         unsigned long long z[2], tmp1, tmp2[2], tmp3, carry;
                         multiply_uint64(get<0>(I), get<1>(I), z);

                         // Multiply input and const_ratio
                         // Round 1
                         multiply_uint64_hw64(z[0], const_ratio_0, &carry);
                         multiply_uint64(z[0], const_ratio_1, tmp2);
                         tmp3 = tmp2[1] + add_uint64(tmp2[0], carry, &tmp1);

                         // Round 2
                         multiply_uint64(z[1], const_ratio_0, tmp2);
                         carry = tmp2[1] + add_uint64(tmp1, tmp2[0], &tmp1);

                         // This is all we care about
                         tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

                         // Barrett subtraction
                         tmp3 = z[0] - tmp1 * modulus_value;

                         // Claim: One more subtraction is enough
                         get<2>(I) = POSEIDON_COND_SELECT(tmp3 >= modulus_value,
                                                          tmp3 - modulus_value, tmp3);
                     });
#endif
}

uint64_t poly_infty_norm_coeffmod(ConstCoeffIter operand, size_t coeff_count,
                                  const Modulus &modulus)
{
#ifdef POSEIDON_DEBUG
    if (!operand && coeff_count > 0)
    {
        POSEIDON_THROW(invalid_argument_error, "operand");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
#endif
    // Construct negative threshold (first negative modulus value) to compute absolute values of
    // coeffs.
    uint64_t modulus_neg_threshold = (modulus.value() + 1) >> 1;

    // Mod out the poly coefficients and choose a symmetric representative from
    // [-modulus,modulus). Keep track of the max.
    uint64_t result = 0;
    POSEIDON_ITERATE(operand, coeff_count,
                     [&](auto I)
                     {
                         uint64_t poly_coeff = barrett_reduce_64(I, modulus);
                         if (poly_coeff >= modulus_neg_threshold)
                         {
                             poly_coeff = modulus.value() - poly_coeff;
                         }
                         if (poly_coeff > result)
                         {
                             result = poly_coeff;
                         }
                     });

    return result;
}

void negacyclic_shift_poly_coeffmod(ConstCoeffIter poly, size_t coeff_count, size_t shift,
                                    const Modulus &modulus, CoeffIter result)
{
#ifdef POSEIDON_DEBUG
    if (!poly)
    {
        POSEIDON_THROW(invalid_argument_error, "poly");
    }
    if (!result)
    {
        POSEIDON_THROW(invalid_argument_error, "result");
    }
    if (poly == result)
    {
        POSEIDON_THROW(invalid_argument_error, "result cannot point to the same value as poly");
    }
    if (modulus.is_zero())
    {
        POSEIDON_THROW(invalid_argument_error, "modulus");
    }
    if (util::get_power_of_two(static_cast<uint64_t>(coeff_count)) < 0)
    {
        POSEIDON_THROW(invalid_argument_error, "coeff_count");
    }
    if (shift >= coeff_count)
    {
        POSEIDON_THROW(invalid_argument_error, "shift");
    }
#endif
    // Nothing to do
    if (shift == 0)
    {
        set_uint(poly, coeff_count, result);
        return;
    }

    uint64_t index_raw = shift;
    uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
    for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++)
    {
        uint64_t index = index_raw & coeff_count_mod_mask;
        if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly)
        {
            result[index] = *poly;
        }
        else
        {
            result[index] = modulus.value() - *poly;
        }
    }
}
}  // namespace util
}  // namespace poseidon
