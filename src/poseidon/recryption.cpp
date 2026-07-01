#include "poseidon/recryption.h"
#include "poseidon/util/exception.h"
#include "poseidon/util/pke_params_defines.h"
#include <limits>
#include <string>

namespace poseidon
{

namespace
{
uint64_t plaintext_modulus_value(const PoseidonContext &context)
{
    return context.parameters_literal()->plain_modulus().value();
}
}  // namespace

RecryptionData::RecryptionData(const PoseidonContext &context) : context_(context)
{
    validate_context();
    parameters_.r = 1;
    recompute_derived_parameters();
}

void RecryptionData::set_auxiliary_exponents(uint32_t e, uint32_t e_prime)
{
    if (e <= e_prime)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires e > e_prime");
    }

    parameters_.e = e;
    parameters_.e_prime = e_prime;
    recompute_derived_parameters();
}

void RecryptionData::validate_context() const
{
    const auto scheme = context_.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption.cpp is for BFV/BGV bootstrapping");
    }

    if (plaintext_modulus_value(context_) < 2)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires plaintext modulus >= 2");
    }
}

void RecryptionData::recompute_derived_parameters()
{
    const auto p = plaintext_modulus_value(context_);
    parameters_.p_power_r = checked_power(p, parameters_.r);

    if (parameters_.e_prime != 0)
    {
        parameters_.p_power_e_prime = checked_power(p, parameters_.e_prime);
    }
    else
    {
        parameters_.p_power_e_prime = 0;
    }

    if (parameters_.e != 0)
    {
        const auto p_power_e = checked_power(p, parameters_.e);
        if (p_power_e == std::numeric_limits<uint64_t>::max())
        {
            POSEIDON_THROW(invalid_argument_error, "p^e overflows uint64_t");
        }
        parameters_.bootstrap_modulus = p_power_e + 1;
    }
    else
    {
        parameters_.bootstrap_modulus = 0;
    }
}

uint64_t RecryptionData::checked_power(uint64_t base, uint32_t exponent)
{
    uint64_t result = 1;
    for (uint32_t i = 0; i < exponent; i++)
    {
        if (base != 0 && result > std::numeric_limits<uint64_t>::max() / base)
        {
            POSEIDON_THROW(invalid_argument_error, "recryption parameter overflow");
        }
        result *= base;
    }
    return result;
}

Recryptor::Recryptor(const PoseidonContext &context, EvaluatorBase &evaluator,
                     const RecryptionData &data)
    : context_(context), evaluator_(evaluator), data_(data)
{
    validate_context();
}

void Recryptor::recrypt(const Ciphertext &ciph, Ciphertext &result,
                        const KSwitchKeys &recryption_key) const
{
    (void)result;
    (void)recryption_key;
    ensure_ciphertext_can_bootstrap(ciph);
    throw_not_implemented("recrypt");
}

void Recryptor::thin_recrypt(const Ciphertext &ciph, Ciphertext &result,
                             const KSwitchKeys &recryption_key) const
{
    (void)result;
    (void)recryption_key;
    ensure_ciphertext_can_bootstrap(ciph);
    throw_not_implemented("thin_recrypt");
}

void Recryptor::validate_context() const
{
    const auto scheme = context_.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption.cpp is for BFV/BGV bootstrapping");
    }

    (void)evaluator_;
}

void Recryptor::ensure_ciphertext_can_bootstrap(const Ciphertext &ciph) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "recryption input ciphertext is empty");
    }

    const auto &params = data_.parameters();
    if (params.e == 0 || params.e_prime == 0 || params.bootstrap_modulus == 0)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption auxiliary exponents are not initialized");
    }
}

void Recryptor::throw_not_implemented(const char *entry_point) const
{
    const std::string message =
        std::string(entry_point) +
        ": BFV/BGV recryption needs raw mod-switch to q=p^e+1, "
        "bootstrapping-key switching, encrypted digit extraction, and "
        "powerful-basis/slot linear maps; these primitives are not present "
        "in the current Poseidon evaluator yet.";
    POSEIDON_THROW(poseidon_logic_error, message);
}

}  // namespace poseidon
