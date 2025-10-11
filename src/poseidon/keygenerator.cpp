#include "keygenerator.h"
#include "basics/randomtostd.h"
#include "basics/util/common.h"
#include "basics/util/galois.h"
#include "basics/util/ntt.h"
#include "basics/util/polyarithsmallmod.h"
#include "basics/util/polycore.h"
#include "basics/util/rlwe.h"
#include "basics/util/uintarithsmallmod.h"
#include "basics/util/uintcore.h"
#include "key/keyswitch.h"
#include "poseidon/factory/poseidon_factory.h"
#include <algorithm>
#ifdef USING_HARDWARE
#include "poseidon_hardware/hardware_drive/ckks_hardware_api.h"
#endif

using namespace std;
using namespace poseidon::util;

namespace poseidon
{
KeyGenerator::KeyGenerator(const PoseidonContext &context) : context_(context)
{
    auto kswitch_variant = context.key_switch_variant();
    using_keyswitch_ = context.crt_context()->using_keyswitch();
    if (kswitch_variant == BV)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenBV>(context);
    }
    else if (kswitch_variant == GHS)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenGHS>(context);
    }
    else if (kswitch_variant == HYBRID)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenHybrid>(context);
    }
    // Secret key has not been generated
    sk_generated_ = false;

    // Generate the secret and public key
    generate_sk();
}

KeyGenerator::KeyGenerator(const PoseidonContext &context, const SecretKey &secret_key)
    : context_(context)
{
    auto kswitch_variant = context.key_switch_variant();
    if (kswitch_variant == BV)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenBV>(context);
    }
    else if (kswitch_variant == GHS)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenGHS>(context);
    }
    else if (kswitch_variant == HYBRID)
    {
        this->kswitch_gen_ = make_shared<KSwitchGenHybrid>(context);
    }
    // Set the secret key
    secret_key_ = secret_key;
    sk_generated_ = true;

    // Generate the public key
    generate_sk(sk_generated_);
}

void KeyGenerator::generate_sk(bool is_initialized)
{
    // Extract encryption parameters.
    auto scheme = context_.parameters_literal()->scheme();
    auto global_context_data = context_.crt_context();
    auto &context_data = *context_.crt_context()->key_context_data();
    auto param_id = context_.crt_context()->key_parms_id();
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    if (!is_initialized)
    {
        // Initialize secret key.
        secret_key_ = SecretKey();
        sk_generated_ = false;
        secret_key_.data().resize(context_, param_id, mul_safe(coeff_count, coeff_modulus_size));

        // Generate secret key
        RNSIter secret_key(secret_key_.data().data(), coeff_count);
        if (scheme == CKKS)
        {
            sample_poly_ternary_with_hamming(context_.random_generator()->create(), context_,
                                             param_id, secret_key);
        }
        else
        {
            sample_poly_ternary(context_.random_generator()->create(), context_, param_id,
                                secret_key);
        }

        // Transform the secret s into NTT representation.
        auto ntt_tables = global_context_data->small_ntt_tables();
        ntt_negacyclic_harvey(secret_key, coeff_modulus_size, ntt_tables);

        // Set the parms_id for secret key
        secret_key_.parms_id() = param_id;
    }

    // Set the secret_key_array to have size 1 (first power of secret)
    secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
    set_poly(secret_key_.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
    secret_key_array_size_ = 1;

    // Secret key has been generated
    sk_generated_ = true;
}

PublicKey KeyGenerator::generate_pk(bool save_seed) const
{
    if (!sk_generated_)
    {
        throw logic_error("cannot generate public key for unspecified secret key");
    }

    // Extract encryption parameters.
    auto global_context_data = context_.crt_context();
    auto &context_data = *context_.crt_context()->key_context_data();
    auto param_id = context_.crt_context()->key_parms_id();
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Size check
    if (!product_fits_in(coeff_count, coeff_modulus_size))
    {
        throw logic_error("invalid parameters");
    }

    PublicKey public_key;
    encrypt_zero_symmetric(secret_key_, context_, param_id, true, save_seed, public_key.data());

    // Set the parms_id for public key
    public_key.parms_id() = param_id;
    public_key.data().is_ntt_form() = true;
    return public_key;
}

const SecretKey &KeyGenerator::secret_key() const
{
    if (!sk_generated_)
    {
        throw logic_error("secret key has not been generated");
    }
    return secret_key_;
}

KSwitchKeys KeyGenerator::create_switch_key(const SecretKey &prev_secret_key,
                                            const SecretKey &new_secret_key) const
{
    if (!using_keyswitch_)
    {
        POSEIDON_THROW(invalid_argument_error, "don't support switch key");
    }
    return kswitch_gen_->create_switch_key(prev_secret_key, new_secret_key);
}

RelinKeys KeyGenerator::create_relin_keys(std::size_t count, bool save_seed) const
{
    if (!using_keyswitch_)
    {
        POSEIDON_THROW(invalid_argument_error, "don't support switch key");
    }
    auto destination = kswitch_gen_->create_relin_keys(count, secret_key_);
    return destination;
}

void KeyGenerator::create_relin_keys(RelinKeys &destination)
{
    destination = create_relin_keys(1, false);
}

void KeyGenerator::create_galois_keys(GaloisKeys &destination)
{
    create_galois_keys(context_.crt_context()->galois_tool()->get_elts_all(), destination);

#ifdef USING_HARDWARE
    if (PoseidonFactory::get_instance()->get_device_type() == DEVICE_TYPE::DEVICE_HARDWARE)
    {
        auto literal = context_.parameters_literal();
        auto degree = literal->degree();
        auto rns_max = literal->q().size() + literal->p().size();
        auto galois_tool = context_.crt_context()->galois_tool();
        HardwareApi::galois_key_config(destination, galois_tool, rns_max, degree);
        if(literal->scheme() != BFV)
            HardwareApi::permutation_tables_config(destination, galois_tool, rns_max, degree);
    }
#endif
}

GaloisKeys KeyGenerator::create_galois_keys(const vector<std::uint32_t> &galois_elts,
                                            bool save_seed) const
{
    if (!using_keyswitch_)
    {
        POSEIDON_THROW(invalid_argument_error, "don't support switch key");
    }
    return kswitch_gen_->create_galois_keys(galois_elts, secret_key_);
}

GaloisKeys KeyGenerator::create_galois_keys(const vector<int> &step, bool save_seed) const
{
    if (!using_keyswitch_)
    {
        POSEIDON_THROW(invalid_argument_error, "don't support switch key");
    }
    return kswitch_gen_->create_galois_keys(step, secret_key_);
}

}  // namespace poseidon
