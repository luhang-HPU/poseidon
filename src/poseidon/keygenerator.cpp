#include "keygenerator.h"
#include "decryptor.h"
#include "encryptor.h"
#include "basics/randomtostd.h"
#include "basics/util/common.h"
#include "basics/util/galois.h"
#include "basics/util/ntt.h"
#include "basics/util/polycore.h"
#include "basics/util/rlwe.h"
#include "key/keyswitch.h"
#include "poseidon/factory/poseidon_factory.h"
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
        POSEIDON_THROW_LOGIC_ERROR("cannot generate public key for unspecified secret key");
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
        POSEIDON_THROW_LOGIC_ERROR("invalid parameters");
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
        POSEIDON_THROW_LOGIC_ERROR("secret key has not been generated");
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

BootstrappingKey
KeyGenerator::create_bootstrapping_key(const SecretKey &boot_secret_key, const std::shared_ptr<EvaluatorBgvBase> bgv_eva) const
{
    BootstrappingKey result;

    // Create a key-switching key from secret_key_ (data) to boot_secret_key.
    // This allows switching a ciphertext from the data key to the boot key
    // before the raw modulus switch during bootstrapping.
    KSwitchKeys ksk = create_switch_key(secret_key_, boot_secret_key);

    // Store the switch key for use during bootstrapping
    result.switch_key() = ksk;

    // Store the encrypted form as a simple ciphertext.
    // For bootstrapping, we need Enc(boot_sk) under the data key.
    // We use symmetric encryption of the boot secret key polynomial.
    Encryptor encryptor(context_, secret_key_);

    // Get the boot secret key polynomial and convert from NTT to coefficient form
    const auto &boot_poly = boot_secret_key.data();
    size_t coeff_count = boot_poly.coeff_count();

    // Create a plaintext in coefficient form (BGV default)
    Plaintext plain(coeff_count);
    plain.parms_id() = boot_poly.parms_id();

    // The boot_secret_key.data() is a Plaintext containing the polynomial
    // in NTT form. We copy it directly and trust the encryptor to handle
    // the format conversion. For BGV, encrypt_symmetric expects coefficient form.
    // Since this is a simple ternary polynomial, we copy the data as-is
    // and let the encryption process work correctly.
    for (size_t i = 0; i < coeff_count; i++)
    {
        plain[i] = boot_poly[i];
    }

    bgv_eva->transform_from_ntt_inplace(plain, boot_poly.parms_id());

    encryptor.encrypt_symmetric(plain, result.recrypt_ekey());

    return result;
}

}  // namespace poseidon
