#pragma once

#include "basics/memorymanager.h"
#include "basics/serializable.h"
#include "basics/util/defines.h"
#include "basics/util/iterator.h"
#include "key/galoiskeys.h"
#include "key/keyswitch_bv.h"
#include "key/publickey.h"
#include "key/relinkeys.h"
#include "key/secretkey.h"
#include "poseidon_context.h"
#include <random>

namespace poseidon
{
/**
Generates matching secret key and public key. An existing KeyGenerator can
also at any time be used to generate relinearization keys and Galois keys.
Constructing a KeyGenerator requires only a PoseidonContext.

@see EncryptionParameters for more details on encryption parameters.
@see SecretKey for more details on secret key.
@see PublicKey for more details on public key.
@see RelinKeys for more details on relinearization keys.
@see GaloisKeys for more details on Galois keys.
*/
class KeyGenerator
{
public:
    /**
    Creates a KeyGenerator initialized with the specified PoseidonContext.

    @param[in] context The PoseidonContext
    @throws std::invalid_argument if the encryption parameters are not valid
    */
    KeyGenerator(const PoseidonContext &context);

    /**
    Creates an KeyGenerator instance initialized with the specified PoseidonContext
    and specified previously secret key. This can e.g. be used to increase
    the number of relinearization keys from what had earlier been generated,
    or to generate Galois keys in case they had not been generated earlier.

    @param[in] context The PoseidonContext
    @param[in] secret_key A previously generated secret key
    @throws std::invalid_argument if encryption parameters are not valid
    @throws std::invalid_argument if secret_key is not valid for encryption
    parameters
    */
    KeyGenerator(const PoseidonContext &context, const SecretKey &secret_key);

    /**
    Returns a const reference to the secret key.
    */
    POSEIDON_NODISCARD const SecretKey &secret_key() const;

    /**
    Generates a public key and stores the result in destination. Every time
    this function is called, a new public key will be generated.

    @param[out] destination The public key to overwrite with the generated
    public key
    */
    inline void create_public_key(PublicKey &destination) const
    {
        destination = generate_pk(false);
    }

    /**
    Generates and returns a public key as a serializable object. Every time
    this function is called, a new public key will be generated.

    Half of the key data is pseudo-randomly generated from a seed to reduce
    the object size. The resulting serializable object cannot be used
    directly and is meant to be serialized for the size reduction to have an
    impact.
    */
    POSEIDON_NODISCARD inline Serializable<PublicKey> create_public_key() const
    {
        return generate_pk(true);
    }

    /**
    Generates relinearization keys and stores the result in destination.
    Every time this function is called, new relinearization keys will be
    generated.

    @param[out] destination The relinearization keys to overwrite with the
    generated relinearization keys
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    */
    void create_relin_keys(RelinKeys &destination);

    /**
    Generates and returns relinearization keys as a serializable object.
    Every time this function is called, new relinearization keys will be
    generated.

    Half of the key data is pseudo-randomly generated from a seed to reduce
    the object size. The resulting serializable object cannot be used
    directly and is meant to be serialized for the size reduction to have an
    impact.

    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    */
    POSEIDON_NODISCARD inline Serializable<RelinKeys> create_relin_keys()
    {
        return create_relin_keys(1, true);
    }

    /**
    Generates Galois keys and stores the result in destination. Every time
    this function is called, new Galois keys will be generated.

    This function creates specific Galois keys that can be used to apply
    specific Galois automorphisms on encrypted data. The user needs to give
    as input a vector of Galois elements corresponding to the keys that are
    to be created.

    The Galois elements are odd integers in the interval [1, M-1], where
    M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
    3^i % M corresponds to a cyclic row rotation i steps to the left, and
    a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
    steps to the right. The Galois element M-1 corresponds to a column rotation
    (row swap) in BFV, and complex conjugation in ckks. In the polynomial view
    (not batching), a Galois automorphism by a Galois element p changes
    Enc(plain(x)) to Enc(plain(x^p)).

    @param[in] galois_elts The Galois elements for which to generate keys
    @param[out] destination The Galois keys to overwrite with the generated
    Galois keys
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    @throws std::invalid_argument if the Galois elements are not valid
    */
    inline void create_galois_keys(const std::vector<std::uint32_t> &galois_elts,
                                   GaloisKeys &destination)
    {
        destination = create_galois_keys(galois_elts, false);
    }

    /**
    Generates and returns Galois keys as a serializable object. Every time
    this function is called, new Galois keys will be generated.

    Half of the key data is pseudo-randomly generated from a seed to reduce
    the object size. The resulting serializable object cannot be used
    directly and is meant to be serialized for the size reduction to have an
    impact.

    This function creates specific Galois keys that can be used to apply
    specific Galois automorphisms on encrypted data. The user needs to give
    as input a vector of Galois elements corresponding to the keys that are
    to be created.

    The Galois elements are odd integers in the interval [1, M-1], where
    M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
    3^i % M corresponds to a cyclic row rotation i steps to the left, and
    a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
    steps to the right. The Galois element M-1 corresponds to a column rotation
    (row swap) in BFV, and complex conjugation in ckks. In the polynomial view
    (not batching), a Galois automorphism by a Galois element p changes
    Enc(plain(x)) to Enc(plain(x^p)).

    @param[in] galois_elts The Galois elements for which to generate keys
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    @throws std::invalid_argument if the Galois elements are not valid
    */
    POSEIDON_NODISCARD inline Serializable<GaloisKeys>
    create_galois_keys(const std::vector<std::uint32_t> &galois_elts)
    {
        return create_galois_keys(galois_elts, true);
    }

    /**
    Generates Galois keys and stores the result in destination. Every time
    this function is called, new Galois keys will be generated.

    The user needs to give as input a vector of desired Galois rotation step
    counts, where negative step counts correspond to rotations to the right
    and positive step counts correspond to rotations to the left. A step
    count of zero can be used to indicate a column rotation in the BFV scheme
    and complex conjugation in the ckks scheme.

    @param[in] steps The rotation step counts for which to generate keys
    @param[out] destination The Galois keys to overwrite with the generated
    Galois keys
    @throws std::logic_error if the encryption parameters do not support
    batching and scheme is scheme_type::BFV
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    @throws std::invalid_argument if the step counts are not valid
    */
    inline void create_galois_keys(const std::vector<int> &steps, GaloisKeys &destination)
    {
        destination = create_galois_keys(steps, false);
    }

    POSEIDON_NODISCARD KSwitchKeys create_switch_key(const SecretKey &prev_secret_key,
                                                     const SecretKey &new_secret_key) const;

    POSEIDON_NODISCARD inline KSwitchKeys create_switch_key(const SecretKey &prev_key,
                                                            const PublicKey &new_key) const
    {
        return kswitch_gen_->create_switch_key(prev_key, new_key);
    }

    /**
    Generates and returns Galois keys as a serializable object. Every time
    this function is called, new Galois keys will be generated.

    Half of the key data is pseudo-randomly generated from a seed to reduce
    the object size. The resulting serializable object cannot be used
    directly and is meant to be serialized for the size reduction to have an
    impact.

    The user needs to give as input a vector of desired Galois rotation step
    counts, where negative step counts correspond to rotations to the right
    and positive step counts correspond to rotations to the left. A step
    count of zero can be used to indicate a column rotation in the BFV scheme
    and complex conjugation in the ckks scheme.

    @param[in] steps The rotation step counts for which to generate keys
    @throws std::logic_error if the encryption parameters do not support
    batching and scheme is scheme_type::BFV
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    @throws std::invalid_argument if the step counts are not valid
    */
    POSEIDON_NODISCARD inline Serializable<GaloisKeys>
    create_galois_keys(const std::vector<int> &steps)
    {
        return create_galois_keys(
            context_.crt_context()->galois_tool()->get_elts_from_steps(steps));
    }

    /**
    Generates Galois keys and stores the result in destination. Every time
    this function is called, new Galois keys will be generated.

    This function creates logarithmically many (in degree of the polynomial
    modulus) Galois keys that is sufficient to apply any Galois automorphism
    (e.g., rotations) on encrypted data. Most users will want to use this
    overload of the function.

    Precisely it generates 2*log(n)-1 number of Galois keys where n is the
    degree of the polynomial modulus. When used with batching, these keys
    support direct left and right rotations of power-of-2 steps of rows in BFV
    or vectors in ckks and rotation of columns in BFV or conjugation in ckks.

    @param[out] destination The Galois keys to overwrite with the generated
    Galois keys
    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    */
    void create_galois_keys(GaloisKeys &destination);

    /**
    Generates and returns Galois keys as a serializable object. Every time
    this function is called, new Galois keys will be generated.

    Half of the key data is pseudo-randomly generated from a seed to reduce
    the object size. The resulting serializable object cannot be used
    directly and is meant to be serialized for the size reduction to have an
    impact.

    This function creates logarithmically many (in degree of the polynomial
    modulus) Galois keys that is sufficient to apply any Galois automorphism
    (e.g., rotations) on encrypted data. Most users will want to use this
    overload of the function.

    Precisely it generates 2*log(n)-1 number of Galois keys where n is the
    degree of the polynomial modulus. When used with batching, these keys
    support direct left and right rotations of power-of-2 steps of rows in BFV
    or vectors in ckks and rotation of columns in BFV or conjugation in ckks.

    @throws std::logic_error if the encryption parameters do not support
    keyswitching
    */
    POSEIDON_NODISCARD inline Serializable<GaloisKeys> create_galois_keys()
    {
        return create_galois_keys(context_.crt_context()->galois_tool()->get_elts_all());
    }

private:
    KeyGenerator(const KeyGenerator &copy) = delete;

    KeyGenerator &operator=(const KeyGenerator &assign) = delete;

    KeyGenerator(KeyGenerator &&source) = delete;

    KeyGenerator &operator=(KeyGenerator &&assign) = delete;

    // void compute_secret_key_array(const CrtContext::ContextData &context_data, std::size_t
    // max_power);

    /**
    Generates new secret key.

    @param[in] is_initialized True if the secret key has already been
    initialized so that only the secret_key_array_ should be initialized, for
    example, if the secret key was provided in the constructor
    */
    void generate_sk(bool is_initialized = false);

    /**
    Generates new public key matching to existing secret key.
    */
    PublicKey generate_pk(bool save_seed) const;

    /**
    Generates and returns the specified number of relinearization keys.

    @param[in] count The number of relinearization keys to generate
    @param[in] save_seed If true, save seed instead of a polynomial.
    @throws std::invalid_argument if count is zero or too large
    */
    RelinKeys create_relin_keys(std::size_t count, bool save_seed) const;

    /**
    Generates and returns Galois keys. This function creates specific Galois
    keys that can be used to apply specific Galois automorphisms on encrypted
    data. The user needs to give as input a vector of Galois elements
    corresponding to the keys that are to be created.

    The Galois elements are odd integers in the interval [1, M-1], where
    M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
    3^i % M corresponds to a cyclic row rotation i steps to the left, and
    a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
    steps to the right. The Galois element M-1 corresponds to a column rotation
    (row swap) in BFV, and complex conjugation in ckks. In the polynomial view
    (not batching), a Galois automorphism by a Galois element p changes
    Enc(plain(x)) to Enc(plain(x^p)).

    @param[in] galois_elts The Galois elements for which to generate keys
    @param[in] save_seed If true, replace second poly in Ciphertext with seed
    @throws std::invalid_argument if the Galois elements are not valid
    */
    GaloisKeys create_galois_keys(const std::vector<std::uint32_t> &galois_elts,
                                  bool save_seed) const;
    GaloisKeys create_galois_keys(const std::vector<int> &step, bool save_seed) const;

    std::shared_ptr<KSwitchGenBase> kswitch_gen_{nullptr};
    // We use a fresh memory pool with `clear_on_destruction' enabled.
    MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    PoseidonContext context_;

    SecretKey secret_key_;

    std::size_t secret_key_array_size_ = 0;

    util::Pointer<std::uint64_t> secret_key_array_;

    mutable util::ReaderWriterLocker secret_key_array_locker_;

    bool sk_generated_ = false;

    bool using_keyswitch_ = true;
};
}  // namespace poseidon
