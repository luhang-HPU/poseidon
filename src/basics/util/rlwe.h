#pragma once

#include "src/basics/randomgen.h"
#include "src/ciphertext.h"
#include "src/key/publickey.h"
#include "src/key/secretkey.h"
#include "src/parameters_literal.h"
#include "src/poseidon_context.h"
#include <cstdint>

namespace poseidon
{
namespace util
{
/**
Generate a uniform ternary polynomial and store in RNS representation.

@param[in] prng A uniform random generator
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_ternary(std::shared_ptr<UniformRandomGenerator> prng,
                         const PoseidonContext &context, parms_id_type id,
                         std::uint64_t *destination);

void sample_poly_ternary_with_hamming(shared_ptr<UniformRandomGenerator> prng,
                                      const PoseidonContext &context, parms_id_type id,
                                      uint64_t *destination);

/**
Generate a polynomial from a normal distribution and store in RNS representation.

@param[in] prng A uniform random generator
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_normal(std::shared_ptr<UniformRandomGenerator> prng,
                        const PoseidonContext &context, parms_id_type id,
                        std::uint64_t *destination);

/**
Generate a polynomial from a centered binomial distribution and store in RNS representation.

@param[in] prng A uniform random generator.
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_cbd(std::shared_ptr<UniformRandomGenerator> prng, const PoseidonContext &context,
                     parms_id_type id, std::uint64_t *destination);

/**
Generate a uniformly random polynomial and store in RNS representation.

@param[in] prng A uniform random generator
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_uniform(std::shared_ptr<UniformRandomGenerator> prng,
                         const PoseidonContext &context, parms_id_type id,
                         std::uint64_t *destination);

/**
Generate a uniformly random polynomial and store in RNS representation.
This implementation corresponds to Poseidon 3.4 and earlier.

@param[in] prng A uniform random generator
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_uniform_seal_3_4(std::shared_ptr<UniformRandomGenerator> prng,
                                  const PoseidonContext &context, parms_id_type id,
                                  std::uint64_t *destination);

/**
Generate a uniformly random polynomial and store in RNS representation.
This implementation corresponds to Poseidon 3.5 and earlier.

@param[in] prng A uniform random generator
@param[in] parms EncryptionParameters used to parameterize an RNS polynomial
@param[out] destination Allocated space to store a random polynomial
*/
void sample_poly_uniform_seal_3_5(std::shared_ptr<UniformRandomGenerator> prng,
                                  const PoseidonContext &context, parms_id_type id,
                                  std::uint64_t *destination);

/**
Create an encryption of zero with a public key and store in a ciphertext.

@param[in] public_key The public key used for encryption
@param[in] context The PoseidonContext containing a chain of ContextData
@param[in] parms_id Indicates the level of encryption
@param[in] is_ntt_form If true, store ciphertext in NTT form
@param[out] destination The output ciphertext - an encryption of zero
*/
void encrypt_zero_asymmetric(const PublicKey &public_key, const PoseidonContext &context,
                             parms_id_type parms_id, bool is_ntt_form, Ciphertext &destination);

/**
Create an encryption of zero with a secret key and store in a ciphertext.

@param[out] destination The output ciphertext - an encryption of zero
@param[in] secret_key The secret key used for encryption
@param[in] context The PoseidonContext containing a chain of ContextData
@param[in] parms_id Indicates the level of encryption
@param[in] is_ntt_form If true, store ciphertext in NTT form
@param[in] save_seed If true, the second component of ciphertext is
replaced with the random seed used to sample this component
*/
void encrypt_zero_symmetric(const SecretKey &secret_key, const PoseidonContext &context,
                            parms_id_type parms_id, bool is_ntt_form, bool save_seed,
                            Ciphertext &destination);
}  // namespace util
}  // namespace poseidon
