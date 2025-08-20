#include "encryptor.h"
#include "basics/modulus.h"
#include "basics/randomtostd.h"
#include "basics/util/common.h"
#include "basics/util/iterator.h"
#include "basics/util/polyarithsmallmod.h"
#include "basics/util/rlwe.h"
#include "basics/util/scalingvariant.h"
#include <algorithm>
#include <stdexcept>
using namespace std;
using namespace poseidon::util;

namespace poseidon
{
Encryptor::Encryptor(const PoseidonContext &context, const PublicKey &public_key)
    : context_(context)
{
    set_public_key(public_key);
    auto context_data = context_.crt_context()->key_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = context_data->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Quick sanity check
    if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }
}

Encryptor::Encryptor(const PoseidonContext &context, const SecretKey &secret_key)
    : context_(context)
{
    set_secret_key(secret_key);

    auto context_data = context_.crt_context()->key_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = context_data->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Quick sanity check
    if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }
}

Encryptor::Encryptor(const PoseidonContext &context, const PublicKey &public_key,
                     const SecretKey &secret_key)
    : context_(context)
{
    set_public_key(public_key);
    set_secret_key(secret_key);

    auto context_data = context_.crt_context()->key_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = context_data->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Quick sanity check
    if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
    {
        throw logic_error("invalid parameters");
    }
}

void Encryptor::encrypt_zero_internal(parms_id_type parms_id, bool is_asymmetric, bool save_seed,
                                      Ciphertext &destination, MemoryPoolHandle pool) const
{
    // Verify parameters.
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    auto context_data_ptr = context_.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }

    auto &context_data = *context_.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    bool is_ntt_form = false;

    if (parms.scheme() == CKKS || parms.scheme() == BGV)
    {
        is_ntt_form = true;
    }
    else if (parms.scheme() != BFV)
    {
        POSEIDON_THROW(invalid_argument_error, "unsupported scheme");
    }

    // Resize destination and save results
    destination.resize(context_, parms_id, 2);

    // If asymmetric key encryption
    if (is_asymmetric)
    {
        auto first_params_id = context_.crt_context()->first_parms_id();
        if (first_params_id != parms_id)
        {
            util::encrypt_zero_asymmetric(public_key_, context_, parms_id, is_ntt_form,
                                          destination);
        }
        else
        {
            // Does not require modulus switching
            util::encrypt_zero_asymmetric(public_key_, context_, parms_id, is_ntt_form,
                                          destination);
        }
    }
    else
    {
        // Does not require modulus switching
        util::encrypt_zero_symmetric(secret_key_, context_, parms_id, is_ntt_form, save_seed,
                                     destination);
    }
}

void Encryptor::encrypt_internal(const Plaintext &plain, bool is_asymmetric, bool save_seed,
                                 Ciphertext &destination, MemoryPoolHandle pool) const
{
    auto scheme = context_.crt_context()->key_context_data()->parms().scheme();
    if (scheme == BFV)
    {
        if (plain.is_ntt_form())
        {
            POSEIDON_THROW(invalid_argument_error, "plain cannot be in NTT form");
        }

        encrypt_zero_internal(context_.crt_context()->first_parms_id(), is_asymmetric, save_seed,
                              destination, pool);

        // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
        // Result gets added into the c_0 term of ciphertext (c_0,c_1).
        multiply_add_plain_with_scaling_variant(
            plain, *context_.crt_context()->first_context_data(), *iter(destination));
    }
    else if (scheme == CKKS)
    {
        if (!plain.is_ntt_form())
        {
            POSEIDON_THROW(invalid_argument_error, "plain must be in NTT form");
        }

        auto context_data_ptr = context_.crt_context()->get_context_data(plain.parms_id());
        if (!context_data_ptr)
        {
            POSEIDON_THROW(invalid_argument_error, "plain is not valid for encryption parameters");
        }
        encrypt_zero_internal(plain.parms_id(), is_asymmetric, save_seed, destination, pool);

        auto context_data = context_.crt_context()->get_context_data(plain.parms_id());
        auto &parms = context_data->parms();
        auto &coeff_modulus = context_data->coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.degree();

        // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
        ConstRNSIter plain_iter(plain.data(), coeff_count);
        RNSIter destination_iter = *iter(destination);
        add_poly_coeffmod(destination_iter, plain_iter, coeff_modulus_size, coeff_modulus,
                          destination_iter);

        destination.scale() = plain.scale();
    }
    else if (scheme == BGV)
    {
        if (plain.is_ntt_form())
        {
            POSEIDON_THROW(invalid_argument_error, "plain cannot be in NTT form");
        }
        encrypt_zero_internal(context_.crt_context()->first_parms_id(), is_asymmetric, save_seed,
                              destination, pool);

        auto &context_data = *context_.crt_context()->first_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = context_data.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.degree();
        size_t plain_coeff_count = plain.coeff_count();
        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();
        auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());

        // c_{0} = pk_{0}*u + p*e_{0} + M
        Plaintext plain_copy = plain;
        // Resize to fit the entire NTT transformed (ciphertext size) polynomial
        // Note that the new coefficients are automatically set to 0
        plain_copy.resize(coeff_count * coeff_modulus_size);
        RNSIter plain_iter(plain_copy.data(), coeff_count);
        if (!context_data.using_fast_plain_lift())
        {
            // Allocate temporary space for an entire RNS polynomial
            // Slight semantic misuse of RNSIter here, but this works well
            POSEIDON_ALLOCATE_ZERO_GET_RNS_ITER(temp, coeff_modulus_size, coeff_count, pool);

            POSEIDON_ITERATE(iter(plain_copy.data(), temp), plain_coeff_count,
                             [&](auto I)
                             {
                                 auto plain_value = get<0>(I);
                                 if (plain_value >= plain_upper_half_threshold)
                                 {
                                     add_uint(plain_upper_half_increment, coeff_modulus_size,
                                              plain_value, get<1>(I));
                                 }
                                 else
                                 {
                                     *get<1>(I) = plain_value;
                                 }
                             });

            context_data.rns_tool()->base_q()->decompose_array(temp, coeff_count, pool);

            // Copy data back to plain
            set_poly(temp, coeff_count, coeff_modulus_size, plain_copy.data());
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo
            // the coeff_modulus primes.

            // Create a "reversed" helper iterator that iterates in the reverse order both plain RNS
            // components and the plain_upper_half_increment values.
            auto helper_iter = reverse_iter(plain_iter, plain_upper_half_increment);
            advance(helper_iter, -safe_cast<ptrdiff_t>(coeff_modulus_size - 1));

            POSEIDON_ITERATE(helper_iter, coeff_modulus_size,
                             [&](auto I)
                             {
                                 POSEIDON_ITERATE(iter(*plain_iter, get<0>(I)), plain_coeff_count,
                                                  [&](auto J)
                                                  {
                                                      get<1>(J) = POSEIDON_COND_SELECT(
                                                          get<0>(J) >= plain_upper_half_threshold,
                                                          get<0>(J) + get<1>(I), get<0>(J));
                                                  });
                             });
        }
        // Transform to NTT domain
        ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables);

        // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
        RNSIter destination_iter = *iter(destination);
        add_poly_coeffmod(destination_iter, plain_iter, coeff_modulus_size, coeff_modulus,
                          destination_iter);
    }
    else
    {
        POSEIDON_THROW(invalid_argument_error, "unsupported scheme");
    }
}
}  // namespace poseidon
