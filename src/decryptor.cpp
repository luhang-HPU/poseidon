#include "decryptor.h"

#include "basics/util/common.h"
#include "basics/util/polyarithsmallmod.h"
#include "basics/util/polycore.h"

#include "basics/util/uintarith.h"
#include "basics/util/uintcore.h"
#include <algorithm>
#include <stdexcept>

using namespace std;
using namespace poseidon::util;

namespace poseidon
{
namespace
{
void poly_infty_norm_coeffmod(StrideIter<const uint64_t *> poly, size_t coeff_count,
                              const uint64_t *modulus, uint64_t *result, MemoryPool &pool)
{
    size_t coeff_uint64_count = poly.stride();

    // Construct negative threshold: (modulus + 1) / 2
    auto modulus_neg_threshold(allocate_uint(coeff_uint64_count, pool));
    half_round_up_uint(modulus, coeff_uint64_count, modulus_neg_threshold.get());

    // Mod out the poly coefficients and choose a symmetric representative from [-modulus,modulus)
    set_zero_uint(coeff_uint64_count, result);
    auto coeff_abs_value(allocate_uint(coeff_uint64_count, pool));
    POSEIDON_ITERATE(
        poly, coeff_count,
        [&](auto I)
        {
            if (is_greater_than_or_equal_uint(I, modulus_neg_threshold.get(), coeff_uint64_count))
            {
                sub_uint(modulus, I, coeff_uint64_count, coeff_abs_value.get());
            }
            else
            {
                set_uint(I, coeff_uint64_count, coeff_abs_value.get());
            }

            if (is_greater_than_uint(coeff_abs_value.get(), result, coeff_uint64_count))
            {
                // Store the new max
                set_uint(coeff_abs_value.get(), coeff_uint64_count, result);
            }
        });
}
}  // namespace

Decryptor::Decryptor(const PoseidonContext &context, const SecretKey &secret_key)
    : context_(context)
{
    auto context_data = context_.crt_context()->key_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = context_data->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Set the secret_key_array to have size 1 (first power of secret)
    // and copy over data
    secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
    set_poly(secret_key.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
    secret_key_array_size_ = 1;
}

void Decryptor::decrypt(const Ciphertext &encrypted, Plaintext &destination)
{
    // Additionally check that ciphertext doesn't have trivial size
    if (encrypted.size() < POSEIDON_CIPHERTEXT_SIZE_MIN)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted is empty");
    }

    auto &context_data = *context_.crt_context()->first_context_data();
    auto &parms = context_data.parms();

    switch (parms.scheme())
    {
    case BFV:
        bfv_decrypt(encrypted, destination, pool_);
        return;

    case CKKS:
        ckks_decrypt(encrypted, destination, pool_);
        return;

    case BGV:
        bgv_decrypt(encrypted, destination, pool_);
        return;

    default:
        POSEIDON_THROW(invalid_argument_error, "unsupported scheme");
    }
}

void Decryptor::bfv_decrypt(const Ciphertext &encrypted, Plaintext &destination,
                            MemoryPoolHandle pool)
{
    if (encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted cannot be in NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
    // This is equal to Delta m + v where ||v|| < Delta/2.
    // Add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
    // Therefore, we can (integer) divide by Delta and the answer will round down to m.

    // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
    POSEIDON_ALLOCATE_ZERO_GET_RNS_ITER(tmp_dest_modq, coeff_count, coeff_modulus_size, pool);

    // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
    // Now do the dot product of encrypted_copy and the secret key array using NTT.
    // The secret key powers are already NTT transformed.
    dot_product_ct_sk_array(encrypted, tmp_dest_modq, pool_);

    // Allocate a full size destination to write to
    destination.parms_id() = parms_id_zero;
    destination.resize(coeff_count);

    // Divide scaling variant using BEHZ FullRNS techniques
    context_data.rns_tool()->decrypt_scale_and_round(tmp_dest_modq, destination.data(), pool);

    // How many non-zero coefficients do we really have in the result?
    size_t plain_coeff_count = get_significant_uint64_count_uint(destination.data(), coeff_count);

    // Resize destination to appropriate size
    destination.resize(max(plain_coeff_count, size_t(1)));
}

void Decryptor::ckks_decrypt(const Ciphertext &encrypted, Plaintext &destination,
                             MemoryPoolHandle pool)
{
    if (!encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted must be in NTT form");
    }

    // We already know that the parameters are valid
    auto context_data = context_.crt_context()->key_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = context_data->coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);

    // Decryption consists in finding
    // c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
    // as long as ||m + v|| < q_1 * q_2 * q_3.
    // This is equal to m + v where ||v|| is small enough.

    // Since we overwrite destination, we zeroize destination parameters
    // This is necessary, otherwise resize will throw an exception.
    destination.parms_id() = parms_id_zero;

    // Resize destination to appropriate size
    destination.resize(context_, encrypted.parms_id(), rns_poly_uint64_count);

    // Do the dot product of encrypted and the secret key array using NTT.
    dot_product_ct_sk_array(encrypted, RNSIter(destination.data(), coeff_count), pool);

    // Set destination parameters as in encrypted

    destination.scale() = encrypted.scale();
}

void Decryptor::bgv_decrypt(const Ciphertext &encrypted, Plaintext &destination,
                            MemoryPoolHandle pool)
{
    if (!encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted must be in NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());

    POSEIDON_ALLOCATE_ZERO_GET_RNS_ITER(tmp_dest_modq, coeff_count, coeff_modulus_size, pool);

    dot_product_ct_sk_array(encrypted, tmp_dest_modq, pool_);

    destination.parms_id() = parms_id_zero;
    destination.resize(coeff_count);

    inverse_ntt_negacyclic_harvey(tmp_dest_modq, coeff_modulus_size, ntt_tables);

    context_data.rns_tool()->decrypt_modt(tmp_dest_modq, destination.data(), pool);

    if (encrypted.correction_factor() != 1)
    {
        uint64_t fix = 1;
        if (!try_invert_uint_mod(encrypted.correction_factor(), plain_modulus, fix))
        {
            throw logic_error("invalid correction factor");
        }
        multiply_poly_scalar_coeffmod(CoeffIter(destination.data()), coeff_count, fix,
                                      plain_modulus, CoeffIter(destination.data()));
    }

    // How many non-zero coefficients do we really have in the result?
    size_t plain_coeff_count = get_significant_uint64_count_uint(destination.data(), coeff_count);

    // Resize destination to appropriate size
    destination.resize(max(plain_coeff_count, size_t(1)));
}

void Decryptor::compute_secret_key_array(size_t max_power)
{
#ifdef POSEIDON_DEBUG
    if (max_power < 1)
    {
        POSEIDON_THROW(invalid_argument_error, "max_power must be at least 1");
    }
    if (!secret_key_array_size_ || !secret_key_array_)
    {
        throw logic_error("secret_key_array_ is uninitialized");
    }
#endif
    // WARNING: This function must be called with the original context_data
    auto &context_data = *context_.crt_context()->key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();

    ReaderLock reader_lock(secret_key_array_locker_.acquire_read());

    size_t old_size = secret_key_array_size_;
    size_t new_size = max(max_power, old_size);

    if (old_size == new_size)
    {
        return;
    }

    reader_lock.unlock();

    // Need to extend the array
    // Compute powers of secret key until max_power
    auto secret_key_array(allocate_poly_array(new_size, coeff_count, coeff_modulus_size, pool_));
    PolyIter secret_key_array_iter(secret_key_array.get(), coeff_count, coeff_modulus_size);
    set_poly_array(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size,
                   secret_key_array_iter);

    // Since all of the key powers in secret_key_array_ are already NTT transformed,
    // to get the next one we simply need to compute a dyadic product of the last
    // one with the first one [which is equal to NTT(secret_key_)].
    POSEIDON_ITERATE(iter(secret_key_array_iter + (old_size - 1), secret_key_array_iter + old_size),
                     new_size - old_size,
                     [&](auto I)
                     {
                         dyadic_product_coeffmod(get<0>(I), *secret_key_array_iter,
                                                 coeff_modulus_size, coeff_modulus, get<1>(I));
                     });

    // Take writer lock to update array
    WriterLock writer_lock(secret_key_array_locker_.acquire_write());

    // Do we still need to update size?
    old_size = secret_key_array_size_;
    new_size = max(max_power, secret_key_array_size_);

    if (old_size == new_size)
    {
        return;
    }

    // Acquire new array
    secret_key_array_size_ = new_size;
    secret_key_array_.acquire(move(secret_key_array));
}

// Compute c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q.
// Store result in destination in RNS form.
void Decryptor::dot_product_ct_sk_array(const Ciphertext &encrypted, RNSIter destination,
                                        MemoryPoolHandle pool)
{
    auto &context_data = *context_.crt_context()->get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t key_coeff_modulus_size =
        context_.crt_context()->key_context_data()->coeff_modulus().size();
    size_t encrypted_size = encrypted.size();
    auto is_ntt_form = encrypted.is_ntt_form();
    // cout << is_ntt_form << endl;

    auto ntt_tables = context_.crt_context()->small_ntt_tables();

    // Make sure we have enough secret key powers computed
    compute_secret_key_array(encrypted_size - 1);

    if (encrypted_size == 2)
    {
        ConstRNSIter secret_key_array(secret_key_array_.get(), coeff_count);
        ConstRNSIter c0(encrypted.data(0), coeff_count);
        ConstRNSIter c1(encrypted.data(1), coeff_count);
        if (is_ntt_form)
        {
            POSEIDON_ITERATE(
                iter(c0, c1, secret_key_array, coeff_modulus, destination), coeff_modulus_size,
                [&](auto I)
                {
                    // put < c_1 * s > mod q in destination
                    dyadic_product_coeffmod(get<1>(I), get<2>(I), coeff_count, get<3>(I),
                                            get<4>(I));
                    // add c_0 to the result; note that destination should be in the
                    // same (NTT) form as encrypted
                    add_poly_coeffmod(get<4>(I), get<0>(I), coeff_count, get<3>(I), get<4>(I));
                });
        }
        else
        {
            POSEIDON_ITERATE(iter(c0, c1, secret_key_array, coeff_modulus, ntt_tables, destination),
                             coeff_modulus_size,
                             [&](auto I)
                             {
                                 set_uint(get<1>(I), coeff_count, get<5>(I));
                                 // Transform c_1 to NTT form
                                 ntt_negacyclic_harvey_lazy(get<5>(I), get<4>(I));
                                 // put < c_1 * s > mod q in destination
                                 dyadic_product_coeffmod(get<5>(I), get<2>(I), coeff_count,
                                                         get<3>(I), get<5>(I));
                                 // Transform back
                                 inverse_ntt_negacyclic_harvey(get<5>(I), get<4>(I));
                                 // add c_0 to the result; note that destination should be in the
                                 // same (NTT) form as encrypted
                                 add_poly_coeffmod(get<5>(I), get<0>(I), coeff_count, get<3>(I),
                                                   get<5>(I));
                             });
        }
    }
    else
    {
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        POSEIDON_ALLOCATE_GET_POLY_ITER(encrypted_copy, encrypted_size - 1, coeff_count,
                                        coeff_modulus_size, pool);
        set_poly_array(encrypted.data(1), encrypted_size - 1, coeff_count, coeff_modulus_size,
                       encrypted_copy);

        // Transform c_1, c_2, ... to NTT form unless they already are
        if (!is_ntt_form)
        {
            ntt_negacyclic_harvey_lazy(encrypted_copy, encrypted_size - 1, ntt_tables);
        }

        // Compute dyadic product with secret power array
        auto secret_key_array =
            PolyIter(secret_key_array_.get(), coeff_count, key_coeff_modulus_size);
        POSEIDON_ITERATE(iter(encrypted_copy, secret_key_array), encrypted_size - 1,
                         [&](auto I) {
                             dyadic_product_coeffmod(get<0>(I), get<1>(I), coeff_modulus_size,
                                                     coeff_modulus, get<0>(I));
                         });
        // Aggregate all polynomials together to complete the dot product
        set_zero_poly(coeff_count, coeff_modulus_size, destination);
        POSEIDON_ITERATE(
            encrypted_copy, encrypted_size - 1,
            [&](auto I)
            { add_poly_coeffmod(destination, I, coeff_modulus_size, coeff_modulus, destination); });

        if (!is_ntt_form)
        {
            // If the input was not in NTT form, need to transform back
            inverse_ntt_negacyclic_harvey(destination, coeff_modulus_size, ntt_tables);
        }

        // Finally add c_0 to the result; note that destination should be in the same (NTT) form as
        // encrypted
        add_poly_coeffmod(destination, *iter(encrypted), coeff_modulus_size, coeff_modulus,
                          destination);
    }
}

int Decryptor::invariant_noise_budget(const Ciphertext &encrypted)
{
    // Additionally check that ciphertext doesn't have trivial size
    if (encrypted.size() < POSEIDON_CIPHERTEXT_SIZE_MIN)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted is empty");
    }

    auto scheme = context_.crt_context()->key_context_data()->parms().scheme();
    if (scheme != SchemeType::BFV && scheme != SchemeType::BGV)
    {
        throw logic_error("unsupported scheme");
    }
    if (scheme == SchemeType::BFV && encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BFV encrypted cannot be in NTT form");
    }
    if (scheme == SchemeType::BGV && !encrypted.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV encrypted must be in NTT form");
    }

    auto &context_data = *context_.crt_context()->get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto ntt_tables = iter(context_.crt_context()->small_ntt_tables());

    // Storage for the infinity norm of noise poly
    auto norm(allocate_uint(coeff_modulus_size, pool_));

    // Storage for noise poly
    POSEIDON_ALLOCATE_ZERO_GET_RNS_ITER(noise_poly, coeff_count, coeff_modulus_size, pool_);

    // Now need to compute c(s) - Delta*m (mod q)
    // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
    // This is equal to Delta m + v where ||v|| < Delta/2.
    // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
    // in destination_poly.
    // Now do the dot product of encrypted_copy and the secret key array using NTT.
    // The secret key powers are already NTT transformed.
    dot_product_ct_sk_array(encrypted, noise_poly, pool_);

    if (scheme == SchemeType::BGV)
    {
        inverse_ntt_negacyclic_harvey(noise_poly, coeff_modulus_size, ntt_tables);
    }

    // Multiply by plain_modulus and reduce mod coeff_modulus to get
    // coeff_modulus()*noise.
    if (scheme == SchemeType::BFV)
    {
        multiply_poly_scalar_coeffmod(noise_poly, coeff_modulus_size, plain_modulus.value(),
                                      coeff_modulus, noise_poly);
    }

    // CRT-compose the noise
    context_data.rns_tool()->base_q()->compose_array(noise_poly, coeff_count, pool_);

    // Next we compute the infinity norm mod parms.coeff_modulus()
    StrideIter<const uint64_t *> wide_noise_poly((*noise_poly).ptr(), coeff_modulus_size);
    poly_infty_norm_coeffmod(wide_noise_poly, coeff_count, context_data.total_coeff_modulus(),
                             norm.get(), pool_);

    // The -1 accounts for scaling the invariant noise by 2;
    // note that we already took plain_modulus into account in compose
    // so no need to subtract log(plain_modulus) from this
    int bit_count_diff = context_data.total_coeff_modulus_bit_count() -
                         get_significant_bit_count_uint(norm.get(), coeff_modulus_size) - 1;
    return max(0, bit_count_diff);
}
}  // namespace poseidon
