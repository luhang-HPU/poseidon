#include "poseidon/batchencoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/recryption.h"
#include "poseidon/util/debug.h"
#include <iostream>

using namespace poseidon;

namespace
{
void apply_group(EvaluatorBase &evaluator, const Ciphertext &input,
                 const LinearMatrixGroup &group, const GaloisKeys &galois_keys,
                 Ciphertext &output)
{
    evaluator.multiply_by_diag_matrix_bsgs(input, group.data().front(), output, galois_keys);
    for (std::size_t i = 1; i < group.data().size(); ++i)
    {
        Ciphertext next;
        evaluator.multiply_by_diag_matrix_bsgs(output, group.data()[i], next, galois_keys);
        output = std::move(next);
    }
}
}  // namespace

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << std::endl;

    ParametersLiteralDefault params(BFV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(params);
    auto evaluator = PoseidonFactory::get_instance()->create_bfv_evaluator(context);
    BatchEncoder encoder(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    LinearMatrixGroup coeff_to_slot;
    LinearMatrixGroup slot_to_coeff;
    bgv_build_thin_recryption_maps(context, encoder, params.q().size() - 1, coeff_to_slot,
                                   slot_to_coeff);

    RecryptionData data(context);
    data.set_plain_base(2, 1);
    data.set_auxiliary_exponents(2, 1);
    data.set_linear_maps(coeff_to_slot, slot_to_coeff);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    const auto slots = params.slot();
    const auto plain_modulus = params.plain_modulus().value();

    LinearMatrixGroup identity_group;
    MatrixPlain identity_matrix;
    identity_matrix.log_slots = params.log_slots();
    identity_matrix.n1 = 1;
    identity_matrix.level = params.q().size() - 1;
    identity_matrix.scale = 1.0;
    std::vector<std::uint64_t> identity_diag(slots, 1);
    encoder.encode(identity_diag, identity_matrix.plain_vec[0]);
    identity_matrix.rot_index.push_back(0);
    identity_group.data().push_back(identity_matrix);

    Plaintext plain(slots);
    std::vector<std::uint64_t> coeffs(slots);
    for (std::size_t i = 0; i < slots; ++i)
    {
        coeffs[i] = (7 * i + 3) % plain_modulus;
        plain.data()[i] = coeffs[i];
    }

    Ciphertext encrypted;
    Ciphertext transformed;
    Plaintext decrypted;
    std::vector<std::uint64_t> decoded;
    std::vector<std::uint64_t> identity_slots(slots);
    for (std::size_t i = 0; i < slots; ++i)
    {
        identity_slots[i] = (11 * i + 5) % plain_modulus;
    }
    encoder.encode(identity_slots, plain);
    encryptor.encrypt(plain, encrypted);
    apply_group(*evaluator, encrypted, identity_group, galois_keys, transformed);
    Plaintext identity_decrypted;
    std::vector<std::uint64_t> identity_decoded;
    decryptor.decrypt(transformed, identity_decrypted);
    encoder.decode(identity_decrypted, identity_decoded);
    std::size_t identity_mismatch = 0;
    for (std::size_t i = 0; i < slots; ++i)
    {
        if (identity_decoded[i] != identity_slots[i])
        {
            ++identity_mismatch;
        }
    }
    std::cout << "identity coefficient mismatches = " << identity_mismatch << std::endl;

    evaluator->rotate_row(encrypted, transformed, 1, galois_keys);
    decryptor.decrypt(transformed, decrypted);
    encoder.decode(decrypted, decoded);
    const auto expected_rotate_left = matrix_operations::rotate_slots_vec(identity_slots, 1);
    const auto expected_rotate_right = matrix_operations::rotate_slots_vec(identity_slots, -1);
    std::size_t rotate_left_mismatch = 0;
    std::size_t rotate_right_mismatch = 0;
    for (std::size_t i = 0; i < slots; ++i)
    {
        rotate_left_mismatch += decoded[i] != expected_rotate_left[i];
        rotate_right_mismatch += decoded[i] != expected_rotate_right[i];
    }
    std::cout << "rotate_row(+1) left mismatches = " << rotate_left_mismatch
              << ", right mismatches = " << rotate_right_mismatch << std::endl;

    evaluator->rotate_col(encrypted, transformed, galois_keys);
    decryptor.decrypt(transformed, decrypted);
    encoder.decode(decrypted, decoded);
    std::vector<std::uint64_t> expected_col_swap(slots);
    const auto half_slots = slots >> 1;
    for (std::size_t i = 0; i < half_slots; ++i)
    {
        expected_col_swap[i] = identity_slots[i + half_slots];
        expected_col_swap[i + half_slots] = identity_slots[i];
    }
    std::size_t col_swap_mismatch = 0;
    for (std::size_t i = 0; i < slots; ++i)
    {
        col_swap_mismatch += decoded[i] != expected_col_swap[i];
    }
    std::cout << "rotate_col swap mismatches = " << col_swap_mismatch << std::endl;

    for (std::size_t i = 0; i < slots; ++i)
    {
        plain.data()[i] = coeffs[i];
    }
    encryptor.encrypt(plain, encrypted);
    evaluator->multiply_by_diag_matrix_bsgs(encrypted, coeff_to_slot.data().front(),
                                            transformed, galois_keys);
    decryptor.decrypt(transformed, decrypted);
    encoder.decode(decrypted, decoded);
    std::cout << "first coeff_to_slot layer decoded[0..3] = " << decoded[0] << ", "
              << decoded[1] << ", " << decoded[2] << ", " << decoded[3] << std::endl;

    apply_group(*evaluator, encrypted, coeff_to_slot, galois_keys, transformed);

    decryptor.decrypt(transformed, decrypted);
    encoder.decode(decrypted, decoded);

    std::size_t mismatch = 0;
    for (std::size_t i = 0; i < slots; ++i)
    {
        if (decoded[i] != coeffs[i])
        {
            if (mismatch < 8)
            {
                std::cout << "coeff_to_slot mismatch[" << i << "] got " << decoded[i]
                          << " expected " << coeffs[i] << std::endl;
            }
            ++mismatch;
        }
    }
    std::cout << "coeff_to_slot mismatches = " << mismatch << std::endl;

    std::vector<std::uint64_t> slot_values(slots);
    for (std::size_t i = 0; i < slots; ++i)
    {
        slot_values[i] = (5 * i + 1) % plain_modulus;
    }
    encoder.encode(slot_values, plain);
    encryptor.encrypt(plain, encrypted);
    apply_group(*evaluator, encrypted, slot_to_coeff, galois_keys, transformed);
    decryptor.decrypt(transformed, decrypted);

    mismatch = 0;
    for (std::size_t i = 0; i < slots; ++i)
    {
        const auto got = i < decrypted.coeff_count() ? decrypted.data()[i] : 0;
        if (got != slot_values[i])
        {
            if (mismatch < 8)
            {
                std::cout << "slot_to_coeff mismatch[" << i << "] got " << got
                          << " expected " << slot_values[i] << std::endl;
            }
            ++mismatch;
        }
    }
    std::cout << "slot_to_coeff mismatches = " << mismatch << std::endl;

    return mismatch == 0 ? 0 : 1;
}
