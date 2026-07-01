#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/recryption.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <chrono>
#include <complex>
#include <vector>

using namespace poseidon;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 40, 1, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(std::vector<uint32_t>(30, 40), std::vector<uint32_t>{40});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    CKKSEncoder encoder(context);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key, keygen.secret_key());
    Decryptor decryptor(context, keygen.secret_key());

    const int slot_count = 1 << ckks_param_literal.log_slots();
    std::vector<std::complex<double>> message;
    sample_random_complex_vector(message, slot_count);
    for (auto &slot : message)
    {
        slot = sin(slot);
    }

    Plaintext plain, decoded_plain;
    Ciphertext cipher, refreshed;
    encoder.encode(message, ckks_param_literal.scale(), plain);
    encryptor.encrypt(plain, cipher);

    evaluator->multiply_relin(cipher, cipher, cipher, relin_keys);
    evaluator->rescale_dynamic(cipher, cipher, ckks_param_literal.scale());

    std::cout << "before recryption, level = " << cipher.level() << std::endl;

    RecryptionData recrypt_data(context, RecryptionConfig{});
    Recryptor recryptor(context, *evaluator, encoder);

    auto start = std::chrono::high_resolution_clock::now();
    recryptor.recrypt(cipher, refreshed, recrypt_data, relin_keys, galois_keys);
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);

    std::cout << "Recryption TIME: " << duration.count() << " microseconds" << std::endl;
    std::cout << "after recryption, level = " << refreshed.level() << std::endl;

    std::vector<std::complex<double>> result;
    decryptor.decrypt(refreshed, decoded_plain);
    encoder.decode(decoded_plain, result);

    for (int i = 0; i < 10; i++)
    {
        message[i] *= message[i];
        printf("source vec[%d] : %0.10f + %0.10f I \n", i, real(message[i]), imag(message[i]));
        printf("result vec[%d] : %0.10f + %0.10f I \n", i, real(result[i]), imag(result[i]));
    }
    GetPrecisionStats(result, message);

    return 0;
}
