#include "poseidon/batchencoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/recryption.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <chrono>
#include <vector>

using namespace poseidon;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault bfv_param_literal(BFV, 8192, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    auto bfv_eva = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    std::vector<uint64_t> vec_result;
    int mat_size = bfv_param_literal.slot();
    uint64_t plain_modulus = bfv_param_literal.plain_modulus().value();

    // create message
    vector<uint64_t> message1;
    sample_random_vector(message1, mat_size, 10);

    // init Plaintext and Ciphertext
    Plaintext plain, plain_res;
    Ciphertext cipher;
    PublicKey public_key;
    RelinKeys relin_keys;
    BatchEncoder bfv_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    auto recryption_key = kgen.create_switch_key(kgen.secret_key(), kgen.secret_key());
    Encryptor enc(context, public_key);
    Decryptor dec(context, kgen.secret_key());

    // encode && encrypt
    bfv_encoder.encode(message1, plain);
    enc.encrypt(plain, cipher);

    // evaluate
    auto start = std::chrono::high_resolution_clock::now();
    bfv_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    bfv_eva->drop_modulus_to_next(cipher, cipher);

    RecryptionData recryption_data(context);
    recryption_data.set_auxiliary_exponents(2, 1);
    Recryptor recryptor(context, *bfv_eva, recryption_data);

    std::cout << "before recryption, level = " << cipher.level() << std::endl;

    recryptor.recrypt(cipher, cipher, recryption_key);
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Recryption TIME: " << duration.count() << " microseconds" << std::endl;

    std::cout << "after recryption, level = " << cipher.level() << std::endl;

    // decode && decrypt
    dec.decrypt(cipher, plain_res);
    bfv_encoder.decode(plain_res, vec_result);
    for (int i = 0; i < 10; i++)
    {
        message1[i] *= message1[i];
        message1[i] %= plain_modulus;
        printf("source vec[%d] : %ld\n", i, message1[i]);
        printf("result vec[%d] : %ld\n", i, vec_result[i]);
        if (message1[i] != vec_result[i])
        {
            std::cerr << "BFV recryption mismatch at slot " << i << std::endl;
            return 1;
        }
    }

    return 0;
}
