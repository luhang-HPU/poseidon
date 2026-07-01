#include "poseidon/batchencoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/recryption.h"
#include "poseidon/util/debug.h"
#include <exception>
#include <vector>

using namespace poseidon;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);

    ParametersLiteralDefault bfv_param_literal(BFV, 8192, poseidon::sec_level_type::tc128);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    BatchEncoder encoder(context);
    KeyGenerator keygen(context);

    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    std::vector<uint64_t> message(encoder.slot_count(), 0);
    message[0] = 7;
    message[1] = 11;
    message[2] = 19;

    Plaintext plain, decoded_plain;
    Ciphertext cipher, squared, refreshed;
    encoder.encode(message, plain);
    encryptor.encrypt(plain, cipher);

    evaluator->multiply_relin(cipher, cipher, squared, relin_keys);
    evaluator->read(squared);

    std::vector<uint64_t> before;
    decryptor.decrypt(squared, decoded_plain);
    encoder.decode(decoded_plain, before);

    std::cout << "before recryption level: " << squared.level() << std::endl;
    for (int i = 0; i < 3; i++)
    {
        std::cout << "before[" << i << "] = " << before[i] << std::endl;
    }

    RecryptionData recryption_data(context);
    recryption_data.set_auxiliary_exponents(2, 1);

    auto recryption_key = keygen.create_switch_key(keygen.secret_key(), keygen.secret_key());
    Recryptor recryptor(context, *evaluator, recryption_data);

    try
    {
        recryptor.recrypt(squared, refreshed, recryption_key);

        std::vector<uint64_t> after;
        decryptor.decrypt(refreshed, decoded_plain);
        encoder.decode(decoded_plain, after);

        std::cout << "after recryption level: " << refreshed.level() << std::endl;
        for (int i = 0; i < 3; i++)
        {
            std::cout << "after[" << i << "] = " << after[i] << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "BFV recryption entry point reached: " << e.what() << std::endl;
    }

    return 0;
}
