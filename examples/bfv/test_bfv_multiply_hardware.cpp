
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

void bfv_multiply(bool is_hard)
{
    cout << "POSEIDON VERSION:" << POSEIDON_VERSION << std::endl;
    if (is_hard)
    {
        std::cout << "ckks multiply_relin Hardware" << std::endl;
        PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    }
    else
    {
        std::cout << "ckks multiply_relin Software" << std::endl;
        PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    }

    ParametersLiteral bfv_param_literal{BFV, 15, 15 - 1, 32, 5, 1, 0, {}, {}};
    vector<uint32_t> log_q(11, 55);
    vector<uint32_t> log_p(1, 56);
    bfv_param_literal.set_log_modulus(log_q, log_p);
    bfv_param_literal.set_plain_modulus(PlainModulus::Batching(32768, 30));

    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    std::shared_ptr<EvaluatorBfvBase> bfv_eva =
        PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    BatchEncoder enc(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plain1, plain2, plain_res;
    Ciphertext ciph1, ciph2;
    vector<uint64_t> message1 = {77, 2, 3};
    vector<uint64_t> message2 = {11, 33, 22};
    vector<uint64_t> message_res;

    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);

    Timestacs timestacs;
    auto message_want = message1;

    // MULTIPLY
    {
        timestacs.start();
        bfv_eva->multiply_relin(ciph1, ciph1, ciph1, relin_keys);
        timestacs.end();
        bfv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] *= message_want[i];
            message_want[i] %= 65537;
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }
}


int main()
{
    bfv_multiply(true);
}
