
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

void bgv_multiply(bool is_hard)
{
    ParametersLiteralDefault bgv_param_literal(BGV, 16384, poseidon::sec_level_type::tc128);
    cout << "POSEIDON VERSION:" << POSEIDON_VERSION << std::endl;
    if (is_hard)
    {
        std::cout << "bgv multiply_relin Hardware" << std::endl;
        PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
        bgv_param_literal.set_plain_modulus(PlainModulus::Batching(16384, 30));
    }
    else
    {
        std::cout << "bgv multiply_relin Software" << std::endl;
        PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    }

    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    std::shared_ptr<EvaluatorBgvBase> bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

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
    auto slot_num = bgv_param_literal.slot();
    vector<uint64_t> message1 = {55, 2, 3};
    vector<uint64_t> message2 = {11, 33, 22};
    vector<uint64_t> message_res, message_cur;
    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);
    Timestacs timestacs;
    auto message_want = message1;
    // multiply_relin
    {
        print_example_banner("Example: multiply_relin in bgv");
        timestacs.start();
        bgv_eva->multiply_relin(ciph2, ciph2, ciph2, relin_keys);
        bgv_eva->read(ciph2);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph2, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
            message_want[i] = message2[i] * message2[i];

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }
}

int main() { bgv_multiply(false); }
