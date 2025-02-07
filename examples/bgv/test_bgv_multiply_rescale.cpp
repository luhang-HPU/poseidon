#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault bgv_param_literal(BGV, 8192, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    auto bgv_eva = PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    BatchEncoder enc(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    Plaintext plain1, plain2, plain_res;
    Ciphertext ciph1, ciph2;
    auto slot_num = bgv_param_literal.slot();
    vector<uint64_t> message1 = {5, 2, 3};
    vector<uint64_t> message2 = {2, 3, 2};
    vector<uint64_t> message_res;

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
        bgv_eva->multiply(ciph1, ciph1, ciph1);
        bgv_eva->relinearize(ciph1, ciph1, relin_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
            message_want[i] *= message_want[i];

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // RESCALE
    {
        print_example_banner("Example: RESCALE / RESCALE in bgv");
        timestacs.start();
        bgv_eva->rescale(ciph1);
        timestacs.end();
        timestacs.print_time("RESCALE TIME: ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // RESCALE
    {
        print_example_banner("Example: last multiply_relin in bgv");
        timestacs.start();
        bgv_eva->multiply(ciph1, ciph1, ciph1);
        bgv_eva->relinearize(ciph1, ciph1, relin_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
            message_want[i] *= message_want[i];

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // RESCALE
    {
        print_example_banner("Example: RESCALE / RESCALE in bgv");
        timestacs.start();
        bgv_eva->rescale(ciph2);
        timestacs.end();
        timestacs.print_time("RESCALE TIME: ");
        decryptor.decrypt(ciph2, plain_res);
        enc.decode(plain_res, message_res);
        message_want = message2;
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // multiply_relin
    {
        print_example_banner("Example: last multiply_relin in bgv");
        timestacs.start();
        bgv_eva->multiply(ciph2, ciph2, ciph2);
        bgv_eva->relinearize(ciph2, ciph2, relin_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph2, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
            message_want[i] *= message_want[i];

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    return 0;
}
