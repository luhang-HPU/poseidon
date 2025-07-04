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

    /*
    SchemeType Type,    BGV
    uint32_t log_n,      13
    uint32_t log_slots,  13
    uint32_t log_scale,  40
    uint32_t hamming_weight,     5
    uint32_t q0_level,          0
    Modulus plain_modulus,      1032193
    const vector<Modulus> &q,
    const vector<Modulus> &P,
    MemoryPoolHandle pool)
    */

    ParametersLiteralDefault bgv_param_literal(BGV, 16384, poseidon::sec_level_type::tc128);
    bgv_param_literal.set_plain_modulus(PlainModulus::Batching(16384, 30));

    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    std::shared_ptr<EvaluatorBgvBase> bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

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
    vector<uint64_t> message1 = {55, 2, 3};
    vector<uint64_t> message2 = {11, 33, 22};
    vector<uint64_t> message_res, message_cur;
    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);
    Timestacs timestacs;
    auto message_want = message1;

    // ADD
    {
        print_example_banner("Example: ADD in bgv");
        timestacs.start();
        bgv_eva->add(ciph1, ciph2, ciph1);
        bgv_eva->read(ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] += message2[i];
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // SUB
    {
        print_example_banner("Example: SUB in bgv");
        timestacs.start();
        bgv_eva->sub(ciph1, ciph2, ciph1);
        bgv_eva->read(ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] -= message2[i];
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // ADD_PLAIN
    {
        print_example_banner("Example: ADD_PLAIN in bgv");
        timestacs.start();
        bgv_eva->add_plain(ciph1, plain2, ciph1);
        bgv_eva->read(ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] += message2[i];
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // // SUB_PLAIN
    // {
    //     print_example_banner("Example: SUB_PLAIN in bgv");
    //     timestacs.start();
    //     bgv_eva->sub_plain(ciph1, plain2, ciph1);
    //     bgv_eva->read(ciph1);
    //     timestacs.end();
    //     timestacs.print_time("TIME : ");
    //     decryptor.decrypt(ciph1, plain_res);
    //     enc.decode(plain_res, message_res);

    //     for (auto i = 0; i < message_want.size(); i++)
    //         message_want[i] -= message2[i];

    //     for (auto i = 0; i < message_want.size(); i++)
    //     {
    //         printf("source_data[%d] : %ld\n", i, message_want[i]);
    //         printf("result_data[%d] : %ld\n", i, message_res[i]);
    //     }
    // }
    // MULTIPLY_PLAIN
    {
        print_example_banner("Example: MULTIPLY_PLAIN in bgv");
        timestacs.start();
        bgv_eva->multiply_plain(ciph1, plain1, ciph1);
        bgv_eva->read(ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] *= message1[i];
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }

        for (size_t i = 0; i < message_want.size(); i++)
            message1[i] *= message1[i];
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bgv");
        timestacs.start();
        bgv_eva->rotate_col(ciph1, ciph1, galois_keys);
        bgv_eva->read(ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
        bgv_eva->rotate_col(ciph1, ciph1, galois_keys);
    }

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bgv");
        timestacs.start();
        bgv_eva->rotate_row(ciph1, ciph1, 1, galois_keys);
        timestacs.end();
        bgv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
        bgv_eva->rotate_row(ciph1, ciph1, -1, galois_keys);
    }

    // drop_modulus
    {
        print_example_banner("Example: drop_modulus in bgv");
        std::cout << "Before drop_modulus level : " << ciph1.level() << std::endl;
        timestacs.start();
        bgv_eva->drop_modulus_to_next(ciph1, ciph1);
        timestacs.end();
        std::cout << "After drop_modulus level : " << ciph1.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

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

    return 0;
}