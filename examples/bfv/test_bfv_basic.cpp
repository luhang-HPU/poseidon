
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    cout << BANNER << std::endl;
    cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    cout << "" << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    ParametersLiteralDefault bfv_param_literal(BFV, 16384, poseidon::sec_level_type::tc128);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    std::shared_ptr<EvaluatorBfvBase> bfv_eva =
        PoseidonFactory::get_instance()->create_bfv_evaluator(context);

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
    vector<uint64_t> message1 = {77, 2, 3};
    vector<uint64_t> message2 = {11, 33, 22};
    vector<uint64_t> message_res;

    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);

    Timestacs timestacs;
    auto message_want = message1;

    // NTT
    {
        print_example_banner("Example: NTT & INTT in bfv");
        cout << "Before NTT & INTT level : " << ciph1.level() << std::endl;
        timestacs.start();
        bfv_eva->transform_to_ntt_inplace(ciph1);
        bfv_eva->transform_from_ntt_inplace(ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
        cout << "After NTT & INTT level : " << ciph1.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message1[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ciph1.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ciph1, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
        cout << "After  Mod Switch level : " << ciph1.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message1[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ciph2.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ciph2, ciph2);
        timestacs.end();
        bfv_eva->read(ciph2);
        cout << "After  Mod Switch level : " << ciph2.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph2, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message2[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // ADD
    {
        print_example_banner("Example: ADD / ADD in bfv");
        timestacs.start();
        bfv_eva->add(ciph1, ciph2, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
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

        print_example_banner("Example: SUB / SUB in bfv");
        timestacs.start();
        bfv_eva->sub(ciph1, ciph2, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
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

    // NTT
    {
        print_example_banner("Example: NTT / NTT in bfv");
        timestacs.start();
        bfv_eva->ntt_fwd(ciph1, ciph1);
        bfv_eva->ntt_inv(ciph1, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ciph1.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ciph1, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
        cout << "After  Mod Switch level : " << ciph1.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // MULTIPLY_PLAIN
    {
        print_example_banner("Example: MULTIPLY_PLAIN / MULTIPLY_PLAIN in bfv");
        timestacs.start();
        bfv_eva->multiply_plain(ciph1, plain1, ciph1);
        timestacs.end();
        bfv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] *= message1[i];
            message_want[i] %= 65537;
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    // MULTIPLY
    {
        print_example_banner("Example: MULTIPLY / MULTIPLY in bfv");
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

    // MULTIPLY
    {
        print_example_banner("Example: MULTIPLY / MULTIPLY in bfv");
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

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bfv");
        timestacs.start();
        bfv_eva->rotate_row(ciph1, ciph1, 1, galois_keys);
        timestacs.end();
        bfv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
        bfv_eva->rotate_row(ciph1, ciph1, -1, galois_keys);
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bfv");
        timestacs.start();
        bfv_eva->rotate_col(ciph1, ciph1, galois_keys);
        timestacs.end();
        bfv_eva->read(ciph1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
        bfv_eva->rotate_col(ciph1, ciph1, galois_keys);
    }

    // ADD_PLAIN
    {
        print_example_banner("Example: ADD_PLAIN / ADD_PLAIN in bfv");
        timestacs.start();
        bfv_eva->add_plain(ciph1, plain1, ciph1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        bfv_eva->read(ciph1);
        decryptor.decrypt(ciph1, plain_res);
        enc.decode(plain_res, message_res);

        for (auto i = 0; i < message_want.size(); i++)
        {
            message_want[i] += message1[i];
        }
        for (auto i = 0; i < message_want.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }
    return 0;
}