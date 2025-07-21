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

    ParametersLiteralDefault bgv_param_literal(BGV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    std::shared_ptr<EvaluatorBgvBase> bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2;
    vector<uint64_t> msg1 = {55, 2, 3};
    vector<uint64_t> msg2 = {11, 33, 22};
    vector<uint64_t> msg_res, msg_expect;

    encoder.encode(msg1, plt1);
    encoder.encode(msg2, plt2);
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    Timestacs timestacs;

    // ADD
    {
        print_example_banner("Example: ADD in bgv");
        timestacs.start();
        bgv_eva->add(ct1, ct2, ct1);
        bgv_eva->read(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        msg_expect = msg1;
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] += msg2[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // SUB
    {
        print_example_banner("Example: SUB in bgv");
        timestacs.start();
        bgv_eva->sub(ct1, ct2, ct1);
        bgv_eva->read(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] -= msg2[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // ADD_PLAIN
    {
        print_example_banner("Example: ADD_PLAIN in bgv");
        timestacs.start();
        bgv_eva->add_plain(ct1, plt2, ct1);
        bgv_eva->read(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] += msg2[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // MULTIPLY_PLAIN
    {
        print_example_banner("Example: MULTIPLY_PLAIN in bgv");
        timestacs.start();
        bgv_eva->multiply_plain(ct1, plt1, ct1);
        bgv_eva->read(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] *= msg1[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }

        for (size_t i = 0; i < msg_expect.size(); i++)
            msg1[i] *= msg1[i];
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bgv");
        timestacs.start();
        bgv_eva->rotate_col(ct1, ct1, galois_keys);
        bgv_eva->read(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        bgv_eva->rotate_col(ct1, ct1, galois_keys);
    }

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bgv");
        timestacs.start();
        bgv_eva->rotate_row(ct1, ct1, 1, galois_keys);
        timestacs.end();
        bgv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        bgv_eva->rotate_row(ct1, ct1, -1, galois_keys);
    }

    // drop_modulus
    {
        print_example_banner("Example: drop_modulus in bgv");
        std::cout << "Before drop_modulus level : " << ct1.level() << std::endl;
        timestacs.start();
        bgv_eva->drop_modulus_to_next(ct1, ct1);
        timestacs.end();
        std::cout << "After drop_modulus level : " << ct1.level() << std::endl;
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // multiply_relin
    {
        print_example_banner("Example: multiply_relin in bgv");
        timestacs.start();
        bgv_eva->multiply_relin(ct2, ct2, ct2, relin_keys);
        bgv_eva->read(ct2);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct2, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
            msg_expect[i] = msg2[i] * msg2[i];

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    return 0;
}