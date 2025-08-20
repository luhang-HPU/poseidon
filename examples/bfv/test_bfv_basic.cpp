
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"

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

    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    keygen.create_relin_keys(relin_keys);

    Encryptor enc(context, public_key);
    Decryptor dec(context, keygen.secret_key());

    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2;
    vector<uint64_t> msg1 = {77, 2, 3};
    vector<uint64_t> msg2 = {11, 33, 22};
    vector<uint64_t> msg_res, msg_expect;

    encoder.encode(msg1, plt1);
    encoder.encode(msg2, plt2);
    enc.encrypt(plt1, ct1);
    enc.encrypt(plt2, ct2);

    Timestacs timestacs;

    // NTT
    {
        print_example_banner("Example: NTT & INTT in bfv");
        cout << "Before NTT & INTT level : " << ct1.level() << std::endl;
        timestacs.start();
        bfv_eva->transform_to_ntt_inplace(ct1);
        bfv_eva->transform_from_ntt_inplace(ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        cout << "After NTT & INTT level : " << ct1.level() << std::endl;
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);
        msg_expect = msg1;
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg1[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ct1.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ct1, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        cout << "After Mod Switch level : " << ct1.level() << std::endl;
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg1[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ct2.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ct2, ct2);
        timestacs.end();
        bfv_eva->read(ct2);
        cout << "After Mod Switch level : " << ct2.level() << std::endl;
        timestacs.print_time("TIME : ");
        dec.decrypt(ct2, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg2[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // ADD
    {
        print_example_banner("Example: ADD / ADD in bfv");
        timestacs.start();
        bfv_eva->add(ct1, ct2, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
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

    // SUB
    {
        print_example_banner("Example: SUB / SUB in bfv");
        timestacs.start();
        bfv_eva->sub(ct1, ct2, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
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

    // NTT
    {
        print_example_banner("Example: NTT / NTT in bfv");
        timestacs.start();
        bfv_eva->ntt_fwd(ct1, ct1);
        bfv_eva->ntt_inv(ct1, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // Mod Switch
    {
        print_example_banner("Example: Mod Switch / Mod Switch in bfv");
        cout << "Before Mod Switch level : " << ct1.level() << std::endl;
        timestacs.start();
        bfv_eva->drop_modulus_to_next(ct1, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        cout << "After  Mod Switch level : " << ct1.level() << std::endl;
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // MULTIPLY_PLAIN
    {
        print_example_banner("Example: MULTIPLY_PLAIN / MULTIPLY_PLAIN in bfv");
        timestacs.start();
        bfv_eva->multiply_plain(ct1, plt1, ct1);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] *= msg1[i];
            msg_expect[i] %= 65537;
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // MULTIPLY
    {
        print_example_banner("Example: MULTIPLY / MULTIPLY in bfv");
        timestacs.start();
        bfv_eva->multiply_relin(ct1, ct1, ct1, relin_keys);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] *= msg_expect[i];
            msg_expect[i] %= 65537;
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bfv");
        timestacs.start();
        bfv_eva->rotate_row(ct1, ct1, 1, galois_keys);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        bfv_eva->rotate_row(ct1, ct1, -1, galois_keys);
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bfv");
        timestacs.start();
        bfv_eva->rotate_col(ct1, ct1, galois_keys);
        timestacs.end();
        bfv_eva->read(ct1);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        bfv_eva->rotate_col(ct1, ct1, galois_keys);
    }

    // ADD_PLAIN
    {
        print_example_banner("Example: ADD_PLAIN / ADD_PLAIN in bfv");
        timestacs.start();
        bfv_eva->add_plain(ct1, plt1, ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        bfv_eva->read(ct1);
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] += msg1[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }
    return 0;
}