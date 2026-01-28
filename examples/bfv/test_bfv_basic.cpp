
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
    size_t poly_modulus_degree = 32768;
    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    ParametersLiteralDefault bfv_param_literal(BFV, poly_modulus_degree, poseidon::sec_level_type::tc128);
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
    Ciphertext ct1, ct2, ct_res;
    vector<uint64_t> msg1 = {77, 2, 3};
    vector<uint64_t> msg2 = {11, 33, 22};
    vector<uint64_t> msg_res, msg_expect;
    msg_expect = vector<uint64_t>(msg1.size(), 0);
    auto plain_modulus = bfv_param_literal.plain_modulus();
    uint64_t plain_mod = plain_modulus.value();

    encoder.encode(msg1, plt1);
    encoder.encode(msg2, plt2);
    enc.encrypt(plt1, ct1);
    enc.encrypt(plt2, ct2);

    Timestacs timestacs;

    // MULTIPLY_PLAIN
    {
        print_example_banner("Example: MULTIPLY_PLAIN / MULTIPLY_PLAIN in bfv");
        timestacs.start();
        bfv_eva->multiply_plain(ct1, plt2, ct_res);
        timestacs.end();
        timestacs.print_time("TIME : ");
        dec.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i <  msg_expect.size(); i++)
        {
            msg_expect[i] = msg1[i] * msg2[i];
            msg_expect[i] %= plain_mod;
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
        bfv_eva->multiply(ct1, ct2, ct_res);
        timestacs.end();
        timestacs.print_time("TIME : ");
        dec.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] = msg1[i] * msg2[i];
            msg_expect[i] %= plain_mod;
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    //Relinearize
    {
        print_example_banner("Example: RELIN / RELIN in bfv");
        timestacs.start();
        bfv_eva->relinearize(ct_res, ct_res, relin_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        dec.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    //Square
    {
        print_example_banner("Example: SQUARE / SQUARE in bfv");
        timestacs.start();
        bfv_eva->square_inplace(ct1);
        timestacs.end();
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] = msg1[i] * msg1[i];
            msg_expect[i] %= plain_mod;
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        bfv_eva->relinearize(ct1, ct1, relin_keys);
    }

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bfv");
        timestacs.start();
        bfv_eva->rotate_row(ct1, ct1, 111, galois_keys);
        timestacs.end();
        bfv_eva->rotate_row(ct1, ct1, -111, galois_keys);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bfv");
        timestacs.start();
        bfv_eva->rotate_col(ct1, ct1, galois_keys);
        timestacs.end();
        bfv_eva->rotate_col(ct1, ct1, galois_keys);
        timestacs.print_time("TIME : ");
        dec.decrypt(ct1, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        
    }

    return 0;
}