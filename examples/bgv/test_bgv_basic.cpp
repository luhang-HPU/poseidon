#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault bgv_param_literal(BGV, 32768, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    auto context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    auto bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);
    

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2, ct_res;
    vector<uint64_t> msg1 = {55, 2, 3};
    vector<uint64_t> msg2 = {11, 33, 22};
    vector<uint64_t> msg_res, msg_expect;
    msg_expect = msg1;

    encoder.encode(msg1, plt1);
    encoder.encode(msg2, plt2);
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    Timestacs timestacs;

    // MULTIPLY
    print_example_banner("Example: MULTIPLY / MULTIPLY in bgv");
    {
        timestacs.start();
        bgv_eva->multiply(ct1, ct2, ct_res);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            msg_expect[i] = msg1[i] * msg2[i];
        }
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // RELINEARIZE
    print_example_banner("Example: RELINEARIZE / RELINEARIZE in bgv");
    {
        timestacs.start();
        bgv_eva->relinearize(ct_res, ct_res, relin_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);   
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // ROTATE_COL
    {
        print_example_banner("Example: ROTATE_COL / ROTATE_COL in bgv");
        timestacs.start();
        bgv_eva->rotate_col(ct1, ct_res, galois_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        bgv_eva->rotate_col(ct_res, ct_res, galois_keys);
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        msg_expect = msg1;
        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
    }

    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bgv");
        timestacs.start();
        bgv_eva->rotate_row(ct1, ct_res, 111, galois_keys);
        timestacs.end();
        timestacs.print_time("TIME : ");
        bgv_eva->rotate_row(ct_res, ct_res, -111, galois_keys);
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < msg_expect.size(); i++)
        {
            printf("source_data[%d] : %ld\n", i, msg_expect[i]);
            printf("result_data[%d] : %ld\n", i, msg_res[i]);
        }
        
    }

    

    return 0;
}