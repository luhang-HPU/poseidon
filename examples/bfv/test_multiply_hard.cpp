
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

void ckks_multiply(bool is_hard)
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

    ParametersLiteralDefault ckks_param_literal(CKKS, 16384, poseidon::sec_level_type::tc128);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    PublicKey public_key;
    RelinKeys relin_keys;
    CKKSEncoder enc(context);
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> message1, message2;
    vector<complex<double>> message_want(slot_num);
    vector<complex<double>> message_res;
    sample_random_complex_vector(message1, slot_num);
    sample_random_complex_vector(message2, slot_num);

    Plaintext plaintext, plaintext2, plaintext_res;
    double scale = std::pow(2.0, 48);
    enc.encode(message1, scale, plaintext);
    enc.encode(message2, scale, plaintext2);

    Ciphertext ct1, ct2, ct_res;
    encryptor.encrypt(plaintext, ct1);
    encryptor.encrypt(plaintext2, ct2);

    Timestacs timestacs;
    timestacs.start();
    ckks_eva->multiply_relin_dynamic(ct1, ct2, ct_res, relin_keys);
    timestacs.end();
    ckks_eva->rescale(ct_res, ct_res);
    ckks_eva->read(ct_res);

    timestacs.print_time("MULTIPLY_RELIN TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = message1[i] * message2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lfi\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lfi\n", i, message_res[i].real(),
               message_res[i].imag());
    }
}

int main()
{
    bfv_multiply(false);
    // bgv_multiply(false);
    // ckks_multiply(false);
}
