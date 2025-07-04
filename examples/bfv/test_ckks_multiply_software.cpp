
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

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

int main() { ckks_multiply(false); }
