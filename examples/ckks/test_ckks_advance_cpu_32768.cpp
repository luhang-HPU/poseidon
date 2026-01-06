#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

const int times = 100;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "CPU version" << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 55, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55};
    vector<uint32_t> log_p_tmp{56};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);
    // ParametersLiteralDefault ckks_param_literal(CKKS, 32768, poseidon::sec_level_type::tc128);

    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 40);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_galois_keys(galois_keys);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> msg1, msg2, msg_expect, msg_res;

    sample_random_complex_vector(msg1, slot_num);
    sample_random_complex_vector(msg2, slot_num);

    Timestacs timestacs;
    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2, ct_res;

    // encode
    encoder.encode(msg1, scale, plt1);
    encoder.encode(msg2, scale, plt2);

    // encrypt
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    std::cout << "================================================" << std::endl;
    std::cout << "All tests is based on the following parameters" << std::endl;
    std::cout << "polynomial degree: " << ckks_param_literal.degree() << std::endl;
    std::cout << "multiplication depth: " << ckks_param_literal.q().size() + 1 << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;

    timestacs.start();
    for (auto i = 0; i < times; ++i)
    {
        ckks_eva->sigmoid_approx(ct1, ct_res, encoder, relin_keys);
    }
    timestacs.end();
    std::cout << "Sigmoid Average Time: " << (double)timestacs.microseconds() / times << " us" << std::endl;

    timestacs.start();
    for (auto i = 0; i < times; ++i)
    {
        ckks_eva->conv(ct1, ct2, ct_res, 1, encoder, encryptor, galois_keys, relin_keys);
    }
    timestacs.end();
    std::cout << "Conv Average Time: " << (double)timestacs.microseconds() / times << " us" << std::endl;

    return 0;
}
