#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault ckks_param_literal(CKKS, 4096, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);
    double const_num = 5.0;

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> msg1, msg2, msg_expect, msg_res;

    sample_random_complex_vector(msg1, slot_num);
    sample_random_complex_vector(msg2, slot_num);

    Timestacs timestacs, timestacs_total;
    uint64_t total_time = 0;
    uint64_t encode_time = 0;
    uint64_t decode_time = 0;
    uint64_t encrypt_time = 0;
    uint64_t decrypt_time = 0;
    uint64_t multiply_time = 0;
    timestacs_total.start();
    for (auto i = 0; i < 100; i++)
    {
        Plaintext plt1, plt2, plt_res;
        timestacs.start();
        encoder.encode(msg1, scale, plt1);
        timestacs.end();
        encode_time += timestacs.microseconds();

        encoder.encode(msg2, scale, plt2);
        Ciphertext ct1, ct2, ct_res;

        timestacs.start();
        encryptor.encrypt(plt1, ct1);
        timestacs.end();
        encrypt_time += timestacs.microseconds();
        encryptor.encrypt(plt2, ct2);

        // MULTIPLY_RELIN_DYNAMIC
        timestacs.start();
        ckks_eva->multiply_relin_dynamic(ct1, ct2, ct_res, relin_keys);
        timestacs.end();
        multiply_time += timestacs.microseconds();
        ckks_eva->rescale(ct_res, ct_res);
        ckks_eva->read(ct_res);
        timestacs.start();
        decryptor.decrypt(ct_res, plt_res);
        timestacs.end();
        decrypt_time += timestacs.microseconds();
        timestacs.start();
        encoder.decode(plt_res, msg_res);
        timestacs.end();
        decode_time += timestacs.microseconds();

        // for (auto i = 0; i < slot_num; i++)
        // {
        //     msg_expect[i] *= msg2[i];
        // }
    }
    timestacs_total.end();
    total_time = timestacs_total.microseconds();
    std::cout << "Average Encode Time: " << encode_time / 100.0 << " us" << std::endl;
    std::cout << "Average Encrypt Time: " << encrypt_time / 100.0 << " us" << std::endl;
    std::cout << "Average Multiply Time: " << multiply_time / 100.0 << " us" << std::endl;
    std::cout << "Average Decrypt Time: " << decrypt_time / 100.0 << " us" << std::endl;
    std::cout << "Average Decode Time: " << decode_time / 100.0 << " us" << std::endl;
    std::cout << "Total Average Time: " << total_time / 100.0 << " us" << std::endl;
    return 0;
}
