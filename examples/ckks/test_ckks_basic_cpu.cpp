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

    ParametersLiteralDefault ckks_param_literal(CKKS, 4096, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);

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

    Timestacs timestacs;
    uint64_t encode_time = 0;
    uint64_t decode_time = 0;
    uint64_t encrypt_time = 0;
    uint64_t decrypt_time = 0;
    uint64_t multiply_time = 0;
    uint64_t rotate_time = 0;
    uint64_t kswitch_time = 0;
    uint64_t relinearize_time = 0;

    for (auto i = 0; i < 100; i++)
    {
        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        timestacs.start();
        encoder.encode(msg1, scale, plt1);
        timestacs.end();
        encode_time += timestacs.microseconds();
        encoder.encode(msg2, scale, plt2);

        // encrypt
        timestacs.start();
        encryptor.encrypt(plt1, ct1);
        timestacs.end();
        encrypt_time += timestacs.microseconds();
        encryptor.encrypt(plt2, ct2);

        // MULTIPLY
        timestacs.start();
        ckks_eva->multiply(ct1, ct2, ct_res);
        timestacs.end();
        multiply_time += timestacs.microseconds();

        // relinearize
        timestacs.start();
        ckks_eva->relinearize(ct_res, ct_res, relin_keys);
        timestacs.end();
        relinearize_time += timestacs.microseconds();
        ckks_eva->rescale(ct_res, ct_res);

        // rotate
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        rotate_time += timestacs.microseconds();

        // kswitch
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        kswitch_time += timestacs.microseconds();

        // decrypt
        timestacs.start();
        decryptor.decrypt(ct_res, plt_res);
        timestacs.end();
        decrypt_time += timestacs.microseconds();

        // decod
        timestacs.start();
        encoder.decode(plt_res, msg_res);
        timestacs.end();
        decode_time += timestacs.microseconds();
    }


    std::cout << "================================================" << std::endl;
    std::cout << "All tests is based on the following parameters" << std::endl;
    std::cout << "polynomial degree: " << ckks_param_literal.degree() << std::endl;
    std::cout << "multiplication depth: " << ckks_param_literal.q().size() + 1 << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;

    std::cout << "Encode Time: " << encode_time / 100.0 << " us" << std::endl;
    std::cout << "Encrypt Time: " << encrypt_time / 100.0 << " us" << std::endl;
    std::cout << "Decrypt Time: " << decrypt_time / 100.0 << " us" << std::endl;
    std::cout << "Decode Time: " << decode_time / 100.0 << " us" << std::endl;
    std::cout << "Multiply Time: " << multiply_time / 100.0 << " us" << std::endl;
    std::cout << "Rotate Time: " << rotate_time / 100.0 << " us" << std::endl;
    std::cout << "KSwitch Time: " << kswitch_time / 100.0 << " us" << std::endl;
    std::cout << "Relinearize Time: " << relinearize_time / 100.0 << " us" << std::endl;

    return 0;