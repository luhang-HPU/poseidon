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

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 55, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55};
    vector<uint32_t> log_p_tmp{56};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    std::cout << "================================================" << std::endl;
    std::cout << "All tests is based on the following parameters" << std::endl;
    std::cout << "polynomial degree: " << ckks_param_literal.degree() << std::endl;
    std::cout << "multiplication depth: " << ckks_param_literal.q().size() + 1 << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 55);

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
    vector<complex<double>> msg1, msg2, msg_res;

    Timestacs timestacs;
    uint64_t multiply_relin_time = 0;
    uint64_t rotate_time = 0;
    uint64_t kswitch_time = 0;

    for (auto i = 0; i < 100; i++)
    {
        sample_random_complex_vector(msg1, slot_num);
        sample_random_complex_vector(msg2, slot_num);

        auto msg_expect = msg1;

        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        encoder.encode(msg1, scale, plt1);
        encoder.encode(msg2, scale, plt2);

        // encrypt
        encryptor.encrypt(plt1, ct1);
        encryptor.encrypt(plt2, ct2);

        // MULTIPLY
        timestacs.start();
        ckks_eva->multiply_relin(ct1, ct2, ct_res, relin_keys);
        timestacs.end();
        multiply_relin_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto j = 0; j < msg_expect.size(); ++j)
        {
            msg_expect[j] = msg1[j] * msg2[j];
        }
        std::cout << "==== MUL and RELIN ====" << std::endl;
        printf("expected value: %8.2lf, answer value: %8.2lf\n", msg_expect[0].real(), msg_res[0].real());

        // rotate
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        rotate_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::rotate(msg_expect.begin(), msg_expect.begin() + 1, msg_expect.end());
        std::cout << "==== ROTATE ====" << std::endl;
        printf("expected value: %8.2lf, answer value: %8.2lf\n", msg_expect[0].real(), msg_res[0].real());

        // kswitch
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        kswitch_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::rotate(msg_expect.begin(), msg_expect.begin() + 1, msg_expect.end());
        std::cout << "==== KEYSWITCH ====" << std::endl;
        printf("expected value: %8.2lf, answer value: %8.2lf\n", msg_expect[0].real(), msg_res[0].real());
    }

    std::cout << std::endl;
    std::cout << "Multiply and Relinearize Time: " << multiply_relin_time / times / 1.0 << " us"
              << std::endl;
    std::cout << "Rotate Time: " << rotate_time / times / 1.0 << " us" << std::endl;
    std::cout << "KSwitch Time: " << kswitch_time / times / 1.0 << " us" << std::endl;

    return 0;
}