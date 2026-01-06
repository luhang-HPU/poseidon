#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

const int times = 100;

double sigmoid(double x)
{
    return (0.5 + 0.197 * x - 0.004 * x * x * x);
}

std::vector<double> conv(std::vector<std::complex<double>> input, std::vector<std::complex<double>> kernel)
{
    int output_size = input.size() - kernel.size() + 1;
    std::vector<double> output(output_size, 0.0);

    // 滑动卷积核，逐位置计算乘积和
    for (int i = 0; i < output_size; ++i) {
        double sum = 0.0;
        for (int j = 0; j < kernel.size(); ++j) {
            sum += input[i + j].real() * kernel[j].real();
        }
        output[i] = sum;
    }

    return output;
}


int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "CPU version" << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 55, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55};
    vector<uint32_t> log_p_tmp{56};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

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

    Timestacs timestacs;
    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2, ct_res;

    uint64_t sigmoid_time;
    uint64_t conv_time;

    std::cout << "================================================" << std::endl;
    std::cout << "All tests is based on the following parameters" << std::endl;
    std::cout << "polynomial degree: " << ckks_param_literal.degree() << std::endl;
    std::cout << "multiplication depth: " << ckks_param_literal.q().size() + 1 << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;

    for (auto i = 0; i < times; ++i)
    {
        sample_random_complex_vector(msg1, slot_num);

        // encode
        encoder.encode(msg1, scale, plt1);

        // encrypt
        encryptor.encrypt(plt1, ct1);

        timestacs.start();
        ckks_eva->sigmoid_approx(ct1, ct_res, encoder, relin_keys);
        timestacs.end();
        sigmoid_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::cout << "==== SIGMOID ====" << std::endl;
        printf("expected value: %8.2lf, answer value: %8.2lf\n", sigmoid(msg1[0].real()), msg_res[0].real());
    }


    for (auto i = 0; i < times; ++i)
    {
        sample_random_complex_vector(msg1, slot_num);
        sample_random_complex_vector(msg2, slot_num);
        std::reverse(msg2.begin(), msg2.end());

        // encode
        encoder.encode(msg1, scale, plt1);
        encoder.encode(msg2, scale, plt2);

        std::reverse(msg2.begin(), msg2.end());

        // encrypt
        encryptor.encrypt(plt1, ct1);
        encryptor.encrypt(plt2, ct2);

        timestacs.start();
        ckks_eva->conv(ct1, ct2, ct_res, 1, encoder, encryptor, galois_keys, relin_keys);
        timestacs.end();
        conv_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::cout << "==== CONVOLUTION ====" << std::endl;
        printf("expected value: %8.2lf, answer value: %8.2lf\n", conv(msg1, msg2)[0], msg_res[0].real());
    }


    std::cout << "Sigmoid Average Time: " << (double)sigmoid_time / times << " us" << std::endl;
    std::cout << "Conv Average Time: " << (double)conv_time / times << " us" << std::endl;

    return 0;
}
