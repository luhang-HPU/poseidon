#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

const int times = 10;
const int kernal_size = 10;
const int output_size = 10;

void print_vector(std::vector<complex<double>> vec, int num = output_size)
{
    for (auto i = 0 ; i < num; ++i)
    {
        printf("%8.5lf ", vec[i].real());
    }
    std::cout << " ... " << std::endl;
}

// approximate sigmoid
double sigmoid(double x)
{
    //    return (0.5 + 0.197 * x - 0.004 * x * x * x);
    return 1.0 / (1.0 + std::exp(-x));
}

std::vector<std::complex<double>> conv(std::vector<std::complex<double>> input, std::vector<std::complex<double>> kernel, int size = kernal_size)
{
    int output_size = input.size();
    std::vector<std::complex<double>> output(output_size, 0.0);

    // 滑动卷积核，逐位置计算乘积和
    for (int i = 0; i < output_size; ++i) {
        std::complex<double> sum(0.0, 0.0);
        for (int j = 0; j < size; ++j) {
            sum += input[(i - j + input.size()) % input.size()] * kernel[j];
        }
        output[i] = sum;
    }

    return output;
}

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "HPU version" << std::endl;

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

    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
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
    uint64_t sigmoid_time = 0;
    uint64_t conv_time = 0;

    std::cout << "=========================================== SIGMOID start ============================================" << std::endl;
    for (auto i = 0; i < times; ++i)
    {
        std::cout << "SIGMOID test case " << i << std::endl;
        sample_random_complex_vector(msg1, slot_num, 0.0, 1.0);

        std::cout << "input value:          ";
        print_vector(msg1);

        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

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

        std::cout << "expect sigmoid value: ";
        for (auto j = 0; j < output_size; ++j)
        {
            printf("%8.5lf ", sigmoid(msg1[j].real()));
        }
        std::cout << std::endl;

        std::cout << "fhe output value:     ";
        print_vector(msg_res);
        std::cout << std::endl;
    }
    std::cout << "============================================ SIGMOID end =============================================" << std::endl;
    std::cout << std::endl;
    std::cout << std::fixed << setprecision(2) << "Sigmoid Average Time on HPU: " << (double)sigmoid_time / times << " us" << std::endl;
    std::cout << std::endl;


    std::cout << "========================================== MUL and RELIN start ============================================" << std::endl;
    for (auto i = 0; i < times; i++)
    {
        std::cout << "Multiply and Relinearize test case " << i << std::endl;
        sample_random_complex_vector(msg1, slot_num);
        sample_random_complex_vector(msg2, slot_num);

        std::cout << "input value x:        ";
        print_vector(msg1);
        std::cout << "input value y:        ";
        print_vector(msg2);

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

        std::cout << "expected output value:";
        print_vector(msg_expect);

        std::cout << "fhe output value:     ";
        print_vector(msg_res);
        std::cout << std::endl;
    }
    std::cout << "============================================ MUL and RELIN end =============================================" << std::endl;

    std::cout << std::endl;
    std::cout << "Multiply and Relinearize Average Time on HPU: " << multiply_relin_time / times / 1.0 << " us"
              << std::endl;
    std::cout << std::endl;

    std::cout << "=============================================== ROTATE start ===============================================" << std::endl;
    for (auto i = 0; i < times; ++i)
    {
        std::cout << "ROTATE test case " << i << std::endl;
        sample_random_complex_vector(msg1, slot_num);

        std::cout << "input value  :    ";
        print_vector(msg1);

        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        encoder.encode(msg1, scale, plt1);

        // encrypt
        encryptor.encrypt(plt1, ct1);

        // rotate
        timestacs.start();
        ckks_eva->rotate(ct1, ct_res, 1, galois_keys);
        timestacs.end();
        rotate_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::cout << "fhe output value: ";
        print_vector(msg_res);
        std::cout << std::endl;
    }
    std::cout << "=============================================== ROTATE end ================================================" << std::endl;

    std::cout << std::endl;
    std::cout << "Rotate Average Time on HPU: " << rotate_time / times / 1.0 << " us" << std::endl;
    std::cout << std::endl;

    std::cout << "============================================= KEYSWITCH start ==============================================" << std::endl;
    for (auto i = 0; i < times; ++i)
    {
        std::cout << "KEYSWITCH test case " << i << std::endl;
        sample_random_complex_vector(msg1, slot_num);

        std::cout << "before keyswitch, input value:     ";
        print_vector(msg1);

        auto msg_expect = msg1;

        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        encoder.encode(msg1, scale, plt1);
        // encrypt
        encryptor.encrypt(plt1, ct1);

        // kswitch
        timestacs.start();
        ckks_eva->rotate(ct1, ct_res, 1, galois_keys);
        timestacs.end();
        ckks_eva->rotate(ct_res, ct_res, -1, galois_keys);
        kswitch_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::cout << "after keyswitch, fhe output value: ";
        print_vector(msg_res);
        std::cout << std::endl;
    }
    std::cout << "============================================== KEYSWITCH end ===============================================" << std::endl;

    std::cout << std::endl;
    std::cout << "KSwitch Average Time on HPU: " << kswitch_time / times / 1.0 << " us" << std::endl;
    std::cout << std::endl;

    std::cout << "========================================= CONVOLUTION start ==========================================" << std::endl;
    for (auto i = 0; i < times; ++i)
    {
        std::cout << "CONVOLUTION test case " << i << std::endl;
        sample_random_complex_vector(msg1, slot_num);
        sample_random_complex_vector(msg2, slot_num);

        std::cout << "input size: " << slot_num << "  kernel size: " << kernal_size
                  << "  formula: output = for n in [0, 16384) for m in [0, 10) input(n-m) * kernel(m)" << std::endl;
        std::cout << "input value:   ";
        print_vector(msg1);
        std::cout << "kernel value:  ";
        print_vector(msg2);

        std::reverse(msg1.begin(), msg1.end());

        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        encoder.encode(msg1, scale, plt1);
        encoder.encode(msg2, scale, plt2);
        std::reverse(msg1.begin(), msg1.end());

        // encrypt
        encryptor.encrypt(plt1, ct1);
        encryptor.encrypt(plt2, ct2);

        timestacs.start();
        ckks_eva->conv(ct1, ct2, ct_res, kernal_size, encoder, encryptor, galois_keys, relin_keys);
        timestacs.end();
        conv_time += timestacs.microseconds();

        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        std::cout << "expect value: ";
        print_vector(conv(msg1, msg2, kernal_size));
        std::cout << "fhe output:   ";
        print_vector(msg_res);
        std::cout << std::endl;
    }

    std::cout << "========================================== CONVOLUTION end ===========================================" << std::endl;
    std::cout << std::endl;
    std::cout << std::fixed << setprecision(2) << "Conv Average Time on HPU: " << (double)conv_time / times << " us" << std::endl;
    std::cout << std::endl;

    return 0;
}