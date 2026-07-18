#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

#include <chrono>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

using namespace poseidon;

namespace
{

std::vector<uint32_t> bootstrap_modulus_chain()
{
    std::vector<uint32_t> chain(16, 51);
    chain[1] = 46;
    // chain[2] = 46;
    return chain;
}

void print_error(const std::vector<std::complex<double>> &actual,
                 const std::vector<std::complex<double>> &expected)
{
    double max_error = 0.0;
    double squared_error_sum = 0.0;
    std::size_t max_error_slot = 0;

    for (std::size_t i = 0; i < expected.size(); ++i)
    {
        const double error = std::abs(actual[i] - expected[i]);
        squared_error_sum += error * error;
        if (error > max_error)
        {
            max_error = error;
            max_error_slot = i;
        }
    }

    const double rmse =
        std::sqrt(squared_error_sum / static_cast<double>(expected.size()));
    std::cout << "max abs error : " << max_error << " at slot " << max_error_slot << '\n';
    std::cout << "rmse          : " << rmse << '\n';
}

int run_legacy_bootstrap()
{
    std::cout << "\nLegacy bootstrap test\n";

    ParametersLiteral parameters{CKKS, 15, 14, 32, 1, 1, 0, {}, {}};
    std::vector<uint32_t> log_q(30, 32);
    parameters.set_log_modulus(log_q, {32});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    const int slot_count = 1 << parameters.log_slots();
    std::vector<std::complex<double>> source;
    sample_random_complex_vector(source, slot_count);
    for (auto &value : source)
    {
        value = std::sin(value);
    }

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    CKKSEncoder encoder(context);
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key, keygen.secret_key());
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plain;
    Ciphertext cipher;
    encoder.encode(source, static_cast<int64_t>(1) << 40, plain);
    encryptor.encrypt(plain, cipher);

    const auto start = std::chrono::high_resolution_clock::now();
    evaluator->multiply_relin(cipher, cipher, cipher, relin_keys);
    evaluator->rescale_dynamic(cipher, cipher, static_cast<int64_t>(1) << 45);

    EvalModPoly eval_mod_poly(context, CosDiscrete, static_cast<uint64_t>(1) << 40,
                              1, 9, 3, 16, 0, 30);
    evaluator->bootstrap(cipher, cipher, relin_keys, galois_keys, encoder, eval_mod_poly);
    const auto stop = std::chrono::high_resolution_clock::now();
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    std::cout << "Bootstrap TIME: " << elapsed << " microseconds\n";

    Plaintext result_plain;
    std::vector<std::complex<double>> result;
    decryptor.decrypt(cipher, result_plain);
    encoder.decode(result_plain, result);
    for (int i = 0; i < 10; ++i)
    {
        source[static_cast<std::size_t>(i)] *= source[static_cast<std::size_t>(i)];
        std::printf("source vec[%d] : %0.10f + %0.10f I \n", i,
                    std::real(source[static_cast<std::size_t>(i)]),
                    std::imag(source[static_cast<std::size_t>(i)]));
        std::printf("result vec[%d] : %0.10f + %0.10f I \n", i,
                    std::real(result[static_cast<std::size_t>(i)]),
                    std::imag(result[static_cast<std::size_t>(i)]));
    }
    GetPrecisionStats(result, source);
    return 0;
}

int run_new_bootstrap()
{
    std::cout << "\nNew 14-level bootstrap test\n";

    constexpr uint32_t log_n = 16;
    constexpr uint32_t log_slots = log_n - 1;
    ParametersLiteral parameters{CKKS, log_n, log_slots, 46, 5, 0, 0, {}, {}};
    const auto q_chain = bootstrap_modulus_chain();
    parameters.set_log_modulus(q_chain, {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, keygen.secret_key());
    Decryptor decryptor(context, keygen.secret_key());

    std::vector<std::complex<double>> source(encoder.slot_count());
    for (std::size_t i = 0; i < source.size(); ++i)
    {
        source[i] = std::sin(static_cast<double>(i) / 32.0);
    }

    Plaintext plain;
    encoder.encode(source, parameters.scale(), plain);
    Ciphertext input;
    encryptor.encrypt(plain, input);

    BootstrapConfig config;
    config.boundary_k = 25;
    config.log_message_ratio = 5;
    config.double_angle = 2;
    config.scaling_log = 51;
    config.output_ratio = 32;
    config.project_real = true;

    std::cout << "bootstrap config: boundary_k=" << config.boundary_k
              << " log_message_ratio=" << config.log_message_ratio
              << " double_angle=" << config.double_angle
              << " scaling_log=" << config.scaling_log << '\n';

    Ciphertext output;
    const auto start = std::chrono::high_resolution_clock::now();
    evaluator->bootstrap(input, output, relin_keys, galois_keys, encoder, config);
    const auto stop = std::chrono::high_resolution_clock::now();

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
    const auto raised_level = context.crt_context()->first_context_data()->level();
    std::cout << "bootstrap levels : " << raised_level - output.level() << " ("
              << raised_level << " -> " << output.level() << ")\n";
    std::cout << "bootstrap time   : " << elapsed << " ms\n";

    Plaintext result_plain;
    std::vector<std::complex<double>> result;
    decryptor.decrypt(output, result_plain);
    encoder.decode(result_plain, result);

    std::cout << "source preview   :";
    for (std::size_t i = 0; i < 8; ++i)
    {
        std::cout << ' ' << source[i].real();
    }
    std::cout << '\n';
    std::cout << "result preview   :";
    for (std::size_t i = 0; i < 8; ++i)
    {
        std::cout << ' ' << result[i].real();
    }
    std::cout << '\n';
    print_error(result, source);

    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    std::cout << BANNER << '\n';
    std::cout << "POSEIDON SOFTWARE VERSION: " << POSEIDON_VERSION << "\n";

    if (argc == 1)
    {
        return run_legacy_bootstrap();
    }

    const std::string mode = argv[1];
    if (mode == "--new")
    {
        return run_new_bootstrap();
    }
    if (mode == "--all")
    {
        const int legacy_status = run_legacy_bootstrap();
        return legacy_status == 0 ? run_new_bootstrap() : legacy_status;
    }

    std::cerr << "usage: " << argv[0] << " [--new|--all]\n";
    return 1;
}
