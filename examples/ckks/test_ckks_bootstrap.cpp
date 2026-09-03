#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

#include "spdlog/spdlog.h"

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
struct ErrorStats
{
    double max_error;
    double rmse;
    std::size_t max_error_slot;
};

std::vector<uint32_t> bootstrap_modulus_chain()
{
    std::vector<uint32_t> chain(16, 51);
    chain[1] = 46;
    // chain[2] = 46;
    return chain;
}

ErrorStats calculate_error(const std::vector<std::complex<double>> &actual,
                           const std::vector<std::complex<double>> &expected)
{
    if (actual.size() != expected.size() || expected.empty())
    {
        throw std::invalid_argument(
            "bootstrap error calculation requires equally sized non-empty vectors");
    }

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
    return {max_error, rmse, max_error_slot};
}

int run_legacy_bootstrap()
{
    std::cout << "\nLegacy bootstrap test "
              << "\n";

    // Uniform 22x40 chain. Parameter self-consistency rules for a uniform p-bit chain
    // (q0_level = 0, so q0 = one p-bit prime):
    //   1) EvalMod scaling factor must equal 2^p (so q_div = sf/2^p ~= 1);
    //   2) message scale <= q0/message_ratio, and after the pre-bootstrap square the scale must
    //      still rescale safely (scale/q >= ~2^24) -> encode 2^33 with ratio 2^7.
    ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}};
    std::vector<uint32_t> log_q;
    log_q.push_back(60);
    for (int i = 0; i < 20; i++) log_q.push_back(40);
    parameters.set_log_modulus(log_q, {60});

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
    evaluator->rescale_dynamic(cipher, cipher, static_cast<int64_t>(1) << 40);

    EvalModPoly eval_mod_poly(context, CosDiscrete, static_cast<uint64_t>(1) << 40,
                              1, 7, 3, 16, 0, 30);
    spdlog::debug("before bootstrap, cipher level = {}", cipher.level());
    evaluator->bootstrap(cipher, cipher, relin_keys, galois_keys, encoder, eval_mod_poly);
    spdlog::debug("after bootstrap, cipher level = {}", cipher.level());
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
    spdlog::debug("after bootstrap, input level = {}", input.level());
    evaluator->bootstrap(input, output, relin_keys, galois_keys, encoder, config);
    spdlog::debug("after bootstrap, output level = {}", output.level());
    const auto stop = std::chrono::high_resolution_clock::now();

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
    const auto raised_level = context.crt_context()->first_context_data()->level();
    const auto consumed_levels = raised_level - output.level();
    std::cout << "bootstrap levels : " << consumed_levels << " ("
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
    const auto error = calculate_error(result, source);
    std::cout << "max abs error : " << error.max_error
              << " at slot " << error.max_error_slot << '\n';
    std::cout << "rmse          : " << error.rmse << '\n';

    constexpr uint32_t expected_level_consumption = 14;
    constexpr double max_error_limit = 2e-4;
    constexpr double rmse_limit = 1e-4;
    if (consumed_levels != expected_level_consumption ||
        error.max_error > max_error_limit || error.rmse > rmse_limit)
    {
        std::cerr << "new bootstrap regression check failed\n";
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    spdlog::set_level(spdlog::level::debug);  // enable [level] traces from the evaluator
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
