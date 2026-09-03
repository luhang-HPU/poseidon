// Head-to-head comparison of the two bootstrap implementations under identical parameters:
//   A) bootstrap(..., EvalModPoly&)      — legacy/lattigo-style inline pipeline (bootstrap_core)
//   B) bootstrap(..., BootstrapConfig&)  — Bootstrapper class (HEAAN-style + cosine-heap composition)
// Same modulus chain (22x40 + p60), same keys, same message, same fresh input ciphertext
// (scale 2^33, full level) fed to both paths; reports level consumption, wall time and precision.
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
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

using namespace poseidon;

namespace
{

struct Result
{
    double seconds;
    int consumed_levels;
    double max_error;
    double rmse;
};

Result run_once(const std::function<void(const Ciphertext &, Ciphertext &)> &bootstrap_call,
                const Ciphertext &input, Decryptor &decryptor, CKKSEncoder &encoder,
                const std::vector<std::complex<double>> &source, uint32_t top_level)
{
    Ciphertext output;
    const auto start = std::chrono::high_resolution_clock::now();
    bootstrap_call(input, output);
    const auto stop = std::chrono::high_resolution_clock::now();
    Result r;
    r.seconds = std::chrono::duration<double>(stop - start).count();
    r.consumed_levels = static_cast<int>(top_level) - static_cast<int>(output.level());

    Plaintext plain;
    std::vector<std::complex<double>> decoded;
    decryptor.decrypt(output, plain);
    encoder.decode(plain, decoded);

    r.max_error = 0.0;
    double squared = 0.0;
    for (std::size_t i = 0; i < source.size(); ++i)
    {
        const double err = std::abs(decoded[i] - source[i]);
        r.max_error = std::max(r.max_error, err);
        squared += err * err;
    }
    r.rmse = std::sqrt(squared / static_cast<double>(source.size()));
    return r;
}

}  // namespace

int main()
{
    spdlog::set_level(spdlog::level::warn);  // keep output readable

    std::cout << "Bootstrap A/B comparison\n";
    std::cout << "chain: 22 x 51-bit q + p{60}, N = 2^15, slots = 2^14\n";

    // Uniform 22x51 chain, self-consistent parameters for both paths (q0 = one 51-bit prime):
    //   EvalMod: sf 2^51, ratio 2^7, encode 2^40 (<= q0/ratio = 2^44)
    //   Config : boundary_k 25 (heap-bound), log_message_ratio 5, double_angle 2, scaling_log 51
    ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}};
    std::vector<uint32_t> log_q(22, 51);
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
    Ciphertext input;
    encoder.encode(source, static_cast<int64_t>(1) << 40, plain);  // <= q0/ratio = 2^44
    encryptor.encrypt(plain, input);
    const uint32_t top_level = input.level();
    std::cout << "input: level = " << top_level << ", scale = 2^"
              << std::log2(input.scale()) << "\n\n";

    // Path A: legacy pipeline (bootstrap_core), EvalModPoly parameterization
    EvalModPoly eval_mod_poly(context, CosDiscrete, static_cast<uint64_t>(1) << 51,
                              1, 7, 3, 16, 0, 30);
    const Result a = run_once(
        [&](const Ciphertext &in, Ciphertext &out) {
            evaluator->bootstrap(in, out, relin_keys, galois_keys, encoder, eval_mod_poly);
        },
        input, decryptor, encoder, source, top_level);

    // Path B: Bootstrapper class, BootstrapConfig parameterization (no real projection,
    // no output scaling, so the output semantics match path A: a pure refresh)
    BootstrapConfig config;
    config.boundary_k = 25;  // must match the embedded cosine-heap interval
    config.log_message_ratio = 5;
    config.double_angle = 2;
    config.scaling_log = 51;
    config.output_scaling_log = 0;
    config.output_ratio = 32;  // required scale compensation of this pipeline
    config.project_real = false;
    const Result b = run_once(
        [&](const Ciphertext &in, Ciphertext &out) {
            evaluator->bootstrap(in, out, relin_keys, galois_keys, encoder, config);
        },
        input, decryptor, encoder, source, top_level);

    std::printf("%-22s %14s %16s\n", "", "A: EvalModPoly", "B: BootstrapConfig");
    std::printf("%-22s %14.2f %16.2f\n", "time [s]", a.seconds, b.seconds);
    std::printf("%-22s %14d %16d\n", "consumed levels", a.consumed_levels, b.consumed_levels);
    std::printf("%-22s %14.3e %16.3e\n", "max abs error", a.max_error, b.max_error);
    std::printf("%-22s %14.3e %16.3e\n", "rmse", a.rmse, b.rmse);
    std::printf("%-22s %14.2f %16.2f\n", "precision(rmse) bits", std::log2(1.0 / a.rmse),
                std::log2(1.0 / b.rmse));
    std::printf("%-22s %14.2f %16.2f\n", "precision(max) bits", std::log2(1.0 / a.max_error),
                std::log2(1.0 / b.max_error));
    return 0;
}
