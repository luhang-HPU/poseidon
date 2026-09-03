// Quantifies what happens when the encode scale is raised from 2^33 to 2^40 on the
// 22x40 chain (test_ckks_bootstrap.cpp line 109), and evaluates the two ways to
// make a 2^40 encode scale bootstrap-compatible.
//
//   default : encode 2^33 -- baseline, self-consistent (Delta <= q0 / 2^7)
//   --a     : encode 2^40 only. Violates Delta <= q0/message_ratio: the ScaleDown
//             factor rounds to 0 and the message enters EvalMod 2^7 times larger
//             than the Chebyshev window [-k*sc_fac, k*sc_fac].
//   --b     : encode 2^40 + first chain prime enlarged to 47 bits, so
//             q0 / 2^7 = 2^40 and the bound holds again.
//   --c     : encode 2^40 + message ratio lowered to 1. Bound holds
//             (Delta <= q0), but the message now fills the whole sine window:
//             the linearization error grows ~ 2^(2*7) versus baseline.
//
// Every mode uses the same deterministic message, keys are generated once per run,
// and each mode reports bootstrap wall time, consumed levels and slot precision.
#include "poseidon/advance/homomorphic_mod.h"
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
#include <exception>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

using namespace poseidon;

namespace
{

struct Config
{
    const char *name;
    uint32_t log_encode;     // encode scale
    uint32_t first_prime;    // bits of chain[0] (q0); the rest are 40-bit
    uint32_t log_ratio;      // EvalModPoly log_message_ratio
};

int run_mode(const Config &cfg)
{
    std::printf("\n=== mode %s: encode 2^%u, q0 = %u-bit, ratio 2^%u ===\n", cfg.name,
                cfg.log_encode, cfg.first_prime, cfg.log_ratio);

    ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}};
    std::vector<uint32_t> log_q(22, 40);
    log_q[0] = cfg.first_prime;
    parameters.set_log_modulus(log_q, {60});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    const std::size_t slot_count = 1u << parameters.log_slots();
    std::vector<std::complex<double>> source(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        source[i] = std::sin(0.7 * static_cast<double>(i) + 0.3);
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

    // Scenario from the question: the application multiplies (squaring here) and
    // rescales at scale ~2^40 before refreshing.
    Plaintext plain;
    Ciphertext cipher;
    encoder.encode(source, static_cast<int64_t>(1) << cfg.log_encode, plain);
    encryptor.encrypt(plain, cipher);
    evaluator->multiply_relin(cipher, cipher, cipher, relin_keys);
    evaluator->rescale_dynamic(cipher, cipher, static_cast<int64_t>(1) << 40);
    std::printf("pre-bootstrap : level = %u, scale = 2^%.1f\n", cipher.level(),
                std::log2(cipher.scale()));

    EvalModPoly eval_mod_poly(context, CosDiscrete, static_cast<uint64_t>(1) << 40, 1,
                              cfg.log_ratio, 3, 16, 0, 30);

    Ciphertext result;
    const uint32_t level_in = cipher.level();
    const auto start = std::chrono::high_resolution_clock::now();
    evaluator->bootstrap(cipher, result, relin_keys, galois_keys, encoder, eval_mod_poly);
    const auto stop = std::chrono::high_resolution_clock::now();

    std::printf("bootstrap     : %.2f s, consumed %d levels (%u -> %u)\n",
                std::chrono::duration<double>(stop - start).count(),
                static_cast<int>(level_in) - static_cast<int>(result.level()), level_in,
                result.level());

    Plaintext result_plain;
    std::vector<std::complex<double>> decoded;
    decryptor.decrypt(result, result_plain);
    encoder.decode(result_plain, decoded);

    // Ground truth: the squared message (the test squares before refreshing).
    double max_err = 0.0;
    double squared = 0.0;
    for (std::size_t i = 0; i < source.size(); ++i)
    {
        const std::complex<double> expected = source[i] * source[i];
        const double err = std::abs(decoded[i] - expected);
        max_err = std::max(max_err, err);
        squared += err * err;
    }
    const double rmse = std::sqrt(squared / static_cast<double>(source.size()));
    std::printf("precision     : max err %.3e (%.2f bits), rmse %.3e (%.2f bits)\n", max_err,
                std::log2(1.0 / max_err), rmse, std::log2(1.0 / rmse));
    return 0;
}

}  // namespace

int main(int argc, char **argv)
{
    spdlog::set_level(spdlog::level::warn);

    const std::string mode = argc > 1 ? argv[1] : "baseline";
    try
    {
        if (mode == "baseline")
        {
            return run_mode({"baseline", 33, 40, 7});
        }
        if (mode == "--a")
        {
            return run_mode({"A: encode 2^40 only", 40, 40, 7});
        }
        if (mode == "--b")
        {
            return run_mode({"B: 2^40 + 47-bit q0", 40, 47, 7});
        }
        if (mode == "--c")
        {
            return run_mode({"C: 2^40 + ratio 1", 40, 40, 0});
        }
    }
    catch (const std::exception &ex)
    {
        std::printf("FAILED        : %s\n", ex.what());
        return 1;
    }

    std::cerr << "usage: " << argv[0] << " [baseline|--a|--b|--c]\n";
    return 1;
}
