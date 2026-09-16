// Four-way bootstrap comparison under one identical parameter set, comparing the
// two bootstrap implementations in evaluator_ckks_base.h:
//   A) old version: bootstrap(..., EvalModPoly&)     -- bootstrap_core inline pipeline
//   B) new version: bootstrap(..., BootstrapConfig&) -- Bootstrapper class pipeline
//
//   1) new/59 : new version, embedded cosine heap (root polynomial degree 59 is
//               compiled into bootstrapper.cpp; cosine_heap_path stays empty)
//   2) old/59 : old version, EvalModPoly sine_degree = 59
//   3) old/30 : old version, EvalModPoly sine_degree = 30
//   4) old/22 : old version, EvalModPoly sine_degree = 22
//
// Shared by all four variants (only the bootstrap configuration differs):
//   ParametersLiteral{CKKS, 15, 14, 40, 1, 0, 0, {}, {}}  -> parameters.scale() = 2^40
//   q chain 20 x 51-bit + p{60}, N = 2^15, slots = 2^14
//   encode at parameters.scale() (2^40), deterministic message sin(0.7*i + 0.3)
//   median of 3 runs. The per-path bootstrap parameters (ratio, double angle,
//   scaling factor, ...) are NOT repeated here: print_header reports the live
//   values read back from the ParametersLiteral, EvalModPoly and BootstrapConfig
//   structures, so the header can never drift from what is actually run.
//
// The 2^40 encode scale is below q0/message_ratio for both paths (q0/2^7 = 2^44
// for the old path, q0/2^5 = 2^46 for the new path), which is the input-scale
// precondition of both implementations; each path raises the input to
// q0/message_ratio before ModRaise.
//
// The fitted degree of the old path is controlled by sine_degree AND k: the
// CosDiscrete fit floors the polynomial degree at 2*k-1 (cosine_approx.cpp
// gen_degrees), so a degree below 2*k-2 is silently raised. k therefore tracks
// the requested degree:
//   deg 59 -> k = 25 (also matches the heap's boundary_k = 25)
//   deg 30 -> k = 16 (2*16-1 = 31 = 30+1, the parameterization used by
//                     test_ckks_bootstrap_compare.cpp)
//   deg 22 -> k = 12 (2*12-1 = 23 = 22+1)
//
// Structure: setup_environment builds the shared world (parameters, context,
// keys, encoder/decryptor and the single input ciphertext every variant uses);
// make_variant_specs assembles every variant's bootstrap configuration once;
// run_once measures one bootstrap call; run_variant repeats and aggregates;
// print_* own all output formatting (reading live values from the config
// structures); main only sequences the steps.
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

using namespace poseidon;

namespace
{

constexpr int kRepeats = 3;

struct ErrorStats
{
    double max_error = 0.0;
    double rmse = 0.0;
};

struct RunResult
{
    double seconds = 0.0;
    int input_level = 0;
    int output_level = 0;
    int consumed_levels = 0;
    double output_scale_log2 = 0.0;
    double max_error = 0.0;
    double rmse = 0.0;
};

// One comparison point: version 0 runs the old bootstrap (EvalModPoly) with the
// given fitting degree, version 1 runs the new bootstrap (BootstrapConfig with
// the embedded degree-59 heap; sine_degree is label-only and must be 59).
// tag names the per-repetition lines, name the summary-table row.
struct Variant
{
    int version;
    uint32_t sine_degree;
    const char *tag;
    const char *name;
};

struct Result
{
    bool ok = false;
    std::string note;
    RunResult median;
};

// Everything the four variants share: context, evaluator, keys, codec and the
// single input ciphertext, so that only the bootstrap configuration differs.
// encoder/decryptor are heap held because they are not default constructible.
struct TestEnvironment
{
    explicit TestEnvironment(PoseidonContext poseidon_context)
        : context(std::move(poseidon_context))  // PoseidonContext has no move ctor; copies
    {
    }

    PoseidonContext context;
    std::unique_ptr<EvaluatorCkksBase> evaluator;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    std::unique_ptr<CKKSEncoder> encoder;
    std::unique_ptr<Decryptor> decryptor;
    Ciphertext input;
    std::vector<std::complex<double>> source;
};

// Build the shared world: parameters, context, keys, codec, and the fresh input
// ciphertext (encode at parameters.scale()) that every variant and repetition
// consumes unchanged.
TestEnvironment setup_environment()
{
    ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}};
    std::vector<uint32_t> log_q(20, 51);
    parameters.set_log_modulus(log_q, {60});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    TestEnvironment env(PoseidonFactory::get_instance()->create_poseidon_context(parameters));
    env.evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(env.context);

    const std::size_t slot_count = 1u << parameters.log_slots();
    env.source.resize(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        env.source[i] = std::sin(0.7 * static_cast<double>(i) + 0.3);  // deterministic message
    }

    PublicKey public_key;  // only needed to encrypt the shared input below
    KeyGenerator keygen(env.context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(env.relin_keys);
    keygen.create_galois_keys(env.galois_keys);

    env.encoder = std::make_unique<CKKSEncoder>(env.context);
    Encryptor encryptor(env.context, public_key, keygen.secret_key());
    env.decryptor = std::make_unique<Decryptor>(env.context, keygen.secret_key());

    Plaintext plain;
    env.encoder->encode(env.source, parameters.scale(), plain);
    encryptor.encrypt(plain, env.input);
    return env;
}

// k realizes the requested fitting degree: the CosDiscrete interpolation needs
// 2*k-1 >= sine_degree+1, and keeping 2*k-1 exactly at sine_degree+1 for the
// small degrees stops gen_degrees from silently inflating the fit (see the
// file header for the degree -> k table).
uint32_t fitting_k(uint32_t sine_degree)
{
    return sine_degree >= 48 ? 25 : (sine_degree + 2) / 2;
}

// Old-version configuration, the parameterization of test_ckks_bootstrap_compare.cpp:
// log_message_ratio = 7 (message ratio 2^7; q0/2^7 = 2^44 >= the 2^40 encode
// scale), double_angle = 3, scaling factor 2^51 (equals the bootstrap prime bit
// size).
std::unique_ptr<EvalModPoly> make_eval_mod_poly(const PoseidonContext &context,
                                                uint32_t sine_degree)
{
    return std::make_unique<EvalModPoly>(context, CosDiscrete,
                                         static_cast<double>(static_cast<uint64_t>(1) << 51), 1, 7,
                                         3, fitting_k(sine_degree), 0, sine_degree);
}

// New-version configuration with the embedded cosine heap. boundary_k must
// match the heap's interval; output_ratio compensates this path's own 2^5
// message ratio. project_real = false keeps the complex message, so the output
// semantics match the old path's pure refresh.
BootstrapConfig make_bootstrap_config()
{
    BootstrapConfig config;
    config.boundary_k = 25;           // must match the embedded cosine-heap interval
    config.log_message_ratio = 5;     // q0/2^5 = 2^46 >= encode scale 2^40
    config.double_angle = 2;
    config.scaling_log = 51;
    config.output_scaling_log = 0;    // keep the q0-derived output scale
    config.output_ratio = 32;         // compensates the 2^5 message ratio
    config.project_real = false;
    config.inverse_coeff = 0.0;       // auto-derive from the heap root polynomial
    config.cosine_heap_path = "";     // embedded heap, root degree 59
    return config;
}

// A variant plus its ready-made bootstrap configuration: eval_mod_poly serves
// version 0 (null otherwise), bootstrap_config serves version 1.
struct VariantSpec
{
    Variant meta;
    std::unique_ptr<EvalModPoly> eval_mod_poly;
    BootstrapConfig bootstrap_config;
};

// Assemble every variant and its configuration once, up front: the variant
// table lives here, and the GMP interpolation inside EvalModPoly construction
// runs exactly once per old variant, outside any measured section.
std::vector<VariantSpec> make_variant_specs(const PoseidonContext &context)
{
    const std::vector<Variant> variants = {
        {1, 59, "new/59", "new/59 (heap)"},
        {0, 59, "old/59", "old/59"},
        {0, 30, "old/30", "old/30"},
        {0, 22, "old/22", "old/22"},
    };

    std::vector<VariantSpec> specs;
    specs.reserve(variants.size());
    for (const Variant &variant : variants)
    {
        VariantSpec spec;
        spec.meta = variant;
        if (variant.version == 0)
        {
            spec.eval_mod_poly = make_eval_mod_poly(context, variant.sine_degree);
        }
        else
        {
            spec.bootstrap_config = make_bootstrap_config();
        }
        specs.push_back(std::move(spec));
    }
    return specs;
}

ErrorStats calculate_error(const std::vector<std::complex<double>> &actual,
                           const std::vector<std::complex<double>> &expected)
{
    ErrorStats stats;
    double squared = 0.0;
    for (std::size_t i = 0; i < expected.size(); ++i)
    {
        const double err = std::abs(actual[i] - expected[i]);
        stats.max_error = std::max(stats.max_error, err);
        squared += err * err;
    }
    stats.rmse = std::sqrt(squared / static_cast<double>(expected.size()));
    return stats;
}

// Median by wall time; error metrics are deterministic across repetitions, so
// the median run's values represent the variant.
RunResult median_of(std::vector<RunResult> runs)
{
    std::sort(runs.begin(), runs.end(),
              [](const RunResult &a, const RunResult &b) { return a.seconds < b.seconds; });
    return runs[runs.size() / 2];
}

// Measure exactly one bootstrap call: wall time, level/scale bookkeeping and,
// after the timed section, the full-slot decoding error against the source.
RunResult run_once(const std::function<void(const Ciphertext &, Ciphertext &)> &bootstrap_call,
                   const Ciphertext &input, Decryptor &decryptor, const CKKSEncoder &encoder,
                   const std::vector<std::complex<double>> &source)
{
    RunResult r;
    Ciphertext output;
    const auto start = std::chrono::high_resolution_clock::now();
    bootstrap_call(input, output);
    const auto stop = std::chrono::high_resolution_clock::now();
    r.seconds = std::chrono::duration<double>(stop - start).count();
    r.input_level = static_cast<int>(input.level());
    r.output_level = static_cast<int>(output.level());
    r.consumed_levels = r.input_level - r.output_level;
    r.output_scale_log2 = std::log2(output.scale());

    Plaintext plain;
    std::vector<std::complex<double>> decoded;
    decryptor.decrypt(output, plain);
    encoder.decode(plain, decoded);

    const ErrorStats errors = calculate_error(decoded, source);
    r.max_error = errors.max_error;
    r.rmse = errors.rmse;
    return r;
}

void print_run(const char *tag, int rep, const RunResult &r)
{
    std::printf("[%s #%d] time %.2f s | level %d -> %d (consumed %d) | out scale 2^%.2f | "
                "max err %.3e | rmse %.3e | prec(rmse) %.2f bits | prec(max) %.2f bits\n",
                tag, rep, r.seconds, r.input_level, r.output_level, r.consumed_levels,
                r.output_scale_log2, r.max_error, r.rmse, std::log2(1.0 / r.rmse),
                std::log2(1.0 / r.max_error));
    std::fflush(stdout);
}

// Bind the variant's pre-built configuration to the shared evaluator/keys and
// aggregate kRepeats runs. No configuration is constructed here.
Result run_variant(const VariantSpec &spec, TestEnvironment &env)
{
    auto bootstrap_call = [&](const Ciphertext &in, Ciphertext &out) {
        if (spec.meta.version == 0)
        {
            env.evaluator->bootstrap(in, out, env.relin_keys, env.galois_keys, *env.encoder,
                                     *spec.eval_mod_poly);
        }
        else
        {
            env.evaluator->bootstrap(in, out, env.relin_keys, env.galois_keys, *env.encoder,
                                     spec.bootstrap_config);
        }
    };

    std::vector<RunResult> runs;
    runs.reserve(kRepeats);
    for (int rep = 1; rep <= kRepeats; ++rep)
    {
        const RunResult r = run_once(bootstrap_call, env.input, *env.decryptor, *env.encoder,
                                     env.source);
        print_run(spec.meta.tag, rep, r);
        runs.push_back(r);
    }

    Result result;
    result.ok = true;
    result.median = median_of(std::move(runs));
    return result;
}

// Run every variant in order; a variant that throws is reported as FAILED and
// does not abort the remaining ones.
std::vector<Result> run_all_variants(const std::vector<VariantSpec> &specs, TestEnvironment &env)
{
    std::vector<Result> results;
    for (const VariantSpec &spec : specs)
    {
        try
        {
            results.push_back(run_variant(spec, env));
        }
        catch (const std::exception &ex)
        {
            std::printf("%s: FAILED: %s\n", spec.meta.name, ex.what());
            Result failed;
            failed.note = ex.what();
            results.push_back(failed);
        }
        std::fflush(stdout);
    }
    return results;
}

const char *scheme_name(SchemeType scheme)
{
    switch (scheme)
    {
    case BFV:
        return "BFV";
    case BGV:
        return "BGV";
    case CKKS:
        return "CKKS";
    default:
        return "unknown";
    }
}

// Summarize a modulus chain by grouping consecutive primes of equal bit size,
// e.g. 20 x 51, or 1 x 60 + 21 x 40 for a mixed chain.
std::string describe_modulus_chain(const std::vector<Modulus> &chain)
{
    std::string description;
    std::size_t i = 0;
    while (i < chain.size())
    {
        const int bits = chain[i].bit_count();
        std::size_t run = i;
        while (run < chain.size() && chain[run].bit_count() == bits)
        {
            ++run;
        }
        if (!description.empty())
        {
            description += " + ";
        }
        description += std::to_string(run - i) + " x " + std::to_string(bits);
        i = run;
    }
    return description;
}

// All header data is read back from the live structures -- ParametersLiteral via
// the context, the old path's EvalModPoly and the new path's BootstrapConfig --
// so the printed configuration can never drift from what is actually run. The
// old variants share every EvalModPoly field except sine_degree, which is
// listed per variant.
void print_header(const TestEnvironment &env, const std::vector<VariantSpec> &specs)
{
    const auto parameters = env.context.parameters_literal();

    const VariantSpec *old_spec = nullptr;
    const VariantSpec *new_spec = nullptr;
    std::string sine_degrees;
    for (const VariantSpec &spec : specs)
    {
        if (spec.meta.version == 0)
        {
            if (old_spec == nullptr)
            {
                old_spec = &spec;
            }
            if (!sine_degrees.empty())
            {
                sine_degrees += "/";
            }
            sine_degrees += std::to_string(spec.meta.sine_degree);
        }
        else if (new_spec == nullptr)
        {
            new_spec = &spec;
        }
    }

    std::printf("=== %s bootstrap old/new comparison (%zu variants) ===\n",
                scheme_name(parameters->scheme()), specs.size());
    std::printf("common: {%s, %u, %u, %u, %u, %u}, q = %s, p = %s, N = 2^%u, slots = 2^%u\n",
                scheme_name(parameters->scheme()), parameters->log_n(), parameters->log_slots(),
                parameters->log_scale(), parameters->hamming_weight(), parameters->q0_level(),
                describe_modulus_chain(parameters->q()).c_str(),
                describe_modulus_chain(parameters->p()).c_str(), parameters->log_n(),
                parameters->log_slots());
    std::printf("        encode 2^%.0f (= parameters.scale()), median of %d runs\n",
                std::log2(parameters->scale()), kRepeats);
    if (old_spec != nullptr)
    {
        const EvalModPoly &poly = *old_spec->eval_mod_poly;
        std::printf("old: EvalModPoly sf = 2^%.0f, ratio = 2^%u, double_angle = %u, k = %.0f, "
                    "sine_degree = %s\n",
                    std::log2(poly.scaling_factor()),
                    static_cast<unsigned>(std::lround(std::log2(poly.message_ratio()))),
                    poly.double_angle(), poly.k() * poly.sc_fac(), sine_degrees.c_str());
    }
    if (new_spec != nullptr)
    {
        const BootstrapConfig &config = new_spec->bootstrap_config;
        std::printf("new: BootstrapConfig boundary_k = %u, ratio = 2^%u, double_angle = %u, "
                    "scaling_log = %u, output_ratio = %u, project_real = %s\n",
                    config.boundary_k, config.log_message_ratio, config.double_angle,
                    config.scaling_log, config.output_ratio,
                    config.project_real ? "true" : "false");
    }
    std::printf("input ciphertext: level = %d, scale = 2^%.2f\n\n",
                static_cast<int>(env.input.level()), std::log2(env.input.scale()));
}

void print_summary(const std::vector<VariantSpec> &specs, const std::vector<Result> &results)
{
    std::printf("\n=== summary (median of %d runs) ===\n", kRepeats);
    std::printf("%-18s %10s %11s %16s %12s %11s %11s\n", "variant", "time [s]", "used levels",
                "max abs error", "rmse", "prec(rmse)", "prec(max)");
    for (std::size_t i = 0; i < specs.size(); ++i)
    {
        const Result &r = results[i];
        if (r.ok)
        {
            std::printf("%-18s %10.2f %11d %16.3e %12.3e %9.2f b %9.2f b\n", specs[i].meta.name,
                        r.median.seconds, r.median.consumed_levels, r.median.max_error,
                        r.median.rmse, std::log2(1.0 / r.median.rmse),
                        std::log2(1.0 / r.median.max_error));
        }
        else
        {
            std::printf("%-18s  FAILED: %s\n", specs[i].meta.name, r.note.c_str());
        }
    }
}

}  // namespace

int main()
{
    spdlog::set_level(spdlog::level::warn);  // keep output readable

    TestEnvironment env = setup_environment();
    const std::vector<VariantSpec> specs = make_variant_specs(env.context);
    print_header(env, specs);

    const std::vector<Result> results = run_all_variants(specs, env);
    print_summary(specs, results);
    return 0;
}
