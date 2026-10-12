// dnum (key-switching decomposition count) scan for the LEGACY bootstrap.
//
// In poseidon dnum is not a free parameter -- it is implied by the modulus
// chains (keyswitch_hybrid.cpp):
//
//     dnum = ceil(#Q / #P)
//     #P = 1   -> BV variant      (every Q prime is its own digit, dnum = #Q)
//     #P = #Q  -> GHS variant     (single digit, dnum = 1)
//     else     -> HYBRID variant  (dnum = ceil(#Q / #P))
//
// With the fixed q chain 22 x 51, dnum = ceil(22 / #P) only takes the values
// {1, 2, 3, 4, 5, 6, 8, 11, 22}: dnum = 7, 9, 10 have no integer #P solution
// (e.g. ceil(22/#P) = 7 needs 22/7 < #P <= 22/6, i.e. 3.14 < #P <= 3.67).
// This scan covers every reachable value up to 11:
//
//     dnum = 1, 2, 3, 4, 5, 6, 8, 11  with  #P = 22, 11, 8, 6, 5, 4, 3, 2
//
// The p chain only feeds key switching, so the q chain and every other
// parameter stay fixed: N = 2^15, encode 2^40, sf = 2^51, k = 25,
// log_message_ratio = 2^5, double_angle = 2, sine_degree = 59, deterministic
// message. Each variant runs 5 repetitions with FRESH keys per repetition
// (so the averages cover key-generation randomness too, which single-key
// runs showed to be worth 1-2 precision bits), and reports mean keygen time,
// mean bootstrap wall time, and mean errors converted to bits.
//
// Bootstrap path selection (first argument):
//   (none)/--legacy : legacy path A -- bootstrap(..., EvalModPoly&), deg 59
//   --new           : new path B -- bootstrap(..., BootstrapConfig), heap 59
//                     (boundary_k=25, ratio 2^5, da=2, scaling_log=51,
//                      output_ratio=32, project_real=false; matches the A/B
//                      baseline test_ckks_bootstrap_ab_same.cpp)
//
// Run with --show-chains to print the actual q/p prime chains and the digit
// partition of each variant without running any bootstrap.
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

using namespace poseidon;

namespace
{

constexpr int kReps = 5;

// Selected in main() from argv: false = legacy path A, true = new path B.
bool g_use_new_bootstrap = false;

struct Variant
{
    const char *name;
    uint32_t p_count;  // number of 60-bit p primes
    uint32_t dnum;     // expected ceil(22 / p_count)
};

struct Result
{
    bool ok = false;
    std::string note;
    double keygen_s = 0.0;
    double relin_mb = 0.0;
    double galois_mb = 0.0;
    double best_s = 0.0;
    double mean_s = 0.0;
    int levels = -1;
    double mean_max_err = 0.0;
    double mean_rmse = 0.0;
};

const char *variant_name(KeySwitchVariant variant)
{
    switch (variant)
    {
    case BV:
        return "BV";
    case GHS:
        return "GHS";
    case HYBRID:
        return "HYBRID";
    default:
        return "none";
    }
}

Result run_variant(const Variant &v)
{
    Result result;

    ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}, sec_level_type::none};
    const std::vector<uint32_t> log_q(22, 51);
    const std::vector<uint32_t> log_p(v.p_count, 60);
    parameters.set_log_modulus(log_q, log_p);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    const std::size_t q_count = parameters.q().size();
    const std::size_t p_count = parameters.p().size();
    const std::size_t actual_dnum = (q_count + p_count - 1) / p_count;
    std::printf("context     : variant %s, #Q = %zu, #P = %zu, dnum = %zu\n",
                variant_name(context.key_switch_variant()), q_count, p_count, actual_dnum);
    if (actual_dnum != v.dnum)
    {
        std::printf("WARNING     : expected dnum %u, got %zu\n", v.dnum, actual_dnum);
    }

    const std::size_t slot_count = 1u << parameters.log_slots();
    std::vector<std::complex<double>> source(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        source[i] = std::sin(0.7 * static_cast<double>(i) + 0.3);
    }

    CKKSEncoder encoder(context);

    std::unique_ptr<EvalModPoly> eval_mod_poly;
    if (!g_use_new_bootstrap)
    {
        eval_mod_poly = std::make_unique<EvalModPoly>(context, CosDiscrete,
                                                      static_cast<uint64_t>(1) << 51, 1, 5, 2, 25,
                                                      0, 59);
    }

    std::vector<double> keygen_times;
    std::vector<double> boot_times;
    std::vector<double> max_errs;
    std::vector<double> rmses;
    int consumed = -1;
    for (int rep = 0; rep < kReps; ++rep)
    {
        // Fresh keys every repetition: the average then covers key randomness
        // (fresh single-key runs showed 1-2 bit precision spread).
        PublicKey public_key;
        RelinKeys relin_keys;
        GaloisKeys galois_keys;
        KeyGenerator keygen(context);
        const auto key_start = std::chrono::high_resolution_clock::now();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(galois_keys);
        const auto key_stop = std::chrono::high_resolution_clock::now();
        keygen_times.push_back(std::chrono::duration<double>(key_stop - key_start).count());
        if (rep == 0)
        {
            result.relin_mb =
                static_cast<double>(relin_keys.save_size(compr_mode_type::none)) / 1048576.0;
            result.galois_mb =
                static_cast<double>(galois_keys.save_size(compr_mode_type::none)) / 1048576.0;
        }

        Encryptor encryptor(context, public_key, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain;
        Ciphertext input;
        encoder.encode(source, static_cast<int64_t>(1) << 40, plain);
        encryptor.encrypt(plain, input);
        const uint32_t level_in = input.level();

        Ciphertext output;
        const auto start = std::chrono::high_resolution_clock::now();
        if (g_use_new_bootstrap)
        {
            BootstrapConfig config;
            config.boundary_k = 25;
            config.log_message_ratio = 5;
            config.double_angle = 2;
            config.scaling_log = 51;
            config.output_scaling_log = 0;
            config.output_ratio = 32;
            config.project_real = false;
            evaluator->bootstrap(input, output, relin_keys, galois_keys, encoder, config);
        }
        else
        {
            evaluator->bootstrap(input, output, relin_keys, galois_keys, encoder, *eval_mod_poly);
        }
        const auto stop = std::chrono::high_resolution_clock::now();
        boot_times.push_back(std::chrono::duration<double>(stop - start).count());
        consumed = static_cast<int>(level_in) - static_cast<int>(output.level());

        Plaintext result_plain;
        std::vector<std::complex<double>> decoded;
        decryptor.decrypt(output, result_plain);
        encoder.decode(result_plain, decoded);

        double max_err = 0.0;
        double squared = 0.0;
        for (std::size_t i = 0; i < source.size(); ++i)
        {
            const double err = std::abs(decoded[i] - source[i]);
            max_err = std::max(max_err, err);
            squared += err * err;
        }
        rmses.push_back(std::sqrt(squared / static_cast<double>(source.size())));
        max_errs.push_back(max_err);

        std::printf("rep %d/%d     : keygen %.1f s | boot %.2f s | max %.3e | rmse %.3e\n", rep + 1,
                    kReps, keygen_times.back(), boot_times.back(), max_err, rmses.back());
        std::fflush(stdout);
    }

    auto mean_of = [](const std::vector<double> &xs) {
        double sum = 0.0;
        for (double x : xs)
        {
            sum += x;
        }
        return sum / xs.size();
    };

    result.ok = true;
    result.keygen_s = mean_of(keygen_times);
    result.mean_s = mean_of(boot_times);
    result.best_s = *std::min_element(boot_times.begin(), boot_times.end());
    result.levels = consumed;
    result.mean_max_err = mean_of(max_errs);
    result.mean_rmse = mean_of(rmses);
    std::printf("mean        : keygen %.1f s | boot %.2f s (best %.2f) | levels %d | "
                "mean max err %.3e (%.2f bits) | mean rmse %.3e (%.2f bits)\n",
                result.keygen_s, result.mean_s, result.best_s, result.levels, result.mean_max_err,
                std::log2(1.0 / result.mean_max_err), result.mean_rmse,
                std::log2(1.0 / result.mean_rmse));
    return result;
}

void print_chain(const char *label, const std::vector<Modulus> &chain)
{
    std::printf("%-12s (%zu):", label, chain.size());
    for (std::size_t i = 0; i < chain.size(); ++i)
    {
        std::printf("%s%llu", (i % 3 == 0 ? "\n    " : "    "),
                    static_cast<unsigned long long>(chain[i].value()));
    }
    std::printf("\n");
}

int show_chains()
{
    const std::vector<Variant> variants = {
        {"dnum=1  (p=22 x 60)", 22, 1},  // GHS
        {"dnum=2  (p=11 x 60)", 11, 2},
        {"dnum=3  (p=8 x 60)", 8, 3},
        {"dnum=4  (p=6 x 60)", 6, 4},
        {"dnum=5  (p=5 x 60)", 5, 5},
        {"dnum=6  (p=4 x 60)", 4, 6},
        {"dnum=8  (p=3 x 60)", 3, 8},
        {"dnum=11 (p=2 x 60)", 2, 11},
    };

    std::printf("q = 22 x 51 bit primes (identical spec in every variant), N = 2^15\n");
    std::printf("dnum = ceil(22 / #P); values 7, 9, 10 have no integer #P and are not "
                "constructible\n\n");

    std::vector<Modulus> q_reference;
    for (const auto &v : variants)
    {
        ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}, sec_level_type::none};
        parameters.set_log_modulus(std::vector<uint32_t>(22, 51),
                                   std::vector<uint32_t>(v.p_count, 60));
        auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);

        const auto &q = parameters.q();
        const auto &p = parameters.p();
        const std::size_t q_count = q.size();
        const std::size_t p_count = p.size();
        const std::size_t dnum = (q_count + p_count - 1) / p_count;

        if (q_reference.empty())
        {
            q_reference = q;
        }
        else if (q_reference != q)
        {
            std::printf("NOTE: q chain differs from the first variant!\n");
        }

        std::printf("=== %s : variant %s, dnum = %zu ===\n", v.name,
                    variant_name(context.key_switch_variant()), dnum);
        print_chain("q chain", q);
        print_chain("p chain", p);

        // Digit partition actually used by key switching: digit i covers the q
        // primes [i * #P, min((i + 1) * #P, #Q)) (keyswitch_hybrid.cpp).
        std::printf("digit split :");
        for (std::size_t i = 0; i < dnum; ++i)
        {
            const std::size_t lo = i * p_count;
            const std::size_t hi = std::min((i + 1) * p_count, q_count);
            std::printf(" q[%zu..%zu](%zu)", lo, hi - 1, hi - lo);
        }
        std::printf("\n\n");
        std::fflush(stdout);
    }
    return 0;
}

}  // namespace

int main(int argc, char **argv)
{
    spdlog::set_level(spdlog::level::warn);

    if (argc > 1 && std::string(argv[1]) == "--show-chains")
    {
        return show_chains();
    }
    if (argc > 1)
    {
        const std::string mode = argv[1];
        if (mode == "--new")
        {
            g_use_new_bootstrap = true;
        }
        else if (mode != "--legacy")
        {
            std::cerr << "usage: " << argv[0] << " [--legacy|--new|--show-chains]\n";
            return 1;
        }
    }

    const std::vector<Variant> variants = {
        {"dnum=1  (p=22 x 60)", 22, 1},  // GHS
        {"dnum=2  (p=11 x 60)", 11, 2},
        {"dnum=3  (p=8 x 60)", 8, 3},
        {"dnum=4  (p=6 x 60)", 6, 4},
        {"dnum=5  (p=5 x 60)", 5, 5},
        {"dnum=6  (p=4 x 60)", 4, 6},
        {"dnum=8  (p=3 x 60)", 3, 8},
        {"dnum=11 (p=2 x 60)", 2, 11},
    };

    std::printf("common: q = 22 x 51, N = 2^15, encode 2^40, sf = 2^51, k = 25, ratio 2^5, "
                "da = 2, deg = 59, %d reps averaged, fresh keys per rep, path = %s\n",
                kReps, g_use_new_bootstrap ? "B (new, BootstrapConfig)" : "A (legacy, EvalModPoly)");

    std::vector<Result> results;
    for (const auto &v : variants)
    {
        std::printf("\n=== %s ===\n", v.name);
        Result r;
        try
        {
            r = run_variant(v);
        }
        catch (const std::exception &ex)
        {
            std::printf("FAILED      : %s\n", ex.what());
            r.note = ex.what();
        }
        if (!r.ok && r.note.empty())
        {
            r.note = "no result";
        }
        results.push_back(r);
        std::fflush(stdout);
    }

    std::printf("\n--- summary (q = 22 x 51, mean of %d reps) ---\n", kReps);
    std::printf("%-22s %8s %8s %9s %8s %8s %7s %9s %9s\n", "variant", "keygen", "relin MB",
                "galois MB", "boot s", "best s", "levels", "max bits", "rmse bits");
    for (std::size_t i = 0; i < variants.size(); ++i)
    {
        const auto &v = variants[i];
        const auto &r = results[i];
        if (r.ok)
        {
            std::printf("%-22s %8.1f %8.0f %9.0f %8.2f %8.2f %7d %9.2f %9.2f\n", v.name,
                        r.keygen_s, r.relin_mb, r.galois_mb, r.mean_s, r.best_s, r.levels,
                        std::log2(1.0 / r.mean_max_err), std::log2(1.0 / r.mean_rmse));
        }
        else
        {
            std::printf("%-22s  FAILED: %s\n", v.name, r.note.c_str());
        }
    }
    return 0;
}
