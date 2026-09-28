// Experimental CtS-first full-slot real bootstrap, with one EvalMod.
// This test deliberately drops encrypted input to level 1 BEFORE bootstrapping.
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "spdlog/spdlog.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace poseidon;
namespace {
using C = std::complex<double>;
using V = std::vector<C>;

V apply_matrices(const std::vector<std::map<int, V>> &matrices, V input)
{
    for (const auto &matrix : matrices)
    {
        V output(input.size());
        for (const auto &[rotation, diagonal] : matrix)
            for (std::size_t i = 0; i < input.size(); ++i)
                output[i] += diagonal[i] * input[(i + rotation) & (input.size() - 1)];
        input = std::move(output);
    }
    return input;
}

// Check the real-half reconstruction identity independently of encryption and
// EvalMod. Constant/nonzero-mean inputs catch the missing DC half-weight bug.
void check_algebra()
{
    double worst = 0.0, wrapped_worst = 0.0;
    for (int l : {3, 4, 5, 8, 10})
    {
        HomomorphicDFTMatrixLiteral cts(0, l + 1, l, 19, {1, 1, 1}, true, 1, false, 1);
        HomomorphicDFTMatrixLiteral stc(1, l + 1, l, 16, {1, 1, 1}, true, 1, false, 1);
        auto forward = cts.gen_matrices();
        auto inverse = stc.gen_matrices();
        for (int kind = 0; kind < 5; ++kind)
        {
            V x(1 << l);
            for (std::size_t i = 0; i < x.size(); ++i)
                x[i] = kind == 0 ? 1.0 : kind == 1 ? (i == 0 ? 1.0 : 0.0) :
                       kind == 2 ? (i % 2 ? 1.0 : -1.0) : std::sin(i * .73 + kind) + .2;
            auto coefficients = apply_matrices(forward, x);
            // Model unrelated integer ModRaise errors in BOTH halves. The
            // errors need not have the real message's coefficient symmetry.
            auto wrapped = coefficients;
            for (std::size_t i = 0; i < wrapped.size(); ++i)
                wrapped[i] = 2.0 * wrapped[i] / 128.0 + C(
                    static_cast<int>((i * 7 + kind) % 19) - 9,
                    static_cast<int>((i * 11 + kind + 3) % 17) - 8);
            auto raised = apply_matrices(inverse, wrapped);
            auto recovered = apply_matrices(forward, raised);
            for (auto &v : recovered)
            {
                const double t = 2 * v.real();
                v = 128 * (t - std::round(t)); // ideal real-lane modular reduction
            }
            recovered[0] *= .5;
            auto restored = apply_matrices(inverse, recovered);
            for (std::size_t i = 0; i < x.size(); ++i)
                wrapped_worst = std::max(wrapped_worst, std::abs(2 * restored[i].real() - x[i]));
            for (auto &v : coefficients) v = 2 * v.real();
            coefficients[0] *= .5;
            auto reconstructed = apply_matrices(inverse, coefficients);
            for (std::size_t i = 0; i < x.size(); ++i)
                worst = std::max(worst, std::abs(2 * reconstructed[i].real() - x[i]));
        }
    }
    if (worst > 1e-10 || wrapped_worst > 1e-9)
        throw std::runtime_error("real-half algebra failed");
    std::cout << "# cleartext reconstruction max_error=" << worst
              << " independent_integer_wrap_error=" << wrapped_worst << '\n';
}

struct Stats { double max_error = 0, rmse = 0, max_imag = 0; };
Stats error(const V &actual, const V &expected)
{
    if (actual.size() != expected.size()) throw std::runtime_error("wrong slot count");
    Stats s;
    for (std::size_t i = 0; i < actual.size(); ++i)
    {
        const double e = std::abs(actual[i] - expected[i]);
        if (!std::isfinite(e)) throw std::runtime_error("non-finite output");
        s.max_error = std::max(s.max_error, e);
        s.max_imag = std::max(s.max_imag, std::abs(actual[i].imag()));
        s.rmse += e * e;
    }
    s.rmse = std::sqrt(s.rmse / actual.size());
    return s;
}

void check_coefficient_api(EvalModPoly poly)
{
    const auto original = poly.sine_poly().data();
    std::vector<double> coefficients;
    for (const auto &c : original) coefficients.push_back(c.real() / poly.sqrt_2pi());
    auto expect_rejection = [&](const std::vector<double> &bad) {
        bool rejected = false;
        try { poly.set_cosine_coefficients(bad); }
        catch (const std::invalid_argument &) { rejected = true; }
        if (!rejected || poly.sine_poly().data() != original || poly.sine_poly().is_odd())
            throw std::runtime_error("coefficient validation did not preserve the polynomial");
    };
    auto bad = coefficients;
    bad.pop_back();
    expect_rejection(bad);
    bad = coefficients;
    bad[0] = std::numeric_limits<double>::quiet_NaN();
    expect_rejection(bad);
    bad = coefficients;
    bad.back() = 0;
    expect_rejection(bad);
    poly.enable_full_cosine_coefficients();
    if (poly.sine_poly().data() != original || !poly.sine_poly().is_even() || !poly.sine_poly().is_odd())
        throw std::runtime_error("full coefficient activation changed data or lost a parity");
    poly.set_cosine_coefficients(coefficients);
    if (!poly.sine_poly().is_even() || !poly.sine_poly().is_odd())
        throw std::runtime_error("loaded coefficients lost a parity");
}
}

int main(int argc, char **argv)
{
    try
    {
        int log_n = 13, h = 5, repeats = 1, rounds = 1, ratio_log = 7, input_level = 1;
        int work_bits = 51, input_bits = 40, degree = 22, angles = 3;
        bool single_only = false, in_place = false, square_between = false, algebra_only = false;
        bool full_coefficients = false, compare_coefficients = false;
        std::string coefficient_file;
        double amplitude = 1.0, max_tolerance = 1e-3;
        std::string distribution = "all";
        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];
            auto value = [&]() -> std::string {
                if (++i == argc) throw std::invalid_argument("missing option value");
                return argv[i];
            };
            if (arg == "--log-n") log_n = std::stoi(value());
            else if (arg == "--h") h = std::stoi(value());
            else if (arg == "--repeats") repeats = std::stoi(value());
            else if (arg == "--rounds") rounds = std::stoi(value());
            else if (arg == "--ratio-log") ratio_log = std::stoi(value());
            else if (arg == "--input-level") input_level = std::stoi(value());
            else if (arg == "--work-bits") work_bits = std::stoi(value());
            else if (arg == "--input-bits") input_bits = std::stoi(value());
            else if (arg == "--degree") degree = std::stoi(value());
            else if (arg == "--double-angle") angles = std::stoi(value());
            else if (arg == "--amplitude") amplitude = std::stod(value());
            else if (arg == "--max-error") max_tolerance = std::stod(value());
            else if (arg == "--distribution") distribution = value();
            else if (arg == "--single-only") single_only = true;
            else if (arg == "--in-place") in_place = true;
            else if (arg == "--square-between") square_between = true;
            else if (arg == "--algebra-only") algebra_only = true;
            else if (arg == "--full-coefficients") full_coefficients = true;
            else if (arg == "--compare-coefficients") compare_coefficients = true;
            else if (arg == "--coefficient-file") coefficient_file = value();
            else throw std::invalid_argument("unknown option: " + arg);
        }
        if (log_n < 10 || log_n > 16 || h < 1 || h > 64 || repeats < 1 || repeats > 10 ||
            rounds < 1 || rounds > 10 || ratio_log < 4 || ratio_log > 12 ||
            input_level < 1 || input_level > 19 || work_bits < 40 || work_bits > 55 ||
            input_bits < 25 || input_bits > work_bits - ratio_log ||
            (degree != 22 && degree != 30 && degree != 59) || angles < 2 || angles > 4 ||
            !std::isfinite(amplitude) || amplitude < 0 ||
            !std::isfinite(max_tolerance) || max_tolerance <= 0)
            throw std::invalid_argument("unsupported test parameters");
        if ((full_coefficients && !coefficient_file.empty()) ||
            (compare_coefficients && !full_coefficients && coefficient_file.empty()))
            throw std::invalid_argument("select exactly one coefficient candidate for comparison");
        spdlog::set_level(spdlog::level::warn);
        std::cout << std::setprecision(12);
        check_algebra();
        if (algebra_only) return 0;
        ParametersLiteral parameters{CKKS, static_cast<uint32_t>(log_n),
            static_cast<uint32_t>(log_n - 1), static_cast<uint32_t>(input_bits),
            static_cast<uint32_t>(h), 0, 0, {}, {}};
        parameters.set_log_modulus(std::vector<uint32_t>(20, work_bits), {60});
        PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
        auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
        auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
        CKKSEncoder encoder(context);
        KeyGenerator keygen(context);
        PublicKey pk;
        RelinKeys relin;
        GaloisKeys galois;
        keygen.create_public_key(pk);
        keygen.create_relin_keys(relin);
        keygen.create_galois_keys(galois);
        Encryptor encryptor(context, pk, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        const int k = degree >= 48 ? 25 : (degree + 2) / 2;
        EvalModPoly poly(context, CosDiscrete, std::ldexp(1.0, work_bits), 1,
                         ratio_log, angles, k, 0, degree);
        if (degree == 22) check_coefficient_api(poly);
        EvalModPoly baseline_poly = poly;
        if (full_coefficients)
            poly.enable_full_cosine_coefficients();
        if (!coefficient_file.empty())
        {
            std::vector<double> coefficients;
            std::ifstream stream(coefficient_file);
            if (!stream) throw std::invalid_argument("cannot open coefficient file");
            double value;
            while (stream >> value) coefficients.push_back(value);
            if (!stream.eof()) throw std::invalid_argument("invalid coefficient file");
            poly.set_cosine_coefficients(coefficients);
        }
        const int actual_degree = poly.sine_poly().degree();
        // The discrete node allocator can stop one degree below an odd request.
        // Always report the actual degree; 22/30 must match exactly.
        if ((degree != 59 && actual_degree != degree) ||
            actual_degree > degree || actual_degree < degree - 1)
            throw std::runtime_error("unexpected fitted degree: " + std::to_string(actual_degree));
        std::cout << "# N=" << (1 << log_n) << " slots=" << encoder.slot_count()
                  << " H=" << h << " Q=20x" << work_bits << " P=60 input_bits=" << input_bits
                  << " degree=" << actual_degree << " requested_degree=" << degree
                  << " DA=" << angles << " K=" << k
                  << " R=" << (1 << ratio_log) << " amplitude=" << amplitude
                  << " max_tolerance=" << max_tolerance << " in_place=" << in_place
                  << " square_between=" << square_between
                  << " coefficient_profile=" << (full_coefficients ? "full-original" :
                      coefficient_file.empty() ? "legacy-even" : coefficient_file)
                  << " compare_coefficients=" << compare_coefficients << '\n';
        std::cout << "mode,distribution,repeat,round,input_level,output_level,used_levels,log2_scale,seconds,max_error,rmse,max_imag\n" << std::flush;
        std::vector<std::string> distributions = {"sine", "random", "constant", "edges", "impulse", "zero"};
        if (distribution != "all")
        {
            const auto supported = distributions;
            distributions.clear();
            std::istringstream selection(distribution);
            std::string name;
            while (std::getline(selection, name, ','))
            {
                if (std::find(supported.begin(), supported.end(), name) == supported.end())
                    throw std::invalid_argument("unknown distribution");
                distributions.push_back(name);
            }
            if (distributions.empty()) throw std::invalid_argument("empty distribution selection");
        }
        std::mt19937_64 rng(20260928);
        std::uniform_real_distribution<double> uniform(-1, 1);
        bool passed = true;
        for (const auto &name : distributions)
        {
            V source(encoder.slot_count());
            for (std::size_t i = 0; i < source.size(); ++i)
                source[i] = amplitude * (name == "sine" ? std::sin(.7 * i + .3) :
                    name == "random" ? uniform(rng) : name == "constant" ? 1.0 :
                    name == "edges" ? (i % 2 ? 1.0 : -1.0) :
                    name == "impulse" ? (i == 0 ? 1.0 : 0.0) : 0.0);
            Plaintext plain;
            encoder.encode(source, parameters.scale(), plain);
            Ciphertext fresh;
            encryptor.encrypt(plain, fresh);
            evaluator->drop_modulus(fresh, fresh, static_cast<uint32_t>(input_level));
            // Fail-fast boundary tests, before any expensive transform.
            Ciphertext level_zero, ignored;
            evaluator->drop_modulus(fresh, level_zero, uint32_t{0});
            bool rejected = false;
            try { evaluator->bootstrap_real(level_zero, ignored, relin, galois, encoder, poly); }
            catch (const std::invalid_argument &) { rejected = true; }
            if (!rejected) throw std::runtime_error("level-zero input was not rejected");
            auto bad_scale = fresh;
            bad_scale.scale() = std::ldexp(1.0, work_bits);
            rejected = false;
            try { evaluator->bootstrap_real(bad_scale, ignored, relin, galois, encoder, poly); }
            catch (const std::invalid_argument &) { rejected = true; }
            if (!rejected) throw std::runtime_error("oversized scale was not rejected");
            for (int repeat = 0; repeat < repeats; ++repeat)
                for (int lane : (single_only ? std::vector<int>{1} : std::vector<int>{2, 1}))
                for (int variant : (compare_coefficients ? std::vector<int>{0, 1} : std::vector<int>{1}))
                {
                    auto &active_poly = variant == 0 ? baseline_poly : poly;
                    auto input = fresh;
                    auto expected_source = source;
                    for (int round = 0; round < rounds; ++round)
                    {
                        evaluator->drop_modulus(input, input, static_cast<uint32_t>(input_level));
                        Ciphertext output;
                        auto start = std::chrono::steady_clock::now();
                        auto &destination = in_place ? input : output;
                        if (lane == 1) evaluator->bootstrap_real(input, destination, relin, galois, encoder, active_poly);
                        else evaluator->bootstrap(input, destination, relin, galois, encoder, active_poly);
                        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
                        decryptor.decrypt(destination, plain);
                        V decoded;
                        encoder.decode(plain, decoded);
                        auto stats = error(decoded, expected_source);
                        const int used = 19 - destination.level();
                        const int expected = 6 + static_cast<int>(std::ceil(std::log2(actual_degree + 1))) + angles;
                        std::cout << (lane == 1 ? "single" : "dual")
                                  << (compare_coefficients ? (variant == 0 ? "_baseline" : "_candidate") : "")
                                  << ',' << name << ',' << repeat
                                  << ',' << round << ',' << input_level << ',' << destination.level()
                                  << ',' << used << ',' << std::log2(destination.scale()) << ',' << seconds
                                  << ',' << stats.max_error << ',' << stats.rmse << ',' << stats.max_imag << std::endl;
                        passed &= stats.max_error <= max_tolerance && used == expected &&
                                  std::abs(std::log2(destination.scale()) - input_bits) < 1e-6;
                        if (!in_place) input = std::move(output);
                        if (square_between && round + 1 < rounds)
                        {
                            evaluator->multiply_relin(input, input, input, relin);
                            evaluator->rescale(input, input);
                            for (auto &value : expected_source) value *= value;
                        }
                    }
                }
        }
        std::cout << "# " << (passed ? "PASS" : "FAIL") << std::endl;
        return passed ? 0 : 2;
    }
    catch (const std::exception &e)
    {
        std::cerr << "CF-real test failed: " << e.what() << std::endl;
        return 1;
    }
}
