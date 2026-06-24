#include <cmath>
#include <complex>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#define private public
#include "poseidon/evaluator/software/evaluator_ckks_software.h"
#undef private

#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

namespace
{
struct Event
{
    std::string stage;
    std::string op;
    uint32_t before_level;
    uint32_t after_level;
    double before_scale;
    double after_scale;
};

struct EventSummary
{
    uint32_t calls = 0;
    int level_delta_sum = 0;
};

uint32_t bit_len(uint32_t x)
{
    uint32_t n = 0;
    while (x != 0)
    {
        n++;
        x >>= 1;
    }
    return n;
}

void print_ct(const std::string &label, const Ciphertext &ct)
{
    std::cout << std::left << std::setw(46) << label << " level=" << ct.level()
              << " scale=2^" << std::fixed << std::setprecision(4) << std::log2(ct.scale())
              << '\n';
}

void print_events(const std::vector<Event> &events, const std::string &prefix)
{
    std::cout << "\n" << prefix << '\n';
    for (const auto &e : events)
    {
        std::cout << "  " << std::left << std::setw(44) << e.stage << " " << std::setw(15)
                  << e.op << " level " << e.before_level << " -> " << e.after_level
                  << " consumed=" << static_cast<int>(e.before_level) -
                                         static_cast<int>(e.after_level)
                  << " scale 2^" << std::fixed << std::setprecision(3)
                  << std::log2(e.before_scale) << " -> 2^" << std::log2(e.after_scale) << '\n';
    }
}

void print_event_summary(const std::vector<Event> &events, const std::string &prefix)
{
    std::map<std::string, EventSummary> by_stage_op;
    for (const auto &e : events)
    {
        auto key = e.stage + " / " + e.op;
        auto &summary = by_stage_op[key];
        summary.calls++;
        summary.level_delta_sum +=
            static_cast<int>(e.before_level) - static_cast<int>(e.after_level);
    }

    std::cout << "\n" << prefix << '\n';
    for (const auto &[key, summary] : by_stage_op)
    {
        std::cout << "  " << std::left << std::setw(64) << key << " calls=" << summary.calls
                  << " summed_level_delta=" << summary.level_delta_sum << '\n';
    }
}

void print_segment(const std::string &label, const Ciphertext &before, const Ciphertext &after)
{
    std::cout << "  " << std::left << std::setw(38) << label << " level " << before.level()
              << " -> " << after.level()
              << " consumed=" << static_cast<int>(before.level()) - static_cast<int>(after.level())
              << " scale 2^" << std::fixed << std::setprecision(4) << std::log2(before.scale())
              << " -> 2^" << std::log2(after.scale()) << '\n';
}

class ProbeEvaluator : public EvaluatorCkksSoftware
{
public:
    explicit ProbeEvaluator(PoseidonContext &context) : EvaluatorCkksSoftware(context) {}

    void set_stage(std::string stage) const { stage_ = std::move(stage); }

    void clear_events() const { events_.clear(); }

    const std::vector<Event> &events() const { return events_; }

    double current_min_scale() const { return min_scale_; }

    void force_min_scale(double scale) { set_min_scale(scale); }

    void rescale_dynamic(const Ciphertext &ciph, Ciphertext &result, double min_scale) const override
    {
        auto before_level = ciph.level();
        auto before_scale = ciph.scale();
        EvaluatorCkksSoftware::rescale_dynamic(ciph, result, min_scale);
        events_.push_back(
            {stage_, "rescale_dynamic", before_level, result.level(), before_scale, result.scale()});
    }

    void drop_modulus(const Ciphertext &ciph, Ciphertext &result, parms_id_type parms_id) const override
    {
        auto before_level = ciph.level();
        auto before_scale = ciph.scale();
        EvaluatorCkksSoftware::drop_modulus(ciph, result, parms_id);
        events_.push_back(
            {stage_, "drop_modulus", before_level, result.level(), before_scale, result.scale()});
    }

    void multiply_relin_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result, const RelinKeys &relin_keys) const override
    {
        auto before_level = std::min(ciph1.level(), ciph2.level());
        auto before_scale = ciph1.scale() * ciph2.scale();
        EvaluatorCkksSoftware::multiply_relin_dynamic(ciph1, ciph2, result, relin_keys);
        events_.push_back({stage_, "mul_relin_dyn", before_level, result.level(), before_scale,
                           result.scale()});
    }

private:
    mutable std::string stage_{"unset"};
    mutable std::vector<Event> events_;
};

std::map<uint32_t, Ciphertext> make_power_basis(const Ciphertext &ct)
{
    std::map<uint32_t, Ciphertext> basis;
    basis[1] = ct;
    return basis;
}

void print_basis(const std::string &label, const std::map<uint32_t, Ciphertext> &basis,
                 uint32_t input_level)
{
    std::cout << "\n" << label << '\n';
    for (const auto &[power, ct] : basis)
    {
        std::cout << "  X^" << std::left << std::setw(3) << power << " level=" << ct.level()
                  << " drop=" << static_cast<int>(input_level) - static_cast<int>(ct.level())
                  << " scale=2^" << std::fixed << std::setprecision(4) << std::log2(ct.scale())
                  << '\n';
    }
}

}  // namespace

int main()
{
    constexpr uint32_t log_n = 15;  // poly_modulus_degree = 32768, same family as Poseidon's bootstrap example.
    constexpr uint32_t log_slots = log_n - 1;
    constexpr uint32_t mod1_degree = 30;
    constexpr uint32_t double_angle = 3;
    constexpr uint32_t log_message_ratio = 8;
    constexpr uint32_t k = 16;

    ParametersLiteral ckks_param_literal{CKKS, log_n, log_slots, 32, 1, 1, 0, {}, {}};
    std::vector<uint32_t> log_q{
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    };
    std::vector<uint32_t> log_p{32};
    ckks_param_literal.set_log_modulus(log_q, log_p);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    ProbeEvaluator eval(context);

    CKKSEncoder encoder(context);
    KeyGenerator kgen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key, kgen.secret_key());

    std::vector<std::complex<double>> values(ckks_param_literal.slot());
    for (size_t i = 0; i < values.size(); i++)
    {
        values[i] = std::complex<double>(0.25 * std::sin(static_cast<double>(i)), 0);
    }

    Plaintext pt;
    encoder.encode(values, std::pow(2.0, 40), pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    const double evalmod_scale = std::pow(2.0, 40);
    EvalModPoly eval_mod_poly(context, CosDiscrete, evalmod_scale, 0, log_message_ratio,
                              double_angle, k, 0, mod1_degree);

    Polynomial mod1_poly = eval_mod_poly.sine_poly();
    std::vector<Polynomial> poly_v{mod1_poly};
    std::vector<int> idx(ckks_param_literal.slot());
    for (size_t i = 0; i < idx.size(); i++)
    {
        idx[i] = static_cast<int>(i);
    }
    std::vector<std::vector<int>> slots_index(1, idx);
    PolynomialVector polys(poly_v, slots_index);

    eval.set_stage("setup.drop_to_evalmod_level");
    const uint32_t evalmod_level = 21;
    eval.drop_modulus(ct, ct, context.crt_context()->parms_id_map().at(evalmod_level));
    ct.scale() = evalmod_scale;
    const double initial_min_scale = eval.current_min_scale();
    eval.force_min_scale(evalmod_scale);

    const uint32_t degree = static_cast<uint32_t>(mod1_poly.degree());
    const uint32_t lattigo_log_degree = bit_len(degree);
    const uint32_t lattigo_top_power = 1u << (lattigo_log_degree - 1);
    const uint32_t poseidon_log_degree = lattigo_log_degree;
    const uint32_t poseidon_top_power = lattigo_top_power;
    const uint32_t log_split = static_cast<uint32_t>(optimal_split(poseidon_log_degree));

    Polynomial parity_poly = mod1_poly;
    auto [is_odd, is_even] = is_odd_or_even_polynomial(parity_poly);

    std::cout << "Poseidon CKKS EvalMod polynomial probe\n";
    std::cout << "  poly_modulus_degree=" << ckks_param_literal.degree() << " logN=" << log_n
              << '\n';
    std::cout << "  Mod1Degree=" << degree << " DoubleAngle=" << double_angle
              << " LogMessageRatio=" << log_message_ratio << " K=" << k
              << " EvalModScale=2^40\n";
    std::cout << "  poseidon_log_degree=bits.Len64(" << degree
              << ")=" << poseidon_log_degree << " top_power=" << poseidon_top_power << '\n';
    std::cout << "  lattigo_log_degree=bits.Len64(" << degree
              << ")=" << lattigo_log_degree << " top_power=" << lattigo_top_power << '\n';
    std::cout << "  log_split=" << log_split << " is_odd=" << is_odd
              << " is_even=" << is_even << '\n';
    print_ct("input at EvalMod polynomial level", ct);

    auto poseidon_basis = make_power_basis(ct);
    eval.clear_events();
    eval.set_stage("1.poseidon.gen_power.top_power");
    eval.gen_power(poseidon_basis, poseidon_top_power, false, true, evalmod_scale, relin_keys,
                   encoder);
    eval.set_stage("1.poseidon.gen_power.intermediate");
    for (int i = static_cast<int>((1u << log_split) - 1); i > 2; i--)
    {
        const auto state = i & 1;
        if (!(is_even || is_odd) || (state == 0 && is_even) || (state == 1 && is_odd))
        {
            eval.gen_power(poseidon_basis, static_cast<uint32_t>(i), false, true, evalmod_scale,
                           relin_keys, encoder);
        }
    }
    print_basis("Poseidon current generated powers", poseidon_basis, ct.level());
    print_events(eval.events(), "Poseidon current gen_power events");

    auto lattigo_basis = make_power_basis(ct);
    eval.clear_events();
    eval.set_stage("1.lattigo_like.gen_power.top_power");
    eval.gen_power(lattigo_basis, lattigo_top_power, false, true, evalmod_scale, relin_keys,
                   encoder);
    eval.set_stage("1.lattigo_like.gen_power.intermediate");
    for (int i = static_cast<int>((1u << log_split) - 1); i > 2; i--)
    {
        const auto state = i & 1;
        if (!(is_even || is_odd) || (state == 0 && is_even) || (state == 1 && is_odd))
        {
            eval.gen_power(lattigo_basis, static_cast<uint32_t>(i), false, true, evalmod_scale,
                           relin_keys, encoder);
        }
    }
    print_basis("Lattigo-like generated powers", lattigo_basis, ct.level());
    print_events(eval.events(), "Lattigo-like gen_power events");

    Ciphertext poseidon_result;
    eval.clear_events();
    eval.set_stage("1+2.poseidon.evaluate_poly_vector");
    eval.evaluate_poly_vector(ct, poseidon_result, polys, evalmod_scale, relin_keys, encoder);
    print_ct("\nPoseidon evaluate_poly_vector output", poseidon_result);
    print_events(eval.events(), "Poseidon evaluate_poly_vector events");

    Ciphertext lattigo_like_result;
    uint32_t num = 0;
    eval.clear_events();
    eval.set_stage("1+2.lattigo_like.recurse");
    eval.recurse(lattigo_basis, relin_keys, lattigo_basis.at(lattigo_top_power).level(),
                 evalmod_scale, polys, log_split, poseidon_log_degree, lattigo_like_result, encoder,
                 is_odd, is_even, num);
    eval.set_stage("1+2.lattigo_like.final_rescale");
    eval.rescale_dynamic(lattigo_like_result, lattigo_like_result, evalmod_scale);
    lattigo_like_result.scale() = evalmod_scale;
    print_ct("\nLattigo-like recurse output", lattigo_like_result);
    print_events(eval.events(), "Lattigo-like recurse events");

    Ciphertext after_double_angle = poseidon_result;
    eval.clear_events();
    eval.set_stage("3.poseidon.double_angle_rescale");
    double sqrt2pi = eval_mod_poly.sqrt_2pi();
    for (uint32_t i = 0; i < eval_mod_poly.double_angle(); i++)
    {
        sqrt2pi *= sqrt2pi;
        eval.multiply_relin_dynamic(after_double_angle, after_double_angle, after_double_angle,
                                    relin_keys);
        eval.add(after_double_angle, after_double_angle, after_double_angle);
        eval.add_const(after_double_angle, -sqrt2pi, after_double_angle, encoder);
        eval.rescale_dynamic(after_double_angle, after_double_angle, evalmod_scale);
    }
    print_ct("\nAfter double-angle loop", after_double_angle);
    print_events(eval.events(), "Double-angle events");

    EvalModPoly full_eval_mod_poly(context, CosDiscrete, evalmod_scale, evalmod_level,
                                   log_message_ratio, double_angle, k, 0, mod1_degree);
    Ciphertext full = ct;
    std::vector<std::pair<std::string, std::pair<Ciphertext, Ciphertext>>> full_segments;
    eval.clear_events();

    eval.force_min_scale(full_eval_mod_poly.scaling_factor());
    full.scale() = full_eval_mod_poly.scaling_factor();

    Ciphertext before_segment = full;
    eval.set_stage("full_eval_mod.0.add_cos_const");
    if (full_eval_mod_poly.type() == CosDiscrete || full_eval_mod_poly.type() == CosContinuous)
    {
        double const_data = -0.5 / (full_eval_mod_poly.sc_fac() *
                                    (full_eval_mod_poly.sine_poly_b() -
                                     full_eval_mod_poly.sine_poly_a()));
        eval.add_const(full, const_data, full, encoder);
    }
    full_segments.push_back({"0. add cosine constant", {before_segment, full}});

    before_segment = full;
    eval.set_stage("full_eval_mod.1.evaluate_poly_vector");
    eval.evaluate_poly_vector(full, full, polys, full_eval_mod_poly.scaling_factor(), relin_keys,
                              encoder);
    full_segments.push_back({"1+2. evaluate_poly_vector", {before_segment, full}});

    before_segment = full;
    eval.set_stage("full_eval_mod.3.double_angle");
    sqrt2pi = full_eval_mod_poly.sqrt_2pi();
    for (uint32_t i = 0; i < full_eval_mod_poly.double_angle(); i++)
    {
        sqrt2pi *= sqrt2pi;
        eval.multiply_relin_dynamic(full, full, full, relin_keys);
        eval.add(full, full, full);
        eval.add_const(full, -sqrt2pi, full, encoder);
        eval.rescale_dynamic(full, full, full_eval_mod_poly.scaling_factor());
    }
    full_segments.push_back({"3. double-angle loop", {before_segment, full}});

    before_segment = full;
    eval.set_stage("full_eval_mod.4.final_scale_correction");
    auto context_data = context.crt_context()->get_context_data(ct.parms_id());
    auto &coeff_modulus = context_data->coeff_modulus();
    double diff_scale = full_eval_mod_poly.scaling_factor() / full.scale();
    if (diff_scale < coeff_modulus.back().value())
    {
        diff_scale *= coeff_modulus[full.level()].value();
        diff_scale *= coeff_modulus[full.level() - 1].value();
    }
    eval.multiply_const(full, 1.0, diff_scale, full, encoder);
    eval.rescale_dynamic(full, full, full_eval_mod_poly.scaling_factor());
    full_segments.push_back({"4. final scale correction", {before_segment, full}});

    eval.force_min_scale(evalmod_scale);

    std::cout << "\nFull Poseidon eval_mod segmented summary\n";
    for (const auto &[label, cts] : full_segments)
    {
        print_segment(label, cts.first, cts.second);
    }
    print_ct("full eval_mod segmented output", full);
    print_event_summary(eval.events(), "Full eval_mod event summary");

    Ciphertext direct_eval_mod = ct;
    EvalModPoly direct_eval_mod_poly(context, CosDiscrete, evalmod_scale, evalmod_level,
                                     log_message_ratio, double_angle, k, 0, mod1_degree);
    eval.clear_events();
    eval.set_stage("direct_eval_mod");
    eval.eval_mod(direct_eval_mod, direct_eval_mod, direct_eval_mod_poly, relin_keys, encoder);
    print_ct("\nDirect eval_mod output", direct_eval_mod);
    print_event_summary(eval.events(), "Direct eval_mod event summary");

    eval.force_min_scale(initial_min_scale);

    return 0;
}
