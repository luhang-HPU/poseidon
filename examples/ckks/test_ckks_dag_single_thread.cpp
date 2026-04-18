#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifdef __linux__
#include <sched.h>
#endif

#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/omp_trace.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

namespace
{

using Clock = std::chrono::high_resolution_clock;
using CoreSet = std::set<int>;

struct DagTraceItem
{
    std::string group;
    std::string op;
    double ms = 0.0;
    CoreSet cores;
    std::vector<omp_trace::RegionSnapshot> internal_omp_regions;
    bool has_cipher_state = false;
    std::size_t level_before = 0;
    std::size_t level_after = 0;
    double scale_before = 0.0;
    double scale_after = 0.0;
};

double elapsed_ms(const Clock::time_point &start, const Clock::time_point &stop)
{
    return std::chrono::duration<double, std::milli>(stop - start).count();
}

int current_cpu_id()
{
#ifdef __linux__
    return sched_getcpu();
#else
    return -1;
#endif
}

void add_cpu(CoreSet &cores, int cpu)
{
    if (cpu >= 0)
    {
        cores.insert(cpu);
    }
}

void add_current_cpu(CoreSet &cores)
{
    add_cpu(cores, current_cpu_id());
}

void merge_cores(CoreSet &dst, const CoreSet &src)
{
    dst.insert(src.begin(), src.end());
}

template <typename IntSet>
std::string format_int_set(const IntSet &values, const std::string &empty_value)
{
    if (values.empty())
    {
        return empty_value;
    }

    std::ostringstream oss;
    bool first = true;
    for (int value : values)
    {
        if (!first)
        {
            oss << ",";
        }
        oss << value;
        first = false;
    }
    return oss.str();
}

std::string format_cores(const CoreSet &cores)
{
    return format_int_set(cores, "(unavailable)");
}

bool trace_omp_per_op_enabled()
{
    const char *value = std::getenv("POSEIDON_TRACE_OMP_PER_OP");
    if (!value)
    {
        return false;
    }

    const std::string str(value);
    return !(str.empty() || str == "0" || str == "false" || str == "FALSE");
}

std::vector<omp_trace::RegionSnapshot> capture_internal_omp_regions()
{
    if (!omp_trace::enabled() || !trace_omp_per_op_enabled())
    {
        return {};
    }
    return omp_trace::snapshot();
}

void print_internal_omp_regions(const std::vector<omp_trace::RegionSnapshot> &regions)
{
    for (const auto &region : regions)
    {
        std::cout << "    [libomp] " << region.name
                  << " | omp_threads " << format_int_set(region.omp_threads, "(none)")
                  << " | omp_places " << format_int_set(region.omp_places, "(unavailable)")
                  << " | cpu_cores " << format_int_set(region.cpu_cores, "(unavailable)")
                  << " | hits " << region.hits
                  << " | team " << region.max_team_size
                  << " | level " << region.max_level << std::endl;
    }
}

template <typename Func>
double run_stage(Func &&func, CoreSet *cores = nullptr)
{
    if (cores != nullptr)
    {
        add_current_cpu(*cores);
    }

    const auto start = Clock::now();
    func();
    const auto stop = Clock::now();

    if (cores != nullptr)
    {
        add_current_cpu(*cores);
    }

    return elapsed_ms(start, stop);
}

template <typename Func>
void record_op(std::vector<DagTraceItem> *trace, const std::string &group, const std::string &op,
               Func &&func)
{
    CoreSet cores;
    if (omp_trace::enabled() && trace_omp_per_op_enabled())
    {
        omp_trace::clear();
    }
    add_current_cpu(cores);
    const auto start = Clock::now();
    func();
    const auto stop = Clock::now();
    add_current_cpu(cores);
    auto internal_omp_regions = capture_internal_omp_regions();

    if (trace != nullptr)
    {
        trace->push_back({group, op, elapsed_ms(start, stop), cores, internal_omp_regions});
    }
}

double trace_group_total(const std::vector<DagTraceItem> &trace, const std::string &group)
{
    double total = 0.0;
    for (const auto &item : trace)
    {
        if (item.group == group)
        {
            total += item.ms;
        }
    }
    return total;
}

CoreSet trace_group_cores(const std::vector<DagTraceItem> &trace, const std::string &group)
{
    CoreSet cores;
    for (const auto &item : trace)
    {
        if (item.group == group)
        {
            merge_cores(cores, item.cores);
        }
    }
    return cores;
}

CoreSet trace_all_cores(const std::vector<DagTraceItem> &trace)
{
    CoreSet cores;
    for (const auto &item : trace)
    {
        merge_cores(cores, item.cores);
    }
    return cores;
}

void print_dag_trace(const std::vector<DagTraceItem> &trace)
{
    const std::vector<std::string> groups{"fanout", "branch_add", "branch_cross", "branch_quad",
                                          "merge_tail"};

    std::cout << "CKKS DAG group timing:" << std::endl;
    for (const auto &group : groups)
    {
        std::cout << "  " << group << " TIME: " << trace_group_total(trace, group) << " ms"
                  << std::endl;
        std::cout << "  " << group << " CORES: " << format_cores(trace_group_cores(trace, group))
                  << std::endl;
    }

    std::cout << "CKKS DAG operation timing:" << std::endl;
    for (const auto &item : trace)
    {
        std::cout << "  [" << item.group << "] " << item.op << " TIME: " << item.ms << " ms"
                  ;
        std::cout << " | cores " << format_cores(item.cores);
        if (item.has_cipher_state)
        {
            std::cout << " | level " << item.level_before << " -> " << item.level_after
                      << ", scale " << item.scale_before << " -> " << item.scale_after
                      << ", log2(scale) " << std::log2(item.scale_before) << " -> "
                      << std::log2(item.scale_after);
        }
        std::cout << std::endl;
        if (!item.internal_omp_regions.empty())
        {
            print_internal_omp_regions(item.internal_omp_regions);
        }
    }
}

void print_stage_cores(const std::string &name, const CoreSet &cores)
{
    std::cout << name << " CORES: " << format_cores(cores) << std::endl;
}

void print_internal_omp_stage_report(const std::string &stage)
{
    if (!omp_trace::enabled() || trace_omp_per_op_enabled())
    {
        return;
    }

    omp_trace::print_report(std::cout, "Internal OMP core usage during " + stage + ":");
}

ParametersLiteral make_ckks_dag_parameters()
{
    ParametersLiteral params{CKKS, 15, 14, 40, 5, 0, 0, {}, {},
                             poseidon::sec_level_type::tc128};
    const std::vector<std::uint32_t> log_q(15, 40);
    const std::vector<std::uint32_t> log_p{60};
    params.set_log_modulus(log_q, log_p);
    return params;
}

void print_modulus_chain(const ParametersLiteral &params)
{
    std::cout << "Custom q chain (" << params.q().size() << " primes):" << std::endl;
    for (std::size_t i = 0; i < params.q().size(); ++i)
    {
        const auto &mod = params.q()[i];
        std::cout << "  q[" << i << "] = " << mod.value() << " (hex: 0x" << std::hex
                  << mod.value() << std::dec << ", bits: " << mod.bit_count() << ")"
                  << std::endl;
    }

    std::cout << "Custom p chain (" << params.p().size() << " primes):" << std::endl;
    for (std::size_t i = 0; i < params.p().size(); ++i)
    {
        const auto &mod = params.p()[i];
        std::cout << "  p[" << i << "] = " << mod.value() << " (hex: 0x" << std::hex
                  << mod.value() << std::dec << ", bits: " << mod.bit_count() << ")"
                  << std::endl;
    }
}

std::vector<std::complex<double>> rotate_left_copy(const std::vector<std::complex<double>> &input,
                                                   std::size_t step)
{
    if (input.empty())
    {
        return {};
    }

    std::vector<std::complex<double>> result = input;
    step %= result.size();
    std::rotate(result.begin(), result.begin() + step, result.end());
    return result;
}

void shrink_message(std::vector<std::complex<double>> &message)
{
    for (auto &value : message)
    {
        value /= 8.0;
    }
}

std::vector<std::complex<double>> add_ref(const std::vector<std::complex<double>> &lhs,
                                          const std::vector<std::complex<double>> &rhs)
{
    std::vector<std::complex<double>> result(lhs.size());
    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        result[i] = lhs[i] + rhs[i];
    }
    return result;
}

std::vector<std::complex<double>> sub_ref(const std::vector<std::complex<double>> &lhs,
                                          const std::vector<std::complex<double>> &rhs)
{
    std::vector<std::complex<double>> result(lhs.size());
    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        result[i] = lhs[i] - rhs[i];
    }
    return result;
}

std::vector<std::complex<double>> mul_ref(const std::vector<std::complex<double>> &lhs,
                                          const std::vector<std::complex<double>> &rhs)
{
    std::vector<std::complex<double>> result(lhs.size());
    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        result[i] = lhs[i] * rhs[i];
    }
    return result;
}

std::vector<std::complex<double>> smooth_square_branch_ref(
    const std::vector<std::complex<double>> &msg_a, const std::vector<std::complex<double>> &msg_b)
{
    auto sum_ab = add_ref(msg_a, msg_b);
    auto rot_ab_1 = rotate_left_copy(sum_ab, 1);
    auto smooth_ab = add_ref(sum_ab, rot_ab_1);
    auto smooth_sq = mul_ref(smooth_ab, smooth_ab);
    auto smooth_sq_rot4 = rotate_left_copy(smooth_sq, 4);
    return add_ref(smooth_sq, smooth_sq_rot4);
}

std::vector<std::complex<double>> diff_energy_branch_ref(
    const std::vector<std::complex<double>> &msg_c, const std::vector<std::complex<double>> &msg_d)
{
    auto diff_cd = sub_ref(msg_c, msg_d);
    auto diff_rot2 = rotate_left_copy(diff_cd, 2);
    auto diff_mix = add_ref(diff_cd, diff_rot2);
    auto diff_sq = mul_ref(diff_mix, diff_mix);
    auto diff_sq_rot8 = rotate_left_copy(diff_sq, 8);
    return add_ref(diff_sq, diff_sq_rot8);
}

std::vector<std::complex<double>> cross_mix_branch_ref(
    const std::vector<std::complex<double>> &msg_a, const std::vector<std::complex<double>> &msg_b,
    const std::vector<std::complex<double>> &msg_c, const std::vector<std::complex<double>> &msg_d)
{
    auto prod_ac = mul_ref(msg_a, msg_c);
    auto prod_bd = mul_ref(msg_b, msg_d);
    auto cross_sum = add_ref(prod_ac, prod_bd);
    auto cross_rot8 = rotate_left_copy(cross_sum, 8);
    auto cross_mix = add_ref(cross_sum, cross_rot8);
    auto cross_rot16 = rotate_left_copy(cross_mix, 16);
    return add_ref(cross_mix, cross_rot16);
}

std::vector<std::complex<double>> build_reference(const std::vector<std::complex<double>> &msg_a,
                                                  const std::vector<std::complex<double>> &msg_b,
                                                  const std::vector<std::complex<double>> &msg_c,
                                                  const std::vector<std::complex<double>> &msg_d)
{
    auto branch_add = smooth_square_branch_ref(msg_a, msg_b);
    auto branch_quad = diff_energy_branch_ref(msg_c, msg_d);
    auto branch_cross = cross_mix_branch_ref(msg_a, msg_b, msg_c, msg_d);

    auto merged_left = add_ref(branch_add, branch_quad);
    auto merged_all = add_ref(merged_left, branch_cross);
    auto tail_prod = mul_ref(merged_all, branch_add);
    auto tail_rot32 = rotate_left_copy(tail_prod, 32);
    return add_ref(tail_prod, tail_rot32);
}

void relinearize_and_rescale_inplace(EvaluatorCkksBase &ckks_eva, Ciphertext &cipher,
                                     const RelinKeys &relin_keys, double scale,
                                     std::vector<DagTraceItem> *trace, const std::string &group)
{
    record_op(trace, group, "relinearize", [&]() { ckks_eva.relinearize(cipher, cipher, relin_keys); });

    const auto level_before = cipher.level();
    const auto scale_before = cipher.scale();
    CoreSet cores;
    if (omp_trace::enabled() && trace_omp_per_op_enabled())
    {
        omp_trace::clear();
    }
    add_current_cpu(cores);
    const auto start = Clock::now();
    ckks_eva.rescale_dynamic(cipher, cipher, scale);
    const auto stop = Clock::now();
    add_current_cpu(cores);
    auto internal_omp_regions = capture_internal_omp_regions();

    if (trace != nullptr)
    {
        trace->push_back({group,
                          "rescale_dynamic",
                          elapsed_ms(start, stop),
                          cores,
                          internal_omp_regions,
                          true,
                          level_before,
                          cipher.level(),
                          scale_before,
                          cipher.scale()});
    }
}

void add_rotation_inplace(EvaluatorCkksBase &ckks_eva, Ciphertext &cipher, int step,
                          const GaloisKeys &galois_keys, std::vector<DagTraceItem> *trace,
                          const std::string &group)
{
    Ciphertext rotated;
    record_op(trace, group, "rotate_" + std::to_string(step),
              [&]() { ckks_eva.rotate(cipher, rotated, step, galois_keys); });
    record_op(trace, group, "add_rot_" + std::to_string(step),
              [&]() { ckks_eva.add_inplace(cipher, rotated); });
}

void smooth_square_branch_inplace(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                  const GaloisKeys &galois_keys, double scale,
                                  Ciphertext &branch_add, const Ciphertext &ct_b,
                                  std::vector<DagTraceItem> *trace)
{
    const std::string group = "branch_add";
    record_op(trace, group, "add_a_b", [&]() { ckks_eva.add_inplace(branch_add, ct_b); });
    add_rotation_inplace(ckks_eva, branch_add, 1, galois_keys, trace, group);
    record_op(trace, group, "square", [&]() { ckks_eva.square_inplace(branch_add); });
    relinearize_and_rescale_inplace(ckks_eva, branch_add, relin_keys, scale, trace, group);
    add_rotation_inplace(ckks_eva, branch_add, 4, galois_keys, trace, group);
}

void diff_energy_branch_inplace(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                const GaloisKeys &galois_keys, double scale,
                                Ciphertext &branch_quad, const Ciphertext &ct_d,
                                std::vector<DagTraceItem> *trace)
{
    const std::string group = "branch_quad";
    record_op(trace, group, "sub_c_d", [&]() { ckks_eva.sub(branch_quad, ct_d, branch_quad); });
    add_rotation_inplace(ckks_eva, branch_quad, 2, galois_keys, trace, group);
    record_op(trace, group, "square", [&]() { ckks_eva.square_inplace(branch_quad); });
    relinearize_and_rescale_inplace(ckks_eva, branch_quad, relin_keys, scale, trace, group);
    add_rotation_inplace(ckks_eva, branch_quad, 8, galois_keys, trace, group);
}

void cross_mix_branch_inplace(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                              const GaloisKeys &galois_keys, double scale,
                              Ciphertext &branch_cross, Ciphertext &ct_b,
                              const Ciphertext &ct_c, const Ciphertext &ct_d,
                              std::vector<DagTraceItem> *trace)
{
    const std::string group = "branch_cross";
    record_op(trace, group, "multiply_a_c",
              [&]() { ckks_eva.multiply_inplace(branch_cross, ct_c); });
    relinearize_and_rescale_inplace(ckks_eva, branch_cross, relin_keys, scale, trace, group);

    record_op(trace, group, "multiply_b_d", [&]() { ckks_eva.multiply_inplace(ct_b, ct_d); });
    relinearize_and_rescale_inplace(ckks_eva, ct_b, relin_keys, scale, trace, group);

    record_op(trace, group, "add_products", [&]() { ckks_eva.add_inplace(branch_cross, ct_b); });
    add_rotation_inplace(ckks_eva, branch_cross, 8, galois_keys, trace, group);
    add_rotation_inplace(ckks_eva, branch_cross, 16, galois_keys, trace, group);
}

void ckks_single_thread_workload(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                 const GaloisKeys &galois_keys, double scale,
                                 Ciphertext &ct_a, Ciphertext &ct_b, Ciphertext &ct_c,
                                 Ciphertext &ct_d, Ciphertext &result,
                                 std::vector<DagTraceItem> *trace)
{
    Ciphertext tail_rot32;

    // ct_a is needed by both branch_add and branch_cross; this is the only full ciphertext
    // fanout copy kept in this destructive schedule.
    record_op(trace, "fanout", "copy_a_for_branch_cross", [&]() { result = ct_a; });

    smooth_square_branch_inplace(ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, trace);
    cross_mix_branch_inplace(ckks_eva, relin_keys, galois_keys, scale, result, ct_b, ct_c, ct_d,
                             trace);
    diff_energy_branch_inplace(ckks_eva, relin_keys, galois_keys, scale, ct_c, ct_d, trace);

    // Merge tree followed by one more multiply tail to make the dependency chain
    // deeper.
    const std::string group = "merge_tail";
    record_op(trace, group, "add_branch_quad", [&]() { ckks_eva.add_inplace(result, ct_c); });
    record_op(trace, group, "add_branch_add", [&]() { ckks_eva.add_inplace(result, ct_a); });
    record_op(trace, group, "multiply_tail", [&]() { ckks_eva.multiply_inplace(result, ct_a); });
    relinearize_and_rescale_inplace(ckks_eva, result, relin_keys, scale, trace, group);
    record_op(trace, group, "rotate_32",
              [&]() { ckks_eva.rotate(result, tail_rot32, 32, galois_keys); });
    record_op(trace, group, "add_rot_32", [&]() { ckks_eva.add_inplace(result, tail_rot32); });
}

}  // namespace

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << std::endl;

    const auto example_start = Clock::now();

    CoreSet setup_cores;
    add_current_cpu(setup_cores);
    const auto setup_start = Clock::now();
    auto ckks_param_literal = make_ckks_dag_parameters();

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    const auto setup_stop = Clock::now();
    add_current_cpu(setup_cores);
    const auto setup_ms = elapsed_ms(setup_start, setup_stop);

    omp_trace::clear();
    CoreSet keygen_cores;
    add_current_cpu(keygen_cores);
    const auto keygen_start = Clock::now();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    const std::vector<int> dag_rotation_steps{1, 2, 4, 8, 16, 32};
    keygen.create_galois_keys(dag_rotation_steps, galois_keys);
    const auto keygen_stop = Clock::now();
    add_current_cpu(keygen_cores);
    const auto keygen_ms = elapsed_ms(keygen_start, keygen_stop);
    print_internal_omp_stage_report("key generation");

    CoreSet runtime_setup_cores;
    add_current_cpu(runtime_setup_cores);
    const auto runtime_setup_start = Clock::now();
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    const auto runtime_setup_stop = Clock::now();
    add_current_cpu(runtime_setup_cores);
    const auto runtime_setup_ms = elapsed_ms(runtime_setup_start, runtime_setup_stop);

    const auto slot_num = ckks_param_literal.slot();
    const double scale = ckks_param_literal.scale();
    std::cout << "Initial CKKS scale: " << scale << " (log2: " << std::log2(scale) << ")"
              << std::endl;
    print_modulus_chain(ckks_param_literal);

    CoreSet message_prep_cores;
    add_current_cpu(message_prep_cores);
    const auto message_prep_start = Clock::now();
    std::vector<std::complex<double>> msg_a;
    std::vector<std::complex<double>> msg_b;
    std::vector<std::complex<double>> msg_c;
    std::vector<std::complex<double>> msg_d;
    sample_random_complex_vector(msg_a, slot_num);
    sample_random_complex_vector(msg_b, slot_num);
    sample_random_complex_vector(msg_c, slot_num);
    sample_random_complex_vector(msg_d, slot_num);
    shrink_message(msg_a);
    shrink_message(msg_b);
    shrink_message(msg_c);
    shrink_message(msg_d);
    const auto message_prep_stop = Clock::now();
    add_current_cpu(message_prep_cores);
    const auto message_prep_ms = elapsed_ms(message_prep_start, message_prep_stop);

    Plaintext pt_a;
    Plaintext pt_b;
    Plaintext pt_c;
    Plaintext pt_d;
    Plaintext pt_result;
    omp_trace::clear();
    CoreSet encode_cores;
    add_current_cpu(encode_cores);
    const auto encode_start = Clock::now();
    encoder.encode(msg_a, scale, pt_a);
    encoder.encode(msg_b, scale, pt_b);
    encoder.encode(msg_c, scale, pt_c);
    encoder.encode(msg_d, scale, pt_d);
    const auto encode_stop = Clock::now();
    add_current_cpu(encode_cores);
    const auto encode_ms = elapsed_ms(encode_start, encode_stop);
    print_internal_omp_stage_report("encode");

    Ciphertext ct_a;
    Ciphertext ct_b;
    Ciphertext ct_c;
    Ciphertext ct_d;
    Ciphertext ct_result;
    omp_trace::clear();
    CoreSet encrypt_cores;
    add_current_cpu(encrypt_cores);
    const auto encrypt_start = Clock::now();
    encryptor.encrypt(pt_a, ct_a);
    encryptor.encrypt(pt_b, ct_b);
    encryptor.encrypt(pt_c, ct_c);
    encryptor.encrypt(pt_d, ct_d);
    const auto encrypt_stop = Clock::now();
    add_current_cpu(encrypt_cores);
    const auto encrypt_ms = elapsed_ms(encrypt_start, encrypt_stop);
    print_internal_omp_stage_report("encrypt");

    CoreSet reference_cores;
    add_current_cpu(reference_cores);
    const auto reference_start = Clock::now();
    auto expected = build_reference(msg_a, msg_b, msg_c, msg_d);
    const auto reference_stop = Clock::now();
    add_current_cpu(reference_cores);
    const auto reference_ms = elapsed_ms(reference_start, reference_stop);

    omp_trace::clear();
    std::vector<DagTraceItem> dag_trace;
    const auto evaluation_start = Clock::now();
    ckks_single_thread_workload(*ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c,
                                ct_d, ct_result, &dag_trace);
    ckks_eva->read(ct_result);
    const auto evaluation_stop = Clock::now();
    const auto evaluation_ms = elapsed_ms(evaluation_start, evaluation_stop);
    const auto evaluation_cores = trace_all_cores(dag_trace);
    print_internal_omp_stage_report("evaluation");

    std::vector<std::complex<double>> result;
    omp_trace::clear();
    CoreSet postprocess_cores;
    add_current_cpu(postprocess_cores);
    const auto postprocess_start = Clock::now();
    decryptor.decrypt(ct_result, pt_result);
    encoder.decode(pt_result, result);
    const auto postprocess_stop = Clock::now();
    add_current_cpu(postprocess_cores);
    const auto postprocess_ms = elapsed_ms(postprocess_start, postprocess_stop);
    print_internal_omp_stage_report("decrypt/decode");

    const auto example_stop = Clock::now();
    const auto ckks_full_pipeline_ms = setup_ms + keygen_ms + runtime_setup_ms + message_prep_ms +
                                       encode_ms + encrypt_ms + evaluation_ms + postprocess_ms;
    const auto example_total_ms = elapsed_ms(example_start, example_stop);
    CoreSet full_pipeline_cores = setup_cores;
    merge_cores(full_pipeline_cores, keygen_cores);
    merge_cores(full_pipeline_cores, runtime_setup_cores);
    merge_cores(full_pipeline_cores, message_prep_cores);
    merge_cores(full_pipeline_cores, encode_cores);
    merge_cores(full_pipeline_cores, encrypt_cores);
    merge_cores(full_pipeline_cores, evaluation_cores);
    merge_cores(full_pipeline_cores, postprocess_cores);
    CoreSet example_total_cores = full_pipeline_cores;
    merge_cores(example_total_cores, reference_cores);

    std::cout << "CKKS setup TIME: " << setup_ms << " ms" << std::endl;
    print_stage_cores("CKKS setup", setup_cores);
    std::cout << "CKKS key generation TIME: " << keygen_ms << " ms" << std::endl;
    print_stage_cores("CKKS key generation", keygen_cores);
    std::cout << "CKKS runtime object setup TIME: " << runtime_setup_ms << " ms"
              << std::endl;
    print_stage_cores("CKKS runtime object setup", runtime_setup_cores);
    std::cout << "Message preparation TIME: " << message_prep_ms << " ms" << std::endl;
    print_stage_cores("Message preparation", message_prep_cores);
    std::cout << "CKKS encode TIME: " << encode_ms << " ms" << std::endl;
    print_stage_cores("CKKS encode", encode_cores);
    std::cout << "CKKS encrypt TIME: " << encrypt_ms << " ms" << std::endl;
    print_stage_cores("CKKS encrypt", encrypt_cores);
    std::cout << "CKKS DAG single-thread evaluation TIME: " << evaluation_ms << " ms"
              << std::endl;
    print_stage_cores("CKKS DAG single-thread evaluation", evaluation_cores);
    print_dag_trace(dag_trace);
    std::cout << "CKKS decrypt/decode TIME: " << postprocess_ms << " ms" << std::endl;
    print_stage_cores("CKKS decrypt/decode", postprocess_cores);
    std::cout << "Plaintext reference TIME: " << reference_ms << " ms" << std::endl;
    print_stage_cores("Plaintext reference", reference_cores);
    std::cout << "CKKS full pipeline TIME (setup -> decrypt/decode): " << ckks_full_pipeline_ms
              << " ms" << std::endl;
    print_stage_cores("CKKS full pipeline (setup -> decrypt/decode)", full_pipeline_cores);
    std::cout << "Example total TIME (including reference build): " << example_total_ms
              << " ms" << std::endl;
    print_stage_cores("Example total (including reference build)", example_total_cores);

    for (int i = 0; i < 4; ++i)
    {
        std::printf("expected[%d] : %.10lf + %.10lf I\n", i, expected[i].real(), expected[i].imag());
        std::printf("result[%d]   : %.10lf + %.10lf I\n", i, result[i].real(), result[i].imag());
    }
    GetPrecisionStats(expected, result);

    return 0;
}
