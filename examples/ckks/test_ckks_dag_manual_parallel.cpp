#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdlib>
#include <cstdint>
#include <cmath>
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
#include "poseidon/util/thread_pool.h"

using namespace poseidon;
using namespace poseidon::util;

namespace
{

constexpr int kManualParallelism = 3;

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

std::vector<omp_trace::RegionSnapshot> capture_internal_omp_regions(bool capture_internal_omp)
{
    if (!capture_internal_omp || !omp_trace::enabled() || !trace_omp_per_op_enabled())
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
void record_op(std::vector<DagTraceItem> *trace, const std::string &group, const std::string &op,
               Func &&func, bool capture_internal_omp = false)
{
    CoreSet cores;
    if (capture_internal_omp && omp_trace::enabled() && trace_omp_per_op_enabled())
    {
        omp_trace::clear();
    }
    add_current_cpu(cores);
    const auto start = Clock::now();
    func();
    const auto stop = Clock::now();
    add_current_cpu(cores);
    auto internal_omp_regions = capture_internal_omp_regions(capture_internal_omp);

    if (trace != nullptr)
    {
        trace->push_back({group, op, elapsed_ms(start, stop), cores, internal_omp_regions});
    }
}

void record_rescale_dynamic(EvaluatorCkksBase &ckks_eva, Ciphertext &cipher, double scale,
                            std::vector<DagTraceItem> *trace, const std::string &group,
                            bool capture_internal_omp = false)
{
    const auto level_before = cipher.level();
    const auto scale_before = cipher.scale();
    CoreSet cores;
    if (capture_internal_omp && omp_trace::enabled() && trace_omp_per_op_enabled())
    {
        omp_trace::clear();
    }
    add_current_cpu(cores);
    const auto start = Clock::now();
    ckks_eva.rescale_dynamic(cipher, cipher, scale);
    const auto stop = Clock::now();
    add_current_cpu(cores);
    auto internal_omp_regions = capture_internal_omp_regions(capture_internal_omp);

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

void append_trace(std::vector<DagTraceItem> &trace, const std::vector<DagTraceItem> &items)
{
    trace.insert(trace.end(), items.begin(), items.end());
}

void print_dag_trace(const std::vector<DagTraceItem> &trace)
{
    const std::vector<std::string> groups{"branch_add", "branch_quad", "branch_cross",
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
        std::cout << "  [" << item.group << "] " << item.op << " TIME: " << item.ms << " ms";
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

void print_internal_omp_replay_trace(const std::vector<DagTraceItem> &trace)
{
    if (trace.empty())
    {
        return;
    }

    std::cout << "CKKS DAG manual-parallel per-op internal OMP replay:" << std::endl;
    std::cout << "  (replayed after the timed manual-parallel run for clean per-operation "
                 "attribution)"
              << std::endl;
    for (const auto &item : trace)
    {
        std::cout << "  [" << item.group << "] " << item.op
                  << " REPLAY_TIME: " << item.ms << " ms" << std::endl;
        if (item.internal_omp_regions.empty())
        {
            std::cout << "    [libomp] (no internal OpenMP activity recorded)" << std::endl;
        }
        else
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

ParametersLiteral make_ckks_dag_parameters()
{
    ParametersLiteral params{CKKS, 15, 14, 40, 5, 0, 0, {}, {},
                             poseidon::sec_level_type::tc128};
    const std::vector<std::uint32_t> log_q(15, 40);
    const std::vector<std::uint32_t> log_p{60};
    params.set_log_modulus(log_q, log_p);
    return params;
}

Ciphertext smooth_square_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                const GaloisKeys &galois_keys, double scale,
                                const Ciphertext &ct_a, const Ciphertext &ct_b,
                                std::vector<DagTraceItem> *trace = nullptr,
                                bool capture_internal_omp = false)
{
    const std::string group = "branch_add";
    Ciphertext sum_ab;
    Ciphertext rot_ab_1;
    Ciphertext smooth_ab;
    Ciphertext smooth_sq;
    Ciphertext smooth_sq_relin;
    Ciphertext smooth_sq_rot4;
    Ciphertext branch_add;

    record_op(trace, group, "add_a_b", [&]() { ckks_eva.add(ct_a, ct_b, sum_ab); },
              capture_internal_omp);
    record_op(trace, group, "rotate_1",
              [&]() { ckks_eva.rotate(sum_ab, rot_ab_1, 1, galois_keys); }, capture_internal_omp);
    record_op(trace, group, "add_rot_1", [&]() { ckks_eva.add(sum_ab, rot_ab_1, smooth_ab); },
              capture_internal_omp);
    record_op(trace, group, "square",
              [&]() { ckks_eva.multiply(smooth_ab, smooth_ab, smooth_sq); }, capture_internal_omp);
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(smooth_sq, smooth_sq_relin, relin_keys); },
              capture_internal_omp);
    record_rescale_dynamic(ckks_eva, smooth_sq_relin, scale, trace, group, capture_internal_omp);
    record_op(trace, group, "rotate_4",
              [&]() { ckks_eva.rotate(smooth_sq_relin, smooth_sq_rot4, 4, galois_keys); },
              capture_internal_omp);
    record_op(trace, group, "add_rot_4",
              [&]() { ckks_eva.add(smooth_sq_relin, smooth_sq_rot4, branch_add); },
              capture_internal_omp);
    return branch_add;
}

Ciphertext diff_energy_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                              const GaloisKeys &galois_keys, double scale,
                              const Ciphertext &ct_c, const Ciphertext &ct_d,
                              std::vector<DagTraceItem> *trace = nullptr,
                              bool capture_internal_omp = false)
{
    const std::string group = "branch_quad";
    Ciphertext diff_cd;
    Ciphertext diff_rot2;
    Ciphertext diff_mix;
    Ciphertext diff_sq;
    Ciphertext diff_sq_relin;
    Ciphertext diff_sq_rot8;
    Ciphertext branch_quad;

    record_op(trace, group, "sub_c_d", [&]() { ckks_eva.sub(ct_c, ct_d, diff_cd); },
              capture_internal_omp);
    record_op(trace, group, "rotate_2",
              [&]() { ckks_eva.rotate(diff_cd, diff_rot2, 2, galois_keys); }, capture_internal_omp);
    record_op(trace, group, "add_rot_2", [&]() { ckks_eva.add(diff_cd, diff_rot2, diff_mix); },
              capture_internal_omp);
    record_op(trace, group, "square",
              [&]() { ckks_eva.multiply(diff_mix, diff_mix, diff_sq); }, capture_internal_omp);
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(diff_sq, diff_sq_relin, relin_keys); },
              capture_internal_omp);
    record_rescale_dynamic(ckks_eva, diff_sq_relin, scale, trace, group, capture_internal_omp);
    record_op(trace, group, "rotate_8",
              [&]() { ckks_eva.rotate(diff_sq_relin, diff_sq_rot8, 8, galois_keys); },
              capture_internal_omp);
    record_op(trace, group, "add_rot_8",
              [&]() { ckks_eva.add(diff_sq_relin, diff_sq_rot8, branch_quad); },
              capture_internal_omp);
    return branch_quad;
}

Ciphertext cross_mix_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                            const GaloisKeys &galois_keys, double scale,
                            const Ciphertext &ct_a, const Ciphertext &ct_b,
                            const Ciphertext &ct_c, const Ciphertext &ct_d,
                            std::vector<DagTraceItem> *trace = nullptr,
                            bool capture_internal_omp = false)
{
    const std::string group = "branch_cross";
    Ciphertext prod_ac;
    Ciphertext prod_ac_relin;
    Ciphertext prod_bd;
    Ciphertext prod_bd_relin;
    Ciphertext cross_sum;
    Ciphertext cross_rot8;
    Ciphertext cross_mix;
    Ciphertext cross_rot16;
    Ciphertext branch_cross;

    record_op(trace, group, "multiply_a_c", [&]() { ckks_eva.multiply(ct_a, ct_c, prod_ac); },
              capture_internal_omp);
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(prod_ac, prod_ac_relin, relin_keys); },
              capture_internal_omp);
    record_rescale_dynamic(ckks_eva, prod_ac_relin, scale, trace, group, capture_internal_omp);
    record_op(trace, group, "multiply_b_d", [&]() { ckks_eva.multiply(ct_b, ct_d, prod_bd); },
              capture_internal_omp);
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(prod_bd, prod_bd_relin, relin_keys); },
              capture_internal_omp);
    record_rescale_dynamic(ckks_eva, prod_bd_relin, scale, trace, group, capture_internal_omp);
    record_op(trace, group, "add_products",
              [&]() { ckks_eva.add(prod_ac_relin, prod_bd_relin, cross_sum); },
              capture_internal_omp);
    record_op(trace, group, "rotate_8",
              [&]() { ckks_eva.rotate(cross_sum, cross_rot8, 8, galois_keys); },
              capture_internal_omp);
    record_op(trace, group, "add_rot_8", [&]() { ckks_eva.add(cross_sum, cross_rot8, cross_mix); },
              capture_internal_omp);
    record_op(trace, group, "rotate_16",
              [&]() { ckks_eva.rotate(cross_mix, cross_rot16, 16, galois_keys); },
              capture_internal_omp);
    record_op(trace, group, "add_rot_16",
              [&]() { ckks_eva.add(cross_mix, cross_rot16, branch_cross); },
              capture_internal_omp);
    return branch_cross;
}

void final_reduce(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                  const GaloisKeys &galois_keys, double scale, const Ciphertext &branch_add,
                  const Ciphertext &branch_quad, const Ciphertext &branch_cross, Ciphertext &result,
                  std::vector<DagTraceItem> *trace = nullptr,
                  bool capture_internal_omp = false)
{
    const std::string group = "merge_tail";
    Ciphertext merged_left;
    Ciphertext merged_all;
    Ciphertext tail_prod;
    Ciphertext tail_prod_relin;
    Ciphertext tail_rot32;

    record_op(trace, group, "add_branch_quad",
              [&]() { ckks_eva.add(branch_add, branch_quad, merged_left); }, capture_internal_omp);
    record_op(trace, group, "add_branch_cross",
              [&]() { ckks_eva.add(merged_left, branch_cross, merged_all); },
              capture_internal_omp);
    record_op(trace, group, "multiply_tail",
              [&]() { ckks_eva.multiply(merged_all, branch_add, tail_prod); }, capture_internal_omp);
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(tail_prod, tail_prod_relin, relin_keys); },
              capture_internal_omp);
    record_rescale_dynamic(ckks_eva, tail_prod_relin, scale, trace, group, capture_internal_omp);
    record_op(trace, group, "rotate_32",
              [&]() { ckks_eva.rotate(tail_prod_relin, tail_rot32, 32, galois_keys); },
              capture_internal_omp);
    record_op(trace, group, "add_rot_32",
              [&]() { ckks_eva.add(tail_prod_relin, tail_rot32, result); }, capture_internal_omp);
}

void ckks_manual_parallel_workload(EvaluatorCkksBase &ckks_eva, ThreadPool &thread_pool,
                                   const RelinKeys &relin_keys,
                                   const GaloisKeys &galois_keys, double scale,
                                   const Ciphertext &ct_a, const Ciphertext &ct_b,
                                   const Ciphertext &ct_c, const Ciphertext &ct_d,
                                   Ciphertext &result, std::vector<DagTraceItem> *trace = nullptr)
{
    Ciphertext branch_add;
    Ciphertext branch_quad;
    Ciphertext branch_cross;
    std::vector<DagTraceItem> branch_add_trace;
    std::vector<DagTraceItem> branch_quad_trace;
    std::vector<DagTraceItem> branch_cross_trace;

    ParallelGroup parallel(thread_pool);
    parallel.go([&]()
                {
                    branch_add = smooth_square_branch(ckks_eva, relin_keys, galois_keys, scale,
                                                       ct_a, ct_b, &branch_add_trace);
                });
    parallel.go(
        [&]()
        {
            branch_quad = diff_energy_branch(ckks_eva, relin_keys, galois_keys, scale, ct_c, ct_d,
                                             &branch_quad_trace);
        });
    parallel.go([&]()
                {
                    branch_cross = cross_mix_branch(
                        ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c, ct_d,
                        &branch_cross_trace);
                });
    parallel.wait();

    if (trace != nullptr)
    {
        append_trace(*trace, branch_add_trace);
        append_trace(*trace, branch_quad_trace);
        append_trace(*trace, branch_cross_trace);
    }

    final_reduce(ckks_eva, relin_keys, galois_keys, scale, branch_add, branch_quad, branch_cross,
                 result, trace);
}

std::vector<DagTraceItem> replay_manual_parallel_internal_omp(EvaluatorCkksBase &ckks_eva,
                                                              ThreadPool &thread_pool,
                                                              const RelinKeys &relin_keys,
                                                              const GaloisKeys &galois_keys,
                                                              double scale,
                                                              const Ciphertext &ct_a,
                                                              const Ciphertext &ct_b,
                                                              const Ciphertext &ct_c,
                                                              const Ciphertext &ct_d)
{
    std::vector<DagTraceItem> replay_trace;
    if (!omp_trace::enabled() || !trace_omp_per_op_enabled())
    {
        return replay_trace;
    }

    auto branch_add_future =
        thread_pool.enqueue(
            [&]() {
                std::vector<DagTraceItem> local_trace;
                auto branch = smooth_square_branch(ckks_eva, relin_keys, galois_keys, scale, ct_a,
                                                   ct_b, &local_trace, true);
                return std::make_pair(branch, local_trace);
            });
    auto branch_add_pair = branch_add_future.get();

    auto branch_quad_future =
        thread_pool.enqueue(
            [&]() {
                std::vector<DagTraceItem> local_trace;
                auto branch = diff_energy_branch(ckks_eva, relin_keys, galois_keys, scale, ct_c,
                                                 ct_d, &local_trace, true);
                return std::make_pair(branch, local_trace);
            });
    auto branch_quad_pair = branch_quad_future.get();

    auto branch_cross_future =
        thread_pool.enqueue(
            [&]() {
                std::vector<DagTraceItem> local_trace;
                auto branch = cross_mix_branch(ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b,
                                               ct_c, ct_d, &local_trace, true);
                return std::make_pair(branch, local_trace);
            });
    auto branch_cross_pair = branch_cross_future.get();

    append_trace(replay_trace, branch_add_pair.second);
    append_trace(replay_trace, branch_quad_pair.second);
    append_trace(replay_trace, branch_cross_pair.second);

    auto final_reduce_future =
        thread_pool.enqueue(
            [&]() {
                std::vector<DagTraceItem> local_trace;
                Ciphertext result;
                final_reduce(ckks_eva, relin_keys, galois_keys, scale, branch_add_pair.first,
                             branch_quad_pair.first, branch_cross_pair.first, result, &local_trace,
                             true);
                return local_trace;
            });
    append_trace(replay_trace, final_reduce_future.get());
    return replay_trace;
}

std::vector<std::complex<double>> decrypt_and_decode(const Ciphertext &cipher, Decryptor &decryptor,
                                                     CKKSEncoder &encoder)
{
    Plaintext plain;
    std::vector<std::complex<double>> decoded;
    decryptor.decrypt(cipher, plain);
    encoder.decode(plain, decoded);
    return decoded;
}

void print_head(const char *label, const std::vector<std::complex<double>> &values)
{
    std::cout << label << std::endl;
    for (int i = 0; i < 4; ++i)
    {
        std::printf("  value[%d] : %.10lf + %.10lf I\n", i, values[i].real(), values[i].imag());
    }
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

    CoreSet reference_cores;
    add_current_cpu(reference_cores);
    const auto reference_start = Clock::now();
    auto expected = build_reference(msg_a, msg_b, msg_c, msg_d);
    const auto reference_stop = Clock::now();
    add_current_cpu(reference_cores);
    const auto reference_ms = elapsed_ms(reference_start, reference_stop);

    Plaintext parallel_pt_a;
    Plaintext parallel_pt_b;
    Plaintext parallel_pt_c;
    Plaintext parallel_pt_d;
    omp_trace::clear();
    CoreSet parallel_encode_cores;
    add_current_cpu(parallel_encode_cores);
    const auto parallel_encode_start = Clock::now();
    encoder.encode(msg_a, scale, parallel_pt_a);
    encoder.encode(msg_b, scale, parallel_pt_b);
    encoder.encode(msg_c, scale, parallel_pt_c);
    encoder.encode(msg_d, scale, parallel_pt_d);
    const auto parallel_encode_stop = Clock::now();
    add_current_cpu(parallel_encode_cores);
    const auto parallel_encode_ms = elapsed_ms(parallel_encode_start, parallel_encode_stop);
    print_internal_omp_stage_report("manual-parallel encode");

    Ciphertext parallel_ct_a;
    Ciphertext parallel_ct_b;
    Ciphertext parallel_ct_c;
    Ciphertext parallel_ct_d;
    omp_trace::clear();
    CoreSet parallel_encrypt_cores;
    add_current_cpu(parallel_encrypt_cores);
    const auto parallel_encrypt_start = Clock::now();
    encryptor.encrypt(parallel_pt_a, parallel_ct_a);
    encryptor.encrypt(parallel_pt_b, parallel_ct_b);
    encryptor.encrypt(parallel_pt_c, parallel_ct_c);
    encryptor.encrypt(parallel_pt_d, parallel_ct_d);
    const auto parallel_encrypt_stop = Clock::now();
    add_current_cpu(parallel_encrypt_cores);
    const auto parallel_encrypt_ms = elapsed_ms(parallel_encrypt_start, parallel_encrypt_stop);
    print_internal_omp_stage_report("manual-parallel encrypt");

    CoreSet thread_pool_setup_cores;
    add_current_cpu(thread_pool_setup_cores);
    const auto thread_pool_setup_start = Clock::now();
    ThreadPool thread_pool(kManualParallelism);
    const auto thread_pool_setup_stop = Clock::now();
    add_current_cpu(thread_pool_setup_cores);
    const auto thread_pool_setup_ms =
        elapsed_ms(thread_pool_setup_start, thread_pool_setup_stop);

    omp_trace::clear();
    Ciphertext parallel_result_cipher;
    std::vector<DagTraceItem> dag_trace;
    const auto parallel_evaluation_start = Clock::now();
    ckks_manual_parallel_workload(*ckks_eva, thread_pool, relin_keys, galois_keys, scale,
                                  parallel_ct_a, parallel_ct_b, parallel_ct_c, parallel_ct_d,
                                  parallel_result_cipher, &dag_trace);
    ckks_eva->read(parallel_result_cipher);
    const auto parallel_evaluation_stop = Clock::now();
    const auto parallel_evaluation_ms =
        elapsed_ms(parallel_evaluation_start, parallel_evaluation_stop);
    const auto parallel_evaluation_cores = trace_all_cores(dag_trace);
    print_internal_omp_stage_report("manual-parallel evaluation");
    auto per_op_internal_omp_replay = replay_manual_parallel_internal_omp(
        *ckks_eva, thread_pool, relin_keys, galois_keys, scale, parallel_ct_a, parallel_ct_b,
        parallel_ct_c, parallel_ct_d);

    omp_trace::clear();
    CoreSet parallel_postprocess_cores;
    add_current_cpu(parallel_postprocess_cores);
    const auto parallel_postprocess_start = Clock::now();
    auto parallel_result = decrypt_and_decode(parallel_result_cipher, decryptor, encoder);
    const auto parallel_postprocess_stop = Clock::now();
    add_current_cpu(parallel_postprocess_cores);
    const auto parallel_postprocess_ms =
        elapsed_ms(parallel_postprocess_start, parallel_postprocess_stop);
    print_internal_omp_stage_report("manual-parallel decrypt/decode");

    const auto example_stop = Clock::now();

    const auto shared_setup_ms =
        setup_ms + keygen_ms + runtime_setup_ms + message_prep_ms;
    const auto parallel_full_pipeline_ms =
        shared_setup_ms + parallel_encode_ms + parallel_encrypt_ms + thread_pool_setup_ms +
        parallel_evaluation_ms + parallel_postprocess_ms;
    const auto example_total_ms = elapsed_ms(example_start, example_stop);
    CoreSet parallel_full_pipeline_cores = setup_cores;
    merge_cores(parallel_full_pipeline_cores, keygen_cores);
    merge_cores(parallel_full_pipeline_cores, runtime_setup_cores);
    merge_cores(parallel_full_pipeline_cores, message_prep_cores);
    merge_cores(parallel_full_pipeline_cores, parallel_encode_cores);
    merge_cores(parallel_full_pipeline_cores, parallel_encrypt_cores);
    merge_cores(parallel_full_pipeline_cores, thread_pool_setup_cores);
    merge_cores(parallel_full_pipeline_cores, parallel_evaluation_cores);
    merge_cores(parallel_full_pipeline_cores, parallel_postprocess_cores);
    CoreSet example_total_cores = parallel_full_pipeline_cores;
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
    std::cout << "Plaintext reference TIME: " << reference_ms << " ms" << std::endl;
    print_stage_cores("Plaintext reference", reference_cores);
    std::cout << "Manual-parallel encode TIME: " << parallel_encode_ms << " ms"
              << std::endl;
    print_stage_cores("Manual-parallel encode", parallel_encode_cores);
    std::cout << "Manual-parallel encrypt TIME: " << parallel_encrypt_ms << " ms"
              << std::endl;
    print_stage_cores("Manual-parallel encrypt", parallel_encrypt_cores);
    std::cout << "Manual-parallel thread-pool setup TIME: " << thread_pool_setup_ms
              << " ms" << std::endl;
    print_stage_cores("Manual-parallel thread-pool setup", thread_pool_setup_cores);
    std::cout << "CKKS DAG manual-parallel evaluation TIME: " << parallel_evaluation_ms
              << " ms" << std::endl;
    print_stage_cores("CKKS DAG manual-parallel evaluation", parallel_evaluation_cores);
    print_dag_trace(dag_trace);
    print_internal_omp_replay_trace(per_op_internal_omp_replay);
    std::cout << "Manual-parallel decrypt/decode TIME: " << parallel_postprocess_ms
              << " ms" << std::endl;
    print_stage_cores("Manual-parallel decrypt/decode", parallel_postprocess_cores);
    std::cout << "Manual-parallel full pipeline TIME (shared setup included): "
              << parallel_full_pipeline_ms << " ms" << std::endl;
    print_stage_cores("Manual-parallel full pipeline (shared setup included)",
                      parallel_full_pipeline_cores);
    std::cout << "Example total TIME (including reference build): "
              << example_total_ms << " ms" << std::endl;
    print_stage_cores("Example total (including reference build)", example_total_cores);

    print_head("Expected head:", expected);
    print_head("Manual-parallel result head:", parallel_result);

    std::cout << "Manual-parallel vs expected:" << std::endl;
    GetPrecisionStats(parallel_result, expected);

    return 0;
}
