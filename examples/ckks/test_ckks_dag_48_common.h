#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
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

namespace ckks_dag48 {

constexpr int kParallelBranchCount = 48;
constexpr int kManualParallelism = kParallelBranchCount;

using Clock = std::chrono::high_resolution_clock;
using CoreSet = std::set<int>;

enum class ExecutionMode { SingleThread, ManualParallel };

struct DagTraceItem {
  std::string group;
  std::string op;
  double ms = 0.0;
  CoreSet cores;
  bool has_cipher_state = false;
  std::size_t level_before = 0;
  std::size_t level_after = 0;
  double scale_before = 0.0;
  double scale_after = 0.0;
};

struct BranchSpec {
  int lhs = 0;
  int rhs = 1;
  int pre_rotation = 1;
  int post_rotation = 4;
};

double elapsed_ms(const Clock::time_point &start,
                  const Clock::time_point &stop) {
  return std::chrono::duration<double, std::milli>(stop - start).count();
}

int current_cpu_id() {
#ifdef __linux__
  return sched_getcpu();
#else
  return -1;
#endif
}

void add_cpu(CoreSet &cores, int cpu) {
  if (cpu >= 0) {
    cores.insert(cpu);
  }
}

void add_current_cpu(CoreSet &cores) { add_cpu(cores, current_cpu_id()); }

void merge_cores(CoreSet &dst, const CoreSet &src) {
  dst.insert(src.begin(), src.end());
}

template <typename IntSet>
std::string format_int_set(const IntSet &values,
                           const std::string &empty_value) {
  if (values.empty()) {
    return empty_value;
  }

  std::ostringstream oss;
  bool first = true;
  for (int value : values) {
    if (!first) {
      oss << ",";
    }
    oss << value;
    first = false;
  }
  return oss.str();
}

std::string format_cores(const CoreSet &cores) {
  return format_int_set(cores, "(unavailable)");
}

std::string branch_group_name(int index) {
  std::ostringstream oss;
  oss << "branch_" << std::setw(2) << std::setfill('0') << index;
  return oss.str();
}

template <typename Func>
void record_op(std::vector<DagTraceItem> *trace, const std::string &group,
               const std::string &op, Func &&func) {
  CoreSet cores;
  add_current_cpu(cores);
  const auto start = Clock::now();
  func();
  const auto stop = Clock::now();
  add_current_cpu(cores);

  if (trace != nullptr) {
    trace->push_back({group, op, elapsed_ms(start, stop), cores});
  }
}

void record_rescale_dynamic(EvaluatorCkksBase &ckks_eva, Ciphertext &cipher,
                            double scale, std::vector<DagTraceItem> *trace,
                            const std::string &group) {
  const auto level_before = cipher.level();
  const auto scale_before = cipher.scale();
  CoreSet cores;
  add_current_cpu(cores);
  const auto start = Clock::now();
  ckks_eva.rescale_dynamic(cipher, cipher, scale);
  const auto stop = Clock::now();
  add_current_cpu(cores);

  if (trace != nullptr) {
    trace->push_back({group, "rescale_dynamic", elapsed_ms(start, stop), cores,
                      true, level_before, cipher.level(), scale_before,
                      cipher.scale()});
  }
}

double trace_group_total(const std::vector<DagTraceItem> &trace,
                         const std::string &group) {
  double total = 0.0;
  for (const auto &item : trace) {
    if (item.group == group) {
      total += item.ms;
    }
  }
  return total;
}

CoreSet trace_group_cores(const std::vector<DagTraceItem> &trace,
                          const std::string &group) {
  CoreSet cores;
  for (const auto &item : trace) {
    if (item.group == group) {
      merge_cores(cores, item.cores);
    }
  }
  return cores;
}

CoreSet trace_all_cores(const std::vector<DagTraceItem> &trace) {
  CoreSet cores;
  for (const auto &item : trace) {
    merge_cores(cores, item.cores);
  }
  return cores;
}

void append_trace(std::vector<DagTraceItem> &trace,
                  const std::vector<DagTraceItem> &items) {
  trace.insert(trace.end(), items.begin(), items.end());
}

void print_dag_trace(const std::vector<DagTraceItem> &trace) {
  double branch_total = 0.0;
  CoreSet branch_cores;

  std::cout << "CKKS DAG group timing:" << std::endl;
  for (int i = 0; i < kParallelBranchCount; ++i) {
    const auto group = branch_group_name(i);
    const auto group_ms = trace_group_total(trace, group);
    const auto group_cores = trace_group_cores(trace, group);
    branch_total += group_ms;
    merge_cores(branch_cores, group_cores);
    std::cout << "  " << group << " TIME: " << group_ms << " ms" << std::endl;
    std::cout << "  " << group << " CORES: " << format_cores(group_cores)
              << std::endl;
  }

  std::cout << "  parallel_48_branches TOTAL_TIME: " << branch_total << " ms"
            << std::endl;
  std::cout << "  parallel_48_branches CORES: " << format_cores(branch_cores)
            << std::endl;
  std::cout << "  merge_tail TIME: " << trace_group_total(trace, "merge_tail")
            << " ms" << std::endl;
  std::cout << "  merge_tail CORES: "
            << format_cores(trace_group_cores(trace, "merge_tail"))
            << std::endl;

  std::cout << "CKKS DAG operation timing:" << std::endl;
  for (const auto &item : trace) {
    std::cout << "  [" << item.group << "] " << item.op << " TIME: " << item.ms
              << " ms";
    std::cout << " | cores " << format_cores(item.cores);
    if (item.has_cipher_state) {
      std::cout << " | level " << item.level_before << " -> "
                << item.level_after << ", scale " << item.scale_before << " -> "
                << item.scale_after << ", log2(scale) "
                << std::log2(item.scale_before) << " -> "
                << std::log2(item.scale_after);
    }
    std::cout << std::endl;
  }
}

void print_stage_cores(const std::string &name, const CoreSet &cores) {
  std::cout << name << " CORES: " << format_cores(cores) << std::endl;
}

void print_internal_omp_stage_report(const std::string &stage) {
  if (!omp_trace::enabled()) {
    return;
  }

  omp_trace::print_report(std::cout,
                          "Internal OMP core usage during " + stage + ":");
}

ParametersLiteral make_ckks_dag_parameters() {
  ParametersLiteral params{CKKS, 15, 14, 40, 5,
                           0,    0,  {}, {}, poseidon::sec_level_type::tc128};
  const std::vector<std::uint32_t> log_q(15, 40);
  const std::vector<std::uint32_t> log_p{60};
  params.set_log_modulus(log_q, log_p);
  return params;
}

BranchSpec branch_spec_for_index(int index) {
  constexpr std::array<std::array<int, 2>, 6> input_pairs{{
      {{0, 1}},
      {{0, 2}},
      {{0, 3}},
      {{1, 2}},
      {{1, 3}},
      {{2, 3}},
  }};
  constexpr std::array<int, 6> rotations{{1, 2, 4, 8, 16, 32}};

  const int lane = index % 6;
  const int cycle = index / 6;
  const auto &pair = input_pairs[lane];
  return {pair[0], pair[1], rotations[(lane + cycle) % 6],
          rotations[(lane + cycle + 2) % 6]};
}

std::array<BranchSpec, kParallelBranchCount> make_branch_specs() {
  std::array<BranchSpec, kParallelBranchCount> specs{};
  for (int i = 0; i < kParallelBranchCount; ++i) {
    specs[i] = branch_spec_for_index(i);
  }
  return specs;
}

std::vector<std::complex<double>>
rotate_left_copy(const std::vector<std::complex<double>> &input,
                 std::size_t step) {
  if (input.empty()) {
    return {};
  }

  std::vector<std::complex<double>> result = input;
  step %= result.size();
  std::rotate(result.begin(), result.begin() + step, result.end());
  return result;
}

void shrink_message(std::vector<std::complex<double>> &message) {
  for (auto &value : message) {
    value /= 128.0;
  }
}

std::vector<std::complex<double>>
add_ref(const std::vector<std::complex<double>> &lhs,
        const std::vector<std::complex<double>> &rhs) {
  std::vector<std::complex<double>> result(lhs.size());
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    result[i] = lhs[i] + rhs[i];
  }
  return result;
}

std::vector<std::complex<double>>
mul_ref(const std::vector<std::complex<double>> &lhs,
        const std::vector<std::complex<double>> &rhs) {
  std::vector<std::complex<double>> result(lhs.size());
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    result[i] = lhs[i] * rhs[i];
  }
  return result;
}

std::vector<std::complex<double>>
parallel_branch_ref(const std::vector<std::complex<double>> &lhs,
                    const std::vector<std::complex<double>> &rhs,
                    int pre_rotation, int post_rotation) {
  auto input_sum = add_ref(lhs, rhs);
  auto pre_rot = rotate_left_copy(input_sum, pre_rotation);
  auto mixed = add_ref(input_sum, pre_rot);
  auto squared = mul_ref(mixed, mixed);
  auto post_rot = rotate_left_copy(squared, post_rotation);
  return add_ref(squared, post_rot);
}

std::vector<std::complex<double>>
build_reference(const std::vector<std::complex<double>> &msg_a,
                const std::vector<std::complex<double>> &msg_b,
                const std::vector<std::complex<double>> &msg_c,
                const std::vector<std::complex<double>> &msg_d) {
  const auto specs = make_branch_specs();
  const std::array<const std::vector<std::complex<double>> *, 4> messages{
      &msg_a, &msg_b, &msg_c, &msg_d};
  std::vector<std::vector<std::complex<double>>> branches;
  branches.reserve(kParallelBranchCount);

  for (const auto &spec : specs) {
    branches.push_back(
        parallel_branch_ref(*messages[spec.lhs], *messages[spec.rhs],
                            spec.pre_rotation, spec.post_rotation));
  }

  auto merged = branches[0];
  for (std::size_t i = 1; i < branches.size(); ++i) {
    merged = add_ref(merged, branches[i]);
  }

  auto tail_prod = mul_ref(merged, branches[0]);
  auto tail_rot32 = rotate_left_copy(tail_prod, 32);
  return add_ref(tail_prod, tail_rot32);
}

Ciphertext parallel_branch(EvaluatorCkksBase &ckks_eva,
                           const RelinKeys &relin_keys,
                           const GaloisKeys &galois_keys, double scale,
                           const Ciphertext &lhs, const Ciphertext &rhs,
                           int pre_rotation, int post_rotation,
                           const std::string &group,
                           std::vector<DagTraceItem> *trace) {
  Ciphertext input_sum;
  Ciphertext pre_rot;
  Ciphertext mixed;
  Ciphertext squared;
  Ciphertext squared_relin;
  Ciphertext post_rot;
  Ciphertext branch;

  record_op(trace, group, "add_inputs",
            [&]() { ckks_eva.add(lhs, rhs, input_sum); });
  record_op(trace, group, "rotate_pre_" + std::to_string(pre_rotation), [&]() {
    ckks_eva.rotate(input_sum, pre_rot, pre_rotation, galois_keys);
  });
  record_op(trace, group, "add_pre_rot",
            [&]() { ckks_eva.add(input_sum, pre_rot, mixed); });
  record_op(trace, group, "square",
            [&]() { ckks_eva.multiply(mixed, mixed, squared); });
  record_op(trace, group, "relinearize", [&]() {
    ckks_eva.relinearize(squared, squared_relin, relin_keys);
  });
  record_rescale_dynamic(ckks_eva, squared_relin, scale, trace, group);
  record_op(
      trace, group, "rotate_post_" + std::to_string(post_rotation), [&]() {
        ckks_eva.rotate(squared_relin, post_rot, post_rotation, galois_keys);
      });
  record_op(trace, group, "add_post_rot",
            [&]() { ckks_eva.add(squared_relin, post_rot, branch); });
  return branch;
}

void merge_parallel_branches(EvaluatorCkksBase &ckks_eva,
                             const RelinKeys &relin_keys,
                             const GaloisKeys &galois_keys, double scale,
                             const std::vector<const Ciphertext *> &branches,
                             Ciphertext &result,
                             std::vector<DagTraceItem> *trace) {
  const std::string group = "merge_tail";
  Ciphertext tail_rot32;

  record_op(trace, group, "copy_branch_00", [&]() { result = *branches[0]; });
  for (std::size_t i = 1; i < branches.size(); ++i) {
    record_op(trace, group, "add_" + branch_group_name(static_cast<int>(i)),
              [&]() { ckks_eva.add_inplace(result, *branches[i]); });
  }

  record_op(trace, group, "multiply_tail_branch_00",
            [&]() { ckks_eva.multiply_inplace(result, *branches[0]); });
  record_op(trace, group, "relinearize",
            [&]() { ckks_eva.relinearize(result, result, relin_keys); });
  record_rescale_dynamic(ckks_eva, result, scale, trace, group);
  record_op(trace, group, "rotate_32",
            [&]() { ckks_eva.rotate(result, tail_rot32, 32, galois_keys); });
  record_op(trace, group, "add_rot_32",
            [&]() { ckks_eva.add_inplace(result, tail_rot32); });
}

void ckks_single_thread_workload(EvaluatorCkksBase &ckks_eva,
                                 const RelinKeys &relin_keys,
                                 const GaloisKeys &galois_keys, double scale,
                                 const Ciphertext &ct_a, const Ciphertext &ct_b,
                                 const Ciphertext &ct_c, const Ciphertext &ct_d,
                                 Ciphertext &result,
                                 std::vector<DagTraceItem> *trace) {
  const auto specs = make_branch_specs();
  const std::array<const Ciphertext *, 4> inputs{&ct_a, &ct_b, &ct_c, &ct_d};
  std::array<Ciphertext, kParallelBranchCount> branches;

  for (int i = 0; i < kParallelBranchCount; ++i) {
    const auto &spec = specs[i];
    branches[i] =
        parallel_branch(ckks_eva, relin_keys, galois_keys, scale,
                        *inputs[spec.lhs], *inputs[spec.rhs], spec.pre_rotation,
                        spec.post_rotation, branch_group_name(i), trace);
  }

  std::vector<const Ciphertext *> branch_ptrs;
  branch_ptrs.reserve(branches.size());
  for (const auto &branch : branches) {
    branch_ptrs.push_back(&branch);
  }
  merge_parallel_branches(ckks_eva, relin_keys, galois_keys, scale, branch_ptrs,
                          result, trace);
}

void ckks_manual_parallel_workload(
    EvaluatorCkksBase &ckks_eva, ThreadPool &thread_pool,
    const RelinKeys &relin_keys, const GaloisKeys &galois_keys, double scale,
    const Ciphertext &ct_a, const Ciphertext &ct_b, const Ciphertext &ct_c,
    const Ciphertext &ct_d, Ciphertext &result,
    std::vector<DagTraceItem> *trace) {
  const auto specs = make_branch_specs();
  const std::array<const Ciphertext *, 4> inputs{&ct_a, &ct_b, &ct_c, &ct_d};
  std::array<Ciphertext, kParallelBranchCount> branches;
  std::array<std::vector<DagTraceItem>, kParallelBranchCount> branch_traces;

  ParallelGroup parallel(thread_pool);
  for (int i = 0; i < kParallelBranchCount; ++i) {
    const auto spec = specs[i];
    const auto group = branch_group_name(i);
    parallel.go([&, i, spec, group]() {
      branches[i] = parallel_branch(ckks_eva, relin_keys, galois_keys, scale,
                                    *inputs[spec.lhs], *inputs[spec.rhs],
                                    spec.pre_rotation, spec.post_rotation,
                                    group, &branch_traces[i]);
    });
  }
  parallel.wait();

  if (trace != nullptr) {
    for (const auto &branch_trace : branch_traces) {
      append_trace(*trace, branch_trace);
    }
  }

  std::vector<const Ciphertext *> branch_ptrs;
  branch_ptrs.reserve(branches.size());
  for (const auto &branch : branches) {
    branch_ptrs.push_back(&branch);
  }
  merge_parallel_branches(ckks_eva, relin_keys, galois_keys, scale, branch_ptrs,
                          result, trace);
}

void run_example(ExecutionMode mode) {
  const bool manual_parallel = mode == ExecutionMode::ManualParallel;
  const char *mode_label =
      manual_parallel ? "manual-parallel" : "single-thread";
  const std::string evaluation_label =
      std::string("CKKS DAG ") + mode_label + " 48-branch evaluation";

  std::cout << BANNER << std::endl;
  std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
  std::cout << std::endl;

  const auto example_start = Clock::now();

  CoreSet setup_cores;
  add_current_cpu(setup_cores);
  const auto setup_start = Clock::now();
  auto ckks_param_literal = make_ckks_dag_parameters();

  PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
  auto context = PoseidonFactory::get_instance()->create_poseidon_context(
      ckks_param_literal);
  auto ckks_eva =
      PoseidonFactory::get_instance()->create_ckks_evaluator(context);
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
  const auto runtime_setup_ms =
      elapsed_ms(runtime_setup_start, runtime_setup_stop);

  const auto slot_num = ckks_param_literal.slot();
  const double scale = ckks_param_literal.scale();
  std::cout << "Initial CKKS scale: " << scale << " (log2: " << std::log2(scale)
            << ")" << std::endl;
  std::cout << "CKKS DAG independent branch count: " << kParallelBranchCount
            << std::endl;
  if (manual_parallel) {
    std::cout << "Manual thread-pool workers: " << kManualParallelism
              << std::endl;
  }

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
  const auto message_prep_ms =
      elapsed_ms(message_prep_start, message_prep_stop);

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

  CoreSet thread_pool_setup_cores;
  double thread_pool_setup_ms = 0.0;
  std::unique_ptr<ThreadPool> thread_pool;
  if (manual_parallel) {
    add_current_cpu(thread_pool_setup_cores);
    const auto thread_pool_setup_start = Clock::now();
    thread_pool.reset(new ThreadPool(kManualParallelism));
    const auto thread_pool_setup_stop = Clock::now();
    add_current_cpu(thread_pool_setup_cores);
    thread_pool_setup_ms =
        elapsed_ms(thread_pool_setup_start, thread_pool_setup_stop);
  }

  omp_trace::clear();
  std::vector<DagTraceItem> dag_trace;
  const auto evaluation_start = Clock::now();
  if (manual_parallel) {
    ckks_manual_parallel_workload(*ckks_eva, *thread_pool, relin_keys,
                                  galois_keys, scale, ct_a, ct_b, ct_c, ct_d,
                                  ct_result, &dag_trace);
  } else {
    ckks_single_thread_workload(*ckks_eva, relin_keys, galois_keys, scale, ct_a,
                                ct_b, ct_c, ct_d, ct_result, &dag_trace);
  }
  ckks_eva->read(ct_result);
  const auto evaluation_stop = Clock::now();
  const auto evaluation_ms = elapsed_ms(evaluation_start, evaluation_stop);
  const auto evaluation_cores = trace_all_cores(dag_trace);
  print_internal_omp_stage_report(evaluation_label);

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
  const auto ckks_full_pipeline_ms =
      setup_ms + keygen_ms + runtime_setup_ms + message_prep_ms + encode_ms +
      encrypt_ms + thread_pool_setup_ms + evaluation_ms + postprocess_ms;
  const auto example_total_ms = elapsed_ms(example_start, example_stop);
  CoreSet full_pipeline_cores = setup_cores;
  merge_cores(full_pipeline_cores, keygen_cores);
  merge_cores(full_pipeline_cores, runtime_setup_cores);
  merge_cores(full_pipeline_cores, message_prep_cores);
  merge_cores(full_pipeline_cores, encode_cores);
  merge_cores(full_pipeline_cores, encrypt_cores);
  merge_cores(full_pipeline_cores, thread_pool_setup_cores);
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
  std::cout << "Message preparation TIME: " << message_prep_ms << " ms"
            << std::endl;
  print_stage_cores("Message preparation", message_prep_cores);
  std::cout << "CKKS encode TIME: " << encode_ms << " ms" << std::endl;
  print_stage_cores("CKKS encode", encode_cores);
  std::cout << "CKKS encrypt TIME: " << encrypt_ms << " ms" << std::endl;
  print_stage_cores("CKKS encrypt", encrypt_cores);
  if (manual_parallel) {
    std::cout << "Manual-parallel thread-pool setup TIME: "
              << thread_pool_setup_ms << " ms" << std::endl;
    print_stage_cores("Manual-parallel thread-pool setup",
                      thread_pool_setup_cores);
  }
  std::cout << evaluation_label << " TIME: " << evaluation_ms << " ms"
            << std::endl;
  print_stage_cores(evaluation_label, evaluation_cores);
  print_dag_trace(dag_trace);
  std::cout << "CKKS decrypt/decode TIME: " << postprocess_ms << " ms"
            << std::endl;
  print_stage_cores("CKKS decrypt/decode", postprocess_cores);
  std::cout << "Plaintext reference TIME: " << reference_ms << " ms"
            << std::endl;
  print_stage_cores("Plaintext reference", reference_cores);
  std::cout << "CKKS full pipeline TIME (setup -> decrypt/decode): "
            << ckks_full_pipeline_ms << " ms" << std::endl;
  print_stage_cores("CKKS full pipeline (setup -> decrypt/decode)",
                    full_pipeline_cores);
  std::cout << "Example total TIME (including reference build): "
            << example_total_ms << " ms" << std::endl;
  print_stage_cores("Example total (including reference build)",
                    example_total_cores);

  for (int i = 0; i < 4; ++i) {
    std::printf("expected[%d] : %.10lf + %.10lf I\n", i, expected[i].real(),
                expected[i].imag());
    std::printf("result[%d]   : %.10lf + %.10lf I\n", i, result[i].real(),
                result[i].imag());
  }
  GetPrecisionStats(expected, result);
}

} // namespace ckks_dag48
