#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <cmath>
#include <iostream>
#include <string>
#include <vector>

#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/util/thread_pool.h"

using namespace poseidon;
using namespace poseidon::util;

namespace
{

constexpr int kManualParallelism = 3;

using Clock = std::chrono::high_resolution_clock;

struct DagTraceItem
{
    std::string group;
    std::string op;
    double ms = 0.0;
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

template <typename Func>
void record_op(std::vector<DagTraceItem> *trace, const std::string &group, const std::string &op,
               Func &&func)
{
    const auto start = Clock::now();
    func();
    const auto stop = Clock::now();

    if (trace != nullptr)
    {
        trace->push_back({group, op, elapsed_ms(start, stop)});
    }
}

void record_rescale_dynamic(EvaluatorCkksBase &ckks_eva, Ciphertext &cipher, double scale,
                            std::vector<DagTraceItem> *trace, const std::string &group)
{
    const auto level_before = cipher.level();
    const auto scale_before = cipher.scale();
    const auto start = Clock::now();
    ckks_eva.rescale_dynamic(cipher, cipher, scale);
    const auto stop = Clock::now();

    if (trace != nullptr)
    {
        trace->push_back({group,
                          "rescale_dynamic",
                          elapsed_ms(start, stop),
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
    }

    std::cout << "CKKS DAG operation timing:" << std::endl;
    for (const auto &item : trace)
    {
        std::cout << "  [" << item.group << "] " << item.op << " TIME: " << item.ms << " ms";
        if (item.has_cipher_state)
        {
            std::cout << " | level " << item.level_before << " -> " << item.level_after
                      << ", scale " << item.scale_before << " -> " << item.scale_after
                      << ", log2(scale) " << std::log2(item.scale_before) << " -> "
                      << std::log2(item.scale_after);
        }
        std::cout << std::endl;
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
                                std::vector<DagTraceItem> *trace = nullptr)
{
    const std::string group = "branch_add";
    Ciphertext sum_ab;
    Ciphertext rot_ab_1;
    Ciphertext smooth_ab;
    Ciphertext smooth_sq;
    Ciphertext smooth_sq_relin;
    Ciphertext smooth_sq_rot4;
    Ciphertext branch_add;

    record_op(trace, group, "add_a_b", [&]() { ckks_eva.add(ct_a, ct_b, sum_ab); });
    record_op(trace, group, "rotate_1",
              [&]() { ckks_eva.rotate(sum_ab, rot_ab_1, 1, galois_keys); });
    record_op(trace, group, "add_rot_1", [&]() { ckks_eva.add(sum_ab, rot_ab_1, smooth_ab); });
    record_op(trace, group, "square",
              [&]() { ckks_eva.multiply(smooth_ab, smooth_ab, smooth_sq); });
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(smooth_sq, smooth_sq_relin, relin_keys); });
    record_rescale_dynamic(ckks_eva, smooth_sq_relin, scale, trace, group);
    record_op(trace, group, "rotate_4",
              [&]() { ckks_eva.rotate(smooth_sq_relin, smooth_sq_rot4, 4, galois_keys); });
    record_op(trace, group, "add_rot_4",
              [&]() { ckks_eva.add(smooth_sq_relin, smooth_sq_rot4, branch_add); });
    return branch_add;
}

Ciphertext diff_energy_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                              const GaloisKeys &galois_keys, double scale,
                              const Ciphertext &ct_c, const Ciphertext &ct_d,
                              std::vector<DagTraceItem> *trace = nullptr)
{
    const std::string group = "branch_quad";
    Ciphertext diff_cd;
    Ciphertext diff_rot2;
    Ciphertext diff_mix;
    Ciphertext diff_sq;
    Ciphertext diff_sq_relin;
    Ciphertext diff_sq_rot8;
    Ciphertext branch_quad;

    record_op(trace, group, "sub_c_d", [&]() { ckks_eva.sub(ct_c, ct_d, diff_cd); });
    record_op(trace, group, "rotate_2",
              [&]() { ckks_eva.rotate(diff_cd, diff_rot2, 2, galois_keys); });
    record_op(trace, group, "add_rot_2", [&]() { ckks_eva.add(diff_cd, diff_rot2, diff_mix); });
    record_op(trace, group, "square",
              [&]() { ckks_eva.multiply(diff_mix, diff_mix, diff_sq); });
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(diff_sq, diff_sq_relin, relin_keys); });
    record_rescale_dynamic(ckks_eva, diff_sq_relin, scale, trace, group);
    record_op(trace, group, "rotate_8",
              [&]() { ckks_eva.rotate(diff_sq_relin, diff_sq_rot8, 8, galois_keys); });
    record_op(trace, group, "add_rot_8",
              [&]() { ckks_eva.add(diff_sq_relin, diff_sq_rot8, branch_quad); });
    return branch_quad;
}

Ciphertext cross_mix_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                            const GaloisKeys &galois_keys, double scale,
                            const Ciphertext &ct_a, const Ciphertext &ct_b,
                            const Ciphertext &ct_c, const Ciphertext &ct_d,
                            std::vector<DagTraceItem> *trace = nullptr)
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

    record_op(trace, group, "multiply_a_c", [&]() { ckks_eva.multiply(ct_a, ct_c, prod_ac); });
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(prod_ac, prod_ac_relin, relin_keys); });
    record_rescale_dynamic(ckks_eva, prod_ac_relin, scale, trace, group);
    record_op(trace, group, "multiply_b_d", [&]() { ckks_eva.multiply(ct_b, ct_d, prod_bd); });
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(prod_bd, prod_bd_relin, relin_keys); });
    record_rescale_dynamic(ckks_eva, prod_bd_relin, scale, trace, group);
    record_op(trace, group, "add_products",
              [&]() { ckks_eva.add(prod_ac_relin, prod_bd_relin, cross_sum); });
    record_op(trace, group, "rotate_8",
              [&]() { ckks_eva.rotate(cross_sum, cross_rot8, 8, galois_keys); });
    record_op(trace, group, "add_rot_8", [&]() { ckks_eva.add(cross_sum, cross_rot8, cross_mix); });
    record_op(trace, group, "rotate_16",
              [&]() { ckks_eva.rotate(cross_mix, cross_rot16, 16, galois_keys); });
    record_op(trace, group, "add_rot_16",
              [&]() { ckks_eva.add(cross_mix, cross_rot16, branch_cross); });
    return branch_cross;
}

void final_reduce(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                  const GaloisKeys &galois_keys, double scale, const Ciphertext &branch_add,
                  const Ciphertext &branch_quad, const Ciphertext &branch_cross, Ciphertext &result,
                  std::vector<DagTraceItem> *trace = nullptr)
{
    const std::string group = "merge_tail";
    Ciphertext merged_left;
    Ciphertext merged_all;
    Ciphertext tail_prod;
    Ciphertext tail_prod_relin;
    Ciphertext tail_rot32;

    record_op(trace, group, "add_branch_quad",
              [&]() { ckks_eva.add(branch_add, branch_quad, merged_left); });
    record_op(trace, group, "add_branch_cross",
              [&]() { ckks_eva.add(merged_left, branch_cross, merged_all); });
    record_op(trace, group, "multiply_tail",
              [&]() { ckks_eva.multiply(merged_all, branch_add, tail_prod); });
    record_op(trace, group, "relinearize",
              [&]() { ckks_eva.relinearize(tail_prod, tail_prod_relin, relin_keys); });
    record_rescale_dynamic(ckks_eva, tail_prod_relin, scale, trace, group);
    record_op(trace, group, "rotate_32",
              [&]() { ckks_eva.rotate(tail_prod_relin, tail_rot32, 32, galois_keys); });
    record_op(trace, group, "add_rot_32",
              [&]() { ckks_eva.add(tail_prod_relin, tail_rot32, result); });
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

    const auto setup_start = Clock::now();
    auto ckks_param_literal = make_ckks_dag_parameters();

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    const auto setup_stop = Clock::now();
    const auto setup_ms = elapsed_ms(setup_start, setup_stop);

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
    const auto keygen_ms = elapsed_ms(keygen_start, keygen_stop);

    const auto runtime_setup_start = Clock::now();
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    const auto runtime_setup_stop = Clock::now();
    const auto runtime_setup_ms = elapsed_ms(runtime_setup_start, runtime_setup_stop);

    const auto slot_num = ckks_param_literal.slot();
    const double scale = ckks_param_literal.scale();

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
    const auto message_prep_ms = elapsed_ms(message_prep_start, message_prep_stop);

    const auto reference_start = Clock::now();
    auto expected = build_reference(msg_a, msg_b, msg_c, msg_d);
    const auto reference_stop = Clock::now();
    const auto reference_ms = elapsed_ms(reference_start, reference_stop);

    Plaintext parallel_pt_a;
    Plaintext parallel_pt_b;
    Plaintext parallel_pt_c;
    Plaintext parallel_pt_d;
    const auto parallel_encode_start = Clock::now();
    encoder.encode(msg_a, scale, parallel_pt_a);
    encoder.encode(msg_b, scale, parallel_pt_b);
    encoder.encode(msg_c, scale, parallel_pt_c);
    encoder.encode(msg_d, scale, parallel_pt_d);
    const auto parallel_encode_stop = Clock::now();
    const auto parallel_encode_ms = elapsed_ms(parallel_encode_start, parallel_encode_stop);

    Ciphertext parallel_ct_a;
    Ciphertext parallel_ct_b;
    Ciphertext parallel_ct_c;
    Ciphertext parallel_ct_d;
    const auto parallel_encrypt_start = Clock::now();
    encryptor.encrypt(parallel_pt_a, parallel_ct_a);
    encryptor.encrypt(parallel_pt_b, parallel_ct_b);
    encryptor.encrypt(parallel_pt_c, parallel_ct_c);
    encryptor.encrypt(parallel_pt_d, parallel_ct_d);
    const auto parallel_encrypt_stop = Clock::now();
    const auto parallel_encrypt_ms = elapsed_ms(parallel_encrypt_start, parallel_encrypt_stop);

    const auto thread_pool_setup_start = Clock::now();
    ThreadPool thread_pool(kManualParallelism);
    const auto thread_pool_setup_stop = Clock::now();
    const auto thread_pool_setup_ms =
        elapsed_ms(thread_pool_setup_start, thread_pool_setup_stop);

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

    const auto parallel_postprocess_start = Clock::now();
    auto parallel_result = decrypt_and_decode(parallel_result_cipher, decryptor, encoder);
    const auto parallel_postprocess_stop = Clock::now();
    const auto parallel_postprocess_ms =
        elapsed_ms(parallel_postprocess_start, parallel_postprocess_stop);

    const auto example_stop = Clock::now();

    const auto shared_setup_ms =
        setup_ms + keygen_ms + runtime_setup_ms + message_prep_ms;
    const auto parallel_full_pipeline_ms =
        shared_setup_ms + parallel_encode_ms + parallel_encrypt_ms + thread_pool_setup_ms +
        parallel_evaluation_ms + parallel_postprocess_ms;
    const auto example_total_ms = elapsed_ms(example_start, example_stop);

    std::cout << "CKKS setup TIME: " << setup_ms << " ms" << std::endl;
    std::cout << "CKKS key generation TIME: " << keygen_ms << " ms" << std::endl;
    std::cout << "CKKS runtime object setup TIME: " << runtime_setup_ms << " ms"
              << std::endl;
    std::cout << "Message preparation TIME: " << message_prep_ms << " ms" << std::endl;
    std::cout << "Plaintext reference TIME: " << reference_ms << " ms" << std::endl;
    std::cout << "Manual-parallel encode TIME: " << parallel_encode_ms << " ms"
              << std::endl;
    std::cout << "Manual-parallel encrypt TIME: " << parallel_encrypt_ms << " ms"
              << std::endl;
    std::cout << "Manual-parallel thread-pool setup TIME: " << thread_pool_setup_ms
              << " ms" << std::endl;
    std::cout << "CKKS DAG manual-parallel evaluation TIME: " << parallel_evaluation_ms
              << " ms" << std::endl;
    print_dag_trace(dag_trace);
    std::cout << "Manual-parallel decrypt/decode TIME: " << parallel_postprocess_ms
              << " ms" << std::endl;
    std::cout << "Manual-parallel full pipeline TIME (shared setup included): "
              << parallel_full_pipeline_ms << " ms" << std::endl;
    std::cout << "Example total TIME (including reference build): "
              << example_total_ms << " ms" << std::endl;

    print_head("Expected head:", expected);
    print_head("Manual-parallel result head:", parallel_result);

    std::cout << "Manual-parallel vs expected:" << std::endl;
    GetPrecisionStats(parallel_result, expected);

    return 0;
}
