#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
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

long long elapsed_us(const Clock::time_point &start, const Clock::time_point &stop)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
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

Ciphertext smooth_square_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                const GaloisKeys &galois_keys, double scale,
                                const Ciphertext &ct_a, const Ciphertext &ct_b)
{
    Ciphertext sum_ab;
    Ciphertext rot_ab_1;
    Ciphertext smooth_ab;
    Ciphertext smooth_sq;
    Ciphertext smooth_sq_relin;
    Ciphertext smooth_sq_rot4;
    Ciphertext branch_add;

    ckks_eva.add(ct_a, ct_b, sum_ab);
    ckks_eva.rotate(sum_ab, rot_ab_1, 1, galois_keys);
    ckks_eva.add(sum_ab, rot_ab_1, smooth_ab);
    ckks_eva.multiply(smooth_ab, smooth_ab, smooth_sq);
    ckks_eva.relinearize(smooth_sq, smooth_sq_relin, relin_keys);
    ckks_eva.rescale_dynamic(smooth_sq_relin, smooth_sq_relin, scale);
    ckks_eva.rotate(smooth_sq_relin, smooth_sq_rot4, 4, galois_keys);
    ckks_eva.add(smooth_sq_relin, smooth_sq_rot4, branch_add);
    return branch_add;
}

Ciphertext diff_energy_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                              const GaloisKeys &galois_keys, double scale,
                              const Ciphertext &ct_c, const Ciphertext &ct_d)
{
    Ciphertext diff_cd;
    Ciphertext diff_rot2;
    Ciphertext diff_mix;
    Ciphertext diff_sq;
    Ciphertext diff_sq_relin;
    Ciphertext diff_sq_rot8;
    Ciphertext branch_quad;

    ckks_eva.sub(ct_c, ct_d, diff_cd);
    ckks_eva.rotate(diff_cd, diff_rot2, 2, galois_keys);
    ckks_eva.add(diff_cd, diff_rot2, diff_mix);
    ckks_eva.multiply(diff_mix, diff_mix, diff_sq);
    ckks_eva.relinearize(diff_sq, diff_sq_relin, relin_keys);
    ckks_eva.rescale_dynamic(diff_sq_relin, diff_sq_relin, scale);
    ckks_eva.rotate(diff_sq_relin, diff_sq_rot8, 8, galois_keys);
    ckks_eva.add(diff_sq_relin, diff_sq_rot8, branch_quad);
    return branch_quad;
}

Ciphertext cross_mix_branch(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                            const GaloisKeys &galois_keys, double scale,
                            const Ciphertext &ct_a, const Ciphertext &ct_b,
                            const Ciphertext &ct_c, const Ciphertext &ct_d)
{
    Ciphertext prod_ac;
    Ciphertext prod_ac_relin;
    Ciphertext prod_bd;
    Ciphertext prod_bd_relin;
    Ciphertext cross_sum;
    Ciphertext cross_rot8;
    Ciphertext cross_mix;
    Ciphertext cross_rot16;
    Ciphertext branch_cross;

    ckks_eva.multiply(ct_a, ct_c, prod_ac);
    ckks_eva.relinearize(prod_ac, prod_ac_relin, relin_keys);
    ckks_eva.rescale_dynamic(prod_ac_relin, prod_ac_relin, scale);
    ckks_eva.multiply(ct_b, ct_d, prod_bd);
    ckks_eva.relinearize(prod_bd, prod_bd_relin, relin_keys);
    ckks_eva.rescale_dynamic(prod_bd_relin, prod_bd_relin, scale);
    ckks_eva.add(prod_ac_relin, prod_bd_relin, cross_sum);
    ckks_eva.rotate(cross_sum, cross_rot8, 8, galois_keys);
    ckks_eva.add(cross_sum, cross_rot8, cross_mix);
    ckks_eva.rotate(cross_mix, cross_rot16, 16, galois_keys);
    ckks_eva.add(cross_mix, cross_rot16, branch_cross);
    return branch_cross;
}

void final_reduce(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                  const GaloisKeys &galois_keys, double scale, const Ciphertext &branch_add,
                  const Ciphertext &branch_quad, const Ciphertext &branch_cross, Ciphertext &result)
{
    Ciphertext merged_left;
    Ciphertext merged_all;
    Ciphertext tail_prod;
    Ciphertext tail_prod_relin;
    Ciphertext tail_rot32;

    ckks_eva.add(branch_add, branch_quad, merged_left);
    ckks_eva.add(merged_left, branch_cross, merged_all);
    ckks_eva.multiply(merged_all, branch_add, tail_prod);
    ckks_eva.relinearize(tail_prod, tail_prod_relin, relin_keys);
    ckks_eva.rescale_dynamic(tail_prod_relin, tail_prod_relin, scale);
    ckks_eva.rotate(tail_prod_relin, tail_rot32, 32, galois_keys);
    ckks_eva.add(tail_prod_relin, tail_rot32, result);
}

void ckks_single_thread_workload(EvaluatorCkksBase &ckks_eva, const RelinKeys &relin_keys,
                                 const GaloisKeys &galois_keys, double scale,
                                 const Ciphertext &ct_a, const Ciphertext &ct_b,
                                 const Ciphertext &ct_c, const Ciphertext &ct_d,
                                 Ciphertext &result)
{
    Ciphertext branch_add = smooth_square_branch(ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b);
    Ciphertext branch_quad = diff_energy_branch(ckks_eva, relin_keys, galois_keys, scale, ct_c, ct_d);
    Ciphertext branch_cross =
        cross_mix_branch(ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c, ct_d);
    final_reduce(ckks_eva, relin_keys, galois_keys, scale, branch_add, branch_quad, branch_cross,
                 result);
}

void ckks_manual_parallel_workload(EvaluatorCkksBase &ckks_eva, ThreadPool &thread_pool,
                                   const RelinKeys &relin_keys,
                                   const GaloisKeys &galois_keys, double scale,
                                   const Ciphertext &ct_a, const Ciphertext &ct_b,
                                   const Ciphertext &ct_c, const Ciphertext &ct_d,
                                   Ciphertext &result)
{
    Ciphertext branch_add;
    Ciphertext branch_quad;
    Ciphertext branch_cross;

    ParallelGroup parallel(thread_pool);
    parallel.go(
        [&]() { branch_add = smooth_square_branch(ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b); });
    parallel.go(
        [&]() { branch_quad = diff_energy_branch(ckks_eva, relin_keys, galois_keys, scale, ct_c, ct_d); });
    parallel.go([&]()
                {
                    branch_cross = cross_mix_branch(
                        ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c, ct_d);
                });
    parallel.wait();

    final_reduce(ckks_eva, relin_keys, galois_keys, scale, branch_add, branch_quad, branch_cross,
                 result);
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
    ParametersLiteralDefault ckks_param_literal(CKKS, 32768, poseidon::sec_level_type::tc128);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    const auto setup_stop = Clock::now();
    const auto setup_us = elapsed_us(setup_start, setup_stop);

    const auto keygen_start = Clock::now();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);
    const auto keygen_stop = Clock::now();
    const auto keygen_us = elapsed_us(keygen_start, keygen_stop);

    const auto runtime_setup_start = Clock::now();
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    const auto runtime_setup_stop = Clock::now();
    const auto runtime_setup_us = elapsed_us(runtime_setup_start, runtime_setup_stop);

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
    const auto message_prep_us = elapsed_us(message_prep_start, message_prep_stop);

    const auto reference_start = Clock::now();
    auto expected = build_reference(msg_a, msg_b, msg_c, msg_d);
    const auto reference_stop = Clock::now();
    const auto reference_us = elapsed_us(reference_start, reference_stop);

    Plaintext single_pt_a;
    Plaintext single_pt_b;
    Plaintext single_pt_c;
    Plaintext single_pt_d;
    const auto single_encode_start = Clock::now();
    encoder.encode(msg_a, scale, single_pt_a);
    encoder.encode(msg_b, scale, single_pt_b);
    encoder.encode(msg_c, scale, single_pt_c);
    encoder.encode(msg_d, scale, single_pt_d);
    const auto single_encode_stop = Clock::now();
    const auto single_encode_us = elapsed_us(single_encode_start, single_encode_stop);

    Ciphertext single_ct_a;
    Ciphertext single_ct_b;
    Ciphertext single_ct_c;
    Ciphertext single_ct_d;
    const auto single_encrypt_start = Clock::now();
    encryptor.encrypt(single_pt_a, single_ct_a);
    encryptor.encrypt(single_pt_b, single_ct_b);
    encryptor.encrypt(single_pt_c, single_ct_c);
    encryptor.encrypt(single_pt_d, single_ct_d);
    const auto single_encrypt_stop = Clock::now();
    const auto single_encrypt_us = elapsed_us(single_encrypt_start, single_encrypt_stop);

    Ciphertext single_result_cipher;
    const auto single_evaluation_start = Clock::now();
    ckks_single_thread_workload(*ckks_eva, relin_keys, galois_keys, scale, single_ct_a, single_ct_b,
                                single_ct_c, single_ct_d, single_result_cipher);
    ckks_eva->read(single_result_cipher);
    const auto single_evaluation_stop = Clock::now();
    const auto single_evaluation_us = elapsed_us(single_evaluation_start, single_evaluation_stop);

    const auto single_postprocess_start = Clock::now();
    auto single_result = decrypt_and_decode(single_result_cipher, decryptor, encoder);
    const auto single_postprocess_stop = Clock::now();
    const auto single_postprocess_us =
        elapsed_us(single_postprocess_start, single_postprocess_stop);

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
    const auto parallel_encode_us = elapsed_us(parallel_encode_start, parallel_encode_stop);

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
    const auto parallel_encrypt_us = elapsed_us(parallel_encrypt_start, parallel_encrypt_stop);

    const auto thread_pool_setup_start = Clock::now();
    ThreadPool thread_pool(kManualParallelism);
    const auto thread_pool_setup_stop = Clock::now();
    const auto thread_pool_setup_us =
        elapsed_us(thread_pool_setup_start, thread_pool_setup_stop);

    Ciphertext parallel_result_cipher;
    const auto parallel_evaluation_start = Clock::now();
    ckks_manual_parallel_workload(*ckks_eva, thread_pool, relin_keys, galois_keys, scale,
                                  parallel_ct_a, parallel_ct_b, parallel_ct_c, parallel_ct_d,
                                  parallel_result_cipher);
    ckks_eva->read(parallel_result_cipher);
    const auto parallel_evaluation_stop = Clock::now();
    const auto parallel_evaluation_us =
        elapsed_us(parallel_evaluation_start, parallel_evaluation_stop);

    const auto parallel_postprocess_start = Clock::now();
    auto parallel_result = decrypt_and_decode(parallel_result_cipher, decryptor, encoder);
    const auto parallel_postprocess_stop = Clock::now();
    const auto parallel_postprocess_us =
        elapsed_us(parallel_postprocess_start, parallel_postprocess_stop);

    const auto example_stop = Clock::now();

    const auto shared_setup_us =
        setup_us + keygen_us + runtime_setup_us + message_prep_us;
    const auto single_full_pipeline_us =
        shared_setup_us + single_encode_us + single_encrypt_us + single_evaluation_us +
        single_postprocess_us;
    const auto parallel_full_pipeline_us =
        shared_setup_us + parallel_encode_us + parallel_encrypt_us + thread_pool_setup_us +
        parallel_evaluation_us + parallel_postprocess_us;
    const auto example_total_us = elapsed_us(example_start, example_stop);

    std::cout << "CKKS setup TIME: " << setup_us << " microseconds" << std::endl;
    std::cout << "CKKS key generation TIME: " << keygen_us << " microseconds" << std::endl;
    std::cout << "CKKS runtime object setup TIME: " << runtime_setup_us << " microseconds"
              << std::endl;
    std::cout << "Message preparation TIME: " << message_prep_us << " microseconds" << std::endl;
    std::cout << "Plaintext reference TIME: " << reference_us << " microseconds" << std::endl;
    std::cout << "Single-thread encode TIME: " << single_encode_us << " microseconds"
              << std::endl;
    std::cout << "Single-thread encrypt TIME: " << single_encrypt_us << " microseconds"
              << std::endl;
    std::cout << "CKKS DAG single-thread evaluation TIME: " << single_evaluation_us
              << " microseconds" << std::endl;
    std::cout << "Single-thread decrypt/decode TIME: " << single_postprocess_us
              << " microseconds" << std::endl;
    std::cout << "Manual-parallel encode TIME: " << parallel_encode_us << " microseconds"
              << std::endl;
    std::cout << "Manual-parallel encrypt TIME: " << parallel_encrypt_us << " microseconds"
              << std::endl;
    std::cout << "Manual-parallel thread-pool setup TIME: " << thread_pool_setup_us
              << " microseconds" << std::endl;
    std::cout << "CKKS DAG manual-parallel evaluation TIME: " << parallel_evaluation_us
              << " microseconds" << std::endl;
    std::cout << "Manual-parallel decrypt/decode TIME: " << parallel_postprocess_us
              << " microseconds" << std::endl;
    std::cout << "Single-thread full pipeline TIME (shared setup included): "
              << single_full_pipeline_us << " microseconds" << std::endl;
    std::cout << "Manual-parallel full pipeline TIME (shared setup included): "
              << parallel_full_pipeline_us << " microseconds" << std::endl;
    std::cout << "Example total TIME (including reference build and both paths): "
              << example_total_us << " microseconds" << std::endl;
    std::cout << std::fixed << std::setprecision(2)
              << "Manual parallel evaluation speedup: "
              << static_cast<double>(single_evaluation_us) / parallel_evaluation_us << "x"
              << std::endl;
    std::cout << "Manual parallel full-pipeline speedup: "
              << static_cast<double>(single_full_pipeline_us) / parallel_full_pipeline_us << "x"
              << std::endl;

    print_head("Expected head:", expected);
    print_head("Single-thread result head:", single_result);
    print_head("Manual-parallel result head:", parallel_result);

    std::cout << "Single-thread vs expected:" << std::endl;
    GetPrecisionStats(single_result, expected);
    std::cout << "Manual-parallel vs expected:" << std::endl;
    GetPrecisionStats(parallel_result, expected);
    std::cout << "Manual-parallel vs single-thread:" << std::endl;
    GetPrecisionStats(parallel_result, single_result);

    return 0;
}
