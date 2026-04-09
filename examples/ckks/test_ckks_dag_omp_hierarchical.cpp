#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

namespace
{

constexpr int kOuterParallelism = 3;

using Clock = std::chrono::high_resolution_clock;

long long elapsed_us(const Clock::time_point &start, const Clock::time_point &stop)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
}

int read_positive_env(const char *name, int default_value)
{
    const char *value = std::getenv(name);
    if (!value)
    {
        return default_value;
    }

    char *end = nullptr;
    long parsed = std::strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed <= 0)
    {
        return default_value;
    }
    return static_cast<int>(parsed);
}

const char *env_or_unset(const char *name)
{
    const char *value = std::getenv(name);
    return value ? value : "(unset)";
}

#ifdef _OPENMP
int detect_inner_parallelism(int outer_threads)
{
    const int available_procs = std::max(1, omp_get_num_procs());
    return std::max(1, available_procs / std::max(1, outer_threads));
}

void configure_serial_openmp()
{
    omp_set_dynamic(0);
    omp_set_max_active_levels(1);
    omp_set_num_threads(1);
}

void print_omp_configuration(int outer_threads, int inner_threads)
{
    std::cout << "OpenMP hierarchical layout:" << std::endl;
    std::cout << "  outer branch teams: " << outer_threads << std::endl;
    std::cout << "  inner OMP threads per branch: " << inner_threads << std::endl;
    std::cout << "  available processors reported by OMP: " << omp_get_num_procs() << std::endl;
    std::cout << "  OMP_PLACES: " << env_or_unset("OMP_PLACES") << std::endl;
    std::cout << "  OMP_PROC_BIND: " << env_or_unset("OMP_PROC_BIND") << std::endl;
    std::cout << "  OMP_NUM_THREADS: " << env_or_unset("OMP_NUM_THREADS") << std::endl;
    std::cout << "Suggested run command:" << std::endl;
    std::cout << "  OMP_PLACES=cores OMP_PROC_BIND=spread,close "
              << "/home/guoshuai/github/poseidon/build/bin/test_ckks_dag_omp_hierarchical"
              << std::endl;
}
#else
int detect_inner_parallelism(int)
{
    return 1;
}

void configure_serial_openmp() {}

void print_omp_configuration(int outer_threads, int inner_threads)
{
    std::cout << "OpenMP support is disabled in this build; hierarchical mode falls back to serial."
              << std::endl;
    std::cout << "Requested outer threads: " << outer_threads << std::endl;
    std::cout << "Requested inner threads: " << inner_threads << std::endl;
}
#endif

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

void ckks_omp_hierarchical_workload(EvaluatorCkksBase &eva_add, EvaluatorCkksBase &eva_quad,
                                    EvaluatorCkksBase &eva_cross, EvaluatorCkksBase &eva_reduce,
                                    int outer_threads, int inner_threads,
                                    const RelinKeys &relin_keys,
                                    const GaloisKeys &galois_keys, double scale,
                                    const Ciphertext &ct_a, const Ciphertext &ct_b,
                                    const Ciphertext &ct_c, const Ciphertext &ct_d,
                                    Ciphertext &result)
{
    Ciphertext branch_add;
    Ciphertext branch_quad;
    Ciphertext branch_cross;

#ifdef _OPENMP
    omp_set_dynamic(0);
    omp_set_max_active_levels(2);

#pragma omp parallel sections num_threads(outer_threads)
    {
#pragma omp section
        {
            omp_set_num_threads(inner_threads);
            branch_add = smooth_square_branch(eva_add, relin_keys, galois_keys, scale, ct_a, ct_b);
        }

#pragma omp section
        {
            omp_set_num_threads(inner_threads);
            branch_quad = diff_energy_branch(eva_quad, relin_keys, galois_keys, scale, ct_c, ct_d);
        }

#pragma omp section
        {
            omp_set_num_threads(inner_threads);
            branch_cross =
                cross_mix_branch(eva_cross, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c, ct_d);
        }
    }
#else
    (void) outer_threads;
    (void) inner_threads;
    branch_add = smooth_square_branch(eva_add, relin_keys, galois_keys, scale, ct_a, ct_b);
    branch_quad = diff_energy_branch(eva_quad, relin_keys, galois_keys, scale, ct_c, ct_d);
    branch_cross = cross_mix_branch(eva_cross, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c, ct_d);
#endif

    final_reduce(eva_reduce, relin_keys, galois_keys, scale, branch_add, branch_quad, branch_cross,
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
    auto legacy_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    auto single_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    auto eva_add = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    auto eva_quad = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    auto eva_cross = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    auto eva_reduce = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    const auto runtime_setup_stop = Clock::now();
    const auto runtime_setup_us = elapsed_us(runtime_setup_start, runtime_setup_stop);

    const auto slot_num = ckks_param_literal.slot();
    const double scale = ckks_param_literal.scale();

    int outer_threads = read_positive_env("POSEIDON_OUTER_OMP_THREADS", kOuterParallelism);
    outer_threads = std::max(1, std::min(outer_threads, kOuterParallelism));
    int inner_threads = read_positive_env("POSEIDON_INNER_OMP_THREADS",
                                          detect_inner_parallelism(outer_threads));
    inner_threads = std::max(1, inner_threads);

    print_omp_configuration(outer_threads, inner_threads);

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

    Plaintext legacy_pt_a;
    Plaintext legacy_pt_b;
    Plaintext legacy_pt_c;
    Plaintext legacy_pt_d;
    const auto legacy_encode_start = Clock::now();
    encoder.encode(msg_a, scale, legacy_pt_a);
    encoder.encode(msg_b, scale, legacy_pt_b);
    encoder.encode(msg_c, scale, legacy_pt_c);
    encoder.encode(msg_d, scale, legacy_pt_d);
    const auto legacy_encode_stop = Clock::now();
    const auto legacy_encode_us = elapsed_us(legacy_encode_start, legacy_encode_stop);

    Ciphertext legacy_ct_a;
    Ciphertext legacy_ct_b;
    Ciphertext legacy_ct_c;
    Ciphertext legacy_ct_d;
    const auto legacy_encrypt_start = Clock::now();
    encryptor.encrypt(legacy_pt_a, legacy_ct_a);
    encryptor.encrypt(legacy_pt_b, legacy_ct_b);
    encryptor.encrypt(legacy_pt_c, legacy_ct_c);
    encryptor.encrypt(legacy_pt_d, legacy_ct_d);
    const auto legacy_encrypt_stop = Clock::now();
    const auto legacy_encrypt_us = elapsed_us(legacy_encrypt_start, legacy_encrypt_stop);

    Ciphertext legacy_result_cipher;
    const auto legacy_evaluation_start = Clock::now();
    ckks_single_thread_workload(*legacy_eva, relin_keys, galois_keys, scale, legacy_ct_a,
                                legacy_ct_b, legacy_ct_c, legacy_ct_d, legacy_result_cipher);
    legacy_eva->read(legacy_result_cipher);
    const auto legacy_evaluation_stop = Clock::now();
    const auto legacy_evaluation_us = elapsed_us(legacy_evaluation_start, legacy_evaluation_stop);

    const auto legacy_postprocess_start = Clock::now();
    auto legacy_result = decrypt_and_decode(legacy_result_cipher, decryptor, encoder);
    const auto legacy_postprocess_stop = Clock::now();
    const auto legacy_postprocess_us =
        elapsed_us(legacy_postprocess_start, legacy_postprocess_stop);

    configure_serial_openmp();

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
    ckks_single_thread_workload(*single_eva, relin_keys, galois_keys, scale, single_ct_a,
                                single_ct_b, single_ct_c, single_ct_d, single_result_cipher);
    single_eva->read(single_result_cipher);
    const auto single_evaluation_stop = Clock::now();
    const auto single_evaluation_us = elapsed_us(single_evaluation_start, single_evaluation_stop);

    const auto single_postprocess_start = Clock::now();
    auto single_result = decrypt_and_decode(single_result_cipher, decryptor, encoder);
    const auto single_postprocess_stop = Clock::now();
    const auto single_postprocess_us =
        elapsed_us(single_postprocess_start, single_postprocess_stop);

    Plaintext hierarchical_pt_a;
    Plaintext hierarchical_pt_b;
    Plaintext hierarchical_pt_c;
    Plaintext hierarchical_pt_d;
    const auto hierarchical_encode_start = Clock::now();
    encoder.encode(msg_a, scale, hierarchical_pt_a);
    encoder.encode(msg_b, scale, hierarchical_pt_b);
    encoder.encode(msg_c, scale, hierarchical_pt_c);
    encoder.encode(msg_d, scale, hierarchical_pt_d);
    const auto hierarchical_encode_stop = Clock::now();
    const auto hierarchical_encode_us =
        elapsed_us(hierarchical_encode_start, hierarchical_encode_stop);

    Ciphertext hierarchical_ct_a;
    Ciphertext hierarchical_ct_b;
    Ciphertext hierarchical_ct_c;
    Ciphertext hierarchical_ct_d;
    const auto hierarchical_encrypt_start = Clock::now();
    encryptor.encrypt(hierarchical_pt_a, hierarchical_ct_a);
    encryptor.encrypt(hierarchical_pt_b, hierarchical_ct_b);
    encryptor.encrypt(hierarchical_pt_c, hierarchical_ct_c);
    encryptor.encrypt(hierarchical_pt_d, hierarchical_ct_d);
    const auto hierarchical_encrypt_stop = Clock::now();
    const auto hierarchical_encrypt_us =
        elapsed_us(hierarchical_encrypt_start, hierarchical_encrypt_stop);

    Ciphertext hierarchical_result_cipher;
    const auto hierarchical_evaluation_start = Clock::now();
    ckks_omp_hierarchical_workload(*eva_add, *eva_quad, *eva_cross, *eva_reduce, outer_threads,
                                   inner_threads, relin_keys, galois_keys, scale, hierarchical_ct_a,
                                   hierarchical_ct_b, hierarchical_ct_c, hierarchical_ct_d,
                                   hierarchical_result_cipher);
    eva_reduce->read(hierarchical_result_cipher);
    const auto hierarchical_evaluation_stop = Clock::now();
    const auto hierarchical_evaluation_us =
        elapsed_us(hierarchical_evaluation_start, hierarchical_evaluation_stop);

    const auto hierarchical_postprocess_start = Clock::now();
    auto hierarchical_result = decrypt_and_decode(hierarchical_result_cipher, decryptor, encoder);
    const auto hierarchical_postprocess_stop = Clock::now();
    const auto hierarchical_postprocess_us =
        elapsed_us(hierarchical_postprocess_start, hierarchical_postprocess_stop);

    const auto example_stop = Clock::now();

    const auto shared_setup_us =
        setup_us + keygen_us + runtime_setup_us + message_prep_us;
    const auto legacy_full_pipeline_us =
        shared_setup_us + legacy_encode_us + legacy_encrypt_us + legacy_evaluation_us +
        legacy_postprocess_us;
    const auto single_full_pipeline_us =
        shared_setup_us + single_encode_us + single_encrypt_us + single_evaluation_us +
        single_postprocess_us;
    const auto hierarchical_full_pipeline_us =
        shared_setup_us + hierarchical_encode_us + hierarchical_encrypt_us +
        hierarchical_evaluation_us + hierarchical_postprocess_us;
    const auto example_total_us = elapsed_us(example_start, example_stop);

    std::cout << "CKKS setup TIME: " << setup_us << " microseconds" << std::endl;
    std::cout << "CKKS key generation TIME: " << keygen_us << " microseconds" << std::endl;
    std::cout << "CKKS runtime object setup TIME: " << runtime_setup_us << " microseconds"
              << std::endl;
    std::cout << "Message preparation TIME: " << message_prep_us << " microseconds" << std::endl;
    std::cout << "Plaintext reference TIME: " << reference_us << " microseconds" << std::endl;
    std::cout << "Legacy-compatible encode TIME: " << legacy_encode_us << " microseconds"
              << std::endl;
    std::cout << "Legacy-compatible encrypt TIME: " << legacy_encrypt_us << " microseconds"
              << std::endl;
    std::cout << "CKKS DAG legacy-compatible baseline TIME (outer-serial, inner-OMP enabled): "
              << legacy_evaluation_us << " microseconds" << std::endl;
    std::cout << "Legacy-compatible decrypt/decode TIME: " << legacy_postprocess_us
              << " microseconds" << std::endl;
    std::cout << "True-serial encode TIME: " << single_encode_us << " microseconds" << std::endl;
    std::cout << "True-serial encrypt TIME: " << single_encrypt_us << " microseconds"
              << std::endl;
    std::cout << "CKKS DAG serial evaluation TIME: " << single_evaluation_us << " microseconds"
              << std::endl;
    std::cout << "Serial decrypt/decode TIME: " << single_postprocess_us << " microseconds"
              << std::endl;
    std::cout << "OMP hierarchical encode TIME: " << hierarchical_encode_us << " microseconds"
              << std::endl;
    std::cout << "OMP hierarchical encrypt TIME: " << hierarchical_encrypt_us << " microseconds"
              << std::endl;
    std::cout << "CKKS DAG OMP hierarchical evaluation TIME: " << hierarchical_evaluation_us
              << " microseconds" << std::endl;
    std::cout << "OMP hierarchical decrypt/decode TIME: " << hierarchical_postprocess_us
              << " microseconds" << std::endl;
    std::cout << "Legacy-compatible full pipeline TIME (shared setup included): "
              << legacy_full_pipeline_us << " microseconds" << std::endl;
    std::cout << "Serial full pipeline TIME (shared setup included): " << single_full_pipeline_us
              << " microseconds" << std::endl;
    std::cout << "OMP hierarchical full pipeline TIME (shared setup included): "
              << hierarchical_full_pipeline_us << " microseconds" << std::endl;
    std::cout << "Example total TIME (including reference build): " << example_total_us
              << " microseconds" << std::endl;
    std::cout << std::fixed << std::setprecision(2)
              << "OMP hierarchical speedup vs legacy-compatible baseline: "
              << static_cast<double>(legacy_evaluation_us) / hierarchical_evaluation_us << "x"
              << std::endl;
    std::cout << "OMP hierarchical full-pipeline speedup vs legacy-compatible baseline: "
              << static_cast<double>(legacy_full_pipeline_us) / hierarchical_full_pipeline_us << "x"
              << std::endl;
    std::cout
              << "OMP hierarchical speedup vs true-serial baseline: "
              << static_cast<double>(single_evaluation_us) / hierarchical_evaluation_us << "x"
              << std::endl;
    std::cout
              << "OMP hierarchical full-pipeline speedup vs true-serial baseline: "
              << static_cast<double>(single_full_pipeline_us) / hierarchical_full_pipeline_us << "x"
              << std::endl;
    std::cout << std::fixed << std::setprecision(2)
              << "Legacy-compatible baseline vs true-serial baseline speedup: "
              << static_cast<double>(single_evaluation_us) / legacy_evaluation_us << "x"
              << std::endl;

    print_head("Expected head:", expected);
    print_head("Legacy-compatible baseline result head:", legacy_result);
    print_head("Serial result head:", single_result);
    print_head("OMP hierarchical result head:", hierarchical_result);

    std::cout << "Legacy-compatible baseline vs expected:" << std::endl;
    GetPrecisionStats(legacy_result, expected);
    std::cout << "Serial vs expected:" << std::endl;
    GetPrecisionStats(single_result, expected);
    std::cout << "OMP hierarchical vs expected:" << std::endl;
    GetPrecisionStats(hierarchical_result, expected);
    std::cout << "OMP hierarchical vs legacy-compatible baseline:" << std::endl;
    GetPrecisionStats(hierarchical_result, legacy_result);
    std::cout << "OMP hierarchical vs serial:" << std::endl;
    GetPrecisionStats(hierarchical_result, single_result);

    return 0;
}
