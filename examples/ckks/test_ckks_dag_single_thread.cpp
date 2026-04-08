#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <iostream>
#include <vector>

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

    Ciphertext merged_left;
    Ciphertext merged_all;
    Ciphertext tail_prod;
    Ciphertext tail_prod_relin;
    Ciphertext tail_rot32;

    // Merge tree followed by one more multiply tail to make the dependency chain deeper.
    ckks_eva.add(branch_add, branch_quad, merged_left);
    ckks_eva.add(merged_left, branch_cross, merged_all);
    ckks_eva.multiply(merged_all, branch_add, tail_prod);
    ckks_eva.relinearize(tail_prod, tail_prod_relin, relin_keys);
    ckks_eva.rescale_dynamic(tail_prod_relin, tail_prod_relin, scale);
    ckks_eva.rotate(tail_prod_relin, tail_rot32, 32, galois_keys);
    ckks_eva.add(tail_prod_relin, tail_rot32, result);
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

    Plaintext pt_a;
    Plaintext pt_b;
    Plaintext pt_c;
    Plaintext pt_d;
    Plaintext pt_result;
    const auto encode_start = Clock::now();
    encoder.encode(msg_a, scale, pt_a);
    encoder.encode(msg_b, scale, pt_b);
    encoder.encode(msg_c, scale, pt_c);
    encoder.encode(msg_d, scale, pt_d);
    const auto encode_stop = Clock::now();
    const auto encode_us = elapsed_us(encode_start, encode_stop);

    Ciphertext ct_a;
    Ciphertext ct_b;
    Ciphertext ct_c;
    Ciphertext ct_d;
    Ciphertext ct_result;
    const auto encrypt_start = Clock::now();
    encryptor.encrypt(pt_a, ct_a);
    encryptor.encrypt(pt_b, ct_b);
    encryptor.encrypt(pt_c, ct_c);
    encryptor.encrypt(pt_d, ct_d);
    const auto encrypt_stop = Clock::now();
    const auto encrypt_us = elapsed_us(encrypt_start, encrypt_stop);

    const auto reference_start = Clock::now();
    auto expected = build_reference(msg_a, msg_b, msg_c, msg_d);
    const auto reference_stop = Clock::now();
    const auto reference_us = elapsed_us(reference_start, reference_stop);

    const auto evaluation_start = Clock::now();
    ckks_single_thread_workload(*ckks_eva, relin_keys, galois_keys, scale, ct_a, ct_b, ct_c,
                                ct_d, ct_result);
    ckks_eva->read(ct_result);
    const auto evaluation_stop = Clock::now();
    const auto evaluation_us = elapsed_us(evaluation_start, evaluation_stop);

    std::vector<std::complex<double>> result;
    const auto postprocess_start = Clock::now();
    decryptor.decrypt(ct_result, pt_result);
    encoder.decode(pt_result, result);
    const auto postprocess_stop = Clock::now();
    const auto postprocess_us = elapsed_us(postprocess_start, postprocess_stop);

    const auto example_stop = Clock::now();
    const auto ckks_full_pipeline_us = setup_us + keygen_us + runtime_setup_us + message_prep_us +
                                       encode_us + encrypt_us + evaluation_us + postprocess_us;
    const auto example_total_us = elapsed_us(example_start, example_stop);

    std::cout << "CKKS setup TIME: " << setup_us << " microseconds" << std::endl;
    std::cout << "CKKS key generation TIME: " << keygen_us << " microseconds" << std::endl;
    std::cout << "CKKS runtime object setup TIME: " << runtime_setup_us << " microseconds"
              << std::endl;
    std::cout << "Message preparation TIME: " << message_prep_us << " microseconds" << std::endl;
    std::cout << "CKKS encode TIME: " << encode_us << " microseconds" << std::endl;
    std::cout << "CKKS encrypt TIME: " << encrypt_us << " microseconds" << std::endl;
    std::cout << "CKKS DAG single-thread evaluation TIME: " << evaluation_us << " microseconds"
              << std::endl;
    std::cout << "CKKS decrypt/decode TIME: " << postprocess_us << " microseconds" << std::endl;
    std::cout << "Plaintext reference TIME: " << reference_us << " microseconds" << std::endl;
    std::cout << "CKKS full pipeline TIME (setup -> decrypt/decode): " << ckks_full_pipeline_us
              << " microseconds" << std::endl;
    std::cout << "Example total TIME (including reference build): " << example_total_us
              << " microseconds" << std::endl;

    for (int i = 0; i < 4; ++i)
    {
        std::printf("expected[%d] : %.10lf + %.10lf I\n", i, expected[i].real(), expected[i].imag());
        std::printf("result[%d]   : %.10lf + %.10lf I\n", i, result[i].real(), result[i].imag());
    }
    GetPrecisionStats(expected, result);

    return 0;
}
