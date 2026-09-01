#include "evaluator_ckks_base.h"
#include "poseidon/advance/bootstrapper.h"
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/util/debug.h"
#include <algorithm>
#include <cmath>

#include "spdlog/spdlog.h"

#ifdef DEBUG
#include "poseidon/decryptor.h"
#endif

#include <cstdlib>
#include <iostream>
#include <limits>

namespace poseidon
{

namespace
{
int bit_len(uint n)
{
    int len = 0;
    while (n)
    {
        n = n >> 1;
        len++;
    }
    return len;
}

std::pair<int, int> split_degree(int n)
{
    int a, b;
    if ((n & (n-1)) == 0)
    {
        a = n/2;
        b = n/2;
    }
    else
    {
        int k = bit_len(n) - 1;
        a = (1 << k) - 1;
        b = n + 1 - (1 << k);
    }
    return {a, b};
}

bool scale_in_delta_lattigo(double scale0, double scale1, double log2_delta)
{
    // 对应 Lattigo core/rlwe/scale.go:135-148。
    // Scale.InDelta 判断的是相对误差的 -log2 是否达到阈值，不等价于
    // Poseidon util::is_approximate 的默认近似判断。
    auto diff = std::fabs(scale0 - scale1);
    auto scale_max = std::max(scale0, scale1);
    if (diff == 0)
    {
        return true;
    }
    if (scale_max <= 0)
    {
        return false;
    }
    return -std::log2(diff / scale_max) >= log2_delta;
}

}

#ifdef DEBUG
std::vector<std::complex<double>> EvaluatorCkksBase::decrypt_and_decode(const Ciphertext& ciph)
{
    std::vector<std::complex<double>> result;
    Plaintext plt_tmp;
    ptr_dec_->decrypt(ciph, plt_tmp);
    ptr_encoder_->decode(plt_tmp, result);
    return result;
}
#endif

EvaluatorCkksBase::EvaluatorCkksBase(const PoseidonContext &context)
    : min_scale_(std::pow(2.0, context.parameters_literal()->log_scale())), Base(context)
{
    if (context_.key_switch_variant() == BV)
    {
        kswitch_ = make_shared<KSwitchBV>(context);
    }
    else if (context_.key_switch_variant() == GHS)
    {
        kswitch_ = make_shared<KSwitchGHS>(context);
    }
    else if (context_.key_switch_variant() == HYBRID)
    {
        kswitch_ = make_shared<KSwitchHybrid>(context);
    }
}

void EvaluatorCkksBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                                     uint32_t level) const
{
    auto parms_id = context_.crt_context()->parms_id_map().at(level);
    drop_modulus(ciph, result, parms_id);
}

void EvaluatorCkksBase::drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const
{
    auto level = ciph.level();
    auto parms_id = context_.crt_context()->parms_id_map().at(level - 1);
    drop_modulus(ciph, result, parms_id);
}

void EvaluatorCkksBase::multiply_const_direct(const Ciphertext &ciph, int64_t const_data,
                                              Ciphertext &result, const CKKSEncoder &encoder) const
{
    Plaintext tmp;
    encoder.encode(const_data, ciph.parms_id(), tmp);
    multiply_plain(ciph, tmp, result);
}

void EvaluatorCkksBase::multiply_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                         Ciphertext &result) const
{
    auto level1 = ciph1.level();
    auto level2 = ciph2.level();
    if (level1 > level2)
    {
        Ciphertext tmp;
        if (&result == &ciph2)
        {
            drop_modulus(ciph1, tmp, ciph2.parms_id());
            multiply(ciph2, tmp, result);
        }
        else
        {
            drop_modulus(ciph1, result, ciph2.parms_id());
            multiply(result, ciph2, result);
        }
    }
    else if (level2 > level1)
    {
        Ciphertext tmp;
        if (&result == &ciph1)
        {
            drop_modulus(ciph2, tmp, ciph1.parms_id());
            multiply(ciph1, tmp, result);
        }
        else
        {
            drop_modulus(ciph2, result, ciph1.parms_id());
            multiply(ciph1, result, result);
        }
    }
    else
    {
        multiply(ciph1, ciph2, result);
    }
}

void EvaluatorCkksBase::multiply_by_diag_matrix_bsgs(const Ciphertext &ciph,
                                                     const MatrixPlain &plain_mat,
                                                     Ciphertext &result,
                                                     const GaloisKeys &rot_key) const
{
    auto [index, _, rotn2] =
        bsgs_index(plain_mat.plain_vec, 1 << plain_mat.log_slots, plain_mat.n1);
    map<int, Ciphertext> rot_ciph;
    Ciphertext ciph_inner_sum, ciph_inner, result_tmp;
    for (auto j : rotn2)
    {
        if (j != 0)
        {
            rotate(ciph, rot_ciph[j], j, rot_key);
        }
    }

    int cnt0 = 0;
    for (const auto &j : index)
    {
        int cnt1 = 0;
        for (auto i : index[j.first])
        {
            if (i == 0)
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(ciph, plain_mat.plain_vec.at(j.first), result_tmp);
                    }
                    else
                    {
                        multiply_plain(ciph, plain_mat.plain_vec.at(j.first), ciph_inner_sum);
                    }
                }
                else
                {
                    multiply_plain(ciph, plain_mat.plain_vec.at(j.first), ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result_tmp, ciph_inner, result_tmp);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            else
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first),
                                       result_tmp);
                    }
                    else
                    {
                        multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first),
                                       ciph_inner_sum);
                    }
                }
                else
                {

                    multiply_plain(rot_ciph[i], plain_mat.plain_vec.at(i + j.first), ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result_tmp, ciph_inner, result_tmp);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            cnt1++;
        }
        if (cnt0 != 0)
        {
            auto step_src = j.first;
            rotate(ciph_inner_sum, ciph_inner, j.first, rot_key);
            add(result_tmp, ciph_inner, result_tmp);
        }
        cnt0++;
    }
    rescale_dynamic(result_tmp, result, ciph.scale());
}

void EvaluatorCkksBase::multiply_by_diag_matrix_bsgs_with_mutex(
    const Ciphertext &ciph, MatrixPlain &plain_mat, Ciphertext &result, const GaloisKeys &rot_key,
    std::map<int, std::vector<int>> &ref1, std::vector<int> &ref2, std::vector<int> &ref3) const
{
    map<int, Ciphertext> rot_ciph;
    Ciphertext ciph_inner_sum, ciph_inner, result_tmp;
    for (auto j : ref3)
    {
        if (j != 0)
        {
            rotate(ciph, rot_ciph[j], j, rot_key);
        }
    }

    int cnt0 = 0;
    for (const auto &j : ref1)
    {
        {
            std::unique_lock<std::mutex> lck(plain_mat.mtx_pir);
            while (plain_mat.read_idx == plain_mat.write_idx)
            {
                plain_mat.cv_read.wait(lck);
            }
        }

        int cnt1 = 0;
        for (auto i : ref1[j.first])
        {
            if (i == 0)
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(ciph,
                                       plain_mat.plain_vec_pool[plain_mat.read_idx].at(j.first),
                                       result_tmp);
                    }
                    else
                    {
                        multiply_plain(ciph,
                                       plain_mat.plain_vec_pool[plain_mat.read_idx].at(j.first),
                                       ciph_inner_sum);
                    }
                }
                else
                {
                    multiply_plain(ciph, plain_mat.plain_vec_pool[plain_mat.read_idx].at(j.first),
                                   ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result_tmp, ciph_inner, result_tmp);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            else
            {
                if (cnt1 == 0)
                {
                    if (cnt0 == 0)
                    {
                        multiply_plain(rot_ciph[i],
                                       plain_mat.plain_vec_pool[plain_mat.read_idx].at(i + j.first),
                                       result_tmp);
                    }
                    else
                    {
                        multiply_plain(rot_ciph[i],
                                       plain_mat.plain_vec_pool[plain_mat.read_idx].at(i + j.first),
                                       ciph_inner_sum);
                    }
                }
                else
                {

                    multiply_plain(rot_ciph[i],
                                   plain_mat.plain_vec_pool[plain_mat.read_idx].at(i + j.first),
                                   ciph_inner);
                    if (cnt0 == 0)
                    {
                        add(result_tmp, ciph_inner, result_tmp);
                    }
                    else
                    {
                        add(ciph_inner_sum, ciph_inner, ciph_inner_sum);
                    }
                }
            }
            cnt1++;
        }
        if (cnt0 != 0)
        {
            auto step_src = j.first;
            rotate(ciph_inner_sum, ciph_inner, j.first, rot_key);
            add(result_tmp, ciph_inner, result_tmp);
        }
        cnt0++;

        {
            std::lock_guard<std::mutex> lck(plain_mat.mtx_pir);
            plain_mat.read_idx = (plain_mat.read_idx + 1) % MatrixPlain::sz;
            if (plain_mat.read_idx == (plain_mat.write_idx + 2) % MatrixPlain::sz)
            {
                plain_mat.cv_write.notify_one();
            }
        }
    }
    rescale_dynamic(result_tmp, result, ciph.scale());
}

void EvaluatorCkksBase::dft(const Ciphertext &ciph, const LinearMatrixGroup &matrix_group,
                            Ciphertext &result, const GaloisKeys &rot_key) const
{

    multiply_by_diag_matrix_bsgs(ciph, matrix_group.data()[0], result, rot_key);
    for (int i = 1; i < matrix_group.data().size(); i++)
    {
        multiply_by_diag_matrix_bsgs(result, matrix_group.data()[i], result, rot_key);
    }
}

void EvaluatorCkksBase::coeff_to_slot(const Ciphertext &ciph, const LinearMatrixGroup &matrix_group,
                                      Ciphertext &result_real, Ciphertext &result_imag,
                                      const GaloisKeys &galois_keys,
                                      const CKKSEncoder &encoder) const
{
    Ciphertext ciph_tmp;
    dft(ciph, matrix_group, ciph_tmp, galois_keys);
    conjugate(ciph_tmp, galois_keys, result_imag);
    add(ciph_tmp, result_imag, result_real);
    sub(ciph_tmp, result_imag, result_imag);
    complex<double> const_data(0, -1);

    auto context_data = context_.crt_context()->get_context_data(result_imag.parms_id());
    multiply_const(result_imag, const_data, 1.0, result_imag, encoder);
}

void EvaluatorCkksBase::slot_to_coeff(const Ciphertext &ciph_real, const Ciphertext &ciph_imag,
                                      const LinearMatrixGroup &matrix_group, Ciphertext &result,
                                      const GaloisKeys &galois_keys,
                                      const CKKSEncoder &encoder) const
{
    complex<double> const_data(0, 1);
    Ciphertext result_tmp;
    multiply_const(ciph_imag, const_data, 1.0, result_tmp, encoder);
    add(result_tmp, ciph_real, result);
    dft(result, matrix_group, result, galois_keys);
}

void EvaluatorCkksBase::evaluate_polynomial(const PolynomialVector& poly_vec, const Ciphertext& ct_basis, Ciphertext& ct_res,
    bool is_chev, bool is_lazy, double target_scale, double min_scale, const RelinKeys& relin_key, const CKKSEncoder& encoder)
{
    map<uint32_t, Ciphertext> power_basis;
    power_basis[1] = ct_basis;

    auto log_degree = bit_len(poly_vec[0].degree());
    auto log_split = optimal_split_optimized(log_degree);

    bool is_odd = false;
    bool is_even = false;
    for (auto i = 0; i < poly_vec.polys().size(); i++)
    {
        const auto& poly = poly_vec.polys()[i];
        is_odd = is_odd || poly.is_odd();
        is_even = is_even || poly.is_even();
    }

    gen_power_optimized(power_basis, 1 << (log_degree - 1), is_lazy, is_chev, min_scale, relin_key, encoder);

    for (auto i = (1 << log_split) - 1; i > 2; i--)
    {
        if (!(is_even || is_odd) || (((i&1) == 0) && is_even) || (((i&1) == 1) && is_odd))
        {
            gen_power_optimized(power_basis, i, is_lazy, is_chev, min_scale, relin_key, encoder);
        }
    }

    PatersonStockmeyerPolynomialVector ps_polys_vec;
    int input_level = ct_basis.level();
    double input_scale = ct_basis.scale();
    get_paterson_stockmeyer_polynomial_vector(poly_vec, input_level, input_scale, target_scale, ps_polys_vec);

    evaluate_paterson_stockmeyer_polynomial_vector(ps_polys_vec, power_basis, ct_res, relin_key, encoder);
}

void EvaluatorCkksBase::get_paterson_stockmeyer_polynomial(const Polynomial& poly, int input_level,
    double input_scale, double output_scale, PatersonStockmeyerPolynomial& ps_poly)
{
    auto log_degree = bit_len(poly.degree());
    auto log_split = optimal_split_optimized(log_degree);

    std::map<int, SimPower> power_basis_sim;
    power_basis_sim[1] = {input_level, input_scale};

    auto level_consumed_per_rescale = 1;
    gen_power_sim(power_basis_sim, 1 << log_degree, level_consumed_per_rescale);
    for (auto i = (1 << log_split) - 1; i > 2; i--)
    {
        gen_power_sim(power_basis_sim, i, level_consumed_per_rescale);
    }

    SimPower sim_op;
    std::vector<Polynomial> ps_res;
    // lattigo: inputLevel - eval.PolynomialDepth(degree), where PolynomialDepth(degree) =
    // levelsConsumedPerRescaling * (bits.Len64(degree) - 1) = lcpr * floor(log2(degree))
    recurse_ps(poly, log_split,
               input_level - level_consumed_per_rescale * (bit_len(poly.degree()) - 1),
               output_scale, power_basis_sim, ps_res, sim_op);

    ps_poly.degree_ = poly.degree();
    ps_poly.base_ = 1 << log_split;
    ps_poly.level_ = input_level;
    ps_poly.scale_ = output_scale;
    ps_poly.polys_ = ps_res;
}

void EvaluatorCkksBase::get_paterson_stockmeyer_polynomial_vector(const PolynomialVector& poly_vec,
    int input_level, double intput_scale, double output_scale, PatersonStockmeyerPolynomialVector& ps_poly_vec)
{
    ps_poly_vec.polys_.clear();
    ps_poly_vec.polys_.resize(poly_vec.size());

    for (auto i = 0; i < poly_vec.size(); ++i)
    {
        get_paterson_stockmeyer_polynomial(poly_vec[i], input_level, intput_scale, output_scale, ps_poly_vec.polys_[i]);
    }
}

void EvaluatorCkksBase::evaluate_paterson_stockmeyer_polynomial_vector(const PatersonStockmeyerPolynomialVector &ps_polys_vec,
    const map<uint32_t, Ciphertext> &power_basis, Ciphertext& ct_res, const RelinKeys& relin_key, const CKKSEncoder& encoder) /*const*/
{
    auto split = ps_polys_vec.polys_[0].polys_.size();

    std::vector<BabyStep> baby_steps(split);

    // baby steps: polynomial piece i is evaluated from the power basis into baby_steps[split-i-1]
    for (auto i = 0; i < baby_steps.size(); i++)
    {
        evaluate_baby_step(ps_polys_vec, power_basis, i, baby_steps[split - i - 1], encoder);
    }

    // giant steps: merge the baby steps pairwise until one remains
    while (baby_steps.size() != 1)
    {
        std::vector<int> giant_steps(baby_steps.size());
        for (auto i = 0; i < baby_steps.size(); i++)
        {
            if (i == baby_steps.size() - 1)
            {
                giant_steps[i] = 2;
            }
            else if (baby_steps[i].degree == baby_steps[i+1].degree)
            {
                giant_steps[i] = 1;
                ++i;
            }
        }

        for (auto i = 0; i < baby_steps.size(); i++)
        {
            evaluate_giant_step(i, giant_steps, baby_steps, power_basis, encoder, relin_key);
        }

        for (auto iter = baby_steps.begin(); iter != baby_steps.end();)
        {
            // TODO 使用is_valid()来判断baby_steps[i]已经被合并，是否可行？
            if (!iter->value.is_valid())
            {
                iter = baby_steps.erase(iter);
            }
            else
            {
                ++iter;
            }
        }
    }

    if (baby_steps[0].value.size() == 3)
    {
        relinearize(baby_steps[0].value, baby_steps[0].value, relin_key);
    }

    rescale(baby_steps[0].value, baby_steps[0].value);
    ct_res = baby_steps[0].value;
}

void EvaluatorCkksBase::evaluate_polynomial_vector_from_power_basis_optimized(const PolynomialVector &poly_vec,
    const map<uint32_t, Ciphertext> &power_basis, Ciphertext &ciph_res, int target_level, double target_scale, const CKKSEncoder &encoder) const
{
    auto is_even = poly_vec.is_even();
    auto is_odd = poly_vec.is_odd();

    auto minimum_degree_non_zero_coefficient = poly_vec.polys()[0].data().size() - 1;
    if (is_even && !is_odd)
    {
        minimum_degree_non_zero_coefficient--;
    }

    auto maximum_ciphertext_degree = 0;
    for (auto i = poly_vec.polys()[0].degree(); i > 0; i--)
    {
        if (power_basis.count(i))
        {
            maximum_ciphertext_degree = max(maximum_ciphertext_degree, (int)power_basis.at(i).size() - 1);
        }
    }

    if (poly_vec.index().size() > 0)
    {
        // TODO 暂时不存在通过slot来计算的情况，可暂时忽略该if分支
    }
    else
    {
        // Allocates a zero ciphertext at (target_level, target_scale) — note that X^0 is not
        // stored in the power basis, so the result must start from zero (see lattigo
        // EvaluatePolynomialVectorFromPowerBasis: rlwe.NewCiphertext).
        auto &parms_id = context_.crt_context()->parms_id_map().at(target_level);
        ciph_res.resize(context_, parms_id, 2);
        ciph_res.is_ntt_form() = true;
        ciph_res.scale() = target_scale;

        // Constant term c_0 (encoded at target scale; only even polynomials have one)
        if (is_even)
        {
            add_const(ciph_res, poly_vec[0][0], ciph_res, encoder);
        }

        if (minimum_degree_non_zero_coefficient == 0)
        {
            return;
        }

        // Loops from the highest degree coefficient down to 1.
        // Encodes c_k at scale target_scale / X^k.scale so that the product lands exactly on
        // target_scale (equivalent to lattigo MulThenAdd scalar path).
        for (auto key = poly_vec[0].degree(); key > 0; key--)
        {
            if ((key != 0) && ((!(is_even || is_odd)) || ((key & 1) == 0 && is_even) || ((key & 1) == 1 && is_odd)))
            {
                auto &x_key = power_basis.at(key);
                double scale_k = ciph_res.scale() / x_key.scale();
                if (util::is_approximate<double>(scale_k, 1.0))
                {
                    // lattigo MulThenAdd: when the accumulator and X^k share the same scale the
                    // quotient would be 1.0 and round(c_k * 1.0) would destroy the coefficient.
                    // Lift the accumulator by the prime at its level instead and encode c_k at
                    // that prime (value-preserving).
                    auto lift = context_.crt_context()
                                    ->get_context_data(ciph_res.parms_id())
                                    ->coeff_modulus()[ciph_res.level()]
                                    .value();
                    multiply_const_direct(ciph_res, safe_cast<int64_t>(lift), ciph_res, encoder);
                    ciph_res.scale() *= lift;
                    scale_k = lift;
                }
                Plaintext plain_tmp;
                encoder.encode(poly_vec[0][key], x_key.parms_id(), scale_k, plain_tmp);
                Ciphertext ciph_tmp;
                multiply_plain(x_key, plain_tmp, ciph_tmp);
                add_dynamic(ciph_res, ciph_tmp, ciph_res, encoder);
            }
        }
    }
}

void EvaluatorCkksBase::evaluate_monomial(const Ciphertext& a, Ciphertext& b, const Ciphertext& xpow,
    const CKKSEncoder& encoder, const RelinKeys& relin_key) const
{
    if (b.size() == 3)
    {
        relinearize(b, b, relin_key);
    }
    rescale(b, b);
    multiply_relin_dynamic(b, xpow, b, relin_key);

    add_dynamic(a, b, b, encoder);
}

void EvaluatorCkksBase::evaluate_baby_step(const PatersonStockmeyerPolynomialVector &ps_poly_vec,
                                            const map<uint32_t, Ciphertext> &power_basis,
                                            int j, BabyStep& baby_step, const CKKSEncoder &encoder) /*const*/
{
    auto num_poly = ps_poly_vec.size();

    PolynomialVector poly_vec_tmp;
    poly_vec_tmp.resize(num_poly);
    // PatersonStockmeyerPolynomialVector可能有多组PatersonStockmeyerPolynomial
    // 只选取PatersonStockmeyerPolynomialVector[][j]
    for (auto i = 0; i < num_poly; i++)
    {
        poly_vec_tmp[i] = ps_poly_vec[i][j];
    }

    // TODO level & scale 这样取值是否准确
    auto level = ps_poly_vec[0][j].level();
    auto scale = ps_poly_vec[0][j].scale();

    baby_step.degree = ps_poly_vec[0][j].degree();
    evaluate_polynomial_vector_from_power_basis_optimized(poly_vec_tmp, power_basis, baby_step.value, level, scale, encoder);
}

void EvaluatorCkksBase::evaluate_giant_step(int i, const vector<int> &giant_steps, vector<BabyStep> &baby_steps,
    const map<uint32_t, Ciphertext> &power_basis, const CKKSEncoder& encoder, const RelinKeys &relin_keys) const
{
    // giant_step
    // = 0: no operation
    // = 1: merge
    // = 2: last element, do not merge, rescale to the same degree
    if (giant_steps[i] == 2)
    {
        baby_steps[i].degree = baby_steps[i - 1].degree;
    }
    else if (giant_steps[i] == 1)
    {
        BabyStep &even = baby_steps[i];
        BabyStep &odd = baby_steps[i + 1];

        int deg = 1 << bit_len(baby_steps[i].degree);

        evaluate_monomial(even.value, odd.value, power_basis.at(deg), encoder, relin_keys);

        odd.degree = 2 * deg - 1;
        // TODO even reset to invalid value
        even = BabyStep{};
    }
}

void EvaluatorCkksBase::update_level_and_scale_baby_step(bool lead, int level_old,
    double scale_old, int& level_new, double& scale_new, int level_consumed_per_rescale)
{
    level_new = level_old;
    scale_new = scale_old;

    if (lead)
    {
        for (auto i = 0; i < level_consumed_per_rescale; i++)
        {
            scale_new = scale_new * context_.parameters_literal()->q().at(level_new - i).value();
        }
    }
}

void EvaluatorCkksBase::update_level_and_scale_giant_step(bool lead, int level_old, double scale_old,
    double x_pow_scale, int& level_new, double& scale_new, int level_consumed_per_rescale)
{
    auto q = context_.parameters_literal()->q();

    uint128_t qi;
    if (lead)
    {
        qi = q.at(level_old).value();
        for (auto i = 1; i < level_consumed_per_rescale; ++i)
        {
            qi = qi * q[level_old-i].value();
        }
    }
    else
    {
        qi = q.at(level_old + level_consumed_per_rescale).value();
        for (auto i = 1; i < level_consumed_per_rescale; ++i)
        {
            qi = qi * q[level_old+level_consumed_per_rescale-i].value();
        }
    }

    level_new = level_old + level_consumed_per_rescale;
    scale_new = scale_old * qi / x_pow_scale;
}

void EvaluatorCkksBase::factorize(const Polynomial& poly, int n, Polynomial& pq, Polynomial& pr)
{
    factorize_inner(poly, n, pq, pr);
    pq.max_degree() = poly.max_degree();

    if (poly.max_degree() == poly.degree())
    {
        pr.max_degree() = n - 1;
    }
    else
    {
        pr.max_degree() = poly.max_degree() - (poly.degree() - n + 1);
    }

    if (poly.lead())
    {
        pq.lead() = true;
    }
}

void EvaluatorCkksBase::factorize_inner(const Polynomial& poly, int n, Polynomial& pq, Polynomial& pr)
{
    if (n < (poly.degree() >> 1))
    {
        POSEIDON_THROW_LOGIC_ERROR("error");
    }

    pr.data().resize(n);
    for (auto i = 0; i < n; ++i)
    {
        if (poly.is_valid(i))
        {
            pr.data()[i] = poly.data()[i];
        }
        else
        {
            pr.is_valid(i) = false;
        }
    }

    pq.data().resize(poly.degree()-n+1);
    if (poly.is_valid(n))
    {
        pq.data()[0] = poly.data()[n];
    }

    bool is_odd = poly.is_odd();
    bool is_even = poly.is_even();

    switch (poly.basis_type())
    {
    case Monomial:
        for (auto i = n + 1; i < poly.degree()+1; i++)
        {
            if (poly.is_valid(i) && (!(is_even || is_odd) || (((i&1) == 0) && is_even) || (((i&1) == 1) && is_odd)))
            {
                pq.data()[i-n] = poly.data()[i];
            }
        }
        break;
    case Chebyshev:
        for (int i = n + 1, j = 1; i < poly.degree() + 1; i++, j++)
        {
            if (poly.is_valid(i) && (!(is_even || is_odd) || (((i&1) == 0) && is_even) || (((i&1) == 1) && is_odd)))
            {
                pq.data()[i-n] = poly.data()[i];
                pq.data()[i-n] = pq.data()[i-n] + pq.data()[i-n];
                if (pr.is_valid(n-j))
                {
                    pr.data()[n-j] = pr.data()[n-j] - poly.data()[i];
                }
                else
                {
                    pr.data()[n-j] = poly.data()[i];
                    pr.data()[n-j].real(-pr.data()[n-j].real());
                    pr.data()[n-j].imag(-pr.data()[n-j].imag());
                }
            }
        }
        break;
    default:
        break;
    }

    pq.basis_type() = poly.basis_type();
    pr.basis_type() = poly.basis_type();
    pq.is_odd() = poly.is_odd();
    pr.is_odd() = poly.is_odd();
    pq.is_even() = poly.is_even();
    pr.is_even() = poly.is_even();
    pq.a() = poly.a();
    pq.b() = poly.b();
    pr.a() = poly.a();
    pr.b() = poly.b();
}

void EvaluatorCkksBase::recurse_ps(Polynomial poly, int log_split, int target_level,
    double output_scale, std::map<int, SimPower> pb, std::vector<Polynomial>& poly_vec_res, SimPower& op_res)
{
    if (poly.degree() < (1 << log_split))
    {
        if (poly.lead() && log_split > 1 && poly.max_degree() > (1 << bit_len(poly.max_degree())) - (1 << (log_split - 1)))
        {
            auto log_degree = bit_len(poly.degree());
            log_split = optimal_split(log_degree);
            recurse_ps(poly, log_split, target_level, output_scale, pb, poly_vec_res, op_res);
            return;
        }

        update_level_and_scale_baby_step(poly.lead(), target_level, output_scale, poly.level(), poly.scale());
        poly_vec_res.push_back(poly);
        op_res.level_ = poly.level();
        op_res.scale_ = poly.scale();
        return;
    }

    auto next_power = 1 << log_split;
    while (next_power < (poly.degree() >> 1) + 1)
    {
        next_power <<= 1;
    }

    auto x_pow = pb[next_power];

    Polynomial coeffsq, coeffsr;
    factorize(poly, next_power, coeffsq, coeffsr);

    int level_new;
    double scale_new;
    update_level_and_scale_giant_step(poly.lead(), target_level, output_scale, x_pow.scale_, level_new, scale_new);

    SimPower op_res_recurse_sq{};
    SimPower op_res_recurse_sr{};
    std::vector<Polynomial> poly_vec_res_recurse_sq, poly_vec_res_recurse_sr;
    recurse_ps(coeffsq, log_split, level_new, scale_new, pb, poly_vec_res_recurse_sq, op_res_recurse_sq);

    // rescale simulation
    {
        auto level_consumed_per_rescale = 1;
        for (auto i = 0; i < level_consumed_per_rescale; i++)
        {
            op_res_recurse_sq.scale_ = op_res_recurse_sq.scale_ / context_.parameters_literal()->q()[op_res_recurse_sq.level_].value();
            op_res_recurse_sq.level_--;
        }
    }
    // multiply simulation
    {
        op_res_recurse_sq.level_ = op_res_recurse_sq.level_ < x_pow.level_ ? op_res_recurse_sq.level_ : x_pow.level_;
        op_res_recurse_sq.scale_ = op_res_recurse_sq.scale_ * x_pow.scale_;
    }

    recurse_ps(coeffsr, log_split, target_level, op_res_recurse_sq.scale_, pb, poly_vec_res_recurse_sr, op_res_recurse_sr);

    // Lattigo uses InDelta(ScalePrecision-12) on exact big.Float scales (delta is literally 0
    // unless the decomposition is wrong). Poseidon tracks scales in double, so the invariant
    // only holds up to accumulated floating point rounding (~2^-46 relative per operation).
    // A 30-bit tolerance still separates real decomposition errors (~q_i, i.e. ~2^40) from
    // double rounding noise.
    if (!scale_in_delta_lattigo(op_res_recurse_sr.scale_, op_res_recurse_sq.scale_, 30.0))
    {
        POSEIDON_THROW(invalid_argument_error, "recursePS: res.Scale != tmp.Scale");
    }

    poly_vec_res.insert(poly_vec_res.end(), poly_vec_res_recurse_sq.begin(), poly_vec_res_recurse_sq.end());
    poly_vec_res.insert(poly_vec_res.end(), poly_vec_res_recurse_sr.begin(), poly_vec_res_recurse_sr.end());
    op_res = op_res_recurse_sq;
}

void EvaluatorCkksBase::gen_power_sim(std::map<int, SimPower> &power_basis_sim, int n, int level_consumed_per_rescale)
{
    if (n < 2)
    {
        return;
    }

    auto [a, b] = split_degree(n);
    gen_power_sim(power_basis_sim, a, level_consumed_per_rescale);
    gen_power_sim(power_basis_sim, b, level_consumed_per_rescale);

    // multiplication simulation
    power_basis_sim[n].level_ =
        (power_basis_sim[a].level_ < power_basis_sim[b].level_) ? power_basis_sim[a].level_ : power_basis_sim[b].level_;
    power_basis_sim[n].scale_ = power_basis_sim[a].scale_ * power_basis_sim[b].scale_;
    // rescale simulation
    for (auto i = 0; i < level_consumed_per_rescale; i++)
    {
        power_basis_sim[n].scale_ = power_basis_sim[n].scale_ / context_.parameters_literal()->q()[power_basis_sim[n].level_].value();
        power_basis_sim[n].level_--;
    }
}

void EvaluatorCkksBase::gen_power_optimized(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n,
                                            bool lazy, bool is_chev, double min_scale,
                                            const RelinKeys &relin_keys,
                                            const CKKSEncoder &encoder) const
{
    if (!monomial_basis[n].is_valid())
    {
        bool need_rescale =
            gen_power_optimized_inner(monomial_basis, n, lazy, is_chev, min_scale, relin_keys, encoder);
        if (need_rescale)
        {
            rescale_dynamic(monomial_basis[n], monomial_basis[n], min_scale);
        }
    }
}

bool EvaluatorCkksBase::gen_power_optimized_inner(
    map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy, bool is_chev, double min_scale,
    const RelinKeys &relin_keys, const CKKSEncoder &encoder) const
{
    if (monomial_basis[n].is_valid())
    {
        return false;
    }

    bool is_pow2 = ((n & (n - 1)) == 0);
    auto [a, b] = split_degree(n);

    bool need_rescale_a =
        gen_power_optimized_inner(monomial_basis, a, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                                  encoder);
    bool need_rescale_b =
        gen_power_optimized_inner(monomial_basis, b, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                                  encoder);

    if (lazy)
    {
        if (monomial_basis[a].size() > 2)
        {
            relinearize(monomial_basis[a], monomial_basis[a], relin_keys);
        }
        if (monomial_basis[b].size() > 2)
        {
            relinearize(monomial_basis[b], monomial_basis[b], relin_keys);
        }

        if (need_rescale_a)
        {
            rescale_dynamic(monomial_basis[a], monomial_basis[a], min_scale);
        }
        if (need_rescale_b)
        {
            rescale_dynamic(monomial_basis[b], monomial_basis[b], min_scale);
        }

        multiply_relin(monomial_basis[a], monomial_basis[b], monomial_basis[n], relin_keys);
    }
    else
    {
        if (need_rescale_a)
        {
            rescale_dynamic(monomial_basis[a], monomial_basis[a], min_scale);
        }
        if (need_rescale_b)
        {
            rescale_dynamic(monomial_basis[b], monomial_basis[b], min_scale);
        }

        multiply_relin_dynamic(monomial_basis[a], monomial_basis[b], monomial_basis[n], relin_keys);
    }

    if (is_chev)
    {
        int c = std::abs(a - b);

        add(monomial_basis[n], monomial_basis[n], monomial_basis[n]);

        if (c == 0)
        {
            add_const(monomial_basis[n], -1.0, monomial_basis[n], encoder);
        }
        else
        {
            gen_power_optimized(monomial_basis, c, false, is_chev, min_scale, relin_keys, encoder);

            sub_dynamic(monomial_basis[n], monomial_basis[c], monomial_basis[n], encoder);
        }
    }

    return true;
}

void EvaluatorCkksBase::eval_mod(const Ciphertext &ciph, Ciphertext &result,
                                 const EvalModPoly &eva_poly, const RelinKeys &relin_keys,
                                 const CKKSEncoder &encoder)
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "eval_mod : ciph is empty!");
    }

    if (ciph.level() != eva_poly.level_start())
    {
        POSEIDON_THROW(invalid_argument_error, "eval_mod : level start not match!");
    }
    result = ciph;

    auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto poly_modulus_degree = context_data->parms().degree();
    auto slot_num = poly_modulus_degree >> 1;
    auto &coeff_modulus = context_data->coeff_modulus();

    double prev_scale_ct = result.scale();

    // NOTE (mirrors lattigo Mod1Evaluator.EvaluateNew): setting the scale to the scaling factor
    // is not a metadata fix-up, it is a deliberate change of unit. The ciphertext comes out of
    // CoeffsToSlots at q0/message_ratio; reinterpreting the same raw polynomial at
    // eva_poly.scaling_factor() divides the slot values by message_ratio, which brings them from
    // the ~q0/ratio magnitude into the [-k, k] Chebyshev interpolation interval.
    result.scale() = eva_poly.scaling_factor();

    double pre_min_scale = min_scale_;
    set_min_scale(eva_poly.scaling_factor());
    auto target_scale = eva_poly.scaling_factor();
    vector<Polynomial> poly_sin{eva_poly.sine_poly()};
    vector<Polynomial> poly_asin{eva_poly.arcsine_poly()};

    vector<int> idx(slot_num);
    for (int i = 0; i < slot_num; i++)
    {
        idx[i] = i;  // Index with all even slots
    }
    vector<vector<int>> slots_index(1, vector<int>(slot_num, 0));
    slots_index[0] = idx;  // Assigns index of all even slots to poly[0] = f(x)

    if (eva_poly.type() == CosDiscrete || eva_poly.type() == CosContinuous)
    {
        double const_data =
            -0.5 / (eva_poly.sc_fac() * (eva_poly.sine_poly_b() - eva_poly.sine_poly_a()));
        add_const(result, const_data, result, encoder);
    }

    PolynomialVector polys_sin(poly_sin, slots_index);
    Ciphertext tmp = result;

    spdlog::debug("before evaluate_polynomial level = {}", tmp.level());
    evaluate_polynomial(polys_sin, tmp, result,
        polys_sin.polys()[0].basis_type() == Chebyshev, false, target_scale,
        min_scale_, relin_keys, encoder);
    spdlog::debug("after evaluate_polynomial level = {}", result.level());

    // Double angle
    auto sqrt2pi = eva_poly.sqrt_2pi();
    for (auto i = 0; i < eva_poly.double_angle(); i++)
    {
        sqrt2pi *= sqrt2pi;
        multiply_relin_dynamic(result, result, result, relin_keys);
        add(result, result, result);
        add_const(result, -sqrt2pi, result, encoder);
        rescale_dynamic(result, result, target_scale);
    }

    if (!util::is_approximate(result.scale(), eva_poly.scaling_factor()))
    {
        double diff_scale = eva_poly.scaling_factor() / result.scale();
        if (diff_scale < coeff_modulus.back().value())
        {
            diff_scale *= coeff_modulus[result.level()].value();
            diff_scale *= coeff_modulus[result.level() - 1].value();
        }
        multiply_const(result, 1.0, diff_scale, result, encoder);
        rescale_dynamic(result, result, eva_poly.scaling_factor());
    }

    result.scale() = prev_scale_ct;

    set_min_scale(pre_min_scale);
}

void EvaluatorCkksBase::eval_mod_high_precision(const Ciphertext &ciph, Ciphertext &result,
                                                const EvalModPoly &eva_poly,
                                                const RelinKeys &relin_keys,
                                                const CKKSEncoder &encoder)
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "eval_mod_high_precision : ciph is empty!");
    }

    if (ciph.level() != eva_poly.level_start())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "eval_mod_high_precision : level start not match!");
    }
    result = ciph;

    auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto poly_modulus_degree = context_data->parms().degree();
    auto slot_num = poly_modulus_degree >> 1;

    double prev_scale_ct = result.scale();
    result.scale() = eva_poly.scaling_factor();

    double pre_min_scale = min_scale_;
    set_min_scale(eva_poly.scaling_factor());
    auto target_scale = eva_poly.scaling_factor();
    vector<Polynomial> poly_sin{eva_poly.sine_poly()};

    vector<int> idx(slot_num);
    for (int i = 0; i < slot_num; i++)
    {
        idx[i] = i;
    }
    vector<vector<int>> slots_index(1, vector<int>(slot_num, 0));
    slots_index[0] = idx;

    if (eva_poly.type() == CosDiscrete || eva_poly.type() == CosContinuous)
    {
        double const_data =
            -0.5 / (eva_poly.sc_fac() * (eva_poly.sine_poly_b() - eva_poly.sine_poly_a()));
        add_const(result, const_data, result, encoder);
    }

    PolynomialVector polys_sin(poly_sin, slots_index);
    Ciphertext tmp = result;
    // TODO is_chev, is_lazy noknown
    evaluate_polynomial(polys_sin, tmp, result, true, false, target_scale, min_scale_, relin_keys, encoder);

    auto sqrt2pi = eva_poly.sqrt_2pi();
    for (auto i = 0; i < eva_poly.double_angle(); i++)
    {
        sqrt2pi *= sqrt2pi;
        multiply_relin_dynamic(result, result, result, relin_keys);
        add(result, result, result);
        add_const(result, -sqrt2pi, result, encoder);
        rescale_dynamic(result, result, target_scale);
    }

    result.scale() = prev_scale_ct;
    set_min_scale(pre_min_scale);
}

void EvaluatorCkksBase::rescale_for_bootstrap(Ciphertext &ciph)
{
    auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto &modulus = context_data->coeff_modulus();
    auto new_level = modulus.size() - 1;
    while (ciph.scale() > pow(2, 54))
    {
        if (ciph.scale() / safe_cast<double>(modulus[new_level].value()) > 1.6e+07)
        {
            rescale(ciph, ciph);
            new_level--;
        }
        else
        {
            POSEIDON_THROW(invalid_argument_error,
                           "rescale_for_bootstrap: this cipher's scale can't bootstrap.");
        }
    }
}

void EvaluatorCkksBase::bootstrap(const Ciphertext &ciph, Ciphertext &result,
                                  const RelinKeys &relin_keys, const GaloisKeys &galois_keys,
                                  const CKKSEncoder &encoder, EvalModPoly &eval_mod_poly)
{
    bootstrap_core(ciph, result, relin_keys, galois_keys, encoder, eval_mod_poly, false);
}

void EvaluatorCkksBase::bootstrap(const Ciphertext &ciph, Ciphertext &result,
                                  const RelinKeys &relin_keys,
                                  const GaloisKeys &galois_keys,
                                  const CKKSEncoder &encoder,
                                  const BootstrapConfig &config)
{
    const bool trace_bootstrap = std::getenv("POSEIDON_BOOTSTRAP_TRACE") != nullptr;
    auto trace_state = [&](const char *label, const Ciphertext &cipher) {
        if (trace_bootstrap)
        {
            std::cerr << "[bootstrap trace] " << label << ": level=" << cipher.level()
                      << ", log2(scale)=" << std::log2(cipher.scale()) << '\n';
        }
    };
    if (config.boundary_k == 0)
    {
        throw invalid_argument("bootstrap boundary_k must be positive");
    }
    if (config.log_message_ratio >= 31)
    {
        throw invalid_argument("bootstrap log_message_ratio must be less than 31");
    }
    if (config.double_angle >= 31)
    {
        throw invalid_argument("bootstrap double_angle must be less than 31");
    }
    if (config.scaling_log >= 63)
    {
        throw invalid_argument("bootstrap scaling_log must be less than 63");
    }
    if (config.output_scaling_log >= 63)
    {
        throw invalid_argument("bootstrap output_scaling_log must be less than 63");
    }
    if (config.output_ratio == 0 ||
        (config.project_real && (config.output_ratio & 1U) != 0))
    {
        throw invalid_argument(
            "bootstrap output_ratio must be positive and even for real projection");
    }
    if (config.output_ratio >
        static_cast<uint32_t>(std::numeric_limits<int>::max()))
    {
        throw invalid_argument("bootstrap output_ratio exceeds the supported range");
    }
    if (!std::isfinite(config.inverse_coeff) || config.inverse_coeff < 0.0)
    {
        throw invalid_argument(
            "bootstrap inverse_coeff must be zero or a finite positive value");
    }
    if (ciph.size() != 2)
    {
        throw invalid_argument("bootstrap supports size-2 ciphertexts only");
    }

    Ciphertext prepared = ciph;
    auto input_context_data = context_.crt_context()->get_context_data(prepared.parms_id());
    if (!input_context_data)
    {
        throw invalid_argument("bootstrap input has invalid parms_id");
    }
    if (!std::isfinite(prepared.scale()) || prepared.scale() <= 0.0)
    {
        throw invalid_argument("bootstrap input scale must be finite and positive");
    }

    const auto q0_level = input_context_data->parms().q0_level();
    if (prepared.level() < q0_level)
    {
        throw invalid_argument("bootstrap input is below q0 level");
    }
    if (prepared.level() - q0_level > 1)
    {
        drop_modulus(prepared, prepared,
                     context_.crt_context()->parms_id_map().at(q0_level + 1));
    }

    const double message_ratio =
        std::ldexp(1.0, static_cast<int>(config.log_message_ratio));
    double q0_over_message_ratio = context_.crt_context()->q0() / message_ratio;
    q0_over_message_ratio = std::exp2(std::round(std::log2(q0_over_message_ratio)));
    if (!std::isfinite(q0_over_message_ratio) || q0_over_message_ratio <= 0.0)
    {
        throw invalid_argument("bootstrap target input scale is invalid");
    }
    if (prepared.scale() > q0_over_message_ratio &&
        !util::is_approximate<double>(prepared.scale(), q0_over_message_ratio))
    {
        throw invalid_argument("bootstrap input scale exceeds the supported target scale");
    }

    double remaining_scale = std::round(q0_over_message_ratio / prepared.scale());
    while (remaining_scale > 1.0)
    {
        double factor = std::min(remaining_scale, static_cast<double>(1ULL << 30));
        factor = std::round(factor);
        multiply_const_direct(prepared, static_cast<int>(factor), prepared, encoder);
        prepared.scale() *= factor;
        remaining_scale = std::round(remaining_scale / factor);
    }
    if (!util::is_approximate<double>(prepared.scale(), q0_over_message_ratio))
    {
        throw invalid_argument(
            "bootstrap input scale cannot be aligned to the supported target scale");
    }

    drop_modulus(prepared, prepared,
                 context_.crt_context()->parms_id_map().at(q0_level));
    trace_state("prepared", prepared);

    double slot_to_coeff_final_scale = context_.parameters_literal()->scale();
    if (config.output_scaling_log != 0)
    {
        const double requested_output_scale =
            std::ldexp(1.0, static_cast<int>(config.output_scaling_log));
        slot_to_coeff_final_scale = requested_output_scale * ciph.scale() /
                                    static_cast<double>(context_.crt_context()->q0());
    }
    if (!std::isfinite(slot_to_coeff_final_scale) || slot_to_coeff_final_scale <= 0.0)
    {
        throw invalid_argument("bootstrap output scale produces an invalid SlotToCoeff scale");
    }

    Bootstrapper bootstrapper(
        context_, *this, encoder, context_.parameters_literal()->log_slots(),
        config.boundary_k, ciph.scale(), slot_to_coeff_final_scale,
        config.cosine_heap_path);
    bootstrapper.generate_linear_coefficients();

    Ciphertext raised;
    bootstrapper.mod_raise(prepared, raised);
    const auto first_context_data = context_.crt_context()->first_context_data();
    raised.scale() =
        static_cast<double>(first_context_data->coeff_modulus().front().value());
    trace_state("mod_raise", raised);

    const double eval_mod_scale =
        std::ldexp(1.0, static_cast<int>(config.scaling_log));
    const double raise_factor = eval_mod_scale / (raised.scale() * message_ratio);
    if (raise_factor > 1.0 && raise_factor < static_cast<double>(0x7FFFFFFF))
    {
        const auto integer_factor = static_cast<int>(std::round(raise_factor));
        multiply_const_direct(raised, integer_factor, raised, encoder);
        raised.scale() *= integer_factor;
    }
    else if (raise_factor >= static_cast<double>(0x7FFFFFFF))
    {
        multiply_const(raised, 1.0, raise_factor, raised, encoder);
    }
    trace_state("raise_scale_aligned", raised);

    Ciphertext real_slots;
    Ciphertext imag_slots;
    bootstrapper.coeff_to_slot(raised, real_slots, imag_slots, galois_keys);
    trace_state("coeff_to_slot.real", real_slots);

    const double real_scale_adjust = eval_mod_scale / real_slots.scale();
    const double imag_scale_adjust = eval_mod_scale / imag_slots.scale();
    // Generated NTT primes are close to, but not exactly, powers of two. For
    // a 45-bit q0 the relative difference from 2^45 is about 1.2e-6. Treat
    // that tiny difference as metadata-only scale drift; correcting it with
    // a plaintext multiply and rescale would waste one bootstrap level.
    constexpr double metadata_scale_tolerance = 1e-5;
    if (std::abs(real_scale_adjust - 1.0) > metadata_scale_tolerance ||
        std::abs(imag_scale_adjust - 1.0) > metadata_scale_tolerance)
    {
        multiply_const(real_slots, real_scale_adjust, eval_mod_scale, real_slots, encoder);
        multiply_const(imag_slots, imag_scale_adjust, eval_mod_scale, imag_slots, encoder);
        rescale(real_slots, real_slots);
        rescale(imag_slots, imag_slots);
        real_slots.scale() = eval_mod_scale;
        imag_slots.scale() = eval_mod_scale;
    }
    trace_state("eval_mod_input.real", real_slots);

    const double inverse_coeff = config.inverse_coeff > 0.0
                                     ? config.inverse_coeff
                                     : bootstrapper.inverse_coefficient(config.double_angle);
    Ciphertext real_mod;
    Ciphertext imag_mod;
    bootstrapper.eval_mod(real_slots, real_mod, relin_keys, config.double_angle,
                          inverse_coeff);
    bootstrapper.eval_mod(imag_slots, imag_mod, relin_keys, config.double_angle,
                          inverse_coeff);
    trace_state("eval_mod_output.real", real_mod);

    Ciphertext output;
    bootstrapper.slot_to_coeff(real_mod, imag_mod, output, galois_keys);
    trace_state("slot_to_coeff", output);
    if (config.project_real)
    {
        Ciphertext conjugated;
        conjugate(output, galois_keys, conjugated);
        add(output, conjugated, output);
    }

    const uint32_t effective_ratio =
        config.project_real ? config.output_ratio / 2 : config.output_ratio;
    multiply_const_direct(output, static_cast<int>(effective_ratio), output, encoder);
    result = std::move(output);
}

void EvaluatorCkksBase::bootstrap_high_precision(const Ciphertext &ciph, Ciphertext &result,
                                                 const RelinKeys &relin_keys,
                                                 const GaloisKeys &galois_keys,
                                                 const CKKSEncoder &encoder,
                                                 EvalModPoly &eval_mod_poly)
{
    bootstrap_core(ciph, result, relin_keys, galois_keys, encoder, eval_mod_poly, true);
}

void EvaluatorCkksBase::bootstrap_core(const Ciphertext &ciph, Ciphertext &result,
                                       const RelinKeys &relin_keys,
                                       const GaloisKeys &galois_keys,
                                       const CKKSEncoder &encoder,
                                       EvalModPoly &eval_mod_poly,
                                       bool high_precision_eval_mod)
{
    auto tmp = ciph;
    rescale_for_bootstrap(tmp);

    auto context_data = context_.crt_context()->get_context_data(tmp.parms_id());
    auto &params = context_data->parms();
    auto q0_level = params.q0_level();
    result = tmp;
    uint32_t bootstrap_ratio = eval_mod_poly.message_ratio();
    double q0_over_message_ratio = context_.crt_context()->q0();
    q0_over_message_ratio = exp2(round(log2(q0_over_message_ratio / (double)bootstrap_ratio)));
    auto level = result.level();
    auto level_diff = level - q0_level;

    if (level_diff > 1)
    {
        auto parms_id = context_.crt_context()->parms_id_map().at(q0_level + 1);
        drop_modulus(result, result, parms_id);
    }

    auto scale = q0_over_message_ratio / result.scale();
    scale = round(scale);
    if (scale > 1)
    {
        multiply_const_direct(result, safe_cast<int64_t>(scale), result, encoder);
        result.scale() *= scale;
    }

    auto parms_id = context_.crt_context()->parms_id_map().at(q0_level);
    drop_modulus(result, result, parms_id);

    Ciphertext ciph_raise;
    read(result);
    raise_modulus(result, ciph_raise);
    if (high_precision_eval_mod)
    {
        auto first_context_data = context_.crt_context()->first_context_data();
        ciph_raise.scale() = static_cast<double>(first_context_data->coeff_modulus()[0].value());
    }

    auto scale_raise = eval_mod_poly.scaling_factor() / ciph_raise.scale();
    scale_raise /= eval_mod_poly.message_ratio();
    if (scale_raise > 1 && scale_raise < 0x7FFFFFFF)
    {
        multiply_const_direct(ciph_raise, safe_cast<int>(scale_raise), ciph_raise, encoder);
        ciph_raise.scale() *= scale_raise;
    }
    else if (scale_raise > 0x7FFFFFFF)
    {
        multiply_const(ciph_raise, 1.0, scale_raise, ciph_raise, encoder);
    }

    Ciphertext ciph_real, ciph_imag;
    Ciphertext ciph_real_mod, ciph_imag_mod;
    Ciphertext res;

    auto coeffs_to_slots_scaling =
        eval_mod_poly.q_div() /
        (eval_mod_poly.k() * eval_mod_poly.sc_fac() * eval_mod_poly.q_diff());

    HomomorphicDFTMatrixLiteral tmp_matrix(
        0, context_.parameters_literal()->log_n(), context_.parameters_literal()->log_slots(),
        static_cast<uint32_t>(context_.parameters_literal()->q().size() - 1),
        vector<uint32_t>(3, 1), true, coeffs_to_slots_scaling, false, 1);
    LinearMatrixGroup coeff_to_slot_dft_matrix;
    tmp_matrix.create(coeff_to_slot_dft_matrix, const_cast<CKKSEncoder &>(encoder), 2);

    coeff_to_slot(ciph_raise, coeff_to_slot_dft_matrix, ciph_real, ciph_imag, galois_keys, encoder);

    eval_mod_poly.set_level_start(static_cast<uint32_t>(
        context_.crt_context()->get_context_data(ciph_real.parms_id())->level()));
    if (high_precision_eval_mod)
    {
        eval_mod_high_precision(ciph_imag, ciph_imag_mod, eval_mod_poly, relin_keys,
                                encoder);
    }
    else
    {
        eval_mod(ciph_imag, ciph_imag_mod, eval_mod_poly, relin_keys, encoder);
    }
    if (high_precision_eval_mod)
    {
        eval_mod_high_precision(ciph_real, ciph_real_mod, eval_mod_poly, relin_keys,
                                encoder);
    }
    else
    {
        eval_mod(ciph_real, ciph_real_mod, eval_mod_poly, relin_keys, encoder);
    }

    ciph_imag_mod.scale() = context_.parameters_literal()->scale();
    ciph_real_mod.scale() = context_.parameters_literal()->scale();

    auto slots_to_coeffs_scaling =
        context_.parameters_literal()->scale() /
        ((double)eval_mod_poly.scaling_factor() / (double)eval_mod_poly.message_ratio());
    HomomorphicDFTMatrixLiteral tmp_matrix_inverse(
        1, context_.parameters_literal()->log_n(), context_.parameters_literal()->log_slots(),
        static_cast<uint32_t>(
            context_.crt_context()->get_context_data(ciph_real_mod.parms_id())->level()),
        vector<uint32_t>(3, 1), true, slots_to_coeffs_scaling, false, 1);
    LinearMatrixGroup slot_to_coeff_dft_matrix;
    tmp_matrix_inverse.create(slot_to_coeff_dft_matrix, const_cast<CKKSEncoder &>(encoder), 1);

    slot_to_coeff(ciph_real_mod, ciph_imag_mod, slot_to_coeff_dft_matrix, result, galois_keys,
                  encoder);
}

void EvaluatorCkksBase::ntt_fwd(const Plaintext &plain, Plaintext &result,
                                parms_id_type parms_id) const
{
    ntt_fwd_b(plain, result);
}

void EvaluatorCkksBase::ntt_fwd(const Plaintext &plain, Plaintext &result) const
{
    ntt_fwd_b(plain, result);
}

void EvaluatorCkksBase::ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const
{
    ntt_fwd_b(ciph, result);
}

void EvaluatorCkksBase::ntt_inv(const Plaintext &plain, Plaintext &result) const
{
    ntt_inv_b(plain, result);
}

void EvaluatorCkksBase::ntt_inv(const Ciphertext &ciph, Ciphertext &result) const
{
    ntt_inv_b(ciph, result);
}

void EvaluatorCkksBase::add(const poseidon::Ciphertext &ciph1, const poseidon::Ciphertext &ciph2,
                            poseidon::Ciphertext &result) const
{
    if (&result == &ciph1)
    {
        add_inplace(result, ciph2);
    }
    else
    {
        result = ciph2;
        add_inplace(result, ciph1);
    }
}

void EvaluatorCkksBase::multiply_plain_inplace(Ciphertext &ciph, const Plaintext &plain,
                                               MemoryPoolHandle pool) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "multiply_plain_inplace : Ciphertext is empty!");
    }

    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks ciph must be in NTT form");
    }
    if (!plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks plain must be in NTT form");
    }
    if (ciph.parms_id() != plain.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph and plain parameter mismatch");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph.parms_id());
    auto scale_bit_count_bound = context_data.total_coeff_modulus_bit_count();
    auto ciph_size = ciph.size();

    for (auto i = 0; i < ciph_size; i++)
    {
        ciph[i].multiply(plain.poly(), ciph[i]);
    }

    ciph.scale() *= plain.scale();
    if (ciph.scale() <= 0 || (static_cast<uint32_t>(log2(ciph.scale())) >= scale_bit_count_bound))
    {
        POSEIDON_THROW(invalid_argument_error, "scale out of bounds");
    }
}

void EvaluatorCkksBase::add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "multiply_plain_inplace : Ciphertext is empty!");
    }
    // Verify parameters.
    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks ciph must be in NTT form");
    }
    if (!plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks plain must be in NTT form");
    }
    if (ciph.parms_id() != plain.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "ciph and plain parameter mismatch");
    }
    if (!util::is_approximate<double>(ciph.scale(), plain.scale()))
    {
        POSEIDON_THROW(invalid_argument_error, "add_plain_inplace : scale mismatch");
    }
    ciph[0].add(plain.poly(), ciph[0]);
}

void EvaluatorCkksBase::add_plain(const Ciphertext &ciph, const Plaintext &plain,
                                  Ciphertext &result) const
{
    result = ciph;
    add_plain_inplace(result, plain);
}

void EvaluatorCkksBase::sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                                  Ciphertext &result) const
{
    POSEIDON_THROW(invalid_argument_error, "sub_plain : ckks not support sub_plain");
}

void EvaluatorCkksBase::sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                            Ciphertext &result) const
{
    if (&ciph2 != &result)
    {
        result = ciph1;
    }

    if (!ciph1.is_valid() || !ciph2.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() != ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "sub : NTT form mismatch");
    }
    if (!util::is_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
        POSEIDON_THROW(invalid_argument_error, "sub : scale mismatch");
    }

    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = context_data.coeff_modulus();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();
    size_t max_count = max(ciph1_size, ciph2_size);
    size_t min_count = min(ciph1_size, ciph2_size);

    // Size check
    if (!product_fits_in(max_count, coeff_count))
    {
        POSEIDON_THROW_LOGIC_ERROR("invalid parameters");
    }

    // Prepare result
    result.resize(context_, ciph1.parms_id(), ciph1.size());
    result.is_ntt_form() = ciph1.is_ntt_form();
    for (auto i = 0; i < min_count; i++)
    {
        ciph1[i].sub(ciph2[i], result[i]);
    }
    // Copy the remainding polys of the array with larger count into ciph1
    if (ciph1_size < ciph2_size)
    {
        for (auto i = min_count; i < max_count; ++i)
        {
            result[i].copy(ciph2[i]);
        }
    }
}

void EvaluatorCkksBase::add_inplace(poseidon::Ciphertext &ciph1,
                                    const poseidon::Ciphertext &ciph2) const
{
    // Verify parameters.
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error, "add_inplace : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() != ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "NTT form mismatch");
    }
    if (!util::is_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
        POSEIDON_THROW(invalid_argument_error, "add_inplace : scale mismatch");
    }

    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    size_t coeff_count = parms.degree();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();
    size_t max_count = max(ciph1_size, ciph2_size);
    size_t min_count = min(ciph1_size, ciph2_size);

    // Size check
    if (!product_fits_in(max_count, coeff_count))
    {
        POSEIDON_THROW_LOGIC_ERROR("invalid parameters");
    }
    // Prepare result
    ciph1.resize(context_, context_data.parms().parms_id(), max_count);
    // Add ciphs
    for (auto i = 0; i < min_count; i++)
    {
        ciph1[i].add(ciph2[i], ciph1[i]);
    }

    // Copy the remainding polys of the array with larger count into ciph1
    if (ciph1_size < ciph2_size)
    {
        for (auto i = min_count; i < max_count; ++i)
        {
            ciph1[i].copy(ciph2[i]);
        }
    }
}

void EvaluatorCkksBase::multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                 Ciphertext &result) const
{

    if (&ciph2 == &result)
    {
        multiply_inplace(result, ciph1);
    }
    else
    {
        result = ciph1;
        multiply_inplace(result, ciph2);
    }
}

void EvaluatorCkksBase::square_inplace(Ciphertext &ciph, MemoryPoolHandle pool) const
{
    multiply_inplace(ciph, ciph);
}

void EvaluatorCkksBase::multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                                         MemoryPoolHandle pool) const
{
    if (ciph1.parms_id() != ciph2.parms_id())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "multiply_inplace : ciph1 and ciph2 parameter mismatch");
    }
    ckks_multiply(ciph1, ciph2, std::move(pool));
}

void EvaluatorCkksBase::ckks_multiply(Ciphertext &ciph1, const Ciphertext &ciph2,
                                      MemoryPoolHandle pool) const
{
    if (!(ciph1.is_ntt_form() && ciph2.is_ntt_form()))
    {
        POSEIDON_THROW(invalid_argument_error, "ciph1 or ciph2 must be in NTT form");
    }

    bool is_square = false;
    if (&ciph1 == &ciph2)
    {
        is_square = true;
    }
    // Extract encryption parameters.
    auto &context_data = *context_.crt_context()->get_context_data(ciph1.parms_id());
    auto &parms = context_data.parms();
    auto &modulus = context_data.coeff_modulus();
    auto scale_bit_count_bound = context_data.total_coeff_modulus_bit_count();
    size_t coeff_count = parms.degree();
    size_t coeff_modulus_size = modulus.size();
    size_t ciph1_size = ciph1.size();
    size_t ciph2_size = ciph2.size();

    // Determine result.size()
    // Default is 3 (c_0, c_1, c_2)
    size_t dest_size = sub_safe(add_safe(ciph1_size, ciph2_size), size_t(1));
    // Size check
    if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
    {
        POSEIDON_THROW_LOGIC_ERROR("invalid parameters");
    }

    // Set up iterator for the base
    auto coeff_modulus = iter(modulus);
    // Prepare result

    ciph1.resize(context_, parms.parms_id(), dest_size);

    ciph1.is_ntt_form() = true;
    // Set up iterators for input ciphs
    PolyIter ciph1_iter = iter(ciph1);
    ConstPolyIter ciph2_iter = iter(ciph2);

    if (dest_size == 3)
    {

        if (is_square)
        {
            // Set up iterators for input ciph
            auto ciph_iter = iter(ciph1);

            // Compute c1^2
            dyadic_product_coeffmod(ciph_iter[1], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                                    ciph_iter[2]);

            // Compute 2*c0*c1
            dyadic_product_coeffmod(ciph_iter[0], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                                    ciph_iter[1]);
            add_poly_coeffmod(ciph_iter[1], ciph_iter[1], coeff_modulus_size, coeff_modulus,
                              ciph_iter[1]);

            // Compute c0^2
            dyadic_product_coeffmod(ciph_iter[0], ciph_iter[0], coeff_modulus_size, coeff_modulus,
                                    ciph_iter[0]);
        }
        else
        {
            // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
            // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67
            // coefficients per polynomial, we should keep the tile size at 682 or below. The tile
            // size must divide coeff_count, i.e. be a power of two. Some testing shows similar
            // performance with tile size 256 and 512, and worse performance on smaller tiles. We
            // pick the smaller of the two to prevent L1 cache misses on processors with < 32 KiB L1
            // cache.
            size_t tile_size = min<size_t>(coeff_count, size_t(256));
            size_t num_tiles = coeff_count / tile_size;

            // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor
            // in sequence
            ConstRNSIter ciph2_0_iter(*ciph2_iter[0], tile_size);
            ConstRNSIter ciph2_1_iter(*ciph2_iter[1], tile_size);
            RNSIter ciph1_0_iter(*ciph1_iter[0], tile_size);
            RNSIter ciph1_1_iter(*ciph1_iter[1], tile_size);
            RNSIter ciph1_2_iter(*ciph1_iter[2], tile_size);

            // Temporary buffer to store intermediate results
            POSEIDON_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

            // Computes the output tile_size coefficients at a time
            // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
            // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
            // with appropriate modular reduction

            // 开启 OpenMP 并行化 (作用于最外层模数循环)，每个线程需要处理不同的模数，互不干扰
            #pragma omp parallel for
            for (size_t i = 0; i < coeff_modulus_size; i++) 
            {
                auto &modulus = coeff_modulus[i];

                // 为每个线程准备独立的临时缓冲区
                POSEIDON_ALLOCATE_GET_COEFF_ITER(local_temp, tile_size, pool);

                // 获取第 i 个模数对应的 RNS 迭代器
                // ciph1_iter[0] 指向第 0 个多项式，ciph1_iter[0][i] 指向该多项式的第 i 个 RNS 分量
                RNSIter it_x0(ciph1_iter[0][i], tile_size);
                RNSIter it_x1(ciph1_iter[1][i], tile_size);
                RNSIter it_x2(ciph1_iter[2][i], tile_size);
                ConstRNSIter it_y0(ciph2_iter[0][i], tile_size);
                ConstRNSIter it_y1(ciph2_iter[1][i], tile_size);

                // 中层循环：遍历 Tile
                for (size_t j = 0; j < num_tiles; j++) 
                {
                    // 逻辑：x[2] = x[1] * y[1]，这里 it_x1[0] 返回的是当前 Tile 的 CoeffIter（即双重解引用后的指针）
                    dyadic_product_coeffmod(it_x1[0], it_y1[0], tile_size, modulus, it_x2[0]);
                    // 逻辑：temp = x[1] * y[0]
                    dyadic_product_coeffmod(it_x1[0], it_y0[0], tile_size, modulus, local_temp);

                    // 逻辑：x[1] = x[0] * y[1]
                    dyadic_product_coeffmod(it_x0[0], it_y1[0], tile_size, modulus, it_x1[0]);

                    // 逻辑：x[1] += temp
                    add_poly_coeffmod(it_x1[0], local_temp, tile_size, modulus, it_x1[0]);
                    // 逻辑：x[0] = x[0] * y[0]
                    dyadic_product_coeffmod(it_x0[0], it_y0[0], tile_size, modulus, it_x0[0]);
                    // 指针自增（跳向下一个 Tile）
                    it_x0++; it_x1++; it_x2++;
                    it_y0++; it_y1++;
                }
            }
        }
    }
    else
    {
        // Allocate temporary space for the result
        POSEIDON_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size,
                                             pool);

        POSEIDON_ITERATE(
            iter(size_t(0)), dest_size,
            [&](auto I)
            {
                // We iterate over relevant components of ciph1 and ciph2 in increasing
                // order for ciph1 and reversed (decreasing) order for ciph2. The bounds
                // for the indices of the relevant terms are obtained as follows.
                size_t curr_ciph1_last = min<size_t>(I, ciph1_size - 1);
                size_t curr_ciph2_first = min<size_t>(I, ciph2_size - 1);
                size_t curr_ciph1_first = I - curr_ciph2_first;
                // size_t curr_ciph2_last = secret_power_index - curr_ciph1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_ciph1_last - curr_ciph1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_ciph1_iter = ciph1_iter + curr_ciph1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_ciph2_iter = reverse_iter(ciph2_iter + curr_ciph2_first);

                POSEIDON_ITERATE(iter(shifted_ciph1_iter, shifted_reversed_ciph2_iter), steps,
                                 [&](auto J)
                                 {
                                     // Extra care needed here:
                                     // temp_iter must be dereferenced once to produce an
                                     // appropriate RNSIter
                                     POSEIDON_ITERATE(
                                         iter(J, coeff_modulus, temp[I]), coeff_modulus_size,
                                         [&](auto K)
                                         {
                                             POSEIDON_ALLOCATE_GET_COEFF_ITER(prod, coeff_count,
                                                                              pool);
                                             dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K),
                                                                     coeff_count, get<1>(K), prod);
                                             add_poly_coeffmod(prod, get<2>(K), coeff_count,
                                                               get<1>(K), get<2>(K));
                                         });
                                 });
            });
        // Set the final result
        set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, ciph1.data());
    }

    // Set the scale
    ciph1.scale() *= ciph2.scale();
    if (ciph1.scale() <= 0 || (static_cast<uint32_t>(log2(ciph1.scale())) >= scale_bit_count_bound))
    {
        throw invalid_argument("scale out of bounds");
    }
}

void EvaluatorCkksBase::relinearize(const Ciphertext &ciph, Ciphertext &result,
                                    const RelinKeys &relin_keys) const
{
    kswitch_->relinearize(ciph, result, relin_keys);
}

void EvaluatorCkksBase::rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                               const GaloisKeys &galois_keys) const
{
    kswitch_->rotate(ciph, result, step, galois_keys);
}

void EvaluatorCkksBase::rotate_row(const Ciphertext &ciph, Ciphertext &result, int step,
                                   const GaloisKeys &galois_keys) const
{
    POSEIDON_THROW(invalid_argument_error, "rotate_row : ckks just support rotate");
}

void EvaluatorCkksBase::rotate_col(const Ciphertext &ciph, Ciphertext &result,
                                   const GaloisKeys &galois_keys) const
{
    POSEIDON_THROW(invalid_argument_error, "rotate_col : ckks just support rotate");
}

void EvaluatorCkksBase::conjugate(const Ciphertext &ciph, const GaloisKeys &galois_keys,
                                  Ciphertext &result) const
{
    kswitch_->conjugate(ciph, galois_keys, result);
}

void EvaluatorCkksBase::rescale_inplace(const Ciphertext &ciph, Ciphertext &result,
                                        MemoryPoolHandle pool) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "rescale_inplace : ciph is empty");
    }
    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "rescale_inplace : ckks ciph must be in NTT form");
    }

    auto context_data_ptr = context_.crt_context()->get_context_data(ciph.parms_id());
    auto &context_data = *context_data_ptr;
    auto &next_context_data = *context_data.next_context_data();
    auto &next_parms = next_context_data.parms();
    auto rns_tool = context_data.rns_tool();
    auto ntt_table = context_.crt_context()->small_ntt_tables();
    size_t ciph_size = ciph.size();
    size_t coeff_count = next_parms.degree();
    size_t next_coeff_modulus_size = next_context_data.coeff_modulus().size();
    Ciphertext ciph_copy(pool);
    ciph_copy = ciph;
    POSEIDON_ITERATE(iter(ciph_copy), ciph_size,
                     [&](auto I)
                     { rns_tool->divide_and_round_q_last_ntt_inplace(I, ntt_table, pool); });
    result.resize(context_, next_context_data.parms().parms_id(), ciph_size);
    POSEIDON_ITERATE(iter(ciph_copy, result), ciph_size,
                     [&](auto I)
                     { set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I)); });

    // Set other attributes
    result.is_ntt_form() = ciph.is_ntt_form();
    result.scale() =
        ciph.scale() / static_cast<double>(context_data.coeff_modulus().back().value());
}

void EvaluatorCkksBase::rescale(const Ciphertext &ciph, Ciphertext &result) const
{
    rescale_inplace(ciph, result);
}

void EvaluatorCkksBase::rescale_dynamic(const Ciphertext &ciph, Ciphertext &result,
                                        double min_scale) const
{
    if (!ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "ckks ciph must be in NTT form");
    }

    auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto min_scaling_facor_div2 = (min_scale + 1) / 2;
    auto result_scale = ciph.scale();
    double scale_tmp = 0.0;
    auto &modulus = context_data->coeff_modulus();
    auto new_level = modulus.size() - 1;
    auto rescale_times = 0;

    while (true)
    {
        scale_tmp = result_scale / safe_cast<double>(modulus[new_level].value());
        if (scale_tmp >= min_scaling_facor_div2)
        {
            if (new_level == 0)
            {
                POSEIDON_THROW(invalid_argument_error,
                               "rescale_dynamic failed : modulus chain is not enough!");
            }
            result_scale = scale_tmp;
            new_level--;
            rescale_times++;
        }
        else
        {
            break;
        }
    }

    for (int i = 0; i < rescale_times; i++)
    {
        if (i == 0)
            rescale_inplace(ciph, result);
        else
        {
            rescale_inplace(result, result);
        }
    }
}

void EvaluatorCkksBase::drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                                     parms_id_type parms_id) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "drop_modulus : Ciphertext is empty");
    }

    auto ciph_size = ciph.size();
    auto context_data = context_.crt_context()->get_context_data(parms_id);
    auto coeff_modulus_size = context_data->coeff_modulus().size();

    if (&ciph == &result)
    {
        auto diff_coeff_modulus_size = ciph.coeff_modulus_size() - coeff_modulus_size;
        size_t p = 0;
        for (auto &poly : result.polys())
        {
            auto drop_num = diff_coeff_modulus_size * p;
            poly.drop(drop_num, coeff_modulus_size);
            p++;
        }
        result.resize(context_, parms_id, ciph_size);
    }
    else
    {
        result.resize(context_, parms_id, ciph_size);
        auto p = 0;
        for (auto &poly : result.polys())
        {
            poly.copy(ciph[p], coeff_modulus_size);
            p++;
        }
        result.is_ntt_form() = ciph.is_ntt_form();
        result.scale() = ciph.scale();
    }
}

void EvaluatorCkksBase::raise_modulus(const Ciphertext &ciph, Ciphertext &result) const
{
    auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto &coeff_modulus = context_data->coeff_modulus();
    auto first_param_id = context_.crt_context()->first_parms_id();
    auto first_context_data = context_.crt_context()->first_context_data();
    auto &first_coeff_modulus = first_context_data->coeff_modulus();
    auto coeff_modulus_size = ciph.coeff_modulus_size();
    auto ciph_size = ciph.size();

    Ciphertext tmp = ciph;
    if (ciph.is_ntt_form())
    {
        for (auto i = 0; i < ciph_size; ++i)
        {
            tmp[i].dot_to_coeff();
        }
    }

    Pointer<RNSBase> base_current;
    try
    {
        base_current = allocate<RNSBase>(pool_, coeff_modulus, pool_);
    }
    catch (const invalid_argument &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "RNSBase's constructor  fail!");
    }

    vector<Modulus> coeff_modulus_raise;
    coeff_modulus_raise.insert(coeff_modulus_raise.end(),
                               first_coeff_modulus.begin() +
                                   static_cast<uint32_t>(coeff_modulus_size),
                               first_coeff_modulus.end());
    Pointer<RNSBase> base_raise;
    try
    {
        base_raise = allocate<RNSBase>(pool_, coeff_modulus_raise, pool_);
    }
    catch (const invalid_argument &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "RNSBase's constructor  fail!");
    }
    BaseConverter conv(*base_current, *base_raise, pool_);

    result.resize(context_, first_param_id, ciph_size);
    result.scale() = ciph.scale();
    for (auto i = 0; i < ciph_size; ++i)
    {
        result[i].copy(tmp[i], coeff_modulus_size);
        conv.fast_convert_array(tmp[i][0], result[i][coeff_modulus_size], pool_);
        result[i].coeff_to_dot();
    }
    result.is_ntt_form() = true;
}

void EvaluatorCkksBase::multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                       Ciphertext &result, const RelinKeys &relin_keys) const
{
    multiply(ciph1, ciph2, result);
    relinearize(result, result, relin_keys);
}

void EvaluatorCkksBase::multiply_relin_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                               Ciphertext &result,
                                               const RelinKeys &relin_keys) const
{
    multiply_dynamic(ciph1, ciph2, result);
    relinearize(result, result, relin_keys);
}

void EvaluatorCkksBase::sub_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                    Ciphertext &result, const CKKSEncoder &encoder) const
{
    auto level1 = ciph1.level();
    auto level2 = ciph2.level();
    double scaling_factor_ratio = 0.0;
    Ciphertext tmp_scale;
    bool has_tmp_scale_ciph1 = false;
    bool has_tmp_scale_ciph2 = false;

    if (util::is_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
    }
    else if (ciph1.scale() > ciph2.scale())
    {
        scaling_factor_ratio = ciph1.scale() / ciph2.scale();
        scaling_factor_ratio += 0.5;
        if ((scaling_factor_ratio < min_scale_) && !util::is_approximate<double>(scaling_factor_ratio, min_scale_))
        {
            POSEIDON_THROW(invalid_argument_error, "sub_dynamic : ciph scale don't support! ");
        }
        multiply_const(ciph2, scaling_factor_ratio, 1.0, tmp_scale, encoder);
        tmp_scale.scale() = ciph1.scale();
        has_tmp_scale_ciph2 = true;
    }
    else
    {
        scaling_factor_ratio = ciph2.scale() / ciph1.scale();
        scaling_factor_ratio += 0.5;
        if ((scaling_factor_ratio < min_scale_) && !util::is_approximate<double>(scaling_factor_ratio, min_scale_))
        {
            POSEIDON_THROW(invalid_argument_error, "sub_dynamic : ciph scale don't support! ");
        }
        multiply_const(ciph1, scaling_factor_ratio, 1.0, tmp_scale, encoder);
        tmp_scale.scale() = ciph2.scale();
        has_tmp_scale_ciph1 = true;
    }

    if (level1 > level2)
    {
        Ciphertext tmp;
        if (&result == &ciph2)
        {
            if (!has_tmp_scale_ciph1)
                drop_modulus(ciph1, tmp, ciph2.parms_id());
            else
            {
                drop_modulus(tmp_scale, tmp, ciph2.parms_id());
            }
            if (has_tmp_scale_ciph2)
                sub(tmp, tmp_scale, result);
            else
                sub(tmp, ciph2, result);
        }
        else
        {
            if (!has_tmp_scale_ciph1)
                drop_modulus(ciph1, result, ciph2.parms_id());
            else
            {
                drop_modulus(tmp_scale, result, ciph2.parms_id());
            }

            if (has_tmp_scale_ciph2)
                sub(result, tmp_scale, result);
            else
                sub(result, ciph2, result);
        }
    }
    else if (level2 > level1)
    {
        Ciphertext tmp;
        if (&result == &ciph1)
        {
            if (!has_tmp_scale_ciph2)
                drop_modulus(ciph2, tmp, ciph1.parms_id());
            else
            {
                drop_modulus(tmp_scale, tmp, ciph1.parms_id());
            }

            if (has_tmp_scale_ciph1)
                sub(tmp_scale, tmp, result);
            else
                sub(ciph1, tmp, result);
        }
        else
        {
            if (!has_tmp_scale_ciph2)
                drop_modulus(ciph2, result, ciph1.parms_id());
            else
            {
                drop_modulus(tmp_scale, result, ciph1.parms_id());
            }

            if (has_tmp_scale_ciph1)
                sub(tmp_scale, result, result);
            else
                sub(ciph1, result, result);
        }
    }
    else
    {
        if (has_tmp_scale_ciph1)
        {
            sub(tmp_scale, ciph2, result);
        }
        else if (has_tmp_scale_ciph2)
        {
            sub(ciph1, tmp_scale, result);
        }
        else
        {
            sub(ciph1, ciph2, result);
        }
    }
}

void EvaluatorCkksBase::add_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                    Ciphertext &result, const CKKSEncoder &encoder) const
{
    auto level1 = ciph1.level();
    auto level2 = ciph2.level();
    double scaling_factor_ratio = 0.0;
    Ciphertext tmp_scale;
    bool has_tmp_scale_ciph1 = false;
    bool has_tmp_scale_ciph2 = false;

    if (util::is_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
    }
    else if (ciph1.scale() > ciph2.scale())
    {
        scaling_factor_ratio = ciph1.scale() / ciph2.scale();

        scaling_factor_ratio += 0.5;
        if ((scaling_factor_ratio < min_scale_) && !util::is_approximate<double>(scaling_factor_ratio, min_scale_))
        {
            spdlog::error("scaling_factor_ratio = {}, min_scale_ = {}", scaling_factor_ratio, min_scale_);
            POSEIDON_THROW(invalid_argument_error, "add_dynamic : ciph scale don't support! ");
        }
        multiply_const(ciph2, scaling_factor_ratio, 1.0, tmp_scale, encoder);
        tmp_scale.scale() = ciph1.scale();
        has_tmp_scale_ciph2 = true;
    }
    else
    {
        scaling_factor_ratio = ciph2.scale() / ciph1.scale();
        scaling_factor_ratio += 0.5;
        if ((scaling_factor_ratio < min_scale_) && !util::is_approximate<double>(scaling_factor_ratio, min_scale_))
        {
            spdlog::error("scaling_factor_ratio = {}, min_scale_ = {}", scaling_factor_ratio, min_scale_);
            POSEIDON_THROW(invalid_argument_error, "add_dynamic : ciph scale don't support! ");
        }
        multiply_const(ciph1, scaling_factor_ratio, 1.0, tmp_scale, encoder);
        tmp_scale.scale() = ciph2.scale();

        has_tmp_scale_ciph1 = true;
    }

    if (level1 > level2)
    {
        Ciphertext tmp;
        if (&result == &ciph2)
        {
            if (!has_tmp_scale_ciph1)
                drop_modulus(ciph1, tmp, ciph2.parms_id());
            else
            {
                drop_modulus(tmp_scale, tmp, ciph2.parms_id());
            }
            if (has_tmp_scale_ciph2)
                add(tmp, tmp_scale, result);
            else
                add(tmp, ciph2, result);
        }
        else
        {
            if (!has_tmp_scale_ciph1)
                drop_modulus(ciph1, result, ciph2.parms_id());
            else
            {
                drop_modulus(tmp_scale, result, ciph2.parms_id());
            }

            if (has_tmp_scale_ciph2)
                add(result, tmp_scale, result);
            else
                add(result, ciph2, result);
        }
    }
    else if (level2 > level1)
    {
        Ciphertext tmp;
        if (&result == &ciph1)
        {
            if (!has_tmp_scale_ciph2)
                drop_modulus(ciph2, tmp, ciph1.parms_id());
            else
            {
                drop_modulus(tmp_scale, tmp, ciph1.parms_id());
            }

            if (has_tmp_scale_ciph1)
                add(tmp_scale, tmp, result);
            else
                add(ciph1, tmp, result);
        }
        else
        {
            if (!has_tmp_scale_ciph2)
                drop_modulus(ciph2, result, ciph1.parms_id());
            else
            {
                drop_modulus(tmp_scale, result, ciph1.parms_id());
            }

            if (has_tmp_scale_ciph1)
                add(tmp_scale, result, result);
            else
                add(ciph1, result, result);
        }
    }
    else
    {
        if (has_tmp_scale_ciph1)
        {
            add(tmp_scale, ciph2, result);
        }
        else if (has_tmp_scale_ciph2)
        {
            add(ciph1, tmp_scale, result);
        }
        else
        {
            add(ciph1, ciph2, result);
        }
    }
}

void EvaluatorCkksBase::read(Ciphertext &ciph) const {}
void EvaluatorCkksBase::read(Plaintext &plain) const {}

}  // namespace poseidon
