#include "evaluator_ckks_base.h"
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/encryptor.h"
#include "poseidon/util/debug.h"
#include <algorithm>
#include <cmath>

// debug
#include "spdlog/logger.h"
#include "spdlog/spdlog.h"

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

tuple<Polynomial, Polynomial> factorize_lattigo(const Polynomial &coeffs, int split)
{
    // 对应 Lattigo utils/bignum/polynomial.go:257-314。
    //     func (p Polynomial) Factorize(n int) (pq, pr Polynomial)
    // Lattigo 在 n < Degree()/2 时 panic；这里保持同样的前置条件。
    if (split < (coeffs.degree() >> 1))
    {
        POSEIDON_THROW(invalid_argument_error, "factorize_lattigo: split < degree/2");
    }

    // 对应 Lattigo polynomial.go:267-272：
    //     pr.Coeffs = make([]*Complex, n)
    //     for i := 0; i < n; i++ { ... Clone() }
    // Poseidon 的系数不是 nil 指针，零系数也有显式 complex<double> 值，
    // 所以这里直接复制前 split 项。
    vector<complex<double>> coeffsr_buffer(split, complex<double>(0.0, 0.0));
    for (int i = 0; i < split; i++)
    {
        coeffsr_buffer[i] = coeffs.data()[i];
    }

    // 对应 Lattigo polynomial.go:274-280：
    //     pq.Coeffs = make([]*Complex, p.Degree()-n+1)
    //     pq.Coeffs[0] = p.Coeffs[n].Clone()
    vector<complex<double>> coeffsq_buffer(coeffs.degree() - split + 1,
                                           complex<double>(0.0, 0.0));
    coeffsq_buffer[0] = coeffs.data()[split];

    // 对应 Lattigo polynomial.go:282-283。
    // 合并后的 Poseidon Polynomial 已经有 is_odd/is_even 元数据，因此这里使用
    // 元数据，不重新扫系数推断；这与 Lattigo 的 p.IsOdd/p.IsEven 行为一致。
    auto odd = coeffs.is_odd();
    auto even = coeffs.is_even();

    // 对应 Lattigo polynomial.go:285-307。
    // Monomial 分支只把满足奇偶过滤的高次项搬到 pq；
    // Chebyshev 分支还要做 C_i = 2*C_{i-n}*C_n - C_{n-(i-n)}
    // 对应的余项修正，即 pr[n-j] -= p.Coeffs[i]。
    switch (coeffs.basis_type())
    {
    case Monomial:
        for (auto i = split + 1; i < coeffs.degree() + 1; i++)
        {
            if (is_not_negligible(coeffs.data()[i]) &&
                (!(even || odd) || ((i & 1) == 0 && even) || ((i & 1) == 1 && odd)))
            {
                coeffsq_buffer[i - split] = coeffs.data()[i];
            }
        }
        break;
    case Chebyshev:
        for (auto i = split + 1, j = 1; i < coeffs.degree() + 1; i++, j++)
        {
            if (is_not_negligible(coeffs.data()[i]) &&
                (!(even || odd) || ((i & 1) == 0 && even) || ((i & 1) == 1 && odd)))
            {
                coeffsq_buffer[i - split] = complex<double>(2.0, 0.0) * coeffs.data()[i];
                coeffsr_buffer[split - j] -= coeffs.data()[i];
            }
        }
        break;
    }

    // 对应 Lattigo circuits/common/polynomial/polynomial.go:45-53。
    // bignum.Polynomial.Factorize 只处理系数；外层 Polynomial.Factorize 会恢复
    // MaxDeg/Lead 这些评估元数据。
    auto coeffsq_max_degree = coeffs.max_degree();
    auto coeffsr_max_degree = coeffs.max_degree();
    if (coeffs.max_degree() == coeffs.degree())
    {
        coeffsr_max_degree = split - 1;
    }
    else
    {
        coeffsr_max_degree = coeffs.max_degree() - (coeffs.degree() - split + 1);
    }

    Polynomial coeffsq(coeffsq_buffer, coeffs.a(), coeffs.b(), coeffsq_max_degree,
                       coeffs.basis_type(), coeffs.lead());
    Polynomial coeffsr(coeffsr_buffer, coeffs.a(), coeffs.b(), coeffsr_max_degree,
                       coeffs.basis_type(), false);

    // 对应 Lattigo utils/bignum/polynomial.go:310-312。
    // Poseidon 没有 Interval 字段，所以只同步 Basis/isOdd/isEven；a/b 已经在
    // 构造函数里带过去。
    coeffsq.is_odd() = coeffs.is_odd();
    coeffsq.is_even() = coeffs.is_even();
    coeffsr.is_odd() = coeffs.is_odd();
    coeffsr.is_even() = coeffs.is_even();

    return make_tuple(coeffsq, coeffsr);
}

void factorize_lattigo_poly_vector(const PolynomialVector &polys, PolynomialVector &coeffsq,
                                   PolynomialVector &coeffsr, int split)
{
    // 对应 Lattigo circuits/common/polynomial/polynomial.go:218-228。
    // PolynomialVector.Factorize 逐个调用 Polynomial.Factorize，并原样保留 Mapping。
    coeffsq.index() = polys.index();
    coeffsr.index() = polys.index();

    for (const auto &poly : polys.polys())
    {
        auto [q, r] = factorize_lattigo(poly, split);
        coeffsq.polys().push_back(q);
        coeffsr.polys().push_back(r);
    }
}

bool scale_in_delta_lattigo(double scale0, double scale1, double log2_delta)
{
    // 对应 Lattigo core/rlwe/scale.go:135-148。
    // Scale.InDelta 判断的是相对误差的 -log2 是否达到阈值，不等价于
    // Poseidon util::are_approximate 的默认近似判断。
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

void EvaluatorCkksBase::multiply_const_direct(const Ciphertext &ciph, int const_data,
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
            // std::cout << "READ " << plain_mat.read_cnt++ << " END" << std::endl;
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

void EvaluatorCkksBase::evaluate_poly_vector(const Ciphertext &ciph, Ciphertext &destination,
                                             const PolynomialVector &polys, double scale,
                                             const RelinKeys &relin_keys,
                                             const CKKSEncoder &encoder) const
{
    map<uint32_t, Ciphertext> monomial_basis;
    monomial_basis[1] = ciph;

    int log_degree = ceil(log2(polys.polys()[0].degree()));
    int log_split = optimal_split(log_degree);
    std::cout << "log_degree = " << log_degree << "  log_split = " << log_split << std::endl;

    bool odd = true;
    bool even = true;

    for (auto p : polys.polys())
    {
        odd = odd && p.is_odd();
        even = even && p.is_even();
    }

    bool is_chebyshev = false;
    if (polys.polys()[0].basis_type() == Chebyshev)
    {
        is_chebyshev = true;
    }
    else
    {
        is_chebyshev = false;
    }

    gen_power(monomial_basis, 1 << log_degree, false, is_chebyshev, scale, relin_keys, encoder);
    for (int i = ((int64_t)1 << log_split) - 1; i > 2; i--)
    {
        auto state = i & 1;
        if (!(even || odd) || (state == 0 && even) || ((state == 1 && odd)))
        {
            gen_power(monomial_basis, i, false, is_chebyshev, scale, relin_keys, encoder);
        }
    }

    for (auto &[first, second] : monomial_basis)
    {
        read(second);
    }

    auto index = pow(2, log_degree);
    double target_scale = scale;
    auto target_level = monomial_basis.at(index).level();

    uint32_t num = 0;
    recurse(monomial_basis, relin_keys, target_level, target_scale, polys, log_split, log_degree,
            destination, encoder, odd, even, num);
    rescale_dynamic(destination, destination, target_scale);
    destination.scale() = target_scale;
}

void EvaluatorCkksBase::gen_power(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy,
                                  bool is_chev, double min_scale, const RelinKeys &relin_keys,
                                  const CKKSEncoder &encoder) const
{
    gen_power_inner(monomial_basis, n, lazy, is_chev, min_scale, relin_keys, encoder);
    rescale_dynamic(monomial_basis[n], monomial_basis[n], min_scale);
}

void EvaluatorCkksBase::gen_power_inner(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n,
                                        bool lazy, bool is_chev, double min_scale,
                                        const RelinKeys &relin_keys,
                                        const CKKSEncoder &encoder) const
{
    if (!monomial_basis[n].is_valid())
    {
        bool is_pow2 = ((n & (n - 1)) == 0);
        int a, b, c = 0;
        if (is_pow2)
        {
            a = n / 2;
            b = a;
        }
        else
        {
            int k = ceil(log2((float)n)) - 1;
            a = (1 << k) - 1;
            b = n + 1 - (1 << k);
            if (is_chev)
            {
                c = (int)(abs(a - b));
            }
        }

        gen_power_inner(monomial_basis, a, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                        encoder);
        gen_power_inner(monomial_basis, b, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                        encoder);

        if (lazy)
        {
            POSEIDON_THROW(invalid_argument_error, "gen_power_inner: lazy should be false!");
        }
        else
        {
            rescale_dynamic(monomial_basis[a], monomial_basis[a], min_scale);
            rescale_dynamic(monomial_basis[b], monomial_basis[b], min_scale);
            multiply_relin_dynamic(monomial_basis[a], monomial_basis[b], monomial_basis[n],
                                   relin_keys);
        }

        if (is_chev)
        {
            add(monomial_basis[n], monomial_basis[n], monomial_basis[n]);
            if (c == 0)
            {
                add_const(monomial_basis[n], -1.0, monomial_basis[n], encoder);
            }
            else
            {
                // Since C[0] is not stored (but rather seen as the constant 1), only recurses on c
                gen_power_inner(monomial_basis, c, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                                encoder);
                Ciphertext ciph_tmp;
                auto scale_tmp = monomial_basis[c].scale();
                scale_tmp = monomial_basis[n].scale() / scale_tmp;
                multiply_const(monomial_basis[c], 1.0, scale_tmp, ciph_tmp, encoder);
                sub_dynamic(monomial_basis[n], ciph_tmp, monomial_basis[n], encoder);
            }
        }
    }
}



void EvaluatorCkksBase::recurse(const map<uint32_t, Ciphertext> &monomial_basis,
                                const RelinKeys &relin_keys, uint32_t target_level,
                                double target_scale, const PolynomialVector &pol,
                                uint32_t log_split, uint32_t log_degree, Ciphertext &destination,
                                const CKKSEncoder &encoder, bool is_odd, bool is_even,
                                uint32_t &num) const
{
    double min_target_scale = min_scale_;
    double pow_scale;
    auto log_split_tmp = log_split;
    auto log_degree_tmp = log_degree;
    auto pol_deg = pol.polys()[0].degree();
    auto parms = context_.parameters_literal();
    auto &modulus = parms->q();
    if (pol_deg < (1 << log_split))
    {
        if (pol.polys()[0].lead() && (log_split > 1) &&
            (pol.polys()[0].max_degree() % (1 << (log_split + 1))) > (1 << (log_split - 1)))
        {
            log_degree = log2(pol.polys()[0].degree() + 1);
            log_split = log_degree >> 1;
            recurse(monomial_basis, relin_keys, target_level, target_scale, pol, log_split,
                    log_degree, destination, encoder, is_odd, is_even, num);
            return;
        }
        auto target_scale_new = target_scale;
        auto [tag_level, tag_scale] =
            pre_scalar_level(is_even, is_odd, monomial_basis, target_scale_new, target_level, pol,
                             log_split_tmp, log_degree_tmp);
#ifdef DEBUG
        gmp_printf("inside target level: %d,  target scale: %0.7lf\n", tag_level, tag_scale);
#endif

        evaluate_poly_from_poly_nomial_basis(is_even, is_odd, monomial_basis, relin_keys, tag_level,
                                             tag_scale, pol, log_split, log_degree, destination,
                                             encoder);

        return;
    }
    auto next_power = 1 << log_split;
    while (next_power < ((pol.polys()[0].degree() >> 1) + 1))
    {
        next_power <<= 1;
    }
    PolynomialVector coeffsq, coeffsr;
    coeffsq.index() = pol.index();
    coeffsr.index() = pol.index();
    split_coeffs_poly_vector(pol, coeffsq, coeffsr, next_power);
    auto x_pow = monomial_basis.at(next_power);

    auto target_scale_new = target_scale;
    double tmp_scale;
    auto target_scale_pass = false;
    int new_target_level = target_level;

    if (num == 0 && pol.polys()[0].lead())
    {

        while (!target_scale_pass)
        {
            auto current_qi = safe_cast<double>(modulus[new_target_level - num].value());
            num++;
            target_scale_new *= current_qi;
            tmp_scale = target_scale_new / x_pow.scale();
            if (tmp_scale + 1000000000 >= min_target_scale)
            {
                target_scale_new = tmp_scale;
                target_scale_pass = true;
            }
        }
    }
    else if (pol.polys()[0].lead())
    {

        while (!target_scale_pass)
        {
            new_target_level++;
            auto current_qi = safe_cast<double>(modulus[new_target_level].value());
            target_scale_new *= current_qi;
            tmp_scale = target_scale_new / x_pow.scale();
            if (tmp_scale + 1000000000 >= min_target_scale)
            {
                target_scale_new = tmp_scale;
                target_scale_pass = true;
            }
        }
    }
    else
    {
        target_scale_new /= x_pow.scale();
        pow_scale = target_scale_new;
        while (!target_scale_pass)
        {
            new_target_level++;
            auto current_qi = safe_cast<double>(modulus[new_target_level].value());
            target_scale_new *= current_qi;
            tmp_scale = target_scale_new / x_pow.scale();
            if (tmp_scale + 1000000000 >= min_target_scale)
            {
                target_scale_pass = true;
            }
        }
    }
#ifdef DEBUG
    printf("outside target level: %d,  target scale: %0.7lf\n", new_target_level, target_scale_new);
#endif

    Ciphertext res;
    recurse(monomial_basis, relin_keys, new_target_level, target_scale_new, coeffsq, log_split,
            log_degree, res, encoder, is_odd, is_even, num);
#ifdef DEBUG
    printf("1:res level: %zu,  target scale: %0.lf\n", res.level(), res.scale());
#endif

    if (!pol.polys()[0].lead())
    {
        rescale_dynamic(res, res, pow_scale);
    }
    else
    {
        rescale_dynamic(res, res, context_.parameters_literal()->scale());
    }
#ifdef DEBUG
    printf("2:res level: %zu,  target scale: %0.7lf\n", res.level(), res.scale());
    printf("3:x_pow level: %zu,  target scale: %0.7lf\n", x_pow.level(), x_pow.scale());
#endif

    multiply_relin_dynamic(res, x_pow, res, relin_keys);
#ifdef DEBUG
    printf("3:MUL level: %zu,  target scale: %0.7lf\n", res.level(), res.scale());
    printf("4:new_target_level level: %d,  target scale: %0.7lf\n", new_target_level,
           target_scale_new);
#endif

    Ciphertext tmp;
    recurse(monomial_basis, relin_keys, res.level(), res.scale(), coeffsr, log_split, log_degree,
            tmp, encoder, is_odd, is_even, num);
#ifdef DEBUG
    printf("########### title[%zu]\n", coeffsr.polys()[0].degree());
#endif

    rescale_dynamic(tmp, tmp, res.scale());
#ifdef DEBUG
    gmp_printf("5:tmp level: %d,  target scale: %0.7lf\n", tmp.level(), tmp.scale());
    gmp_printf("5:res level: %d,  target scale: %0.7lf\n", res.level(), res.scale());
#endif
    add_dynamic(res, tmp, destination, encoder);
}

void EvaluatorCkksBase::recursePS(const map<uint32_t, Ciphertext> &monomial_basis,
                                  const RelinKeys &relin_keys, uint32_t target_level,
                                  double target_scale, const PolynomialVector &pol,
                                  uint32_t log_split, uint32_t log_degree,
                                  Ciphertext &destination, const CKKSEncoder &encoder,
                                  bool is_odd, bool is_even, uint32_t &num) const
{
    // 对应 Lattigo circuits/common/polynomial/polynomial.go:108-153。
    //
    // 无法一行一行完全对上的地方：
    // - Lattigo line 109 返回 ([]Polynomial, *SimOperand)。Poseidon 这里必须
    //   保持和原 recurse 相同的接口，所以只把 ciphertext 结果写入 destination。
    // - Lattigo 显式传入 params/eval/pb。Poseidon 从 context_ 取参数，
    //   用 monomial_basis 作为 PowerBasis，并调用本地 rescale/multiply/add。
    // - relin_keys/is_odd/is_even/num 是 Poseidon recurse 接口遗留参数。
    //   Lattigo recursePS 不使用它们；这里保留形参但逻辑按 Lattigo 元数据
    //   pol.is_odd()/pol.is_even() 走。
    (void)relin_keys;
    (void)is_odd;
    (void)is_even;
    (void)num;

    auto pol_deg = static_cast<uint32_t>(pol.polys()[0].degree());
    auto &modulus = context_.parameters_literal()->q();

    // 对应 Lattigo polynomial.go:111。
    //     if p.Degree() < (1 << logSplit) { ... }
    // 这是 Paterson-Stockmeyer 的 baby-step/base-case 分支。
    if (pol_deg < (static_cast<uint32_t>(1) << log_split))
    {
        // 对应 Lattigo polynomial.go:113-120。
        //     if p.Lead && logSplit > 1 && p.MaxDeg > ... { ... }
        // Lattigo 用 bits.Len64(uint64(p.MaxDeg)) 计算有效位数；
        // 合并后的新代码已有 bit_len，这里复用它。
        if (pol.polys()[0].lead() && log_split > 1)
        {
            auto max_deg = static_cast<int64_t>(pol.polys()[0].max_degree());
            auto max_deg_bit_len = bit_len(static_cast<uint>(max_deg));
            auto max_deg_bound = (static_cast<int64_t>(1) << max_deg_bit_len) -
                                 (static_cast<int64_t>(1) << (log_split - 1));
            if (max_deg > max_deg_bound)
            {
                log_degree = bit_len(pol_deg);
                log_split = static_cast<uint32_t>(optimal_split(static_cast<int>(log_degree)));
                recursePS(monomial_basis, relin_keys, target_level, target_scale, pol, log_split,
                          log_degree, destination, encoder, is_odd, is_even, num);
                return;
            }
        }

        // 对应 Lattigo polynomial.go:123。
        //     p.Level, p.Scale = eval.UpdateLevelAndScaleBabyStep(...)
        // 深入到 ckks/polynomial/polynomial_evaluator_sim.go:57-69 后可知：
        // lead=true 时 scale 乘以当前 rescale 会消耗的 qi，level 不变；
        // lead=false 时 level/scale 保持传入值。Poseidon 当前路径按一次
        // rescale 消耗一个 modulus 处理。
        auto tag_level = target_level;
        auto tag_scale = target_scale;
        if (pol.polys()[0].lead())
        {
            tag_scale *= safe_cast<double>(modulus[tag_level].value());
        }

        // 对应 Lattigo polynomial.go:125。
        //     return []Polynomial{p}, &SimOperand{Level: p.Level, Scale: p.Scale}
        // Poseidon 不返回 BSGS polynomial list，所以这里直接按 Lattigo
        // EvaluatePolynomialVectorFromPowerBasis 的逻辑计算 baby-step ciphertext。
        evaluate_polynomial_vector_from_power_basis_lattigo(
            monomial_basis, tag_level, tag_scale, pol, destination, encoder);
        return;
    }

    // 对应 Lattigo polynomial.go:128-131。
    //     nextPower := 1 << logSplit
    //     for nextPower < (p.Degree()>>1)+1 { nextPower <<= 1 }
    auto next_power = static_cast<uint32_t>(1) << log_split;
    while (next_power < ((pol_deg >> 1) + 1))
    {
        next_power <<= 1;
    }

    // 对应 Lattigo polynomial.go:133。
    //     XPow := pb[nextPower]
    auto x_pow = monomial_basis.at(next_power);

    // 对应 Lattigo polynomial.go:135。
    //     coeffsq, coeffsr := p.Factorize(nextPower)
    // 这里必须使用新增的 factorize_lattigo_poly_vector；原
    // split_coeffs_poly_vector 的 Chebyshev 和奇偶过滤逻辑与 Lattigo Factorize
    // 不完全一致，所以保留旧函数但不在 recursePS 中使用。
    PolynomialVector coeffsq, coeffsr;
    factorize_lattigo_poly_vector(pol, coeffsq, coeffsr, static_cast<int>(next_power));

    // 对应 Lattigo polynomial.go:137。
    //     tLevelNew, tScaleNew := eval.UpdateLevelAndScaleGiantStep(...)
    // 深入到 ckks/polynomial/polynomial_evaluator_sim.go:72-89：
    // lead=true 用 q[targetLevel]，lead=false 用 q[targetLevel+levelsConsumed]；
    // tScaleNew = targetScale * qi / XPow.Scale。
    // Poseidon 这里按 levelsConsumedPerRescaling == 1 翻译。
    auto t_level_new = target_level + 1;
    auto qi_index = pol.polys()[0].lead() ? target_level : t_level_new;
    auto t_scale_new = target_scale * safe_cast<double>(modulus[qi_index].value()) / x_pow.scale();

    // 对应 Lattigo polynomial.go:139。
    //     bsgsQ, res := recursePS(... coeffsq ..., tScaleNew, ...)
    Ciphertext res;
    recursePS(monomial_basis, relin_keys, t_level_new, t_scale_new, coeffsq, log_split,
              log_degree, res, encoder, is_odd, is_even, num);

    // 对应 Lattigo polynomial.go:141-142。
    //     eval.Rescale(res)
    //     res = eval.MulNew(res, XPow)
    // 深入到 schemes/ckks/evaluator.go:596-625 可知 MulNew/Mul 是
    // without relinearization，因此这里用 multiply_dynamic，不用
    // multiply_relin_dynamic。
    rescale(res, res);
    multiply_dynamic(res, x_pow, res);

    // 对应 Lattigo polynomial.go:144。
    //     bsgsR, tmp := recursePS(... coeffsr ..., res.Scale, ...)
    Ciphertext tmp;
    recursePS(monomial_basis, relin_keys, target_level, res.scale(), coeffsr, log_split,
              log_degree, tmp, encoder, is_odd, is_even, num);

    // 对应 Lattigo polynomial.go:146-150。
    //     tmp.Scale.InDelta(res.Scale, float64(rlwe.ScalePrecision-12))
    // ScalePrecision 是 128，所以这里使用 116，并且按 Lattigo Scale.InDelta
    // 的相对误差规则检查。
    if (!scale_in_delta_lattigo(tmp.scale(), res.scale(), 116.0))
    {
        POSEIDON_THROW(invalid_argument_error, "recursePS: res.Scale != tmp.Scale");
    }

    // 对应 Lattigo polynomial.go:152。
    //     return append(bsgsQ, bsgsR...), res
    // Poseidon 的可见输出只有 ciphertext，所以将左/右递归结果相加写入 destination。
    add_dynamic(res, tmp, destination, encoder);
}

EvaluatorCkksBase::SimPower EvaluatorCkksBase::recursePS2(
    const map<uint32_t, SimPower> &power_basis_sim, uint32_t log_split, uint32_t target_level,
    double target_scale, const Polynomial &poly, vector<Polynomial> &ps_polys) const
{
    // 对应新版 Lattigo he/polynomial.go:107-147。
    // 这个版本不直接计算 ciphertext，只生成 PatersonStockmeyerPolynomial.Value
    // 对应的 baby-step Polynomial 列表，并返回模拟的 SimOperand{Level, Scale}。
    auto pol_deg = static_cast<uint32_t>(poly.degree());
    auto &modulus = context_.parameters_literal()->q();

    // 对应 Lattigo he/polynomial.go:109。
    //     if p.Degree() < (1 << logSplit) { ... }
    if (pol_deg < (static_cast<uint32_t>(1) << log_split))
    {
        Polynomial p = poly;

        // 对应 Lattigo he/polynomial.go:111-117。
        //     if p.Lead && logSplit > 1 && p.MaxDeg > ... { ... }
        if (p.lead() && log_split > 1)
        {
            auto max_deg = static_cast<int64_t>(p.max_degree());
            auto max_deg_bound = (static_cast<int64_t>(1) << bit_len(static_cast<uint>(max_deg))) -
                                 (static_cast<int64_t>(1) << (log_split - 1));
            if (max_deg > max_deg_bound)
            {
                auto log_degree_new = static_cast<uint32_t>(bit_len(pol_deg));
                auto log_split_new =
                    static_cast<uint32_t>(optimal_split_optimized(static_cast<int>(log_degree_new)));
                return recursePS2(power_basis_sim, log_split_new, target_level, target_scale, p,
                                  ps_polys);
            }
        }

        // 对应 Lattigo he/polynomial.go:119。
        //     p.Level, p.Scale = eval.UpdateLevelAndScaleBabyStep(...)
        // Poseidon 同事这套 SimPower 假设一次 rescale 消耗一个 modulus；
        // 因此 lead=true 时 scale 乘 q[targetLevel]，level 不变。
        p.level() = static_cast<int>(target_level);
        p.scale() = target_scale;
        if (p.lead())
        {
            p.scale() *= safe_cast<double>(modulus[target_level].value());
        }

        // 对应 Lattigo he/polynomial.go:121。
        //     return []Polynomial{p}, &SimOperand{Level: p.Level, Scale: p.Scale}
        ps_polys.push_back(p);
        return {p.level(), p.scale()};
    }

    // 对应 Lattigo he/polynomial.go:124-127。
    //     nextPower := 1 << logSplit
    //     for nextPower < (p.Degree()>>1)+1 { nextPower <<= 1 }
    auto next_power = static_cast<uint32_t>(1) << log_split;
    while (next_power < ((pol_deg >> 1) + 1))
    {
        next_power <<= 1;
    }

    // 对应 Lattigo he/polynomial.go:129。
    //     XPow := pb[nextPower]
    auto x_pow = power_basis_sim.at(next_power);

    // 对应 Lattigo he/polynomial.go:131。
    //     coeffsq, coeffsr := p.Factorize(nextPower)
    auto [coeffsq, coeffsr] = factorize_lattigo(poly, static_cast<int>(next_power));

    // 对应 Lattigo he/polynomial.go:133。
    //     tLevelNew, tScaleNew := eval.UpdateLevelAndScaleGiantStep(...)
    auto t_level_new = target_level + 1;
    auto qi_index = poly.lead() ? target_level : t_level_new;
    auto t_scale_new =
        target_scale * safe_cast<double>(modulus[qi_index].value()) / x_pow.scale_;

    // 对应 Lattigo he/polynomial.go:135。
    //     bsgsQ, res := recursePS(... coeffsq ..., tScaleNew, ...)
    auto res =
        recursePS2(power_basis_sim, log_split, t_level_new, t_scale_new, coeffsq, ps_polys);

    // 对应 Lattigo he/polynomial.go:137-138。
    //     eval.Rescale(res)
    //     res = eval.MulNew(res, XPow)
    res.scale_ /= safe_cast<double>(modulus[res.level_].value());
    res.level_ -= 1;
    res.level_ = std::min(res.level_, x_pow.level_);
    res.scale_ *= x_pow.scale_;

    // 对应 Lattigo he/polynomial.go:140。
    //     bsgsR, tmp := recursePS(... coeffsr ..., res.Scale, ...)
    auto tmp = recursePS2(power_basis_sim, log_split, target_level, res.scale_, coeffsr, ps_polys);

    // 对应 Lattigo he/polynomial.go:144-146。
    // ScalePrecision 仍是 128，因此阈值为 116。
    if (!scale_in_delta_lattigo(tmp.scale_, res.scale_, 116.0))
    {
        POSEIDON_THROW(invalid_argument_error, "recursePS2: res.Scale != tmp.Scale");
    }

    // 对应 Lattigo he/polynomial.go:148。
    // Lattigo 返回 append(bsgsQ, bsgsR...)；这里通过递归 push_back 顺序
    // 直接写入 ps_polys，所以只需返回模拟 res。
    return res;
}

tuple<uint32_t, double> EvaluatorCkksBase::pre_scalar_level(
    bool is_even, bool is_odd, const map<uint32_t, Ciphertext> &monomial_basis,
    double current_scale, uint32_t current_level, const PolynomialVector &pol, uint32_t log_split,
    uint32_t log_degree) const
{

    auto x = monomial_basis;
    auto &slots_index = pol.index();
    auto minimum_degree_non_zero_coefficient = pol.polys()[0].data().size() - 1;

    auto target_scale = current_scale;
    auto target_level = current_level;
    auto params = context_.parameters_literal();
    auto &modulus = params->q();
    auto degree = params->degree();
    auto slots = degree >> 1;
    if (is_even && !is_odd)
        minimum_degree_non_zero_coefficient--;

    size_t maximum_ciphertext_degree = 0;
    for (int i = pol.polys()[0].degree(); i > 0; i--)
    {
        if (x.count(i))
        {
            maximum_ciphertext_degree = max(maximum_ciphertext_degree, x.at(i).size() - 1);
        }
    }
    // If an index slot is given (either multiply polynomials or masking)
    if (!slots_index.empty())
    {
        bool to_encode = false;
        // Allocates temporary buffer for coefficients encoding
        // If the degree of the poly is zero
        if (minimum_degree_non_zero_coefficient == 0)
        {
            while (1)
            {
                if (target_scale + 1000000000 >= min_scale_)
                {
                    break;
                }
                else
                {
                    POSEIDON_THROW(invalid_argument_error, "why!");
                }
            }
        }
        else
        {
            // mult_plain
            for (int key = pol.polys()[0].degree(); key > 0; key--)
            {
                auto reset = false;
                // Loops over the polynomials
                for (int i = 0; i < pol.polys().size(); i++)
                {
                    auto is_not_zero = is_not_negligible(pol.polys()[i].data()[key]);
                    // Looks for a non-zero coefficient
                    if (is_not_zero)
                    {
                        to_encode = true;
                    }
                }

                if (to_encode)
                {
                    Plaintext tmp;
                    double scale;
                    while (1)
                    {
                        scale = target_scale / x[key].scale();
                        if (scale >= min_scale_)
                        {
                            break;
                        }
                        else
                        {
                            target_level++;

                            target_scale *= safe_cast<double>(modulus[target_level].value());
                        }
                    }

                    to_encode = false;
                }
            }
        }
    }
    else
    {
        POSEIDON_THROW(invalid_argument_error, "slots_index is zero");
    }

    return make_tuple(target_level, target_scale);
}

void EvaluatorCkksBase::evaluate_polynomial(const PolynomialVector& poly_vec, const Ciphertext& ct_basis, Ciphertext& ct_res,
    bool is_chev, bool is_lazy, double target_scale, double min_scale, const RelinKeys& relin_key, const CKKSEncoder& encoder)
{
    spdlog::debug("----------  evaluate_polynomial begin  ----------");
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

    spdlog::debug("----------  evaluate_polynomial--gen power end  ----------");

    // debug for
    for (auto i = 0; i < poly_vec.size(); i++)
    {
        spdlog::debug("origin poly[{}], degree = {}, is_odd = {}, is_even = {}, type is chebyshev = {}",
            i, poly_vec[i].degree(), poly_vec[i].is_odd(), poly_vec[i].is_even(), poly_vec[i].basis_type() == Chebyshev);
        for (auto j = 0; j < poly_vec[i].size(); j++)
        {
            spdlog::debug("origin poly[{}] coeff[{}] = {}", i, j, poly_vec[i].data()[j].real());
        }
    }

    PatersonStockmeyerPolynomialVector ps_polys_vec;
    int input_level = ct_basis.level();
    double input_scale = ct_basis.scale();
    spdlog::debug("----------  evaluate_polynomial--get_paterson_stockmeyer_polynomial_vector begin  ----------");
    get_paterson_stockmeyer_polynomial_vector(poly_vec, input_level - log_degree + 1, input_scale, target_scale, ps_polys_vec);
    spdlog::debug("----------  evaluate_polynomial--get_paterson_stockmeyer_polynomial_vector end  ----------");

    // debug for
    for (auto i = 0; i < ps_polys_vec.size(); i++)
    {
        auto& ps_poly = ps_polys_vec[i];
        spdlog::debug("ps_polys_vec[{}], degree = {}, base = {}, level = {}, scale = {}",
            i, ps_poly.degree_, ps_poly.base_, ps_poly.level_, ps_poly.scale_);
        for (auto j = 0; j < ps_poly.size(); j++)
        {
            auto& tmp = ps_poly[j];
            spdlog::debug("ps_polys_vec[{}][{}], degree = {}, is_odd = {}, is_even = {}, type is chebyshev = {}",
                i, j, tmp.degree(), tmp.is_odd(), tmp.is_even(), tmp.basis_type() == Chebyshev);
            for (auto k = 0; k < tmp.size(); k++)
            {
                if (tmp.is_valid(k))
                {
                    spdlog::debug("coeff[{}] = {}", k, tmp.data()[k].real());
                }
            }
        }
    }

    spdlog::debug("----------  evaluate_polynomial--evaluate_paterson_stockmeyer_polynomial_vector begin  ----------");
    evaluate_paterson_stockmeyer_polynomial_vector(ps_polys_vec, power_basis, ct_res, relin_key, encoder);
    spdlog::debug("----------  evaluate_polynomial--evaluate_paterson_stockmeyer_polynomial_vector end  ----------");
    spdlog::debug("----------  evaluate_polynomial end  ----------");
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
    recurse_ps(poly, log_split, input_level - bit_len(level_consumed_per_rescale * (poly.degree()-1)),
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
    const map<uint32_t, Ciphertext> &power_basis, Ciphertext& ct_res, const RelinKeys& relin_key, const CKKSEncoder& encoder) const
{
    auto split = ps_polys_vec.polys_[0].polys_.size();

    std::vector<BabyStep> baby_steps(split);
    for (auto i = 0; i < baby_steps.size(); i++)
    {
        spdlog::debug("----------  evaluate_paterson_stockmeyer_polynomial_vector::evaluate_baby_step[{}] begin  ------------", i);
        evaluate_baby_step(ps_polys_vec, power_basis, i, baby_steps[split-i-1].value, encoder);
        spdlog::debug("----------  evaluate_paterson_stockmeyer_polynomial_vector::evaluate_baby_step[{}] end  ------------", i);
    }

    spdlog::debug("----------  evaluate_paterson_stockmeyer_polynomial_vector::evaluate_giant_step begin  ------------");
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
            evaluate_giant_step(i, giant_steps, baby_steps, power_basis, relin_key);
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

    spdlog::debug("----------  evaluate_paterson_stockmeyer_polynomial_vector::evaluate_giant_step end  ------------");

    if (baby_steps[0].value.size() == 3)
    {
        relinearize(baby_steps[0].value, baby_steps[0].value, relin_key);
    }

    // TODO rescale or rescale_dynamic
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
        if (minimum_degree_non_zero_coefficient == 0)
        {
            if (!ciph_res.is_valid())
            {
                ciph_res.resize(context_, context_.crt_context()->parms_id_map().at(target_level), 2);
                // TODO
                ciph_res.is_ntt_form() = true;
                ciph_res.scale() = target_scale;
            }

            if (is_even)
            {
                add_const(ciph_res, poly_vec.polys()[0].data()[0], ciph_res, encoder);
            }

            return;
        }

        ciph_res.resize(context_, context_.crt_context()->parms_id_map().at(target_level), maximum_ciphertext_degree + 1);
        // TODO
        ciph_res.is_ntt_form() = true;
        ciph_res.scale() = target_scale;

        if (is_even)
        {
            add_const(ciph_res, poly_vec.polys()[0].data()[0], ciph_res, encoder);
        }

        for (auto key = poly_vec.polys()[0].data().size(); key > 0; key--)
        {
            if ((key != 0) && (!(is_even || is_odd)) || ((key & 1) == 0 && is_even) || ((key & 1) == 1 && is_odd))
            {
                Ciphertext ciph_tmp;
                multiply_const(power_basis.at(key), poly_vec.polys()[0].data()[0], 1.0, ciph_tmp, encoder);
                spdlog::debug("target_level = {}, ciph_res.level = {}, ciph_tmp.level = {}, ciph_res.scale = {}, ciph_tmp.scale = {}",
                    target_level, ciph_res.level(), ciph_tmp.level(), ciph_res.scale(), ciph_tmp.scale());
                if (ciph_tmp.level() > target_level)
                {
                    drop_modulus(ciph_tmp, ciph_tmp, target_level);
                }
                add(ciph_res, ciph_tmp, ciph_res);
            }
        }
    }
}

void EvaluatorCkksBase::evaluate_monomial(const Ciphertext& a, Ciphertext& b, const Ciphertext& xpow, const RelinKeys& relin_key) const
{
    if (b.size() == 3)
    {
        relinearize(b, b, relin_key);
    }

    rescale(b, b);
    multiply(b, xpow, b);

    // TODO  特殊条件判断
    // if (a.scale())

    add(a, b, b);
}

void EvaluatorCkksBase::evaluate_baby_step(const PatersonStockmeyerPolynomialVector &ps_poly_vec,
                                            const map<uint32_t, Ciphertext> &power_basis,
                                            int j, Ciphertext& ct_res, const CKKSEncoder &encoder) const
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

    evaluate_polynomial_vector_from_power_basis_optimized(poly_vec_tmp, power_basis, ct_res, level, scale, encoder);
}

void EvaluatorCkksBase::evaluate_giant_step(int i, const vector<int> &giant_steps, vector<BabyStep> &baby_steps,
                                             const map<uint32_t, Ciphertext> &power_basis, const RelinKeys &relin_keys) const
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

        evaluate_monomial(even.value, odd.value, power_basis.at(deg), relin_keys);

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
            if (poly.is_valid(i) && (!(is_even || is_odd)) || (((i&1) == 0) && is_even) || (((i&1) == 1) && is_odd))
            {
                pq.data()[i-n] = poly.data()[i];
            }
        }
        break;
    case Chebyshev:
        for (int i = n + 1, j = 1; i < poly.degree() + 1; i++, j++)
        {
            if (poly.is_valid(i) && (!(is_even || is_odd)) || (((i&1) == 0) && is_even) || (((i&1) == 1) && is_odd))
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

void sim_rescale()
{

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

    if (!scale_in_delta_lattigo(op_res_recurse_sr.scale_, op_res_recurse_sq.scale_, 116.0))
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

    std::cout << "n = " << n << "  a = " << a << "  b = " << b << std::endl;

    bool need_rescale_a =
        gen_power_optimized_inner(monomial_basis, a, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                                  encoder);
    bool need_rescale_b =
        gen_power_optimized_inner(monomial_basis, b, lazy && !is_pow2, is_chev, min_scale, relin_keys,
                                  encoder);

    std::cout << "lazy = " << lazy << "  min_scale = " << min_scale << std::endl;
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

        multiply(monomial_basis[a], monomial_basis[b], monomial_basis[n]);
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

void EvaluatorCkksBase::evaluate_poly_from_poly_nomial_basis(
    bool is_even, bool is_odd, const map<uint32_t, Ciphertext> &monomial_basis,
    const RelinKeys &relin_keys, uint32_t target_level, double target_scale,
    const PolynomialVector &pol, uint32_t log_split, uint32_t log_degree, Ciphertext &destination,
    const CKKSEncoder &encoder) const
{

    auto x = monomial_basis;
    auto &slots_index = pol.index();
    auto minimum_degree_non_zero_coefficient = pol.polys()[0].data().size() - 1;
    auto min_scale = min_scale_;
    auto &id_level_map = context_.crt_context()->parms_id_map();
    auto &parms_id = id_level_map.at(target_level);
    auto slots = context_.parameters_literal()->slot();
    vector<complex<double>> values(slots);

    if (is_even && !is_odd)
    {
        minimum_degree_non_zero_coefficient--;
    }

    size_t maximum_ciphertext_degree = 0;
    for (int i = pol.polys()[0].degree(); i > 0; i--)
    {
        if (x.count(i))
        {
            maximum_ciphertext_degree = max(maximum_ciphertext_degree, x.at(i).size() - 1);
        }
    }

    // If an index slot is given (either multiply polynomials or masking)
    if (!slots_index.empty())
    {
        bool to_encode = false;
        // Allocates temporary buffer for coefficients encoding
        // If the degree of the poly is zero
        if (minimum_degree_non_zero_coefficient == 0)
        {
            if (!destination.is_valid())
            {
                destination.resize(context_, parms_id, 2);
                destination.is_ntt_form() = true;
                destination.scale() = target_scale;
            }

            for (int i = 0; i < pol.polys().size(); i++)
            {
                auto aa = pol.polys()[i].data()[0];
                bool is_not_zero = is_not_negligible(aa);
                if (is_not_zero)
                {
                    to_encode = true;
                    for (auto j : slots_index[i])
                    {
                        values[j] = aa;
                    }
                }
            }

            if (to_encode)
            {
                to_encode = false;
                Plaintext tmp;
                auto level = destination.level();
                auto degree = destination.poly_modulus_degree();
                auto &parms_id_tmp = id_level_map.at(level);
                encoder.encode(values, parms_id_tmp, destination.scale(), tmp);
                add_plain(destination, tmp, destination);
            }
        }
        else
        {
            for (int key = pol.polys()[0].degree(); key > 0; key--)
            {
                auto reset = false;
                // Loops over the polynomials
                for (int i = 0; i < pol.polys().size(); i++)
                {
                    auto is_not_zero = is_not_negligible(pol.polys()[i].data()[key]);
                    // Looks for a non-zero coefficient
                    if (is_not_zero)
                    {
                        to_encode = true;

                        if (!reset)
                        {
                            for (int j = 0; j < values.size(); j++)
                            {
                                values[j] = 0.0;
                            }
                        }

                        for (auto j : slots_index[i])
                        {
                            values[j] = pol.polys()[i].data()[key];
                        }
                    }
                }

                if (to_encode)
                {
                    Plaintext tmp;
                    auto level = x[key].level();
                    auto degree = x[key].poly_modulus_degree();
                    double scale;
                    scale = target_scale / x[key].scale();
                    auto &parms_id_tmp = id_level_map.at(level);
                    encoder.encode(values, parms_id_tmp, scale, tmp);
                    if (!destination.is_valid())
                    {
                        multiply_plain(x.at(key), tmp, destination);
                    }
                    else
                    {
                        Ciphertext ciph;
                        multiply_plain(x.at(key), tmp, ciph);
                        add_dynamic(ciph, destination, destination, encoder);
                    }
                    to_encode = false;
                }
            }

            for (int j = 0; j < values.size(); j++)
            {
                values[j] = 0.0;
            }

            for (int i = 0; i < pol.polys().size(); i++)
            {
                auto aa = pol.polys()[i].data()[0];
                bool is_not_zero = is_not_negligible(aa);
                if (is_not_zero)
                {
                    to_encode = true;
                    for (auto j : slots_index[i])
                    {
                        values[j] = aa;
                    }
                }
            }

            if (to_encode)
            {
                Plaintext tmp;
                auto level = destination.level();

                std::cout << "level = " << level << std::endl;
                auto &parms_id_tmp = id_level_map.at(level);
                encoder.encode(values, parms_id_tmp, target_scale, tmp);
                add_plain(destination, tmp, destination);
            }

            destination.scale() = target_scale;
            if (destination.level() < target_level)
            {
                POSEIDON_THROW_LOGIC_ERROR(
                               "destination : destination level is small than target_level level!");
            }
            else if (target_level < destination.level())
            {
                drop_modulus(destination, destination, parms_id);
            }
        }
    }
    else
    {
        POSEIDON_THROW(invalid_argument_error, "slots_index is zero");
    }
}

void EvaluatorCkksBase::evaluate_polynomial_vector_from_power_basis_lattigo(
    const map<uint32_t, Ciphertext> &monomial_basis, uint32_t target_level,
    double target_scale, const PolynomialVector &pol, Ciphertext &destination,
    const CKKSEncoder &encoder) const
{
    // 对应 Lattigo circuits/common/polynomial/polynomial_evaluator.go:253-360。
    //     EvaluatePolynomialVectorFromPowerBasis(...)
    // 这个 helper 只给 recursePS 使用，不替换原 evaluate_poly_from_poly_nomial_basis。
    auto &slots_index = pol.index();
    auto even = pol.is_even();
    auto odd = pol.is_odd();

    // 对应 Lattigo polynomial_evaluator.go:266-270。
    //     minimumDegreeNonZeroCoefficient := len(pol.Value[0].Coeffs) - 1
    //     if even && !odd { minimumDegreeNonZeroCoefficient-- }
    auto minimum_degree_non_zero_coefficient = pol.polys()[0].data().size() - 1;
    if (even && !odd)
    {
        minimum_degree_non_zero_coefficient--;
    }

    // 对应 Lattigo polynomial_evaluator.go:272-279。
    // Lattigo 记录的是 ciphertext degree；Poseidon resize 需要 size，
    // 且最小合法 ciphertext size 是 2，所以这里用 max(2, power.size())。
    size_t maximum_ciphertext_size = 2;
    for (int i = pol.polys()[0].degree(); i > 0; i--)
    {
        if (monomial_basis.count(i))
        {
            maximum_ciphertext_size = max(maximum_ciphertext_size, monomial_basis.at(i).size());
        }
    }

    auto allocate_destination = [&](size_t size)
    {
        if (!destination.is_valid())
        {
            auto parms_id = context_.crt_context()->parms_id_map().at(target_level);
            destination.resize(context_, parms_id, size);
            destination.is_ntt_form() = true;
            destination.scale() = target_scale;
        }
    };

    auto add_vector_coefficient = [&](int key, double scale)
    {
        // 对应 Lattigo ckks/polynomial/polynomial_evaluator.go:89-108。
        //     GetVectorCoefficient(...)
        // Lattigo 每次都会把 values 全部置 nil，再按 Mapping 填当前 key。
        // Poseidon 用显式 0 表示 nil，因此每次 key 都必须重新清零。
        vector<complex<double>> values(context_.parameters_literal()->slot(),
                                       complex<double>(0.0, 0.0));
        bool to_encode = false;
        for (int i = 0; i < pol.polys().size(); i++)
        {
            auto coeff = pol.polys()[i].data()[key];
            if (is_not_negligible(coeff))
            {
                to_encode = true;
                for (auto j : slots_index[i])
                {
                    values[j] = coeff;
                }
            }
        }

        if (!to_encode)
        {
            return;
        }

        Plaintext tmp;
        auto &parms_id_tmp = context_.crt_context()->parms_id_map().at(destination.level());
        encoder.encode(values, parms_id_tmp, scale, tmp);
        add_plain(destination, tmp, destination);
    };

    auto mul_then_add_vector_coefficient = [&](int key)
    {
        // 对应 Lattigo polynomial_evaluator.go:315。
        //     eval.MulThenAdd(X[key], eval.GetVectorCoefficient(pol, key), res)
        // 深入 schemes/ckks/evaluator.go:909-1024 后，vector/scalar 分支会把
        // 明文 scale 设置成 opOut.Scale / op0.Scale。这里直接编码为
        // target_scale / X[key].scale()，再 multiply_plain + add_dynamic。
        vector<complex<double>> values(context_.parameters_literal()->slot(),
                                       complex<double>(0.0, 0.0));
        bool to_encode = false;
        for (int i = 0; i < pol.polys().size(); i++)
        {
            auto coeff = pol.polys()[i].data()[key];
            if (is_not_negligible(coeff))
            {
                to_encode = true;
                for (auto j : slots_index[i])
                {
                    values[j] = coeff;
                }
            }
        }

        if (!to_encode)
        {
            return;
        }

        Plaintext tmp;
        auto level = monomial_basis.at(key).level();
        auto &parms_id_tmp = context_.crt_context()->parms_id_map().at(level);
        auto scale = target_scale / monomial_basis.at(key).scale();
        encoder.encode(values, parms_id_tmp, scale, tmp);

        Ciphertext ciph;
        multiply_plain(monomial_basis.at(key), tmp, ciph);
        add_dynamic(ciph, destination, destination, encoder);
    };

    auto add_single_coefficient = [&](int key, double scale)
    {
        // 对应 Lattigo polynomial_evaluator.go:330-342 中 mapping == nil 的
        // GetSingleCoefficient/Add 分支。Poseidon 没有 nil mapping 类型，
        // 空 index 在这里按 Lattigo 的 nil mapping 分支处理。
        auto coeff = pol.polys()[0].data()[key];
        if (is_not_negligible(coeff))
        {
            Plaintext tmp;
            auto &parms_id_tmp = context_.crt_context()->parms_id_map().at(destination.level());
            encoder.encode(coeff, parms_id_tmp, scale, tmp);
            add_plain(destination, tmp, destination);
        }
    };

    auto mul_then_add_single_coefficient = [&](int key)
    {
        // 对应 Lattigo polynomial_evaluator.go:351。
        //     eval.MulThenAdd(X[key], eval.GetSingleCoefficient(...), res)
        auto coeff = pol.polys()[0].data()[key];
        if (!is_not_negligible(coeff))
        {
            return;
        }

        Ciphertext ciph;
        auto scale = target_scale / monomial_basis.at(key).scale();
        multiply_const(monomial_basis.at(key), coeff, scale, ciph, encoder);
        add_dynamic(ciph, destination, destination, encoder);
    };

    if (!slots_index.empty())
    {
        // 对应 Lattigo polynomial_evaluator.go:282-321，mapping != nil。
        if (minimum_degree_non_zero_coefficient == 0)
        {
            allocate_destination(2);
            if (even)
            {
                add_vector_coefficient(0, target_scale);
            }
            return;
        }

        allocate_destination(maximum_ciphertext_size);
        if (even)
        {
            add_vector_coefficient(0, target_scale);
        }

        for (int key = pol.polys()[0].degree(); key > 0; key--)
        {
            if (!(even || odd) || ((key & 1) == 0 && even) || ((key & 1) == 1 && odd))
            {
                mul_then_add_vector_coefficient(key);
            }
        }
    }
    else
    {
        // 对应 Lattigo polynomial_evaluator.go:323-356，mapping == nil。
        // Poseidon 的老函数遇到空 index 会报错；这里为了贴近 Lattigo，按单个
        // polynomial 的 nil mapping 分支计算。
        if (minimum_degree_non_zero_coefficient == 0)
        {
            allocate_destination(2);
            if (even)
            {
                add_single_coefficient(0, target_scale);
            }
            return;
        }

        allocate_destination(maximum_ciphertext_size);
        if (even)
        {
            add_single_coefficient(0, target_scale);
        }

        for (int key = pol.polys()[0].degree(); key > 0; key--)
        {
            if (!(even || odd) || ((key & 1) == 0 && even) || ((key & 1) == 1 && odd))
            {
                mul_then_add_single_coefficient(key);
            }
        }
    }

    destination.scale() = target_scale;
    if (destination.level() > target_level)
    {
        auto parms_id = context_.crt_context()->parms_id_map().at(target_level);
        drop_modulus(destination, destination, parms_id);
    }
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
    result.scale() = eva_poly.scaling_factor();

    double pre_min_scale = min_scale_;
    set_min_scale(eva_poly.scaling_factor());
    auto target_scale = eva_poly.scaling_factor();
    vector<Polynomial> poly_sin{eva_poly.sine_poly()};
//  vector<Polynomial> poly_asin{eva_poly.arcsine_poly()};

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
    // evaluate_poly_vector(tmp, result, polys_sin, target_scale, relin_keys, encoder);
    // TODO substitute
    spdlog::debug("target_scale = {}", target_scale);
    evaluate_polynomial(polys_sin, tmp, result,
        polys_sin.polys()[0].basis_type() == Chebyshev, false, target_scale,
        min_scale_, relin_keys, encoder);


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

    double diff_scale = eva_poly.scaling_factor() / result.scale();
    if (diff_scale < coeff_modulus.back().value())
    {
        diff_scale *= coeff_modulus[result.level()].value();
        diff_scale *= coeff_modulus[result.level() - 1].value();
    }
    multiply_const(result, 1.0, diff_scale, result, encoder);
    rescale_dynamic(result, result, eva_poly.scaling_factor());

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
        multiply_const_direct(result, safe_cast<int>(scale), result, encoder);
        result.scale() *= scale;
    }

    auto parms_id = context_.crt_context()->parms_id_map().at(q0_level);
    drop_modulus(result, result, parms_id);

    Ciphertext ciph_raise;
    read(result);
    raise_modulus(result, ciph_raise);

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
    eval_mod(ciph_imag, ciph_imag_mod, eval_mod_poly, relin_keys, encoder);
    eval_mod(ciph_real, ciph_real_mod, eval_mod_poly, relin_keys, encoder);

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
    if (!util::are_approximate<double>(ciph.scale(), plain.scale()))
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
    if (!util::are_approximate<double>(ciph1.scale(), ciph2.scale()))
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
        spdlog::debug("ciph1.level = {}, ciph2.level = {}", ciph1.level(), ciph2.level());
        POSEIDON_THROW(invalid_argument_error, "add_inplace : ciph1 and ciph2 parameter mismatch");
    }
    if (ciph1.is_ntt_form() != ciph2.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "NTT form mismatch");
    }
    if (!util::are_approximate<double>(ciph1.scale(), ciph2.scale()))
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

    if (util::are_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
    }
    else if (ciph1.scale() > ciph2.scale())
    {
        scaling_factor_ratio = ciph1.scale() / ciph2.scale();
        scaling_factor_ratio += 0.5;
        if (scaling_factor_ratio < min_scale_)
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
        if (scaling_factor_ratio < min_scale_)
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

    if (util::are_approximate<double>(ciph1.scale(), ciph2.scale()))
    {
    }
    else if (ciph1.scale() > ciph2.scale())
    {
        scaling_factor_ratio = ciph1.scale() / ciph2.scale();

        scaling_factor_ratio += 0.5;
        if (scaling_factor_ratio < min_scale_)
        {
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
        if (scaling_factor_ratio < min_scale_)
        {
            POSEIDON_THROW(invalid_argument_error, "add_dynamic : ciph scale don't support! ");
        }
        multiply_const(ciph2, scaling_factor_ratio, 1.0, tmp_scale, encoder);
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

void EvaluatorCkksBase::accumulate_top_n(const Ciphertext &ciph, Ciphertext &result, int n,
                                         const CKKSEncoder &encoder, const Encryptor &enc,
                                         const GaloisKeys &rot_keys) const
{
    if (n <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "n cannot be negative");
    }

    Ciphertext ciph_rotate_sum = ciph;

    std::vector<std::complex<double>> zero = {{0.0, 0.0}};
    Plaintext plain_zero;
    Ciphertext ciph_sum;
    encoder.encode(zero, ciph.parms_id(), ciph.scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_sum);

    int cnt = 0;
    int bottom_nth = 0;
    const int const_n = n;
    while (n)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            bottom_nth += 1 << cnt;
            rotate(ciph_rotate_sum, ciph_tmp, const_n - bottom_nth, rot_keys);
            add(ciph_sum, ciph_tmp, ciph_sum);
        }
        n = n >> 1;
        if (n)
        {
            rotate(ciph_rotate_sum, ciph_tmp, 1 << cnt, rot_keys);
            add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
        ++cnt;
    }
    add(ciph_sum, ciph_rotate_sum, ciph_sum);
    result = ciph_sum;
}

void EvaluatorCkksBase::sigmoid_approx(const Ciphertext &ciph, Ciphertext &result,
                                       const CKKSEncoder &encoder, const RelinKeys &relin_keys)
{
    vector<complex<double>> buffer(4, 0);
    buffer[0] = 0.5;
    buffer[1] = 0.197;
    buffer[3] = -0.004;

    Polynomial approxF(buffer, 0, 0, 4, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    vector<vector<int>> slots_index(1,
                                    vector<int>(context_.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context_.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context_.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;  // Index with all even slots
    }
    slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v, slots_index);
    evaluate_poly_vector(ciph, result, polys, ciph.scale(), relin_keys, encoder);
}

void EvaluatorCkksBase::conv(const Ciphertext &ciph_f, const Ciphertext &ciph_g_rev,
                             Ciphertext &result, const uint size, const CKKSEncoder &encoder,
                             const Encryptor &enc, const GaloisKeys &galois_keys,
                             const RelinKeys &relin_keys) const
{
    Ciphertext ciph_res;
    Ciphertext ciph_f_rotate = ciph_f;
    for (auto i = 0; i < size; ++i)
    {
        rotate(ciph_f_rotate, ciph_f_rotate, 1, galois_keys);
        Ciphertext ciph_tmp;
        multiply_relin(ciph_f_rotate, ciph_g_rev, ciph_tmp, relin_keys);
        accumulate_top_n(ciph_tmp, ciph_tmp, size, encoder, enc, galois_keys);

        rotate(ciph_tmp, ciph_tmp, i, galois_keys);

        std::vector<std::complex<double>> zero = {{0.0, 0.0}};
        zero[i] = {1.0, 0.0};
        Plaintext plain_zero;
        encoder.encode(zero, ciph_tmp.parms_id(), ciph_tmp.scale(), plain_zero);

        multiply_plain(ciph_tmp, plain_zero, ciph_tmp);
        relinearize(ciph_tmp, ciph_tmp, relin_keys);

        if (!ciph_res.is_valid())
        {
            ciph_res = ciph_tmp;
        }
        else
        {
            add(ciph_res, ciph_tmp, ciph_res);
        }
    }

    result = ciph_res;
}

}  // namespace poseidon
