#include "evaluator_ckks_base.h"
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/util/debug.h"

namespace poseidon
{

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

    bool odd = true;
    bool even = true;

    for (auto p : polys.polys())
    {
        auto [tmp0, tmp1] = is_odd_or_even_polynomial(p);
        odd = odd && tmp0;
        even = even && tmp1;
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
            if (tmp_scale >= min_target_scale)
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
            if (tmp_scale >= min_target_scale)
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
            if (tmp_scale >= min_target_scale)
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
    if (is_even)
        minimum_degree_non_zero_coefficient--;

    size_t maximum_ciphertext_degree = 0;
    for (int i = pol.polys()[0].degree(); i > 0; i--)
    {
        if (x.count(i))
        {
            maximum_ciphertext_degree = max(maximum_ciphertext_degree, x.at(i).level());
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
                if (target_scale >= min_scale_)
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

    if (is_even)
    {
        minimum_degree_non_zero_coefficient--;
    }

    size_t maximum_ciphertext_degree = 0;
    for (int i = pol.polys()[0].degree(); i > 0; i--)
    {
        if (x.count(i))
        {
            maximum_ciphertext_degree = max(maximum_ciphertext_degree, x.at(i).level());
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

                auto &parms_id_tmp = id_level_map.at(level);
                encoder.encode(values, parms_id_tmp, target_scale, tmp);
                add_plain(destination, tmp, destination);
            }

            destination.scale() = target_scale;
            if (destination.level() < target_level)
            {
                throw logic_error("destination : destination level is small than target_level level!");
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
    evaluate_poly_vector(tmp, result, polys_sin, target_scale, relin_keys, encoder);
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

    auto coeffs_to_slots_scaling = eval_mod_poly.q_div() / (eval_mod_poly.k() * eval_mod_poly.sc_fac() * eval_mod_poly.q_diff());

    HomomorphicDFTMatrixLiteral tmp_matrix(0, context_.parameters_literal()->log_n(), context_.parameters_literal()->log_slots(),
                                    static_cast<uint32_t>(context_.parameters_literal()->q().size() - 1), vector<uint32_t>(3, 1), true,
                                    coeffs_to_slots_scaling, false, 1);
    LinearMatrixGroup coeff_to_slot_dft_matrix;
    tmp_matrix.create(coeff_to_slot_dft_matrix, const_cast<CKKSEncoder &>(encoder), 2);

    coeff_to_slot(ciph_raise, coeff_to_slot_dft_matrix, ciph_real, ciph_imag, galois_keys, encoder);

    eval_mod_poly.set_level_start(static_cast<uint32_t>(context_.crt_context()->get_context_data(ciph_real.parms_id())->level()));
    eval_mod(ciph_imag, ciph_imag_mod, eval_mod_poly, relin_keys, encoder);
    eval_mod(ciph_real, ciph_real_mod, eval_mod_poly, relin_keys, encoder);

    ciph_imag_mod.scale() = context_.parameters_literal()->scale();
    ciph_real_mod.scale() = context_.parameters_literal()->scale();

    auto slots_to_coeffs_scaling = context_.parameters_literal()->scale() / ((double)eval_mod_poly.scaling_factor() /
                                                         (double)eval_mod_poly.message_ratio());
    HomomorphicDFTMatrixLiteral tmp_matrix_inverse(1, context_.parameters_literal()->log_n(), context_.parameters_literal()->log_slots(), static_cast<uint32_t>(context_.crt_context()->get_context_data(ciph_real_mod.parms_id())->level()),
                                                                             vector<uint32_t>(3, 1), true, slots_to_coeffs_scaling, false, 1);
    LinearMatrixGroup slot_to_coeff_dft_matrix;
    tmp_matrix_inverse.create(slot_to_coeff_dft_matrix, const_cast<CKKSEncoder &>(encoder), 1);

    slot_to_coeff(ciph_real_mod, ciph_imag_mod, slot_to_coeff_dft_matrix, result, galois_keys, encoder);
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
    size_t ciph2_size = ciph1.size();
    size_t max_count = max(ciph1_size, ciph2_size);
    size_t min_count = min(ciph1_size, ciph2_size);

    // Size check
    if (!product_fits_in(max_count, coeff_count))
    {
        throw logic_error("invalid parameters");
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
        throw logic_error("invalid parameters");
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

void EvaluatorCkksBase::square_inplace(Ciphertext &ciph,
                                       MemoryPoolHandle pool) const
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
        throw logic_error("invalid parameters");
    }

    // Set up iterator for the base
    auto coeff_modulus = iter(modulus);
    // Prepare result

    ciph1.resize(context_, parms.parms_id(), dest_size);

    ciph1.is_ntt_form() = true;
    // Set up iterators for input ciphs
    PolyIter ciph1_iter = iter(ciph1);
    ConstPolyIter ciph2_iter = iter(ciph2);
    auto start = chrono::high_resolution_clock::now();

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
            POSEIDON_ITERATE(coeff_modulus, coeff_modulus_size,
                             [&](auto I)
                             {
                                 POSEIDON_ITERATE(
                                     iter(size_t(0)), num_tiles,
                                     [&](POSEIDON_MAYBE_UNUSED auto J)
                                     {
                                         // Compute third output polynomial, overwriting input
                                         // x[2] = x[1] * y[1]
                                         dyadic_product_coeffmod(ciph1_1_iter[0], ciph2_1_iter[0],
                                                                 tile_size, I, ciph1_2_iter[0]);

                                         // Compute second output polynomial, overwriting input

                                         // temp = x[1] * y[0]
                                         dyadic_product_coeffmod(ciph1_1_iter[0], ciph2_0_iter[0],
                                                                 tile_size, I, temp);
                                         // x[1] = x[0] * y[1]
                                         dyadic_product_coeffmod(ciph1_0_iter[0], ciph2_1_iter[0],
                                                                 tile_size, I, ciph1_1_iter[0]);
                                         // x[1] += temp
                                         add_poly_coeffmod(ciph1_1_iter[0], temp, tile_size, I,
                                                           ciph1_1_iter[0]);

                                         // Compute first output polynomial, overwriting input
                                         // x[0] = x[0] * y[0]
                                         dyadic_product_coeffmod(ciph1_0_iter[0], ciph2_0_iter[0],
                                                                 tile_size, I, ciph1_0_iter[0]);

                                         // Manually increment iterators
                                         ciph1_0_iter++;
                                         ciph1_1_iter++;
                                         ciph1_2_iter++;
                                         ciph2_0_iter++;
                                         ciph2_1_iter++;
                                     });
                             });
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
}  // namespace poseidon
