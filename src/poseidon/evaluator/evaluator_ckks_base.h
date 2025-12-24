#pragma once

#include "evaluator_base.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/key/keyswitch.h"

namespace poseidon
{
class EvaluatorCkksBase : public EvaluatorBase
{
    using Base = EvaluatorBase;

public:
    explicit EvaluatorCkksBase(const PoseidonContext &context);
    virtual ~EvaluatorCkksBase() = default;

public:
    virtual void read(Plaintext &plain) const override;
    virtual void read(Ciphertext &ciph) const override;

    virtual void ntt_fwd(const Plaintext &plain, Plaintext &result,
                         parms_id_type parms_id = parms_id_zero) const override;
    virtual void ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const override;
    virtual void ntt_inv(const Ciphertext &ciph, Ciphertext &result) const override;

    virtual void sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const override;

    virtual void add_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const override;
    virtual void add(const Ciphertext &ciph1, const Ciphertext &ciph2,
                     Ciphertext &result) const override;
    virtual void sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                     Ciphertext &result) const override;
    virtual void multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                          Ciphertext &result) const override;
    virtual void square_inplace(Ciphertext &ciph,
                                MemoryPoolHandle pool = MemoryManager::GetPool()) const override;

    virtual void relinearize(const Ciphertext &ciph1, Ciphertext &result,
                             const RelinKeys &relin_keys) const override;

    virtual void multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result, const RelinKeys &relin_keys) const override;

    virtual void rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                        const GaloisKeys &galois_keys) const override;
    virtual void rotate_row(const Ciphertext &ciph, Ciphertext &result, int step,
                            const GaloisKeys &galois_keys) const override;
    virtual void rotate_col(const Ciphertext &ciph, Ciphertext &result,
                            const GaloisKeys &galois_keys) const override;
    virtual void drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                              parms_id_type parms_id) const override;
    virtual void
    multiply_plain_inplace(Ciphertext &ciph, const Plaintext &plain,
                           MemoryPoolHandle pool = MemoryManager::GetPool()) const override;
    virtual void multiply_by_diag_matrix_bsgs(const Ciphertext &ciph, const MatrixPlain &plain_mat,
                                              Ciphertext &result,
                                              const GaloisKeys &rot_key) const override;
    virtual void multiply_by_diag_matrix_bsgs_with_mutex(const Ciphertext &ciph,
                                                         MatrixPlain &plain_mat, Ciphertext &result,
                                                         const GaloisKeys &rot_key,
                                                         std::map<int, std::vector<int>> &ref1,
                                                         std::vector<int> &ref2,
                                                         std::vector<int> &ref3) const override;

    void drop_modulus(const Ciphertext &ciph, Ciphertext &result, uint32_t level) const;
    void drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const;

    void multiply_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                          Ciphertext &result) const;
    void dft(const Ciphertext &ciph, const LinearMatrixGroup &matrix_group, Ciphertext &result,
             const GaloisKeys &rot_key) const;
    void coeff_to_slot(const Ciphertext &ciph, const LinearMatrixGroup &matrix_group,
                       Ciphertext &result_real, Ciphertext &result_imag,
                       const GaloisKeys &galois_keys, const CKKSEncoder &encoder) const;
    void slot_to_coeff(const Ciphertext &ciph_real, const Ciphertext &ciph_imag,
                       const LinearMatrixGroup &matrix_group, Ciphertext &result,
                       const GaloisKeys &galois_keys, const CKKSEncoder &encoder) const;

    void evaluate_poly_vector(const Ciphertext &ciph, Ciphertext &destination,
                              const PolynomialVector &polys, double scale,
                              const RelinKeys &relin_keys, const CKKSEncoder &encoder) const;

    void eval_mod(const Ciphertext &ciph, Ciphertext &result, const EvalModPoly &eva_poly,
                  const RelinKeys &relin_keys, const CKKSEncoder &encoder);

    void bootstrap(const Ciphertext &ciph, Ciphertext &result,
                   const RelinKeys &relin_keys, const GaloisKeys &galois_keys,
                   const CKKSEncoder &encoder, EvalModPoly &eval_mod_poly);

    void multiply_const_direct(const Ciphertext &ciph, int const_data, Ciphertext &result,
                               const CKKSEncoder &encoder) const;

    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    void multiply_const(const Ciphertext &ciph, T const_data, double scale, Ciphertext &result,
                        const CKKSEncoder &encoder) const
    {
        if (const_data == 0.0 || const_data == complex<double>(0.0, 0.0))
        {
            multiply_const_direct(ciph, 0, result, encoder);
        }
        else
        {
            Plaintext tmp;
            encoder.encode(const_data, ciph.parms_id(), scale, tmp);
            multiply_plain(ciph, tmp, result);
        }
    }

    template <typename T, typename = std::enable_if_t<
                              std::is_same<std::remove_cv_t<T>, double>::value ||
                              std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    void add_const(const Ciphertext &ciph, T const_data, Ciphertext &result,
                   const CKKSEncoder &encoder) const
    {

        if (const_data == 0.0 || const_data == complex<double>(0.0, 0.0))
        {
            Plaintext tmp;
            encoder.encode(0, ciph.parms_id(), tmp);
            add_plain(ciph, tmp, result);
            return;
        }
        Plaintext tmp;
        encoder.encode(const_data, ciph.parms_id(), ciph.scale(), tmp);
        add_plain(ciph, tmp, result);
    }

    virtual void ntt_fwd(const Plaintext &plain, Plaintext &result) const;
    virtual void ntt_inv(const Plaintext &plain, Plaintext &result) const;

    virtual void conjugate(const Ciphertext &ciph, const GaloisKeys &galois_keys,
                           Ciphertext &result) const;
    virtual void rescale(const Ciphertext &ciph, Ciphertext &result) const;
    virtual void rescale_dynamic(const Ciphertext &ciph, Ciphertext &result,
                                 double min_scale) const;

    virtual void raise_modulus(const Ciphertext &ciph, Ciphertext &result) const;

    virtual void multiply_relin_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                        Ciphertext &result, const RelinKeys &relin_keys) const;
    virtual void sub_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2, Ciphertext &result,
                             const CKKSEncoder &encoder) const;
    virtual void add_dynamic(const Ciphertext &ciph1, const Ciphertext &ciph2, Ciphertext &result,
                             const CKKSEncoder &encoder) const;

    void sigmoid_approx(const Ciphertext &ciph, Ciphertext &result, const CKKSEncoder &encoder,
                        const RelinKeys &relin_keys)
    {
        vector<complex<double>> buffer(4, 0);
        buffer[0] = 0.5;
        buffer[1] = 0.197;
        buffer[3] = -0.004;

        Polynomial approxF(buffer, 0, 0, 4, Monomial);
        approxF.lead() = true;
        vector<Polynomial> poly_v{approxF};
        vector<vector<int>> slots_index(1, vector<int>(context_.parameters_literal()->degree() >> 1, 0));
        vector<int> idxF(context_.parameters_literal()->degree() >> 1);
        for (int i = 0; i < context_.parameters_literal()->degree() >> 1; i++)
        {
            idxF[i] = i;  // Index with all even slots
        }
        slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

        PolynomialVector polys(poly_v, slots_index);
        evaluate_poly_vector(ciph, result, polys, ciph.scale(), relin_keys, encoder);
    }

    void accumulate_top_n(const Ciphertext &ciph, Ciphertext &result, int n, const CKKSEncoder &encoder,
                          const Encryptor &enc, const GaloisKeys &rot_keys) const
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

    // result = conv(ciph_f, ciph_g_rev)
    void conv(const Ciphertext &ciph_f, const Ciphertext &ciph_g_rev, Ciphertext &result,
              const uint size, const CKKSEncoder &encoder, const Encryptor &enc,
              const GaloisKeys &galois_keys, const RelinKeys &relin_keys) const
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


private:
    inline void set_min_scale(double scale) { min_scale_ = scale; }

    void rescale_for_bootstrap(Ciphertext &ciph1);

    void gen_power(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy, bool is_chev,
                   double min_scale, const RelinKeys &relin_keys, const CKKSEncoder &encoder) const;
    void gen_power_inner(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy,
                         bool is_chev, double min_scale, const RelinKeys &relin_keys,
                         const CKKSEncoder &encoder) const;

    void recurse(const map<uint32_t, Ciphertext> &monomial_basis, const RelinKeys &relin_keys,
                 uint32_t target_level, double target_scale, const PolynomialVector &pol,
                 uint32_t log_split, uint32_t log_degree, Ciphertext &destination,
                 const CKKSEncoder &encoder, bool is_odd, bool is_even, uint32_t &num) const;
    POSEIDON_NODISCARD tuple<uint32_t, double>
    pre_scalar_level(bool is_even, bool is_odd, const map<uint32_t, Ciphertext> &monomial_basis,
                     double current_scale, uint32_t current_level, const PolynomialVector &pol,
                     uint32_t log_split, uint32_t log_degree) const;

    void evaluate_poly_from_poly_nomial_basis(bool is_even, bool is_odd,
                                              const map<uint32_t, Ciphertext> &monomial_basis,
                                              const RelinKeys &relin_keys, uint32_t target_level,
                                              double target_scale, const PolynomialVector &pol,
                                              uint32_t log_split, uint32_t log_degree,
                                              Ciphertext &destination,
                                              const CKKSEncoder &encoder) const;

    void add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const;
    void add_inplace(Ciphertext &ciph1, const Ciphertext &ciph2) const;
    void rescale_inplace(const Ciphertext &ciph, Ciphertext &result,
                         MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    void ckks_multiply(Ciphertext &ciph1, const Ciphertext &ciph2, MemoryPoolHandle pool) const;
    void multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                          MemoryPoolHandle pool = MemoryManager::GetPool()) const;

    std::shared_ptr<KSwitchBase> kswitch_{nullptr};

protected:
    double min_scale_;
};

}  // namespace poseidon
