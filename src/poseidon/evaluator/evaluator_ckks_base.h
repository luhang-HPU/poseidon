#pragma once

#include "evaluator_base.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/encryptor.h"
#include "poseidon/key/keyswitch.h"

#include <cstdint>
#include <string>

namespace poseidon
{

#ifdef DEBUG
class CKKSEncoder;
class Decryptor;
#endif

struct BabyStep
{
    Ciphertext value;
    int degree = 0;
};

struct BabyStepMessage
{
    std::complex<double> value = 0.0;
    int degree = 0;
    bool valid = true;
};

struct BootstrapConfig
{
    // Approximation interval [-boundary_k, boundary_k].
    uint32_t boundary_k = 25;
    // Base-2 logarithm of the message ratio used during modulus raising.
    uint32_t log_message_ratio = 5;
    // Number of double-angle iterations after cosine approximation.
    uint32_t double_angle = 2;
    // Working scale used by the modular-reduction polynomial.
    uint32_t scaling_log = 51;
    // Requested ciphertext scale after SlotToCoeff. Zero preserves the
    // legacy output scale derived from q0 and the context scale.
    uint32_t output_scaling_log = 0;
    // Integer compensation applied to the final bootstrap result.
    uint32_t output_ratio = 32;
    // Return the real projection instead of preserving a complex message.
    bool project_real = true;
    // Zero selects the inverse coefficient derived from the cosine heap.
    double inverse_coeff = 0.0;
    // Empty uses the embedded cosine heap.
    std::string cosine_heap_path;
};

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
    // Accumulate an NTT ciphertext/plaintext product directly into an existing
    // ciphertext. This avoids materializing and copying a full temporary
    // ciphertext in linear-algebra hot paths.
    void multiply_plain_accumulate(const Ciphertext &ciph, const Plaintext &plain,
                                   Ciphertext &accumulator) const;
    // Fast path for a real scalar plaintext. A constant CKKS slot vector is a
    // degree-zero polynomial, so its NTT representation is one residue repeated
    // across each limb; no full plaintext allocation or FFT is required.
    void multiply_const_accumulate(const Ciphertext &ciph, double coefficient,
                                   double plain_scale,
                                   Ciphertext &accumulator) const;
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


    void eval_mod(const Ciphertext &ciph, Ciphertext &result, const EvalModPoly &eva_poly,
                  const RelinKeys &relin_keys, const CKKSEncoder &encoder);
    void eval_mod_high_precision(const Ciphertext &ciph, Ciphertext &result,
                                 const EvalModPoly &eva_poly, const RelinKeys &relin_keys,
                                 const CKKSEncoder &encoder);

    void bootstrap(const Ciphertext &ciph, Ciphertext &result, const RelinKeys &relin_keys,
                   const GaloisKeys &galois_keys, const CKKSEncoder &encoder,
                   EvalModPoly &eval_mod_poly);
    // The refreshed result keeps the q0-derived scale. Callers that require the
    // context's default scale must normalize it with one additional rescale.
    void bootstrap(const Ciphertext &ciph, Ciphertext &result, const RelinKeys &relin_keys,
                   const GaloisKeys &galois_keys, const CKKSEncoder &encoder,
                   const BootstrapConfig &config = BootstrapConfig{});
    void bootstrap_high_precision(const Ciphertext &ciph, Ciphertext &result,
                                  const RelinKeys &relin_keys,
                                  const GaloisKeys &galois_keys,
                                  const CKKSEncoder &encoder, EvalModPoly &eval_mod_poly);

    void multiply_const_direct(const Ciphertext &ciph, int64_t const_data, Ciphertext &result,
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

private:
    inline void set_min_scale(double scale) { min_scale_ = scale; }

    void bootstrap_core(const Ciphertext &ciph, Ciphertext &result, const RelinKeys &relin_keys,
                        const GaloisKeys &galois_keys, const CKKSEncoder &encoder,
                        EvalModPoly &eval_mod_poly, bool high_precision_eval_mod);

    void rescale_for_bootstrap(Ciphertext &ciph1);

    void add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const;
    void add_inplace(Ciphertext &ciph1, const Ciphertext &ciph2) const;
    void rescale_inplace(const Ciphertext &ciph, Ciphertext &result,
                         MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    void ckks_multiply(Ciphertext &ciph1, const Ciphertext &ciph2, MemoryPoolHandle pool) const;
    void multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                          MemoryPoolHandle pool = MemoryManager::GetPool()) const;

    std::shared_ptr<KSwitchBase> kswitch_{nullptr};



    // TODO public-->private
public:
    struct PatersonStockmeyerPolynomial
    {
        size_t size() const
        {
            return polys_.size();
        }

        Polynomial& operator[](size_t idx)
        {
            return polys_[idx];
        }

        const Polynomial& operator[](size_t idx) const
        {
            return polys_[idx];
        }

        int degree_;
        int base_;
        int level_;
        double scale_;
        std::vector<Polynomial> polys_;
    };

    struct PatersonStockmeyerPolynomialVector
    {
        size_t size() const
        {
            return polys_.size();
        }

        PatersonStockmeyerPolynomial& operator[](size_t idx)
        {
            return polys_[idx];
        }

        const PatersonStockmeyerPolynomial& operator[](size_t idx) const
        {
            return polys_[idx];
        }

        std::vector<PatersonStockmeyerPolynomial> polys_;
    };

    // 用于模拟power_basis在多项式评估中的level和scale
    struct SimPower
    {
        int level_;
        double scale_;
    };


    /*  多项式计算流程
     *  evaluate_polynomial
     *  |
     *  |----- gen_power
     *  |
     *  |----- get_paterson_stockmeyer_polynomial
     *  |
     *  |----- evaluate_paterson_stockmeyer_polynomial_vector
     *                  |
     *                  |----- evaluate_baby_step
     *                  |       |
     *                  |       |----- evaluate_polynomial_vector_from_power_basis
     *                  |
     *                  |----- evaluate_giant_step
     *                          |
     *                          |----- evaluate_monomial
     */


    void evaluate_polynomial(const PolynomialVector& poly_vec, const Ciphertext& ct_basis, Ciphertext& ct_res,
        bool is_chev, bool is_lazy, double target_scale, double min_scale, const RelinKeys& relin_key, const CKKSEncoder& encoder);

    void get_paterson_stockmeyer_polynomial(const Polynomial& poly, int input_level,
        double input_scale, double output_scale, PatersonStockmeyerPolynomial& ps_polys);

    void get_paterson_stockmeyer_polynomial_vector(const PolynomialVector& poly_vec,
        int input_level, double intput_scale, double output_scale, PatersonStockmeyerPolynomialVector& ps_poly_vec);

    void evaluate_paterson_stockmeyer_polynomial_vector(const PatersonStockmeyerPolynomialVector &ps_polys_vec,
        const map<uint32_t, Ciphertext> &power_basis, Ciphertext& ct_res, const RelinKeys& relin_key, const CKKSEncoder& encoder) /*const*/;

    // Paterson-Stockmeyer: evaluates a baby-step PolynomialVector from precomputed monomial basis.
    // 计算coeff[c0, c1, ... ,cn]与powerbasis[1, pb^1, pb^2, ..., pb^n]的内积
    void evaluate_baby_step(const PatersonStockmeyerPolynomialVector &ps_poly_vec,
                            const map<uint32_t, Ciphertext> &monomial_basis, int j, BabyStep& baby_step,
                            const CKKSEncoder &encoder) /*const*/;

    // Paterson-Stockmeyer: combines consecutive baby steps using a giant-step monomial power.
    // giant_steps[i] == 2: updates baby_steps[i].degree to match baby_steps[i-1].degree.
    // giant_steps[i] == 1: baby_steps[i+1] = baby_steps[i] * monomial_basis[deg] + baby_steps[i+1],
    // then clears baby_steps[i].
    void evaluate_giant_step(int i, const vector<int> &giant_steps, vector<BabyStep> &baby_steps,
        const map<uint32_t, Ciphertext> &power_basis, const CKKSEncoder& encoder, const RelinKeys &relin_keys) const;

    void evaluate_monomial(const Ciphertext& a, Ciphertext& b, const Ciphertext& power_basis,
        const CKKSEncoder& encoder, const RelinKeys& relin_key) const;

    void evaluate_monomial_message(const std::complex<double>& a, std::complex<double>& b,
                                   const std::complex<double>& xpow) const;

    void evaluate_polynomial_vector_from_power_basis_optimized(const PolynomialVector &poly_vec, const map<uint32_t, Ciphertext> &power_basis, Ciphertext &ciph_res,
                                                                int target_level, double target_scale, const CKKSEncoder &encoder) const;

    void gen_power_sim(std::map<int, SimPower> &power_basis_sim, int n, int level_consumed_per_rescale);

    // Optimized gen_power with lazy relinearization and rescale tracking.
    // When lazy=true, the result is NOT relinearized (caller must handle).
    // Non-relinearized sub-powers are automatically relinearized before reuse.
    void gen_power_optimized(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy,
                             bool is_chev, double min_scale, const RelinKeys &relin_keys,
                             const CKKSEncoder &encoder) const;
    // Returns true if the caller should rescale monomial_basis[n].
    bool gen_power_optimized_inner(map<uint32_t, Ciphertext> &monomial_basis, uint32_t n, bool lazy,
                                   bool is_chev, double min_scale, const RelinKeys &relin_keys,
                                   const CKKSEncoder &encoder) const;

    void recurse_ps(Polynomial poly, int log_split, int target_level, double output_scale,
        std::map<int, SimPower> pb, std::vector<Polynomial>& poly_vec_res, SimPower& op_res);

    void update_level_and_scale_baby_step(bool lead, int level_old,
        double scale_old, int& level_new, double& scale_new, int level_consumed_per_rescale = 1);

    void update_level_and_scale_giant_step(bool lead, int level_old, double scale_old,
        double x_pow_scale, int& level_new, double& scale_new, int level_consumed_per_rescale = 1);

    void factorize(const Polynomial& poly, int n, Polynomial& pq, Polynomial& pr);

    void factorize_inner(const Polynomial& poly, int n, Polynomial& pq, Polynomial& pr);

protected:
    double min_scale_;

#ifdef DEBUG
public:
    void set_decryptor(Decryptor* decryptor)
    {
        ptr_dec_ = decryptor;
    }

    Decryptor* get_decryptor()
    {
        return ptr_dec_;
    }

    void set_encoder(CKKSEncoder* encoder)
    {
        ptr_encoder_ = encoder;
    }

    CKKSEncoder* get_encoder()
    {
        return ptr_encoder_;
    }

    void set_encryptor(Encryptor* encryptor)
    {
        ptr_enc_ = encryptor;
    }

    Encryptor* get_encryptor()
    {
        return ptr_enc_;
    }

    std::vector<std::complex<double>> decrypt_and_decode(const Ciphertext& ciph);

    CKKSEncoder* ptr_encoder_ = nullptr;
    Encryptor* ptr_enc_ = nullptr;
    Decryptor* ptr_dec_ = nullptr;
#endif
};

}  // namespace poseidon
