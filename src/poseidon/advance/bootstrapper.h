#pragma once

#include "poseidon/ciphertext.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/galoiskeys.h"
#include "poseidon/key/relinkeys.h"

#include <complex>
#include <string>
#include <vector>

namespace poseidon
{

class Bootstrapper
{
public:
    Bootstrapper(const PoseidonContext &context, EvaluatorCkksBase &evaluator,
                 const CKKSEncoder &encoder, long log_slots, long boundary_k,
                 double initial_scale, double final_scale,
                 std::string cosine_heap_path = {});

    void generate_linear_coefficients();

    void mod_raise(const Ciphertext &cipher, Ciphertext &destination) const;
    void coeff_to_slot(const Ciphertext &cipher, Ciphertext &real_part,
                       Ciphertext &imag_part, const GaloisKeys &galois_keys) const;
    void slot_to_coeff(const Ciphertext &real_part, const Ciphertext &imag_part,
                       Ciphertext &destination, const GaloisKeys &galois_keys) const;
    void eval_mod(const Ciphertext &cipher, Ciphertext &destination,
                  const RelinKeys &relin_keys, uint32_t double_angle,
                  double inverse_coeff, double target_scale) const;
    double inverse_coefficient(uint32_t double_angle) const;

private:
    using Complex = std::complex<double>;
    using Coeff2D = std::vector<std::vector<Complex>>;
    using Coeff3D = std::vector<Coeff2D>;

    static int giant_step(int count);
    static bool has_nonzero(const std::vector<Complex> &values);
    static void rotate_coeff(long log_slots, long full_slots, int shift,
                             const std::vector<Complex> &input,
                             std::vector<Complex> &output);

    void gen_original_coefficients();
    void generate_slot_to_coeff_coefficients();
    void generate_coeff_to_slot_coefficients();

    void multiply_vector_reduced_error(const Ciphertext &cipher,
                                       const std::vector<Complex> &values,
                                       Ciphertext &destination) const;
    void multiply_vector_unit_scale(const Ciphertext &cipher,
                                    const std::vector<Complex> &values,
                                    Ciphertext &destination) const;
    void add_reduced_error(const Ciphertext &lhs, const Ciphertext &rhs,
                           Ciphertext &destination) const;
    void add_inplace_reduced_error(Ciphertext &lhs, const Ciphertext &rhs) const;
    void rotate_allow_transparent(const Ciphertext &cipher, Ciphertext &destination,
                                  int step, const GaloisKeys &galois_keys) const;

    void bsgs_linear_transform(Ciphertext &destination, const Ciphertext &cipher,
                               int total_len, int basic_step, int coeff_log_slots,
                               const std::vector<std::vector<Complex>> &coeffs,
                               const GaloisKeys &galois_keys) const;
    void rotated_bsgs_linear_transform(Ciphertext &destination, const Ciphertext &cipher,
                                       int total_len, int basic_step, int coeff_log_slots,
                                       const std::vector<std::vector<Complex>> &coeffs,
                                       const GaloisKeys &galois_keys) const;

    void slot_to_coeff_transform(Ciphertext &destination, const Ciphertext &cipher,
                                 const GaloisKeys &galois_keys) const;
    void coeff_to_slot_transform(Ciphertext &destination, const Ciphertext &cipher,
                                 const GaloisKeys &galois_keys) const;

    const PoseidonContext &context_;
    EvaluatorCkksBase &evaluator_;
    const CKKSEncoder &encoder_;

    long log_slots_;
    long slots_;
    long boundary_k_;
    double initial_scale_;
    double final_scale_;
    std::string cosine_heap_path_;

    Coeff3D original_coeffs_;
    Coeff3D original_inv_coeffs_;
    Coeff2D fft_coeffs1_;
    Coeff2D fft_coeffs2_;
    Coeff2D fft_coeffs3_;
    Coeff2D inv_fft_coeffs1_;
    Coeff2D inv_fft_coeffs2_;
    Coeff2D inv_fft_coeffs3_;
};

}  // namespace poseidon
