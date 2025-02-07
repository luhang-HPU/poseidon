#pragma once

#include "homomorphic_linear_transform.h"
#include <cmath>
#include <complex>
#include <map>
#include <vector>

using namespace std;

namespace poseidon
{
typedef int LinearType;
const LinearType encode = 0;
const LinearType decode = 1;

vector<complex<double>> get_roots_float64(int nth_root);

tuple<vector<vector<complex<double>>>, vector<vector<complex<double>>>,
      vector<std::vector<complex<double>>>>
ifft_plain_vec(uint32_t log_n, uint32_t dslots, vector<complex<double>> roots, vector<int> pow5);

tuple<vector<vector<complex<double>>>, vector<vector<complex<double>>>,
      vector<std::vector<complex<double>>>>
fft_plain_vec(uint32_t log_n, uint32_t dslots, vector<complex<double>> roots, vector<int> pow5);

void slice_bit_reverse_in_place(std::vector<std::complex<double>> &slice, int n);
void add_to_diag_matrix(std::map<int, std::vector<std::complex<double>>> &diag_mat, int index,
                        const std::vector<std::complex<double>> &vec);
std::vector<std::complex<double>> add(const std::vector<std::complex<double>> &a,
                                      const std::vector<std::complex<double>> &b);
std::vector<std::complex<double>> mul(const std::vector<std::complex<double>> &a,
                                      const std::vector<std::complex<double>> &b);
std::vector<std::complex<double>> rotate(const std::vector<std::complex<double>> &x, int n);
std::map<int, std::vector<std::complex<double>>>
gen_fft_diag_matrix(uint32_t log_l, uint32_t fft_level, std::vector<std::complex<double>> a,
                    std::vector<std::complex<double>> b, std::vector<std::complex<double>> c,
                    LinearType lt_type, bool bit_reversed);

std::map<int, std::vector<std::complex<double>>> multiply_fft_matrix_with_next_fft_level(
    const std::map<int, std::vector<std::complex<double>>> &vec, uint32_t log_l, uint32_t n,
    uint32_t next_level, std::vector<std::complex<double>> a, std::vector<std::complex<double>> b,
    std::vector<std::complex<double>> c, LinearType lt_type, bool bit_reversed);
map<int, vector<complex<double>>> gen_repack_matrix(uint32_t log_l, bool bit_reversed);

class HomomorphicDFTMatrixLiteral
{
public:
    POSEIDON_NODISCARD LinearType get_type() const;
    POSEIDON_NODISCARD uint32_t get_log_n() const;
    POSEIDON_NODISCARD uint32_t get_log_slots() const;
    POSEIDON_NODISCARD uint32_t get_level_start() const;
    POSEIDON_NODISCARD const vector<uint32_t> &get_levels() const;
    POSEIDON_NODISCARD bool get_repack_imag_to_real() const;
    POSEIDON_NODISCARD double get_scaling() const;
    POSEIDON_NODISCARD bool get_bit_reversed() const;
    POSEIDON_NODISCARD uint32_t get_log_bsgs_ratio() const;
    vector<map<int, vector<complex<double>>>> gen_matrices();
    void create(LinearMatrixGroup &mat_group, CKKSEncoder &encoder, uint32_t step);

    HomomorphicDFTMatrixLiteral(LinearType type, uint32_t log_n, uint32_t log_slots,
                                uint32_t level_start, vector<uint32_t> levels,
                                bool repack_imag_to_real = false, double scaling = 1.0,
                                bool bit_reversed = false, uint32_t log_bsgs_ratio = 0);

private:
    LinearType type_;
    uint32_t log_n_;
    uint32_t log_slots_;
    uint32_t level_start_;
    std::vector<uint32_t> levels_;
    bool repack_imag_to_real_;
    double scaling_;
    bool bit_reversed_;
    uint32_t log_bsgs_ratio_;
    uint32_t get_depth(bool actual);
};

}  // namespace poseidon
