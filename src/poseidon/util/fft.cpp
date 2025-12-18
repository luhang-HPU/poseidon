#include "fft.h"
#include <utility>

namespace poseidon::util
{
FFT::FFT(size_t coeff_count, MemoryPoolHandle pool)
    : pool_(std::move(pool)), coeff_count_(coeff_count)
{
    uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
    auto slot = coeff_count >> 1;
    int logn = safe_cast<int>(log2(coeff_count));
    matrix_reps_index_map_ = allocate<size_t>(coeff_count, pool_);

    uint64_t gen = 5;
    uint64_t pos = 1;
    for (size_t i = 0; i < slot; i++)
    {
        // Position in normal bit order
        uint64_t index1 = (pos - 1) >> 1;
        uint64_t index2 = (m - pos - 1) >> 1;

        // Set the bit-reversed locations
        matrix_reps_index_map_[i] = safe_cast<size_t>(reverse_bits(index1, logn));
        matrix_reps_index_map_[slot | i] = safe_cast<size_t>(reverse_bits(index2, logn));

        // Next primitive root
        pos *= gen;
        pos &= (m - 1);
    }

    root_powers_ = allocate<std::complex<double>>(coeff_count, pool_);
    inv_root_powers_ = allocate<std::complex<double>>(coeff_count, pool_);
    // Powers of the primitive 2n-th root have 4-fold symmetry
    if (m >= 8)
    {
        complex_roots_ =
            std::make_shared<util::ComplexRoots>(util::ComplexRoots(static_cast<size_t>(m), pool_));
        for (size_t i = 1; i < coeff_count; i++)
        {
            root_powers_[i] = complex_roots_->get_root(reverse_bits(i, logn));
            inv_root_powers_[i] = conj(complex_roots_->get_root(reverse_bits(i - 1, logn) + 1));
        }
    }
    else if (m == 4)
    {
        root_powers_[1] = {0, 1};
        inv_root_powers_[1] = {0, -1};
    }
    complex_arith_ = ComplexArith();
    fft_handler_ = FFTHandler(complex_arith_);
}

void FFT::embedding_inv(const std::vector<std::complex<double>> &vec,
                        std::vector<std::complex<double>> &vec_res) const
{

    auto values_size = vec.size();
    auto slots = coeff_count_ >> 1;

    auto conj_values = util::allocate<std::complex<double>>(coeff_count_, pool_, 0);
    for (std::size_t i = 0; i < values_size; i++)
    {
        conj_values[matrix_reps_index_map_[i]] = vec[i];
        // TODO: if values are real, the following values should be set to zero, and multiply
        // results by 2.
        conj_values[matrix_reps_index_map_[i + slots]] = std::conj(vec[i]);
    }
    double fix = 1.0 / static_cast<double>(coeff_count_);
    vec_res = vec;
    fft_handler_.transform_from_rev(conj_values.get(), util::get_power_of_two(coeff_count_),
                                    inv_root_powers_.get(), &fix);

    for (std::size_t i = 0; i < values_size; i++)
    {
        vec_res[i] = conj_values[i];
    }
}

void FFT::embedding(const std::vector<std::complex<double>> &vec,
                    std::vector<std::complex<double>> &vec_res) const
{
    vec_res = vec;
    fft_handler_.transform_to_rev(vec_res.data(), util::get_power_of_two(coeff_count_),
                                  root_powers_.get());
}
}  // namespace poseidon::util
