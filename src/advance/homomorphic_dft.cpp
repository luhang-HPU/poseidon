#include "homomorphic_dft.h"

namespace poseidon
{
HomomorphicDFTMatrixLiteral::HomomorphicDFTMatrixLiteral(LinearType type, uint32_t log_n,
                                                         uint32_t log_slots, uint32_t level_start,
                                                         vector<uint32_t> levels,
                                                         bool repack_imag_to_real, double scaling,
                                                         bool bit_reversed, uint32_t log_bsgs_ratio)

    : type_(type), log_n_(log_n), log_slots_(log_slots), level_start_(level_start),
      levels_(std::move(levels)), repack_imag_to_real_(repack_imag_to_real), scaling_(scaling),
      bit_reversed_(bit_reversed), log_bsgs_ratio_(log_bsgs_ratio)
{
}

LinearType HomomorphicDFTMatrixLiteral::get_type() const { return type_; }
uint32_t HomomorphicDFTMatrixLiteral::get_log_n() const { return log_n_; }
uint32_t HomomorphicDFTMatrixLiteral::get_log_slots() const { return log_slots_; }
uint32_t HomomorphicDFTMatrixLiteral::get_level_start() const { return level_start_; }
const std::vector<uint32_t> &HomomorphicDFTMatrixLiteral::get_levels() const { return levels_; }
bool HomomorphicDFTMatrixLiteral::get_repack_imag_to_real() const { return repack_imag_to_real_; }
double HomomorphicDFTMatrixLiteral::get_scaling() const { return scaling_; }
bool HomomorphicDFTMatrixLiteral::get_bit_reversed() const { return bit_reversed_; }
uint32_t HomomorphicDFTMatrixLiteral::get_log_bsgs_ratio() const { return log_bsgs_ratio_; }

uint32_t HomomorphicDFTMatrixLiteral::get_depth(bool actual)
{
    if (actual)
        return levels_.size();
    else
    {
        int depth = 0;
        for (auto iter : levels_)
            depth += iter;
        return depth;
    }
}

void HomomorphicDFTMatrixLiteral::create(LinearMatrixGroup &mat_group, CKKSEncoder &encoder,
                                         uint32_t step)
{
    auto context_data = encoder.context().crt_context()->first_context_data();
    auto &modulus = context_data->parms().q();
    auto x = this->gen_matrices();
    mat_group.data().resize(x.size());
    mat_group.set_step(step);
    auto leveld = level_start_;
    for (int i = 0; i < x.size(); i++)
    {
        auto modulus_group = safe_cast<double>(modulus[leveld].value());
        if (step == 2)
        {
            modulus_group *= safe_cast<double>(modulus[leveld - 1].value());
        }
        else if (step > 2 || step < 1)
        {
            POSEIDON_THROW(invalid_argument_error, "DFT step is too large!");
        }

        gen_linear_transform_bsgs(mat_group.data()[i], mat_group.rot_index(), encoder, x[i], leveld,
                                  modulus_group, log_bsgs_ratio_, log_slots_);
        leveld = leveld - step;
    }
}

vector<map<int, vector<complex<double>>>> HomomorphicDFTMatrixLiteral::gen_matrices()
{
    auto log_slots = log_slots_;
    auto slots = 1 << log_slots;
    auto max_depth = get_depth(false);
    LinearType lt_type = type_;
    bool bit_reversed = bit_reversed_;

    auto logd_slots = log_slots;
    if (logd_slots < log_n_ - 1 && repack_imag_to_real_)
        logd_slots++;

    vector<complex<double>> roots = get_roots_float64(slots << 2);

    vector<int> pow5((slots << 1) + 1);
    pow5[0] = 1;
    for (int i = 1; i < (slots << 1) + 1; i++)
    {
        pow5[i] = pow5[i - 1] * 5;
        pow5[i] &= (slots << 2) - 1;
    }

    uint32_t fft_level, depth, next_fft_level;

    fft_level = log_slots;

    vector<vector<complex<double>>> a, b, c;
    if (lt_type == encode)
    {
        tie(a, b, c) = ifft_plain_vec(log_slots, 1 << log_slots, roots, pow5);
    }
    else
    {
        tie(a, b, c) = fft_plain_vec(log_slots, 1 << log_slots, roots, pow5);
    }

    vector<map<int, vector<complex<double>>>> plain_vector(max_depth);

    vector<int> merge(max_depth);
    for (auto i = 0; i < max_depth; ++i)
    {
        depth = int(ceil(float(fft_level) / float(max_depth - i)));

        if (lt_type == encode)
            merge[i] = depth;
        else
            merge[merge.size() - i - 1] = depth;

        fft_level -= depth;
    }

    fft_level = log_slots;
    for (int i = 0; i < max_depth; i++)
    {
        if (log_slots != logd_slots && lt_type == decode && i == 0 && repack_imag_to_real_)
        {

            // Special initial matrix for the repacking before DFT
            plain_vector[i] = gen_repack_matrix(log_slots, bit_reversed);

            // Merges this special initial matrix with the first layer of DFT
            plain_vector[i] = multiply_fft_matrix_with_next_fft_level(
                plain_vector[i], log_slots, 2 * slots, fft_level, a[log_slots - fft_level],
                b[log_slots - fft_level], c[log_slots - fft_level], lt_type, bit_reversed);

            // Continues the merging with the next layers if the total depth requires it.
            next_fft_level = fft_level - 1;
            for (int j = 0; j < merge[i] - 1; j++)
            {
                plain_vector[i] = multiply_fft_matrix_with_next_fft_level(
                    plain_vector[i], log_slots, 2 * slots, next_fft_level,
                    a[log_slots - next_fft_level], b[log_slots - next_fft_level],
                    c[log_slots - next_fft_level], lt_type, bit_reversed);
                next_fft_level--;
            }
        }
        else
        {
            // First layer of the i-th level of the DFT
            plain_vector[i] = gen_fft_diag_matrix(log_slots, fft_level, a[log_slots - fft_level],
                                                  b[log_slots - fft_level],
                                                  c[log_slots - fft_level], lt_type, bit_reversed);

            // Merges the layer with the next levels of the DFT if the total depth requires it.
            next_fft_level = fft_level - 1;
            for (int j = 0; j < merge[i] - 1; j++)
            {
                plain_vector[i] = multiply_fft_matrix_with_next_fft_level(
                    plain_vector[i], log_slots, slots, next_fft_level,
                    a[log_slots - next_fft_level], b[log_slots - next_fft_level],
                    c[log_slots - next_fft_level], lt_type, bit_reversed);
                next_fft_level--;
            }
        }

        fft_level -= merge[i];
    }
    // Repacking after the IDFT (we multiply the last matrix with the vector [1, 1, ..., 1, 1, 0, 0,
    // ..., 0, 0]).
    if (log_slots != logd_slots && lt_type == encode && repack_imag_to_real_)
    {
        for (auto j : plain_vector[max_depth - 1])
        {
            for (int x = 0; x < slots; x++)
                j.second[x + slots] = complex<double>(0, 0);
        }
    }

    // Rescaling of the DFT matrices.
    complex<double> scaling((double)scaling_, 0.0);

    // If no scaling (Default); set to 1
    if (scaling == complex<double>(0, 0))
        scaling = 1.0;

    // If DFT matrix, rescale by 1/n
    if (lt_type == encode)
    {
        scaling /= double(slots);

        // Real/Imag extraction 1/2 factor
        if (repack_imag_to_real_)
            scaling /= 2;
    }

    // Spreads the scale across the matrices
    scaling = complex<double>(pow(real(scaling), 1.0 / (float)get_depth(false)), 0);

    for (auto &j : plain_vector)
        for (auto &x : j)
            for (auto &i : x.second)
            {
                i *= scaling;
            }

    return plain_vector;
}

vector<complex<double>> get_roots_float64(int nth_root)
{
    vector<complex<double>> roots(nth_root + 1);

    int quarm = nth_root >> 2;

    double angle = 2 * M_PI / static_cast<double>(nth_root);

    for (int i = 0; i < quarm; i++)
    {
        roots[i] = complex<double>(cos(angle * static_cast<double>(i)), 0);
    }

    for (int i = 0; i < quarm; i++)
    {
        roots[quarm - i] += complex<double>(0, real(roots[i]));
    }

    for (int i = 1; i < quarm + 1; i++)
    {
        roots[i + 1 * quarm] = complex<double>(-real(roots[quarm - i]), imag(roots[quarm - i]));
        roots[i + 2 * quarm] = -roots[i];
        roots[i + 3 * quarm] = complex<double>(real(roots[quarm - i]), -imag(roots[quarm - i]));
    }

    roots[nth_root] = roots[0];

    return roots;
}

tuple<vector<vector<complex<double>>>, vector<vector<complex<double>>>,
      vector<std::vector<complex<double>>>>
ifft_plain_vec(uint32_t log_n, uint32_t dslots, vector<complex<double>> roots, vector<int> pow5)
{

    int n, m, index, tt, gap, k, mask, idx1, idx2;

    n = 1 << log_n;

    vector<vector<complex<double>>> a(log_n, vector<complex<double>>(dslots));
    vector<vector<complex<double>>> b(log_n, vector<complex<double>>(dslots));
    vector<vector<complex<double>>> c(log_n, vector<complex<double>>(dslots));

    int size;
    if (2 * n == dslots)
    {
        size = 2;
    }
    else
    {
        size = 1;
    }

    index = 0;
    for (m = n; m >= 2; m >>= 1)
    {
        tt = m >> 1;

        for (int i = 0; i < n; i += m)
        {
            gap = n / m;
            mask = (m << 2) - 1;

            for (int j = 0; j < (m >> 1); j++)
            {
                k = ((m << 2) - (pow5[j] & mask)) * gap;

                idx1 = i + j;
                idx2 = i + j + tt;

                for (int u = 0; u < size; u++)
                {
                    a[index][idx1 + u * n] = 1;
                    a[index][idx2 + u * n] = -roots[k];
                    b[index][idx1 + u * n] = 1;
                    c[index][idx2 + u * n] = roots[k];
                }
            }
        }
        index++;
    }

    return make_tuple(a, b, c);
}

tuple<vector<vector<complex<double>>>, vector<vector<complex<double>>>,
      vector<std::vector<complex<double>>>>
fft_plain_vec(uint32_t log_n, uint32_t dslots, vector<complex<double>> roots, vector<int> pow5)
{

    int n, m, index, tt, gap, k, mask, idx1, idx2;

    n = 1 << log_n;

    vector<vector<complex<double>>> a(log_n, vector<complex<double>>(dslots));
    vector<vector<complex<double>>> b(log_n, vector<complex<double>>(dslots));
    vector<vector<complex<double>>> c(log_n, vector<complex<double>>(dslots));

    int size;
    if (2 * n == dslots)
    {
        size = 2;
    }
    else
    {
        size = 1;
    }

    index = 0;
    for (m = 2; m <= n; m <<= 1)
    {
        tt = m >> 1;

        for (int i = 0; i < n; i += m)
        {
            gap = n / m;
            mask = (m << 2) - 1;

            for (int j = 0; j < (m >> 1); j++)
            {
                k = (pow5[j] & mask) * gap;

                idx1 = i + j;
                idx2 = i + j + tt;

                for (int u = 0; u < size; u++)
                {
                    a[index][idx1 + u * n] = 1;
                    a[index][idx2 + u * n] = -roots[k];
                    b[index][idx1 + u * n] = roots[k];
                    c[index][idx2 + u * n] = 1;
                }
            }
        }
        index++;
    }

    return make_tuple(a, b, c);
}

void slice_bit_reverse_in_place(std::vector<std::complex<double>> &slice, int n)
{
    int bit, j = 0;

    for (auto i = 1; i < n; i++)
    {
        bit = n >> 1;

        while (j >= bit)
        {
            j -= bit;
            bit >>= 1;
        }

        j += bit;

        if (i < j)
        {
            std::swap(slice[i], slice[j]);
        }
    }
}

std::vector<std::complex<double>> add(const std::vector<std::complex<double>> &a,
                                      const std::vector<std::complex<double>> &b)
{
    std::vector<std::complex<double>> res(a.size());

    for (size_t i = 0; i < a.size(); i++)
    {
        res[i] = a[i] + b[i];
    }

    return res;
}

void add_to_diag_matrix(std::map<int, std::vector<std::complex<double>>> &diag_mat, int index,
                        const std::vector<std::complex<double>> &vec)
{
    if (diag_mat.find(index) == diag_mat.end())
    {
        diag_mat[index] = vec;
    }
    else
    {
        diag_mat[index] = add(diag_mat[index], vec);
    }
}

std::map<int, std::vector<std::complex<double>>>
gen_fft_diag_matrix(uint32_t log_l, uint32_t fft_level, std::vector<std::complex<double>> a,
                    std::vector<std::complex<double>> b, std::vector<std::complex<double>> c,
                    LinearType lt_type, bool bit_reversed)
{
    int rot;

    if ((lt_type == encode && !bit_reversed) || (lt_type == decode && bit_reversed))
    {
        rot = 1 << (fft_level - 1);
    }
    else
    {
        rot = 1 << (log_l - fft_level);
    }

    std::map<int, std::vector<std::complex<double>>> vectors;

    if (bit_reversed)
    {
        slice_bit_reverse_in_place(a, 1 << log_l);
        slice_bit_reverse_in_place(b, 1 << log_l);
        slice_bit_reverse_in_place(c, 1 << log_l);

        if (a.size() > (1 << log_l))
        {
            slice_bit_reverse_in_place(a, 1 << log_l);
            slice_bit_reverse_in_place(b, 1 << log_l);
            slice_bit_reverse_in_place(c, 1 << log_l);
        }
    }

    add_to_diag_matrix(vectors, 0, a);
    add_to_diag_matrix(vectors, rot, b);
    add_to_diag_matrix(vectors, (1 << log_l) - rot, c);

    return vectors;
}

std::vector<std::complex<double>> mul(const std::vector<std::complex<double>> &a,
                                      const std::vector<std::complex<double>> &b)
{
    std::vector<std::complex<double>> res(a.size());

    for (size_t i = 0; i < a.size(); i++)
    {
        res[i] = a[i] * b[i];
    }

    return res;
}

std::vector<std::complex<double>> rotate(const std::vector<std::complex<double>> &x, int n)
{
    std::vector<std::complex<double>> y(x.size());

    int mask = int(x.size() - 1);

    // Rotates to the left
    for (size_t i = 0; i < x.size(); i++)
    {
        y[i] = x[(i + n) & mask];
    }

    return y;
}

std::map<int, std::vector<std::complex<double>>> multiply_fft_matrix_with_next_fft_level(
    const std::map<int, std::vector<std::complex<double>>> &vec, uint32_t log_l, uint32_t n,
    uint32_t next_level, std::vector<std::complex<double>> a, std::vector<std::complex<double>> b,
    std::vector<std::complex<double>> c, LinearType lt_type, bool bit_reversed)
{
    int rot;

    std::map<int, std::vector<std::complex<double>>> new_vec;

    if ((lt_type == encode && !bit_reversed) || (lt_type == decode && bit_reversed))
    {
        rot = (1 << (next_level - 1)) & (n - 1);
    }
    else
    {
        rot = (1 << (log_l - next_level)) & (n - 1);
    }

    if (bit_reversed)
    {
        slice_bit_reverse_in_place(a, 1 << log_l);
        slice_bit_reverse_in_place(b, 1 << log_l);
        slice_bit_reverse_in_place(c, 1 << log_l);

        if (a.size() > (1 << log_l))
        {
            slice_bit_reverse_in_place(a, 1 << log_l);
            slice_bit_reverse_in_place(b, 1 << log_l);
            slice_bit_reverse_in_place(c, 1 << log_l);
        }
    }

    for (auto &it : vec)
    {
        int i = it.first;
        std::vector<std::complex<double>> val = it.second;
        add_to_diag_matrix(new_vec, i, mul(val, a));
        add_to_diag_matrix(new_vec, (i + rot) & (n - 1), mul(rotate(val, rot), b));

        add_to_diag_matrix(new_vec, (i - rot) & (n - 1), mul(rotate(val, -rot), c));
    }

    return new_vec;
}

map<int, vector<complex<double>>> gen_repack_matrix(uint32_t log_l, bool bit_reversed)
{
    std::map<int, std::vector<std::complex<double>>> new_vec;

    return new_vec;
}

}  // namespace poseidon
