#pragma once

#include "poseidon/batchencoder.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/util/matrix_operation.h"
#include <condition_variable>
#include <iostream>
#include <map>
#include <mutex>
#include <vector>

namespace poseidon
{
typedef std::map<int, std::vector<int>> IndexMap;
bool is_in_slice_int(int x, const std::vector<int> &slice);

class MatrixPlain
{
public:
    MatrixPlain()
        : log_slots(0), n1(0), level(0),
          scale(1.0), rot_index{}, plain_vec_pool{sz, std::map<int, Plaintext>()}, read_idx(0),
          write_idx(0), is_precompute(false)
    {
        read_cnt = 0;
        write_cnt = 0;
    }

    MatrixPlain(const MatrixPlain &matrix)
        : log_slots(matrix.log_slots), n1(matrix.n1), level(matrix.level), scale(matrix.scale),
          rot_index(matrix.rot_index), plain_vec(matrix.plain_vec),
          plain_vec_pool(matrix.plain_vec_pool), read_idx(matrix.read_idx),
          write_idx(matrix.write_idx), is_precompute(matrix.is_precompute)
    {
        read_cnt = matrix.read_cnt;
        write_cnt = matrix.write_cnt;
    }

public:
    uint32_t log_slots;
    uint32_t n1;
    uint32_t level;
    double scale;
    std::vector<int> rot_index;
    std::map<int, Plaintext> plain_vec;

public:
    // members below for multi-thread purpose
    static const int sz = 4;
    int read_cnt;
    int write_cnt;
    std::vector<std::map<int, Plaintext>> plain_vec_pool;
    int read_idx;
    int write_idx;
    bool is_precompute;
    std::mutex mtx_precompute;
    std::mutex mtx_pir;
    std::condition_variable cv_read;
    std::condition_variable cv_write;
    std::condition_variable cv_precompute;
};

class LinearMatrixGroup
{
public:
    LinearMatrixGroup() = default;
    inline std::vector<MatrixPlain> &data() noexcept { return matrices_; }

    POSEIDON_NODISCARD inline const std::vector<MatrixPlain> &data() const noexcept
    {
        return matrices_;
    }

    POSEIDON_NODISCARD inline std::vector<int> &rot_index() noexcept { return rotate_index_; }

    POSEIDON_NODISCARD inline const std::vector<int> &rot_index() const noexcept
    {
        return rotate_index_;
    }

    POSEIDON_NODISCARD inline uint32_t step() const noexcept { return scalar_step_; }

    inline void set_step(uint32_t step) noexcept { scalar_step_ = step; }

private:
    std::vector<MatrixPlain> matrices_{};
    std::vector<int> rotate_index_{};
    uint32_t scalar_step_ = 0;
};

template <typename T>
tuple<IndexMap, std::vector<int>, std::vector<int>> bsgs_index(const T &el, int slots, int n1)
{
    std::map<int, bool> rot_n1_map;
    std::map<int, bool> rot_n2_map;
    std::vector<int> non_zero_diags;

    IndexMap index;
    std::vector<int> rot_n1, rot_n2;
    // Convert el to non_zero_diags
    non_zero_diags.reserve(el.size());
    for (typename T::const_iterator it = el.begin(); it != el.end(); ++it)
    {
        non_zero_diags.push_back(it->first);
    }

    for (int rot : non_zero_diags)
    {
        rot &= (slots - 1);
        int idx_n1 = ((rot / n1) * n1) & (slots - 1);
        int idx_n2 = rot & (n1 - 1);
        index[idx_n1].push_back(idx_n2);
        if (rot_n1_map.find(idx_n1) == rot_n1_map.end())
        {
            rot_n1_map[idx_n1] = true;
            rot_n1.push_back(idx_n1);
        }
        rot_n2_map[idx_n2] = true;
    }

    rot_n2.clear();
    for (auto &it : rot_n2_map)
    {
        rot_n2.push_back(it.first);
    }

    return make_tuple(index, rot_n1, rot_n2);
}

template <typename T> int find_best_bsgs_ratio(const T &diag_matrix, int max_n, int log_max_ratio)
{
    auto max_ratio = double(1 << log_max_ratio);

    for (int n1 = max_n; n1 >= 2; n1 >>= 1)
    {
        std::vector<int> rot_n1, rot_n2;
        IndexMap index;
        tie(index, rot_n1, rot_n2) = bsgs_index(diag_matrix, max_n, n1);

        auto nb_n1 = rot_n1.size() - 1, nb_n2 = rot_n2.size() - 1;
        if (double(nb_n1) / double(nb_n2) == max_ratio)
        {
            return n1;
        }

        if (double(nb_n1) / double(nb_n2) > max_ratio)
        {
            return n1 * 2;
        }
    }
    return 1;
}

template <typename T> void copy_rot_interface(std::vector<T> &a, std::vector<T> &b, int rot)
{
    size_t n = a.size();

    if (b.size() >= rot)
    {
        copy(b.begin() + rot, b.end(), a.begin());
        copy(b.begin(), b.begin() + rot, a.begin() + n - rot);
    }
    else
    {
        copy(b.begin(), b.end(), a.begin() + n - rot);
    }
}

template <typename T> void copy_rot_interface_bfv(std::vector<T> &a, std::vector<T> &b, int rot)
{
    a = matrix_operations::rotate_slots_vec(b, -rot);
}

template <typename T>
void add_matrix_rot_to_list(const std::map<int, std::vector<T>> &value, std::vector<int> &rot_index,
                            int n1, int slots, bool repack)
{
    int index = 0;
    bool exist;
    rot_index.push_back(0);  // for conjugate
    for (auto i : value)
    {
        index = (i.first / n1) * n1;

        if (repack)
        {
            // Sparse repacking, occurring during the first IDFT matrix.
            index &= (2 * slots - 1);
        }
        else
        {
            // Other cases
            index &= (slots - 1);
        }
        exist = is_in_slice_int(index, rot_index);
        if (index != 0 && !exist)
        {
            rot_index.push_back(index);
        }

        index = i.first & (n1 - 1);
        exist = is_in_slice_int(index, rot_index);
        if (index != 0 && !exist)
        {
            rot_index.push_back(index);
        }
    }
}

template <typename T>
void gen_linear_transform_bsgs(MatrixPlain &plain_mat, std::vector<int> &rotate_index,
                               CKKSEncoder &encoder, std::map<int, std::vector<T>> &value,
                               uint32_t level, double scale, uint32_t log_bsgs_ratio,
                               uint32_t log_slots)
{
    auto slots = 1 << log_slots;
    auto n1 = find_best_bsgs_ratio(value, slots, log_bsgs_ratio);
    auto parms_id_map = encoder.context().crt_context()->parms_id_map();
    auto parms_id = parms_id_map.at(level);
    plain_mat.n1 = n1;
    plain_mat.log_slots = log_slots;
    plain_mat.level = level;
    plain_mat.scale = scale;

    add_matrix_rot_to_list(value, rotate_index, n1, slots, false);
    auto [index, _, __] = bsgs_index(value, slots, n1);
    std::vector<T> values(slots);

    for (auto j : index)
    {
        int a = 0;
        auto rot = -(j.first) & (slots - 1);
        for (auto i : index[j.first])
        {
            copy_rot_interface(values, value[j.first + i], rot);
            encoder.encode(values, parms_id, scale, plain_mat.plain_vec[j.first + i]);
        }
    }
}

template <typename T>
void gen_matrix_form_bsgs(MatrixPlain &plain_mat, std::vector<int> &rotate_index,
                          CKKSEncoder &encoder, std::vector<std::vector<T>> mat_data,
                          uint32_t level, double scale, uint32_t log_bsgs_ratio, uint32_t log_slots)
{

    std::map<int, std::vector<T>> value;
    for (int i = 0; i < mat_data.size(); i++)
    {
        value[i] = mat_data[i];
    }
    auto parms_id_map = encoder.context().crt_context()->parms_id_map();
    auto parms_id = parms_id_map.at(level);
    auto slots = 1 << log_slots;
    auto n1 = find_best_bsgs_ratio(value, slots, log_bsgs_ratio);
    plain_mat.n1 = n1;
    plain_mat.log_slots = log_slots;
    plain_mat.level = level;
    plain_mat.scale = scale;

    add_matrix_rot_to_list(value, rotate_index, n1, slots, false);
    auto [index, _, __] = bsgs_index(value, slots, n1);
    std::vector<T> values(slots);

    for (auto j : index)
    {
        int a = 0;
        auto rot = -(j.first) & (slots - 1);
        for (auto i : index[j.first])
        {
            copy_rot_interface(values, value[j.first + i], rot);
            encoder.encode(values, parms_id, scale, plain_mat.plain_vec[j.first + i]);
        }
    }
}

template <typename T>
void gen_matrix_form_bsgs_multi_thread(MatrixPlain &plain_mat, std::vector<int> &rotate_index,
                                       CKKSEncoder &encoder, std::vector<std::vector<T>> mat_data,
                                       uint32_t level, double scale, uint32_t log_bsgs_ratio,
                                       uint32_t log_slots, std::map<int, std::vector<int>> &ref1,
                                       std::vector<int> &ref2, std::vector<int> &ref3)
{
    std::map<int, std::vector<T>> value;
    for (int i = 0; i < mat_data.size(); i++)
    {
        value[i] = mat_data[i];
    }
    auto parms_id_map = encoder.context().crt_context()->parms_id_map();
    auto parms_id = parms_id_map.at(level);
    auto slots = 1 << log_slots;
    auto n1 = find_best_bsgs_ratio(value, slots, log_bsgs_ratio);
    plain_mat.n1 = n1;
    plain_mat.log_slots = log_slots;
    plain_mat.level = level;
    plain_mat.scale = scale;

    add_matrix_rot_to_list(value, rotate_index, n1, slots, false);
    auto [index, rot_n1, rot_n2] = bsgs_index(value, slots, n1);
    ref1 = index;
    ref2 = rot_n1;
    ref3 = rot_n2;
    {
        std::lock_guard<std::mutex> lck(plain_mat.mtx_precompute);
        plain_mat.is_precompute = true;
        plain_mat.cv_precompute.notify_one();
    }

    std::vector<std::complex<double>> values(slots);

    for (auto j : index)
    {
        auto rot = -(j.first) & (slots - 1);
        {
            std::unique_lock<std::mutex> lck(plain_mat.mtx_pir);
            while (plain_mat.read_idx == (plain_mat.write_idx + 1) % MatrixPlain::sz)
            {
                plain_mat.cv_write.wait(lck);
            }
        }

        // clear current pool
        plain_mat.plain_vec_pool[plain_mat.write_idx].clear();

        for (auto i : index[j.first])
        {
            copy_rot_interface(values, value[j.first + i], rot);
            encoder.encode(values, parms_id, scale,
                           plain_mat.plain_vec_pool[plain_mat.write_idx][j.first + i]);
        }

        {
            std::lock_guard<std::mutex> lck(plain_mat.mtx_pir);
            plain_mat.write_idx = (plain_mat.write_idx + 1) % MatrixPlain::sz;
            if (plain_mat.write_idx == (plain_mat.read_idx + 1) % MatrixPlain::sz)
            {
                plain_mat.cv_read.notify_one();
            }
        }
    }
}

template <typename T>
void gen_matrix_form_bsgs(MatrixPlain &plain_mat, std::vector<int> &rotate_index,
                          const BatchEncoder &encoder, std::vector<std::vector<T>> mat_data,
                          uint32_t level, int log_bsgs_ratio, int log_slots)
{
    std::map<int, std::vector<T>> value;
    for (int i = 0; i < mat_data.size(); i++)
    {
        value[i] = mat_data[i];
    }

    auto parms_id_map = encoder.context().crt_context()->parms_id_map();
    auto parms_id = parms_id_map.at(level);
    auto slots = 1 << log_slots;
    auto n1 = find_best_bsgs_ratio(value, slots, log_bsgs_ratio);

    plain_mat.n1 = n1;
    plain_mat.log_slots = log_slots;
    plain_mat.level = level;
    plain_mat.scale = 1.0;

    add_matrix_rot_to_list(value, rotate_index, n1, slots, false);
    auto [index, _, __] = bsgs_index(value, slots, n1);
    std::vector<T> values(slots);

    for (auto j : index)
    {
        int a = 0;
        auto rot = j.first;
        for (auto i : index[j.first])
        {
            copy_rot_interface_bfv(values, value[j.first + i], rot);
            encoder.encode(values, plain_mat.plain_vec[j.first + i]);
        }
    }
}
}  // namespace poseidon
