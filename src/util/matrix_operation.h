#pragma once

#include "exception.h"
#include <algorithm>
#include <complex>
#include <cstdint>
#include <iostream>
#include <vector>

using namespace std;
namespace matrix_operations
{
template <typename T>
void matrix_vector_multiply(vector<vector<T>> matrix, vector<T> vec, vector<T> &vec_product)
{
    auto size = vec.size();
    vector<T> vec_tmp(size, 0);
    for (int i = 0; i < matrix.size(); ++i)
    {
        for (int j = 0; j < vec.size(); ++j)
        {
            vec_tmp[i] = vec_tmp[i] + matrix[i][j] * vec[j];
        }
    }
    vec_product.swap(vec_tmp);
}

template <typename T>
void matrix_vector_multiply_mod(vector<vector<T>> matrix, vector<T> vec, vector<T> &vec_product,
                                uint32_t mod)
{
    auto size = vec.size();
    vector<T> vec_tmp(size, 0);
    for (int i = 0; i < matrix.size(); ++i)
    {
        for (int j = 0; j < vec.size(); ++j)
        {
            vec_tmp[i] =
                ((uint64_t)vec_tmp[i] + (uint64_t)matrix[i][j] * (uint64_t)vec[j] % (uint64_t)mod) %
                mod;
        }
    }
    vec_product.swap(vec_tmp);
}

// vec_sum = vec_a + vec_b
void add(vector<complex<double>> vec_a, vector<complex<double>> vec_b,
         vector<complex<double>> &vec_sum);
void multiply(vector<complex<double>> vec_a, vector<complex<double>> vec_b,
              vector<complex<double>> &vec_sum);

// matrix_sum = matrix_a + matrix_b
void matrix_add(vector<vector<complex<double>>> matrix_a, vector<vector<complex<double>>> matrix_b,
                vector<vector<complex<double>>> &matrix_sum);

// matrix_product = matrix_a * n
void scalar_multiply(vector<vector<complex<double>>> matrix_a, double n,
                     vector<vector<complex<double>>> &matrix_product);

// matrix_product = matrix_a * matrix_b
void multiply(vector<vector<complex<double>>> matrix_a, vector<vector<complex<double>>> matrix_b,
              vector<vector<complex<double>>> &matrix_product);

// vec_diag = matrix_a.diagonal(diag_index)
template <typename T>
void diagonal(const vector<vector<T>> &matrix_a, size_t diag_index, vector<T> &vec_diag)
{
    vector<T> vec(matrix_a.size());
    for (int i = 0; i < matrix_a.size(); ++i)
    {
        vec[i] = matrix_a[i][(i + diag_index) % matrix_a[0].size()];
    }
    vec_diag.swap(vec);
}

// vec_rotate = vec.rotate(rotation)
template <typename T> void rotate(vector<T> vec, size_t rotation, vector<T> &vec_rotate)
{

    auto size = vec.size();
    vector<T> vec_tmp(size);
    for (size_t i = 0; i < size; ++i)
    {
        vec_tmp[i] = vec[(i + rotation) % vec.size()];
    }
    vec_rotate.swap(vec_tmp);
}

template <typename T> vector<T> rotate(vector<T> vec, size_t rotation)
{
    auto size = vec.size();
    vector<T> vec_tmp(size);
    for (size_t i = 0; i < size; ++i)
    {
        vec_tmp[i] = vec[(i + rotation) % vec.size()];
    }
    return vec_tmp;
}

// matrix_conj = conjugate of matrix
void conjugate_matrix(vector<vector<complex<double>>> matrix,
                      vector<vector<complex<double>>> &matrix_conj);

// matrix_trans = transpose of matrix
// void transpose_matrix(const vector<vector<complex<double>>> &matrix,
// vector<vector<complex<double>>> &matrix_trans);
template <typename T>
void transpose_matrix(const vector<vector<T>> &matrix, vector<vector<T>> &matrix_trans)
{
    vector<vector<T>> trans_matrix(matrix[0].size(), vector<T>(matrix.size()));
    for (int i = 0; i < matrix[0].size(); ++i)
    {
        for (int j = 0; j < matrix.size(); ++j)
        {
            trans_matrix[i][j] = matrix[j][i];
        }
    }
    matrix_trans.swap(trans_matrix);
}

// for bfv
template <typename T> vector<T> rotate_slots_vec(const vector<T> &vec, int k)
{
    auto size = vec.size();
    vector<T> ret(size);
    auto slots = size >> 1;

    vector<T> half_l(slots);
    vector<T> half_h(slots);
    copy_n(vec.cbegin(), slots, half_l.begin());
    copy_n(vec.cbegin() + slots, slots, half_h.begin());
    auto rot0 = rotate(half_l, k);
    auto rot1 = rotate(half_h, k);
    if (abs(k) >= slots && abs(k) < size)
    {
        copy_n(rot0.cbegin(), slots, ret.begin() + slots);
        copy_n(rot1.cbegin(), slots, ret.begin());
    }
    else if (abs(k) < slots)
    {
        copy_n(rot0.cbegin(), slots, ret.begin());
        copy_n(rot1.cbegin(), slots, ret.begin() + slots);
    }
    else
    {
        POSEIDON_THROW(poseidon::invalid_argument_error, "rotate out of range");
    }

    return ret;
}

template <typename T>
void rotate_slots_matrix(const vector<vector<T>> &matrix, vector<vector<T>> &matrix_trans)
{
    vector<vector<T>> trans_matrix(matrix[0].size(), vector<T>(matrix.size()));
    vector<vector<T>> trans_matrix_rot_slot(matrix[0].size(), vector<T>(matrix.size()));
    for (int i = 0; i < matrix[0].size(); ++i)
    {

        trans_matrix_rot_slot[i] = rotate_slots_vec(matrix[i], i);
    }

    transpose_matrix(trans_matrix_rot_slot, matrix_trans);
}

void PrintVec(vector<vector<complex<double>>> &A);
}  // namespace matrix_operations
