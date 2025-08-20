#include "matrix_operation.h"

using namespace std;
namespace matrix_operations
{
// vec_sum = vec_a + vec_b
void add(vector<complex<double>> vec_a, vector<complex<double>> vec_b,
         vector<complex<double>> &vec_sum)
{
    vector<complex<double>> c;
    for (int i = 0; i < vec_a.size(); ++i)
        c.push_back(vec_a[i] + vec_b[i]);
    vec_sum.swap(c);
    return;
}

void multiply(vector<complex<double>> vec_a, vector<complex<double>> vec_b,
              vector<complex<double>> &vec_sum)
{
    vector<complex<double>> c;
    for (int i = 0; i < vec_a.size(); ++i)
        c.push_back(vec_a[i] * vec_b[i]);
    vec_sum.swap(c);
    return;
}

// matrix_sum = matrix_a + matrix_b
void matrix_add(vector<vector<complex<double>>> matrix_a, vector<vector<complex<double>>> matrix_b,
                vector<vector<complex<double>>> &matrix_sum)
{
    vector<vector<complex<double>>> matrix_c;
    for (int i = 0; i < matrix_a.size(); ++i)
    {
        vector<complex<double>> c;
        for (int j = 0; j < matrix_a[0].size(); ++j)
        {
            c.push_back(matrix_a[i][j] + matrix_b[i][j]);
        }
        matrix_c.push_back(c);
    }
    matrix_sum.swap(matrix_c);
    return;
}

// matrix_product = matrix_a * n
void scalar_multiply(vector<vector<complex<double>>> matrix_a, double n,
                     vector<vector<complex<double>>> &matrix_product)
{
    vector<vector<complex<double>>> matrix_c;
    for (int i = 0; i < matrix_a.size(); ++i)
    {
        vector<complex<double>> c;
        for (int j = 0; j < matrix_a[0].size(); ++j)
        {
            c.push_back(matrix_a[i][j] * n);
        }
        matrix_c.push_back(c);
    }
    matrix_product.swap(matrix_c);
    return;
}

// matrix_product = matrix_a * matrix_b
void multiply(vector<vector<complex<double>>> matrix_a, vector<vector<complex<double>>> matrix_b,
              vector<vector<complex<double>>> &matrix_product)
{
    vector<vector<complex<double>>> matrix_c;
    for (int i = 0; i < matrix_a.size(); ++i)
    {
        vector<complex<double>> c;
        for (int j = 0; j < matrix_b[0].size(); ++j)
        {
            complex<double> tmp(0, 0);
            for (int k = 0; k < matrix_a[0].size(); ++k)
            {
                tmp += matrix_a[i][k] * matrix_b[k][j];
            }
            c.push_back(tmp);
        }
        matrix_c.push_back(c);
    }
    matrix_product.swap(matrix_c);
    return;
}

// vec_diag = matrix_a.diagonal(diag_index)
// vec_rotate = vec.rotate(rotation)
// matrix_conj = conjugate of matrix
void conjugate_matrix(vector<vector<complex<double>>> matrix,
                      vector<vector<complex<double>>> &matrix_conj)
{
    vector<vector<complex<double>>> conj_matrix;
    for (int i = 0; i < matrix.size(); ++i)
    {
        vector<complex<double>> tmp;
        for (int j = 0; j < matrix[0].size(); ++j)
        {
            tmp.push_back(conj(matrix[i][j]));
        }
        conj_matrix.push_back(tmp);
    }
    matrix_conj.swap(conj_matrix);
    return;
}

// matrix_trans = transpose of matrix
void PrintVec(vector<vector<complex<double>>> &A)
{
    for (int i = 0; i < A.size(); i++)
    {
        for (int j = 0; j < A[i].size(); j++)
        {
            cout << A[i][j] << " ";
        }
        cout << endl;
    }
    return;
}

}  // namespace matrix_operations
