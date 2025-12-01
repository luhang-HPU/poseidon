#include "/usr/local/houmo/include/tcim/tcim_runtime.h"
// 文件在目录/usr/local/houmo/include/tcim下

#include <complex>
#include <iostream>
#include <map>
#include <vector>

using namespace tcim;
using namespace std;


class HOUMO_API
{
public:
    HOUMO_API();
    void complex_to_int16_vectors_raw(const std::complex<double> *op1, size_t size,
                                      std::vector<int16_t> &real_vec,
                                      std::vector<int16_t> &imag_vec)
    {
        real_vec.clear();
        imag_vec.clear();
        real_vec.reserve(size);
        imag_vec.reserve(size);

        for (size_t i = 0; i < size; ++i)
        {
            double real_part = op1[i].real();
            double imag_part = op1[i].imag();
            real_vec.push_back(static_cast<int16_t>(real_part));
            imag_vec.push_back(static_cast<int16_t>(imag_part));
        }
    }

    void houmo_add(const uint64_t *op1, const uint64_t *op2, uint64_t *res, int size)
    {
        std::vector<int16_t> temp1(op1, op1 + size);
        std::vector<int16_t> temp2(op2, op2 + size);
        std::vector<int16_t> temp_result(size);
        houmo_add(temp1.data(), temp2.data(), temp_result.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = temp_result[i];
        }
    }

    void houmo_add(const std::complex<double> *op1, const std::complex<double> *op2,
                   std::complex<double> *res, int size)
    {
        std::vector<int16_t> op_real, op_imag, op2_real, op2_imag, res_real, res_imag;
        complex_to_int16_vectors_raw(op1, size, op_real, op_imag);
        complex_to_int16_vectors_raw(op2, size, op2_real, op2_imag);
        houmo_add(op_real.data(), op2_real.data(), res_real.data(), size);
        houmo_add(op_imag.data(), op2_imag.data(), res_imag.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = std::complex<double>(res_real[i], res_imag[i]);
        }
    }

    void houmo_sub(const uint64_t *op1, const uint64_t *op2, uint64_t *res, int size)
    {
        std::vector<int16_t> temp1(op1, op1 + size);
        std::vector<int16_t> temp2(op2, op2 + size);
        std::vector<int16_t> temp_result(size);
        houmo_sub(temp1.data(), temp2.data(), temp_result.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = temp_result[i];
        }
    }

    void houmo_sub(const std::complex<double> *op1, const std::complex<double> *op2,
                   std::complex<double> *res, int size)
    {
        std::vector<int16_t> op_real, op_imag, op2_real, op2_imag, res_real, res_imag;
        complex_to_int16_vectors_raw(op1, size, op_real, op_imag);
        complex_to_int16_vectors_raw(op2, size, op2_real, op2_imag);
        houmo_sub(op_real.data(), op2_real.data(), res_real.data(), size);
        houmo_sub(op_imag.data(), op2_imag.data(), res_imag.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = std::complex<double>(res_real[i], res_imag[i]);
        }
    }

    void houmo_mul(const uint64_t *op1, const uint64_t *op2, uint64_t *res, int size)
    {
        std::vector<int16_t> temp1(op1, op1 + size);
        std::vector<int16_t> temp2(op2, op2 + size);
        std::vector<int16_t> temp_result(size);
        houmo_add(temp1.data(), temp2.data(), temp_result.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = temp_result[i];
        }
    }
    void houmo_mul(const std::complex<double> *op1, const std::complex<double> *op2,
                   std::complex<double> *res, int size)
    {
        std::vector<int16_t> op_real, op_imag, op2_real, op2_imag, res_real, res_imag;
        complex_to_int16_vectors_raw(op1, size, op_real, op_imag);
        complex_to_int16_vectors_raw(op2, size, op2_real, op2_imag);
        houmo_mul(op_real.data(), op2_real.data(), res_real.data(), size);
        houmo_mul(op_imag.data(), op2_imag.data(), res_imag.data(), size);
        for (int i = 0; i < size; i++)
        {
            res[i] = std::complex<double>(res_real[i], res_imag[i]);
        }
    }

    // res = op1 + op2
    void houmo_add(const int16_t *op1, const int16_t *op2, int16_t *res, int size);
    // res = op1 - op2
    void houmo_sub(const int16_t *op1, const int16_t *op2, int16_t *res, int size);
    // res = op1 * p2
    void houmo_mul(const int16_t *op1, const int16_t *op2, int16_t *res, int size);

    // res = op1 + op2
    void houmo_add_less_2048(const int16_t* op1, const int16_t* op2, int16_t* res, int size = 2048);

    // res = op1 - op2
    void houmo_sub_less_2048(const int16_t *op1, const int16_t *op2, int16_t *res, int size = 2048);

    // res = op1 * op2
    void houmo_mul_less_2048(const int16_t *op1, const int16_t *op2, int16_t *res, int size = 2048);

private:
    const int size_ = 2048;
    const std::string path_add = "./add.hmm";
    const std::string path_sub = "./sub.hmm";
    const std::string path_mul = "./mul.hmm";

    tcim::Module module_add_;
    tcim::Module module_sub_;
    tcim::Module module_mul_;
};
