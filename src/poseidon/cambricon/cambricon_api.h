#ifndef POSEIDON_CAMBRICON_API_H
#define POSEIDON_CAMBRICON_API_H

#include <iostream>
#include <torch/torch.h>
#include <torch_mlu/torch_mlu.h>
#include <cstring>
#include <memory>
#include <mutex>

using uint16_t = unsigned short;

class CAMBRICON_API
{
public:
    CAMBRICON_API()
    {
        torch::torch_mlu_init();
    }

    static std::shared_ptr<CAMBRICON_API> get_instance()
    {
        if (!cambricon_api_)
        {
            std::lock_guard<std::mutex> lck(mtx_);
            if (!cambricon_api_)
            {
                cambricon_api_ = std::make_shared<CAMBRICON_API>();
            }
        }
        return cambricon_api_;
    }

    template <typename T>
    void add(const T* op1, const T* op2, T* res, int size)
    {
        uint16_t arr_op1[size];
        uint16_t arr_op2[size];
        uint16_t arr_res[size];

        if constexpr (std::is_same_v<T, std::complex<double>*>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i].real());
                arr_op2[i] = static_cast<uint16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int*>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double*>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }

        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::uint16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::uint16).clone();

        auto op1_mlu = tensor_op1.to(at::kMLU);
        auto op2_mlu = tensor_op2.to(at::kMLU);

        auto res_mlu = op1_mlu + op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<uint16_t>(), tensor_res.numel * sizeof(uint16_t));


        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = std::complex<double>(arr_res[i], 0);
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }


        {
            // 验证数据
            std::cout << "=================== add expected data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << op1[i] + op2[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== add int[] data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << res[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== add torch::Tensor data ==================" << std::endl;
            std::cout << tensor_res << std::endl;
        }
    }

    template <typename T>
    void sub(const T* op1, const T* op2, T* res, int size)
    {
        uint16_t arr_op1[size];
        uint16_t arr_op2[size];
        uint16_t arr_res[size];

        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i].real());
                arr_op2[i] = static_cast<uint16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }

        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::uint16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::uint16).clone();

        auto op1_mlu = tensor_op1.to(at::kMLU);
        auto op2_mlu = tensor_op2.to(at::kMLU);

        auto res_mlu = op1_mlu - op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<uint16_t>(), tensor_res.numel * sizeof(uint16_t));


        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = std::complex<double>(arr_res[i], 0);
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }

        {
            // 验证数据
            std::cout << "=================== sub expected data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << op1[i] - op2[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== sub int[] data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << res[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== sub torch::Tensor data ==================" << std::endl;
            std::cout << tensor_res << std::endl;
        }
    }

    template <typename T>
    void mul(const T* op1, const T* op2, T* res, int size)
    {
        uint16_t arr_op1[size];
        uint16_t arr_op2[size];
        uint16_t arr_res[size];

        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i].real());
                arr_op2[i] = static_cast<uint16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<uint16_t>(op1[i]);
                arr_op2[i] = static_cast<uint16_t>(op2[i]);
            }
        }

        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::uint16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::uint16).clone();

        auto op1_mlu = tensor_op1.to(at::kMLU);
        auto op2_mlu = tensor_op2.to(at::kMLU);

        auto res_mlu = op1_mlu * op2_mlu;
        // dot product
        // auto res_mlu = torch::matmul(op1_mlu, op2_mlu);
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<uint16_t>(), tensor_res.numel * sizeof(uint16_t));


        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = std::complex<double>(arr_res[i], 0);
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                res[i] = static_cast<T>(arr_res[i]);
            }
        }


        {
            // 验证数据
            std::cout << "=================== mul expected data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << op1[i] * op2[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== mul int[] data ==================" << std::endl;
            for (auto i = 0; i < size; ++i)
            {
                std::cout << res[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "=================== mul torch::Tensor data ==================" << std::endl;
            std::cout << tensor_res << std::endl;
        }
    }

private:
    static std::mutex mtx_;
    static std::shared_ptr<CAMBRICON_API> cambricon_api_;
};

#endif  // POSEIDON_CAMBRICON_API_H
