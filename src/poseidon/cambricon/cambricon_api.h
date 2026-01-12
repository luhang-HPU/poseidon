#ifndef POSEIDON_CAMBRICON_API_H
#define POSEIDON_CAMBRICON_API_H

#include <iostream>
#include <cstring>
#include <memory>
#include <complex>

#include <torch/library.h>
#include <torch/script.h>
#include "framework/core/device.h"
#include "framework/core/caching_allocator.h"

class CAMBRICON_API
{
public:
    CAMBRICON_API() : device_("mlu:0")
    {
    }

    static std::shared_ptr<CAMBRICON_API> get_instance()
    {
        if (!cambricon_api_)
        {
            cambricon_api_ = std::make_shared<CAMBRICON_API>();
        }
        return cambricon_api_;
    }

    void test()
    {
        int size = 10;
        int16_t arr_op1[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        int16_t arr_op2[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::kInt16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::kInt16).clone();

        auto op1_mlu = tensor_op1.to(device_);
        auto op2_mlu = tensor_op2.to(device_);

        auto res_mlu = op1_mlu + op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        int16_t arr_res[10];
        std::memcpy(arr_res, tensor_res.data_ptr<int16_t>(), tensor_res.numel() * sizeof(int16_t));
        for (auto i = 0; i < 10; ++i)
        {
            std::cout << arr_res[i] << std::endl;
        }
    }

    template <typename T>
    void add(const T* op1, const T* op2, T* res, int size)
    {
        int16_t arr_op1[size];
        int16_t arr_op2[size];
        int16_t arr_res[size];

        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i].real());
                arr_op2[i] = static_cast<int16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int*>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i]);
                arr_op2[i] = static_cast<int16_t>(op2[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double*>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i]);
                arr_op2[i] = static_cast<int16_t>(op2[i]);
            }
        }
        
        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::kInt16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::kInt16).clone();

        auto op1_mlu = tensor_op1.to(device_);
        auto op2_mlu = tensor_op2.to(device_);

        auto res_mlu = op1_mlu + op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<int16_t>(), tensor_res.numel() * sizeof(int16_t));


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


//        {
//            // 验证数据
//            std::cout << "=================== add expected data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << op1[i] + op2[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== add int[] data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << res[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== add torch::Tensor data ==================" << std::endl;
//            std::cout << tensor_res << std::endl;
//        }
    }

    template <typename T>
    void sub(const T* op1, const T* op2, T* res, int size)
    {
        int16_t arr_op1[size];
        int16_t arr_op2[size];
        int16_t arr_res[size];

        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i].real());
                arr_op2[i] = static_cast<int16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i]);
                arr_op2[i] = static_cast<int16_t>(op2[i]);
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[i] = static_cast<int16_t>(op1[i]);
                arr_op2[i] = static_cast<int16_t>(op2[i]);
            }
        }
        
        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size}, torch::kInt16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size}, torch::kInt16).clone();

        auto op1_mlu = tensor_op1.to(device_);
        auto op2_mlu = tensor_op2.to(device_);

        auto res_mlu = op1_mlu - op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<int16_t>(), tensor_res.numel() * sizeof(int16_t));


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

//        {
//            // 验证数据
//            std::cout << "=================== sub expected data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << op1[i] - op2[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== sub int[] data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << res[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== sub torch::Tensor data ==================" << std::endl;
//            std::cout << tensor_res << std::endl;
//        }
    }

    template <typename T>
    void mul(const T* op1, const T* op2, T* res, int size)
    {
        int16_t arr_op1[size * 4];
        int16_t arr_op2[size * 4];
        int16_t arr_res[size * 4];

        if constexpr (std::is_same_v<T, std::complex<double>>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[4*i] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+1] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+1] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+2] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+2] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+3] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+3] = static_cast<int16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, unsigned long int>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[4*i] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+1] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+1] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+2] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+2] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+3] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+3] = static_cast<int16_t>(op2[i].real());
            }
        }
        else if constexpr (std::is_same_v<T, double>)
        {
            for (auto i = 0; i < size; ++i)
            {
                arr_op1[4*i] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+1] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+1] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+2] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+2] = static_cast<int16_t>(op2[i].real());
                arr_op1[4*i+3] = static_cast<int16_t>(op1[i].real());
                arr_op2[4*i+3] = static_cast<int16_t>(op2[i].real());
            }
        }
        
        torch::Tensor tensor_op1 = torch::from_blob(arr_op1, {size * 4}, torch::kInt16).clone();
        torch::Tensor tensor_op2 = torch::from_blob(arr_op2, {size * 4}, torch::kInt16).clone();

        auto op1_mlu = tensor_op1.to(device_);
        auto op2_mlu = tensor_op2.to(device_);

        auto res_mlu = op1_mlu * op2_mlu;
        torch::Tensor tensor_res = res_mlu.cpu();

        std::memcpy(arr_res, tensor_res.data_ptr<int16_t>(), tensor_res.numel() * sizeof(int16_t));


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


//        {
//            // 验证数据
//            std::cout << "=================== mul expected data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << op1[i] * op2[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== mul int[] data ==================" << std::endl;
//            for (auto i = 0; i < size; ++i)
//            {
//                std::cout << res[i] << " ";
//            }
//            std::cout << std::endl;
//            std::cout << "=================== mul torch::Tensor data ==================" << std::endl;
//            std::cout << tensor_res << std::endl;
//        }
    }

private:
    at::Device device_;
    static std::shared_ptr<CAMBRICON_API> cambricon_api_;
};

#endif  // POSEIDON_CAMBRICON_API_H
