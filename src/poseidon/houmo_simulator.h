
#ifndef POSEIDON_HOUMO_SIMULATOR_H
#define POSEIDON_HOUMO_SIMULATOR_H

#include <iostream>
#include <vector>
#include <complex>

class Houmo
{
public:
    template<typename>
    std::vector<std::complex<double>> float_add(std::vector<std::complex<double>>& op1, std::vector<std::complex<double>>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<std::complex<double>> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<double>(op1[i].real());
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_add op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<double>(op2[i].real());
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_add op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<double>(f1[i] + f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_add failed" << std::endl;
            }
        }

        return res;
    }

    template <typename T, std::enable_if_t<std::is_arithmetic<T>::value, bool> = true>
    std::vector<T> float_add(std::vector<T>& op1, std::vector<T>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<T> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1[i]);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_add op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2[i]);
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_add op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<T>(f1[i] + f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_add failed" << std::endl;
            }
        }

        return res;
    }

    template<typename>
    std::vector<std::complex<double>> float_sub(std::vector<std::complex<double>>& op1, std::vector<std::complex<double>>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<std::complex<double>> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<double>(op1[i].real());
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_sub op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<double>(op2[i].real());
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_sub op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<double>(f1[i] - f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_sub failed" << std::endl;
            }
        }

        return res;
    }

    template <typename T, std::enable_if_t<std::is_arithmetic<T>::value, bool> = true>
    std::vector<T> float_sub(std::vector<T>& op1, std::vector<T>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<T> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1[i]);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_sub op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2[i]);
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_sub op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<T>(f1[i] - f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_sub failed" << std::endl;
            }
        }

        return res;
    }

    template<typename>
    std::vector<std::complex<double>> float_mul(std::vector<std::complex<double>>& op1, std::vector<std::complex<double>>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<std::complex<double>> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<double>(op1[i].real());
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_mul op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<double>(op2[i].real());
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_mul op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<double>(f1[i] * f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_mul failed" << std::endl;
            }
        }

        return res;
    }

    template <typename T, std::enable_if_t<std::is_arithmetic<T>::value, bool> = true>
    std::vector<T> float_mul(std::vector<T>& op1, std::vector<T>& op2, std::size_t size)
    {
        std::vector<float> f1(size);
        std::vector<float> f2(size);
        std::vector<T> res(size);

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1[i]);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_add op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2[i]);
            }
            catch (...)
            {
                f2[i] = 1;
                std::cout << "float_add op2 error" << std::endl;
            }

            try
            {
                res[i] = static_cast<T>(f1[i] * f2[i]);
            }
            catch (...)
            {
                res[i] = f1[i];
                std::cout << "float_add failed" << std::endl;
            }
        }

        return res;
    }


};

#endif  // POSEIDON_HOUMO_SIMULATOR_H
