
#ifndef POSEIDON_HOUMO_SIMULATOR_H
#define POSEIDON_HOUMO_SIMULATOR_H

#include <iostream>
#include <vector>

class Houmo
{
public:
    template <typename T>
    std::vector<T> float_add(std::vector<T> op1, std::vector<T> op2, int size)
    {
        std::vector<float> f1, f2;
        std::vector<T> res;

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_add op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2);
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

    template <typename T>
    std::vector<T> float_sub(std::vector<T> op1, std::vector<T> op2, int size)
    {
        std::vector<float> f1, f2;
        std::vector<T> res;

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_sub op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2);
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

    template <typename T>
    std::vector<T> float_mul(std::vector<T> op1, std::vector<T> op2, int size)
    {
        std::vector<float> f1, f2;
        std::vector<T> res;

        for (auto i = 0; i < size; ++i)
        {
            try
            {
                f1[i] = static_cast<T>(op1);
            }
            catch (...)
            {
                f1[i] = 1;
                std::cout << "float_add op1 error" << std::endl;
            }

            try
            {
                f2[i] = static_cast<T>(op2);
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
