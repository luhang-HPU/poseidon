#pragma once

#include "examples.h"
#include "precision.h"
#include <chrono>
#include <gmpxx.h>
#include <iomanip>
#include <map>
#include <mutex>
#include <vector>

using namespace std;
namespace poseidon
{
namespace util
{
int conv_rns_to_x(std::vector<uint32_t> modulus, std::vector<std::vector<uint32_t>> coeffs,
                  mpz_t *x, int x_num);
void data_to_vector(uint64_t *data, std::vector<std::vector<uint32_t>> &coeffs, uint32_t rns_num,
                    uint32_t degree);

class Timestacs
{
private:
    chrono::time_point<chrono::system_clock> start_;
    chrono::time_point<chrono::system_clock> end_;

public:
    inline void start() { start_ = chrono::high_resolution_clock::now(); }
    inline void end() { end_ = chrono::high_resolution_clock::now(); }

    inline long microseconds()
    {
        return chrono::duration_cast<chrono::microseconds>(end_ - start_).count();
    }

    inline void print_time(const std::string &str)
    {
        std::cout << str << microseconds() << " microseconds" << endl;
    }
    inline void print_time_ms(const std::string &str)
    {
        std::cout << str << microseconds()/1000 << " ms" << endl;
    }
    inline void print_time_s(const std::string &str)
    {
        std::cout << str << microseconds()/1000/1000 << " s" << endl;
    }
    inline std::string get_time_s(const std::string &prefix = "")
    {
        std::ostringstream oss;
        oss << prefix << static_cast<double>(microseconds()) / 1000000.0 << " s";
        return oss.str();
    }
};

class LocalTimer
{
public:
    explicit LocalTimer(const std::string& str) : str_(str), is_owner_(false)
    {
        {
            std::lock_guard<std::mutex> lck(mtx_);
            if (is_timing_)
            {
                return;
            }
            else
            {
                is_timing_ = true;
                is_owner_ = true;
                timer_.start();
            }
        }

        if (function2time_.find(str) == function2time_.end())
        {
            function2time_.insert({str, 0});
        }
    }

    ~LocalTimer()
    {
        if (is_owner_)
        {
            {
                std::lock_guard<std::mutex> lck(mtx_);
                is_timing_ = false;
            }

            timer_.end();
            if (function2time_.find(str_) != function2time_.end())
            {
                function2time_[str_] += timer_.microseconds();
            }
        }
    }

    static void print()
    {
        std::cout << "======== TIME TABLE ========" << std::endl;
        for (auto iter : function2time_)
        {
            std::cout << iter.first << " : " << iter.second << " microseconds" << std::endl;
        }
        std::cout << std::endl;
    }

    static void print_and_clear()
    {
        const int COL1_WIDTH = 20;  // 算子名列宽度
        const int COL2_WIDTH = 10;  // 时间列宽度
        const std::string DIVIDER =
            "+" + std::string(COL1_WIDTH + 2, '-') + "+" + std::string(COL2_WIDTH + 2, '-') + "+";

        // 打印标题
        std::cout << DIVIDER << std::endl;
        std::cout << "| " << std::left << std::setw(COL1_WIDTH) << "OPERATOR"
                  << " | " << std::right << std::setw(COL2_WIDTH) << "TIME" << " |"
                  << std::endl;
        std::cout << DIVIDER << std::endl;

        // 打印数据行
        int total;
        for (const auto &iter : function2time_)
        {
            total += iter.second;
            std::cout << "| " << std::left << std::setw(COL1_WIDTH) << iter.first << " | "
                      << std::right << std::setw(COL2_WIDTH)
                      << std::to_string(iter.second / 1000) + " ms" << " |" << std::endl;
        }

        std::cout << "| " << std::left << std::setw(COL1_WIDTH) << "TOTAL" << " | " << std::right
                  << std::setw(COL2_WIDTH) << std::to_string(total / 1000) + " ms" << " |"
                  << std::endl;

        // 打印底部边框
        if (!function2time_.empty())
        {
            std::cout << DIVIDER << std::endl;
        }

        std::cout << std::endl;
        function2time_.clear();
    }

private:
    std::string str_;
    Timestacs timer_;
    bool is_owner_;
    static bool is_timing_;
    static std::mutex mtx_;
    static std::map<std::string, uint64_t> function2time_;
};

}  // namespace util
}  // namespace poseidon
