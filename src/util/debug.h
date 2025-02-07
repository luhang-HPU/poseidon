#pragma once

#include "examples.h"
#include "precision.h"
#include <chrono>
#include <gmpxx.h>
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
    chrono::microseconds duration_;

public:
    inline void start() { start_ = chrono::high_resolution_clock::now(); }
    inline void end() { end_ = chrono::high_resolution_clock::now(); }

    inline long microseconds()
    {
        duration_ = chrono::duration_cast<chrono::microseconds>(end_ - start_);
        return duration_.count();
    }

    inline void print_time(const std::string &str)
    {
        std::cout << str << microseconds() << " microseconds" << endl;
    }
};
}  // namespace util
}  // namespace poseidon
