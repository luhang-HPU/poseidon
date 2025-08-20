#pragma once

#include <algorithm>
#include <cmath>
#include <complex>
#include <random>
#include <vector>

using namespace std;
namespace poseidon
{

int sample_hamming_weight_vector(int *sample, int length, int hamming_weight);
int sample_triangle(int *uniform_res, int num_samples);
void sample_random_complex_vector(vector<complex<double>> &vec, int length);
template <typename T> void sample_random_vector(vector<T> &vec, int length, int max)
{
    vec.resize(length);
    std::random_device rd;
    default_random_engine e(time(0));
    uniform_int_distribution<unsigned> u(0, max);
    for (int i = 0; i < length; i++)
    {
        vec[i] = u(e);
    }
}
void sample_random_complex_vector2(std::vector<complex<double>> &vec, int length);

}  // namespace poseidon
