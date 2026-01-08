#include "random_sample.h"
#include <chrono>

namespace poseidon
{
int sample_hamming_weight_vector(int *sample, int length, int hamming_weight)
{

    int total_weight = 0;
    int index = 0;
    int r = 0;
    while (total_weight < hamming_weight)
    {
        index = rand() % length;
        if (sample[index] == 0)
        {
            r = rand() % 2;
            if (r == 0)
            {
                sample[index] = -1;
            }
            else
            {
                sample[index] = 1;
            }
            total_weight++;
        }
    }

    return 0;
}

/*

Args:
        min_val (mpz_t): Minimum value (inclusive).
        max_val (mpz_t): Maximum value (exclusive).
        num_samples (int): Number of samples to be drawn.
*/

int sample_triangle(int *uniform_res, int num_samples)
{
    int r = 0;
    // srand( (unsigned)time( NULL ));
    srand(1);
    for (int i = 0; i < num_samples; i++)
    {
        r = rand() % 4;
        if (r == 0)
        {
            uniform_res[i] = -1;
        }
        else if (r == 1)
        {
            uniform_res[i] = 1;
        }
        else
        {
            uniform_res[i] = 0;
        }
    }

    return 0;
}

void sample_random_complex_vector(vector<complex<double>> &vec, int length, double min, double max)
{
    auto seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::mt19937 engine(seed);
    std::uniform_real_distribution<double> dist(min, max);

    vec.resize(length);
    for (int i = 0; i < length; i++)
    {
        vec[i].imag(0.0);
        vec[i].real(dist(engine));
    }
}

}  // namespace poseidon
