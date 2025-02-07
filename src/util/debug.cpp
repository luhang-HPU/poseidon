#include "src/util/debug.h"

using namespace std;
namespace poseidon
{
namespace util
{

int mod_inv(std::vector<uint32_t> modulus_q, std::vector<uint32_t> &mod_inv_result)
{
    mod_inv_result.clear();
    int q_len = modulus_q.size();

    mpz_t q_i;
    mpz_init(q_i);

    mpz_t q_i_m;
    mpz_t q;
    mpz_t q_i_m_inv;

    mpz_init(q_i_m);
    mpz_init(q);
    mpz_init(q_i_m_inv);

    mpz_set_ui(q, 1);

    for (int i = 0; i < q_len; i++)
    {
        mpz_mul_ui(q, q, modulus_q[i]);
    }

    for (int i = 0; i < q_len; i++)
    {
        mpz_div_ui(q_i_m, q, modulus_q[i]);
        mpz_set_ui(q_i, modulus_q[i]);
        mpz_invert(q_i_m_inv, q_i_m, q_i);
        mod_inv_result.push_back(mpz_get_ui(q_i_m_inv));
    }

    mpz_clear(q_i_m);
    mpz_clear(q);
    mpz_clear(q_i_m_inv);
    mpz_clear(q_i);
    return 0;
}

int conv_rns_to_x(std::vector<uint32_t> modulus, std::vector<std::vector<uint32_t>> coeffs,
                  mpz_t *x, int x_num)
{
    int degree = x_num;
    int rns_num = modulus.size();
    std::vector<uint32_t> mod_inv_result;

    mpz_t q;
    mpz_t mult_mod_tmp;
    mpz_t sum;
    mpz_t mult_m;
    mpz_init(mult_mod_tmp);
    mpz_init(sum);
    mpz_init(mult_m);
    mpz_init(q);
    mpz_set_ui(q, 1);

    mpz_t *q_i_m = new mpz_t[rns_num];

    for (int i = 0; i < rns_num; i++)
    {
        mpz_init(q_i_m[i]);
    }

    mod_inv(modulus, mod_inv_result);

    for (int i = 0; i < rns_num; i++)
    {
        mpz_mul_ui(q, q, modulus[i]);
    }

    for (int i = 0; i < rns_num; i++)
    {
        mpz_div_ui(q_i_m[i], q, modulus[i]);
    }

    for (int j = 0; j < degree; j++)
    {
        mpz_set_ui(sum, 0);

        for (int i = 0; i < rns_num; i++)
        {
            mpz_set_ui(mult_mod_tmp, 1);
            mpz_mul_ui(mult_mod_tmp, mult_mod_tmp, coeffs[i][j]);
            mpz_mul_ui(mult_mod_tmp, mult_mod_tmp, mod_inv_result[i]);
            mpz_mod_ui(mult_mod_tmp, mult_mod_tmp, modulus[i]);
            mpz_mul(mult_m, q_i_m[i], mult_mod_tmp);
            mpz_mod(mult_m, mult_m, q);
            mpz_add(sum, sum, mult_m);
            mpz_mod(sum, sum, q);
        }
        mpz_mod(x[j], sum, q);
    }

    for (int i = 0; i < rns_num; i++)
    {
        mpz_clear(q_i_m[i]);
    }
    delete[] q_i_m;
    mpz_clear(sum);
    mpz_clear(q);
    mpz_clear(mult_m);
    mpz_clear(mult_mod_tmp);

    return 0;
}

void data_to_vector(uint64_t *data, std::vector<std::vector<uint32_t>> &coeffs, uint32_t rns_num,
                    uint32_t degree)
{
    coeffs.resize(rns_num);
    for (auto i = 0; i < rns_num; ++i)
    {
        coeffs[i].resize(degree);
        for (auto j = 0; j < degree; ++j)
        {
            coeffs[i][j] = data[i * degree + j];
        }
    }
}

}  // namespace util

}  // namespace poseidon
