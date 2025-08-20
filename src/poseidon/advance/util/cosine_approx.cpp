#include "cosine_approx.h"

namespace poseidon
{
namespace util
{

int max_index(const vector<double> &array)
{
    int maxind = 0;
    auto max = array[0];
    for (int i = 1; i < array.size(); i++)
    {
        if (array[i] > max)
        {
            maxind = i;
            max = array[i];
        }
    }
    return maxind;
}

void BigintCos(const mpf_class &x, mpf_class &cosx)
{
    mpf_class tmp(0.0, DEF_PREC);
    auto k = 1000;  // number of iterations
    mpf_class t(0.5, DEF_PREC);
    mpf_class half(0.5, DEF_PREC);

    for (int i = 1; i < k - 1; i++)
    {
        mpf_mul(t.get_mpf_t(), t.get_mpf_t(), half.get_mpf_t());
    }

    mpf_class s(0.0, DEF_PREC);
    mpf_mul(s.get_mpf_t(), x.get_mpf_t(), t.get_mpf_t());
    mpf_mul(s.get_mpf_t(), s.get_mpf_t(), x.get_mpf_t());
    mpf_mul(s.get_mpf_t(), s.get_mpf_t(), t.get_mpf_t());

    mpf_class four(4.0, DEF_PREC);

    for (int i = 1; i < k; i++)
    {
        mpf_sub(tmp.get_mpf_t(), four.get_mpf_t(), s.get_mpf_t());
        mpf_mul(s.get_mpf_t(), s.get_mpf_t(), tmp.get_mpf_t());
    }
    mpf_div(cosx.get_mpf_t(), s.get_mpf_t(), mpf_class(2.0, DEF_PREC).get_mpf_t());
    mpf_sub(cosx.get_mpf_t(), mpf_class(1.0, DEF_PREC).get_mpf_t(), cosx.get_mpf_t());
}

tuple<int, vector<int>> gen_degrees(int degree, int k, double dev)
{
    auto degbdd = degree + 1;
    auto totdeg = 2 * k - 1;
    auto err = 1.0 / dev;

    vector<int> deg(k, 1.0);
    vector<double> bdd(k, 0.0);
    double temp = 0.0;

    for (double i = 1; i <= (2 * k - 1); ++i)
    {
        temp -= log2(i);
    }

    temp += (2 * static_cast<double>(k) - 1.0) * log2(2.0 * M_PI);
    temp += log2(err);

    for (int i = 0; i < k; ++i)
    {
        bdd[i] = temp;
        for (double j = 1; j <= k - 1 - i; ++j)
        {
            bdd[i] += log2(j + err);
        }
        for (double j = 1; j <= k - 1 + i; ++j)
        {
            bdd[i] += log2(j + err);
        }
    }

    int maxiter = 200;
    for (int iter = 0; iter < maxiter; iter++)
    {
        if (totdeg >= degbdd)
        {
            break;
        }
        auto maxi = max_index(bdd);

        if (maxi != 0)
        {
            if (totdeg + 2 > degbdd)
            {
                break;
            }

            for (int i = 0; i < k; i++)
            {
                bdd[i] -= log2((double)(totdeg + 1));
                bdd[i] -= log2((double)(totdeg + 2));
                bdd[i] += 2.0 * log2(2.0 * M_PI);

                if (i != maxi)
                {
                    bdd[i] += log2(abs((double)(i - maxi)) + err);
                    bdd[i] += log2((double)(i + maxi) + err);
                }
                else
                {
                    bdd[i] += log2(err) - 1.0;
                    bdd[i] += log2(2.0 * (double)(i) + err);
                }
            }

            totdeg += 2;
        }
        else
        {
            bdd[0] -= log2((double)(totdeg + 1));
            bdd[0] += log2(err) - 1.0;
            bdd[0] += log2(2.0 * M_PI);
            for (int i = 1; i < k; i++)
            {
                bdd[i] -= log2((double)(totdeg + 1));
                bdd[i] += log2(2.0 * M_PI);
                bdd[i] += log2((double)(i) + err);
            }

            totdeg++;
        }

        deg[maxi]++;
    }
    return make_tuple(totdeg, deg);
}

void gen_nodes(const vector<int> &deg, double dev, int &totdeg, int k, int scnum, mpf_class *x,
               mpf_class *p, mpf_class *c)
{

    mpf_class PI;
    mpf_set_prec(PI.get_mpf_t(), DEF_PREC);
    mpf_set_str(PI.get_mpf_t(), pi.c_str(), 10);
    mpf_class scfac = mpf_class(double(1 << scnum), DEF_PREC);
    mpf_class intersize = mpf_class(double(1.0 / dev), DEF_PREC);

    mpf_class z[totdeg];
    mpf_class aa;

    int cnt = 0;
    if (deg[0] % 2 != 0)
    {
        z[cnt] = mpf_class(0.0, DEF_PREC);
        cnt++;
    }

    mpf_class tmp;
    for (int i = k - 1; i > 0; i--)
    {
        for (int j = 1; j <= deg[i]; j++)
        {
            tmp = mpf_class((double)(2 * j - 1), DEF_PREC);
            mpf_mul(tmp.get_mpf_t(), tmp.get_mpf_t(), PI.get_mpf_t());
            mpf_div(tmp.get_mpf_t(), tmp.get_mpf_t(), mpf_class(2 * deg[i], DEF_PREC).get_mpf_t());

            BigintCos(tmp, tmp);
            mpf_mul(tmp.get_mpf_t(), tmp.get_mpf_t(), intersize.get_mpf_t());

            z[cnt] = mpf_class((double)i, DEF_PREC);
            mpf_add(z[cnt].get_mpf_t(), z[cnt].get_mpf_t(), tmp.get_mpf_t());
            cnt++;
            z[cnt] = mpf_class((double)(-i), DEF_PREC);
            mpf_sub(z[cnt].get_mpf_t(), z[cnt].get_mpf_t(), tmp.get_mpf_t());
            cnt++;
        }
    }

    for (int j = 1; j <= deg[0] / 2; j++)
    {
        tmp = mpf_class((double)(2 * j - 1), DEF_PREC);
        mpf_mul(tmp.get_mpf_t(), tmp.get_mpf_t(), PI.get_mpf_t());
        mpf_div(tmp.get_mpf_t(), tmp.get_mpf_t(), mpf_class(2 * deg[0], DEF_PREC).get_mpf_t());
        BigintCos(tmp, tmp);

        mpf_mul(tmp.get_mpf_t(), tmp.get_mpf_t(), intersize.get_mpf_t());

        z[cnt] = mpf_class((double)0.0, DEF_PREC);
        mpf_add(z[cnt].get_mpf_t(), z[cnt].get_mpf_t(), tmp.get_mpf_t());
        cnt++;
        z[cnt] = mpf_class((double)(0.0), DEF_PREC);
        mpf_sub(z[cnt].get_mpf_t(), z[cnt].get_mpf_t(), tmp.get_mpf_t());
        cnt++;
    }

    // cos(2*pi*(x-0.25)/r)
    mpf_class d[totdeg];
    for (int i = 0; i < totdeg; i++)
    {
        d[i] = mpf_class(2.0, DEF_PREC);
        mpf_mul(d[i].get_mpf_t(), d[i].get_mpf_t(), PI.get_mpf_t());
        mpf_sub(z[i].get_mpf_t(), z[i].get_mpf_t(), mpf_class(0.25).get_mpf_t());
        mpf_div(z[i].get_mpf_t(), z[i].get_mpf_t(), scfac.get_mpf_t());
        mpf_mul(d[i].get_mpf_t(), d[i].get_mpf_t(), z[i].get_mpf_t());
        BigintCos(d[i], d[i]);
    }

    for (auto j = 1; j < totdeg; j++)
    {
        for (auto l = 0; l < totdeg - j; l++)
        {
            mpf_sub(d[l].get_mpf_t(), d[l + 1].get_mpf_t(), d[l].get_mpf_t());
            mpf_sub(tmp.get_mpf_t(), z[l + j].get_mpf_t(), z[l].get_mpf_t());
            mpf_div(d[l].get_mpf_t(), d[l].get_mpf_t(), tmp.get_mpf_t());
        }
    }
    totdeg++;

    for (auto i = 0; i < totdeg; i++)
    {
        x[i] = mpf_class((double)k, DEF_PREC);
        mpf_div(x[i].get_mpf_t(), x[i].get_mpf_t(), scfac.get_mpf_t());
        mpf_mul(tmp.get_mpf_t(), mpf_class((double)i, DEF_PREC).get_mpf_t(), PI.get_mpf_t());
        mpf_div(tmp.get_mpf_t(), tmp.get_mpf_t(),
                mpf_class((double)(totdeg - 1), DEF_PREC).get_mpf_t());
        BigintCos(tmp, tmp);
        mpf_mul(x[i].get_mpf_t(), x[i].get_mpf_t(), tmp.get_mpf_t());
    }

    for (auto i = 0; i < totdeg; i++)
    {
        p[i] = d[0];
        for (auto j = 1; j < totdeg - 1; j++)
        {
            mpf_sub(tmp.get_mpf_t(), x[i].get_mpf_t(), z[j].get_mpf_t());
            mpf_mul(p[i].get_mpf_t(), p[i].get_mpf_t(), tmp.get_mpf_t());
            mpf_add(p[i].get_mpf_t(), p[i].get_mpf_t(), d[j].get_mpf_t());
        }
    }
}

vector<complex<double>> ApproximateCos(int k, int degree, double dev, int scnum)
{
    mpf_class scfac = mpf_class((double)(1 << scnum), DEF_PREC);

    auto [totdeg, deg] = gen_degrees(degree, k, dev);
    auto totdeg2 = totdeg;
    mpf_class *x = new mpf_class[totdeg + 1];
    mpf_class *p = new mpf_class[totdeg + 1];
    mpf_class *c = new mpf_class[totdeg + 1];
    mpf_class tmp(0.0, DEF_PREC);
    gen_nodes(deg, dev, totdeg, k, scnum, x, p, c);

    mpf_class t[totdeg][totdeg];

    for (auto i = 0; i < totdeg; i++)
    {
        t[i][0] = mpf_class(1.0, DEF_PREC);

        t[i][1] = x[i];
        mpf_div(tmp.get_mpf_t(), mpf_class((double)k, DEF_PREC).get_mpf_t(), scfac.get_mpf_t());
        mpf_div(t[i][1].get_mpf_t(), t[i][1].get_mpf_t(), tmp.get_mpf_t());

        for (auto j = 2; j < totdeg; j++)
        {
            t[i][j] = mpf_class(2.0, DEF_PREC);
            mpf_div(tmp.get_mpf_t(), mpf_class((double)k, DEF_PREC).get_mpf_t(), scfac.get_mpf_t());
            mpf_div(tmp.get_mpf_t(), x[i].get_mpf_t(), tmp.get_mpf_t());
            mpf_mul(t[i][j].get_mpf_t(), t[i][j].get_mpf_t(), tmp.get_mpf_t());
            mpf_mul(t[i][j].get_mpf_t(), t[i][j].get_mpf_t(), t[i][j - 1].get_mpf_t());
            mpf_sub(t[i][j].get_mpf_t(), t[i][j].get_mpf_t(), t[i][j - 2].get_mpf_t());
        }
    }
    mpf_class maxabs(0.0, DEF_PREC);
    int maxindex = 0;

    for (auto i = 0; i < totdeg - 1; i++)
    {
        mpf_abs(maxabs.get_mpf_t(), t[i][i].get_mpf_t());
        maxindex = i;
        for (auto j = i + 1; j < totdeg; j++)
        {
            mpf_abs(tmp.get_mpf_t(), t[j][i].get_mpf_t());
            auto flag = mpf_cmp(tmp.get_mpf_t(), maxabs.get_mpf_t());
            if (flag > 0)
            {
                mpf_abs(maxabs.get_mpf_t(), t[j][i].get_mpf_t());
                maxindex = j;
            }
        }

        if (i != maxindex)
        {
            for (auto j = i; j < totdeg; j++)
            {
                tmp = t[maxindex][j];
                t[maxindex][j] = t[i][j];
                t[i][j] = tmp;
            }
            tmp = p[maxindex];
            p[maxindex] = p[i];
            p[i] = tmp;
        }

        for (auto j = i + 1; j < totdeg; j++)
        {
            mpf_div(t[i][j].get_mpf_t(), t[i][j].get_mpf_t(), t[i][i].get_mpf_t());
        }
        mpf_div(p[i].get_mpf_t(), p[i].get_mpf_t(), t[i][i].get_mpf_t());
        t[i][i] = mpf_class(1.0, DEF_PREC);

        for (auto j = i + 1; j < totdeg; j++)
        {
            mpf_mul(tmp.get_mpf_t(), t[j][i].get_mpf_t(), p[i].get_mpf_t());
            mpf_sub(p[j].get_mpf_t(), p[j].get_mpf_t(), tmp.get_mpf_t());

            for (auto l = i + 1; l < totdeg; l++)
            {
                mpf_mul(tmp.get_mpf_t(), t[j][i].get_mpf_t(), t[i][l].get_mpf_t());
                mpf_sub(t[j][l].get_mpf_t(), t[j][l].get_mpf_t(), tmp.get_mpf_t());
            }
            t[j][i] = mpf_class(0.0, DEF_PREC);
        }
    }

    c[totdeg - 1] = p[totdeg - 1];
    for (auto i = totdeg - 2; i >= 0; i--)
    {
        c[i] = p[i];
        for (auto j = i + 1; j < totdeg; j++)
        {
            mpf_mul(tmp.get_mpf_t(), t[i][j].get_mpf_t(), c[j].get_mpf_t());
            mpf_sub(c[i].get_mpf_t(), c[i].get_mpf_t(), tmp.get_mpf_t());
        }
    }

    totdeg--;
    vector<complex<double>> res(totdeg);

    for (auto i = 0; i < totdeg; i++)
    {
        res[i] = complex<double>(c[i].get_d(), 0);
    }

    delete[] x;
    delete[] p;
    delete[] c;
    return res;
}

}  // namespace util
}  // namespace poseidon
