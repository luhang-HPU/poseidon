#include "chebyshev_interpolation.h"

namespace poseidon
{
namespace util
{

Polynomial approximate(FunComp fun, double a, double b, int degree)
{
    vector<double> nodes;
    nodes = util::chebyshev_nodes(degree, a, b);
    vector<complex<double>> fi(degree);
    for (int i = 0; i < nodes.size(); i++)
    {
        fi[i] = fun(complex<double>(nodes[i], 0));
    }
    auto buffer = util::cheby_coeffs(nodes, fi, a, b);
    Polynomial poly(buffer, a, b, degree - 1, Chebyshev);
    return poly;
}
Polynomial approximate(FunD fun, double a, double b, int degree)
{
    vector<double> nodes;
    nodes = util::chebyshev_nodes(degree, a, b);
    vector<complex<double>> fi(degree);
    for (int i = 0; i < nodes.size(); i++)
    {
        fi[i] = complex<double>(fun(nodes[i]), 0);
    }

    auto buffer = util::cheby_coeffs(nodes, fi, a, b);
    Polynomial poly(buffer, a, b, degree - 1, Chebyshev);
    return poly;
}

vector<double> chebyshev_nodes(int n, double a, double b)
{
    vector<double> u(n, 0);
    auto x = 0.5 * (a + b);
    auto y = 0.5 * (b - a);
    for (int k = 1; k < n + 1; k++)
    {
        u[k - 1] = x + y * cos(((double)k - 0.5) * M_PI / (double)n);
    }
    return u;
}

vector<complex<double>> cheby_coeffs(const vector<double> &nodes, const vector<complex<double>> &fi,
                                     double a, double b)
{
    complex<double> u, tprev, t, tnext;
    size_t n = nodes.size();
    vector<complex<double>> coeffs(n);

    for (int i = 0; i < n; i++)
    {
        u = complex<double>((2 * nodes[i] - a - b) / (b - a), 0);
        tprev = 1.0;
        t = u;
        for (int j = 0; j < n; j++)
        {
            coeffs[j] += fi[i] * tprev;
            tnext = complex<double>(2, 0) * u * t - tprev;
            tprev = t;
            t = tnext;
        }
    }

    coeffs[0] /= complex<double>(double(n), 0);
    for (int i = 1; i < n; i++)
    {
        coeffs[i] *= (2.0 / complex<double>(double(n), 0));
    }
    return coeffs;
}
}  // namespace util
}  // namespace poseidon
