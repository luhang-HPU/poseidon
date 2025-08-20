#pragma once

#include "poseidon/advance/polynomial_evaluation.h"
#include <complex>
#include <vector>
using namespace std;

namespace poseidon
{
enum SineType
{
    CosDiscrete,
    SinContinuous,
    CosContinuous
};
namespace util
{

typedef double (*FunD)(double);
typedef complex<double> (*FunComp)(const complex<double> &);
Polynomial approximate(FunD fun, double a, double b, int degree);
Polynomial approximate(FunComp fun, double a, double b, int degree);

vector<double> chebyshev_nodes(int n, double a, double b);
vector<complex<double>> cheby_coeffs(const vector<double> &nodes, const vector<complex<double>> &fi,
                                     double a, double b);
}  // namespace util
}  // namespace poseidon
