#pragma once

#include <complex>
#include <vector>

#define PRECISION_TITLE                                                                                           \
    "┌─────────┬───────┬───────┬───────┐\n" \
    "│    Log2 │ REAL  │ IMAG  │ L2    │\n"                                                             \
    "├─────────┼───────┼───────┼───────┤\n" \
    "│MIN Prec │ %5.2f │ %5.2f │ %5.2f │\n"                                                             \
    "│MAX Prec │ %5.2f │ %5.2f │ %5.2f │\n"                                                             \
    "│AVG Prec │ %5.2f │ %5.2f │ %5.2f │\n"                                                             \
    "└─────────┴───────┴───────┴───────┘\n"

using namespace std;

namespace poseidon
{
namespace util
{

struct PrecisionStats
{
    double Real;
    double Imag;
    double L2;
};
void GetPrecisionStats(vector<complex<double>> value_test, vector<complex<double>> value_want);

}  // namespace util
}  // namespace poseidon
