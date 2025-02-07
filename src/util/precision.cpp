#include "precision.h"

namespace poseidon
{
namespace util
{

PrecisionStats delta_to_precision(const PrecisionStats &c)
{
    return PrecisionStats{log2(1 / c.Real), log2(1 / c.Imag), log2(1 / c.L2)};
}

void GetPrecisionStats(vector<complex<double>> value_test, vector<complex<double>> value_want)
{
    double delta_real, delta_imag, delta_l2;
    auto slots = value_want.size();
    vector<double> prec_real(slots);
    vector<double> prec_imag(slots);
    vector<double> prec_l2(slots);
    std::vector<PrecisionStats> diff;
    diff.resize(slots);
    PrecisionStats MeanDelta{0, 0, 0};
    PrecisionStats MaxDelta{0, 0, 0};
    PrecisionStats MinDelta{1, 1, 1};

    for (int i = 0; i < slots; i++)
    {
        delta_real = abs(real(value_test[i]) - real(value_want[i]));
        delta_imag = abs(imag(value_test[i]) - imag(value_want[i]));
        delta_l2 = sqrt(delta_real * delta_real + delta_imag * delta_imag);
        prec_real[i] = log2(1 / delta_real);
        prec_imag[i] = log2(1 / delta_imag);
        prec_l2[i] = log2(1 / delta_l2);
        diff[i].Real = delta_real;
        diff[i].Imag = delta_imag;
        diff[i].L2 = delta_l2;
        MeanDelta.Real += delta_real;
        MeanDelta.Imag += delta_imag;
        MeanDelta.L2 += delta_l2;

        if (delta_real > MaxDelta.Real)
        {
            MaxDelta.Real = delta_real;
        }
        if (delta_imag > MaxDelta.Imag)
        {
            MaxDelta.Imag = delta_imag;
        }
        if (delta_imag > MaxDelta.L2)
        {
            MaxDelta.L2 = delta_l2;
        }

        if (delta_real < MinDelta.Real)
        {
            MinDelta.Real = delta_real;
        }

        if (delta_imag < MinDelta.Imag)
        {
            MinDelta.Imag = delta_imag;
        }

        if (delta_l2 < MinDelta.L2)
        {
            MinDelta.L2 = delta_l2;
        }
    }

    auto MinPrecision = delta_to_precision(MaxDelta);
    auto MaxPrecision = delta_to_precision(MinDelta);
    MeanDelta.Real /= (double)slots;
    MeanDelta.Imag /= (double)slots;
    MeanDelta.L2 /= (double)slots;
    auto MeanPrecision = delta_to_precision(MeanDelta);
    printf(PRECISION_TITLE, MinPrecision.Real, MinPrecision.Imag, MinPrecision.L2,
           MaxPrecision.Real, MaxPrecision.Imag, MaxPrecision.L2, MeanPrecision.Real,
           MeanPrecision.Imag, MeanPrecision.L2);
}

//"┌─────────┬───────┬───────┬───────┐\n"  \
//"│    Log2 │ REAL  │ IMAG  │ L2    │\n"  \
//"├─────────┼───────┼───────┼───────┤\n"  \
//"│MIN Prec │ %5.2f │ %5.2f │ %5.2f │\n"  \
//"│MAX Prec │ %5.2f │ %5.2f │ %5.2f │\n"  \
//"│AVG Prec │ %5.2f │ %5.2f │ %5.2f │\n"  \
//"│MED Prec │ %5.2f │ %5.2f │ %5.2f │\n"  \
//"└─────────┴───────┴───────┴───────┘\n" ;
}  // namespace util
}  // namespace poseidon