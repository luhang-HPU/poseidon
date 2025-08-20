#include "homomorphic_mod.h"

using namespace poseidon::util;
namespace poseidon
{
EvalModPoly::EvalModPoly(const PoseidonContext &context, SineType type, double scaling_factor,
                         uint32_t level_start, uint32_t log_message_ratio, uint32_t double_angle,
                         uint32_t k, uint32_t arcsine_degree, uint32_t sine_degree)
    : type_(type), scaling_factor_(scaling_factor), level_start_(level_start),
      log_message_ratio_(log_message_ratio)
{
    this->double_angle_ = double_angle;
    if (type == SinContinuous)
        this->double_angle_ = 0;

    this->sc_fac_ = exp2((double)this->double_angle_);
    this->k_ = (double)k / sc_fac_;
    auto q = context.crt_context()->q0();

    this->q_diff_ = q / exp2(round(log2(q)));
    this->q_div_ = (double)scaling_factor_ / exp2(round(log2(q)));
    if (q_div_ > 1)
    {
        q_div_ = 1;
    }
    if (arcsine_degree > 0)
    {
        this->sqrt_2pi_ = 1.0;
        vector<complex<double>> arc_buffer;

        arc_buffer.resize(arcsine_degree + 1);
        arc_buffer[1] = 0.15915494309189535 * complex<double>(q_diff_, 0);

        for (int i = 3; i < arcsine_degree + 1; i += 2)
        {
            arc_buffer[i] = arc_buffer[i - 2] *
                            complex<double>((double)(i * i - 4 * i + 4) / (double)(i * i - i), 0);
        }
        arcsine_poly_.data() = arc_buffer;
        arcsine_poly_.lead() = true;
        arcsine_poly_.a() = 0;
        arcsine_poly_.b() = 0;
        arcsine_poly_.max_degree() = arcsine_degree;
    }
    else
    {
        this->sqrt_2pi_ = pow(1 / (2 * M_PIl) * q_diff_, 1.0 / sc_fac_);
    }

    switch (type_)
    {
    case SinContinuous:
        sine_poly_ = approximate(sin2pi2pi, -k, k, sine_degree);
        sine_poly_.lead() = true;
        sine_poly_a_ = -k_;
        sine_poly_b_ = k_;

        break;
    case CosDiscrete:
        sine_poly_.lead() = true;
        sine_poly_a_ = -k_;
        sine_poly_b_ = k_;
        sine_poly_.lead() = true;

        sine_poly_.a() = -k_;
        sine_poly_.b() = k_;  // this k_ is the  size of double_angle
        sine_poly_.basis_type() = Chebyshev;
        sine_poly_.data() = ApproximateCos(k, sine_degree, (double)(1 << log_message_ratio),
                                           double_angle);  // this k is total size
        sine_poly_.max_degree() = sine_poly_.data().size() - 1;
        break;

    case CosContinuous:
        exit(0);
    }

    for (int i = 0; i < sine_poly_.data().size(); i++)
    {
        this->sine_poly_.data()[i] *= complex<double>(sqrt_2pi_, 0);
    }
}

int optimal_split(int log_degree)
{
    int log_split = log_degree >> 1;
    if (log_degree - log_split > log_split)
    {
        log_split++;
    }
    return log_split;
}

bool is_not_negligible(complex<double> c)
{
    if (abs(real(c)) > util::IsNegligibleThreshold || abs(imag(c)) > util::IsNegligibleThreshold)
    {
        return true;
    }
    else
    {
        return false;
    }
}
pair<bool, bool> is_odd_or_even_polynomial(Polynomial &poly)
{
    bool even = true;
    bool odd = true;
    auto poly_degree = poly.max_degree();
    auto &data = poly.data();

    for (int i = 0; i < poly_degree; i++)
    {
        auto isnotnegligible = is_not_negligible(data[i]);

        auto state = i & 1;

        odd = odd && (state != 0 && isnotnegligible);
        even = even && (state != 1 && isnotnegligible);
        if (!odd && !even)
        {
            break;
        }
    }
    // If even or odd, then sets the expected zero coefficients to zero
    if (even || odd)
    {
        int start = 0;
        if (even)
        {
            start = 1;
        }
        for (int i = start; i < poly_degree; i += 2)
        {
            poly.data()[i] = complex<double>(0, 0);
        }
    }
    return make_pair(odd, even);
}

}  // namespace poseidon