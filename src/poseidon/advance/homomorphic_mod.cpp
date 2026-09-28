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
        arcsine_poly_.is_even() = false;
    }
    else
    {
        this->sqrt_2pi_ = pow(1 / (2 * M_PIl) * q_diff_, 1.0 / sc_fac_);
    }

    switch (type_)
    {
    case SinContinuous:
        sine_poly_ = approximate(sin_2pi_x, -k, k, sine_degree);
        sine_poly_.lead() = true;
        sine_poly_a_ = -k_;
        sine_poly_b_ = k_;
        sine_poly_.is_even() = false;
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
        sine_poly_.is_odd() = false;
        break;

    case CosContinuous:
        // TODO
        exit(0);
    }

    for (int i = 0; i < sine_poly_.data().size(); i++)
    {
        this->sine_poly_.data()[i] *= complex<double>(sqrt_2pi_, 0);
    }
}

void EvalModPoly::set_cosine_coefficients(const std::vector<double> &coefficients)
{
    if (type_ != CosDiscrete || coefficients.size() != sine_poly_.data().size() ||
        coefficients.empty() || coefficients.back() == 0.0)
        throw std::invalid_argument("cosine coefficients must preserve the existing nonzero degree");
    for (std::size_t i = 0; i < coefficients.size(); ++i)
    {
        if (!std::isfinite(coefficients[i]) || !std::isfinite(coefficients[i] * sqrt_2pi_))
            throw std::invalid_argument("cosine coefficients must be finite");
    }
    for (std::size_t i = 0; i < coefficients.size(); ++i)
        sine_poly_.data()[i] = coefficients[i] * sqrt_2pi_;
    enable_full_cosine_coefficients();
}

void EvalModPoly::enable_full_cosine_coefficients()
{
    if (type_ != CosDiscrete)
        throw std::invalid_argument("full cosine coefficients require CosDiscrete");
    bool has_even = false, has_odd = false;
    for (std::size_t i = 0; i < sine_poly_.data().size(); ++i)
        if (sine_poly_.data()[i] != std::complex<double>{})
            (i % 2 ? has_odd : has_even) = true;
    // These flags select which coefficient parities the PS evaluator visits.
    // Both true means a general polynomial, including its constant term.
    sine_poly_.is_even() = has_even;
    sine_poly_.is_odd() = has_odd;
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

int optimal_split_optimized(int log_degree)
{
    auto log_split = log_degree >> 1;
    auto a = (1 << log_split) + (1 << (log_degree - log_split)) + log_degree - log_split - 3;
    auto b = (1 << (log_split + 1)) + (1 << (log_degree - log_split - 1)) + log_degree - log_split - 4;
    if (a > b) {
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

}  // namespace poseidon
