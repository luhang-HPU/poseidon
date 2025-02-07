#pragma once

#include "polynomial_evaluation.h"
#include "src/advance/util/chebyshev_interpolation.h"
#include "src/advance/util/cosine_approx.h"
#include "src/basics/util/common.h"
#include "src/poseidon_context.h"
#include <utility>

namespace poseidon
{
int optimal_split(int log_degree);
bool is_not_negligible(complex<double> c);
pair<bool, bool> is_odd_or_even_polynomial(Polynomial &coeffs);

class EvalModPoly
{
public:
    EvalModPoly(const PoseidonContext &context, SineType type, double scaling_factor,
                uint32_t level_start, uint32_t log_message_ratio, uint32_t double_angle, uint32_t k,
                uint32_t arcsine_degree, uint32_t sine_degree);

    inline static complex<double> sin2pi2pi(const complex<double> &x)
    {
        return sin(6.283185307179586 * x);
    }

    inline SineType type() const { return this->type_; }

    inline int k() const { return this->k_; }

    inline double q_div() const { return this->q_div_; }

    inline int level_start() const { return this->level_start_; }

    inline double scaling_factor() const { return this->scaling_factor_; }

    inline uint32_t message_ratio() const { return 1 << this->log_message_ratio_; }

    inline uint32_t double_angle() const { return this->double_angle_; }

    inline double q_diff() const { return this->q_diff_; }

    inline double sc_fac() const { return this->sc_fac_; }

    inline double sqrt_2pi() const { return this->sqrt_2pi_; }

    inline int32_t sine_poly_a() const { return sine_poly_a_; }
    inline int32_t sine_poly_b() const { return sine_poly_b_; }
    inline const Polynomial &sine_poly() const { return this->sine_poly_; }

    inline const Polynomial &arcsine_poly() const { return this->arcsine_poly_; }

private:
    SineType type_;
    double scaling_factor_;
    uint32_t level_start_;
    uint32_t log_message_ratio_;
    uint32_t double_angle_;
    uint32_t k_;
    double q_div_;
    double q_diff_;
    double sc_fac_;
    double sqrt_2pi_;
    Polynomial sine_poly_;
    int32_t sine_poly_a_;
    int32_t sine_poly_b_;

    Polynomial arcsine_poly_;
};

}  // namespace poseidon
