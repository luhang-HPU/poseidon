#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/advance/util/chebyshev_interpolation.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

double f(double x)
{
    return sin(6.283185307179586 * x);
}

int main()
{
    spdlog::set_level(spdlog::level::debug);

    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 40, 1, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(std::vector<uint32_t>(30, 40), std::vector<uint32_t>{40});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    auto a = -16.0;
    auto b = 16.0;
    auto deg = 32;
    printf("Evaluation of f(x)=sin(2πx) in range [%0.2f, %0.2f] (degree: %d)\n\n", a, b, deg);

    // ======================
    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 40, 1, 9, 3, 16, 0, 30);
    Polynomial approx_f = eval_mod_poly.sine_poly();
    // ======================


    bool is_chev = (approx_f.basis_type() == Chebyshev);
    printf("Basis type: %s\n", is_chev ? "Chebyshev" : "Monomial");

    vector<Polynomial> poly_v{approx_f};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idx_f(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < (context.parameters_literal()->degree() >> 1); i++)
    {
        idx_f[i] = i;
    }
    slots_index[0] = idx_f;
    PolynomialVector polys(poly_v, slots_index);

    // Evaluate polynomial at many points and compare against ground truth
    int test_points = 200;
    double max_error = 0.0;
    double avg_error = 0.0;

    printf("\n%-8s %-16s %-16s %-16s %-16s\n", "x", "expected", "message_result", "error", "x_normalized");
    printf("-------------------------------------------------------------------------------\n");

    for (int i = 0; i < 1; i++)
    {
        double x = a + (b - a) * (double)i / (double)(test_points - 1);
        // Normalize: maps [a,b] -> domain expected by Chebyshev polynomial
        double x_normalized = (2.0 * x - a - b) / (b - a);

        complex<double> input(x_normalized, 0);
        complex<double> result;

        ckks_eva->evaluate_polynomial_message(polys, input, result, is_chev, false);

        double expected = f(x);
        double error = std::abs(result.real() - expected);
        max_error = std::max(max_error, error);
        avg_error += error;

        if (i < 10 || i >= test_points - 5)
        {
            printf("%-8.4f %-16.10f %-16.10f %-16.10f %-16.10f\n",
                   x, expected, result.real(), error, x_normalized);
        }
        else if (i == 10)
        {
            printf("...\n");
        }
    }
    avg_error /= test_points;

    printf("\nError stats over %d points in [%.2f, %.2f]:\n", test_points, a, b);
    printf("  Max error: %.10f\n", max_error);
    printf("  Avg error: %.10f\n", avg_error);

    double tolerance = 1e-4;
    if (max_error < tolerance)
    {
        printf("PASS: max error %.10f < %.10f\n", max_error, tolerance);
        return 0;
    }
    else
    {
        printf("WARN: max error %.10f exceeds tolerance %.10f\n", max_error, tolerance);
        return 1;
    }
}
