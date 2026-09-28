#!/usr/bin/env python3
"""Regenerate the full degree-22 CosDiscrete coefficients (K=12, DA=3).

Output is either 23 unscaled Chebyshev coefficients (one per line), or JSON
including scalar checks. No encryption/key material is used. Requires mpmath.
The selected interpolation fixes integer roots, rather than optimizing a
continuous cosine interval at the expense of those roots. It DOES NOT remove
the R/(2*pi)*sin(2*pi*m/R) linearization bias.
"""
import argparse
import json
import math
import mpmath as mp


def fit(precision):
    mp.mp.dps = precision
    matrix, values = [], []
    for integer in range(-11, 12):
        z = (mp.mpf(integer) - mp.mpf(1) / 4) / 12
        row = [mp.mpf(1), z]
        for _ in range(2, 23):
            row.append(2 * z * row[-1] - row[-2])
        matrix.append(row)
        values.append(mp.cos(3 * mp.pi * z))
    return list(mp.lu_solve(mp.matrix(matrix), mp.matrix(values)))


def evaluate(coefficients, t, ratio):
    # Clenshaw in the same normalized basis as the ciphertext evaluator.
    x = (t - .25) / 12
    b1 = b2 = 0.0
    for c in reversed(coefficients[1:]):
        b0 = 2 * x * b1 - b2 + c
        b2, b1 = b1, b0
    value = coefficients[0] + x * b1 - b2
    for _ in range(3):
        value = 2 * value * value - 1
    return ratio * value / (2 * math.pi)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--precision', type=int, default=100)
    p.add_argument('--ratio', type=int, default=128)
    p.add_argument('--format', choices=['coefficients', 'json'], default='coefficients')
    args = p.parse_args()
    if args.precision < 50 or args.precision > 500 or args.ratio < 16:
        p.error('precision must be 50..500 and ratio >=16')
    high_precision = fit(args.precision)
    coefficients = [float(v) for v in high_precision]
    if args.format == 'coefficients':
        for c in coefficients:
            print(format(c, '.17g'))
        return
    profiles = {'full': coefficients,
                'even_only': [v if i % 2 == 0 else 0.0 for i, v in enumerate(coefficients)]}
    checks = {}
    for name, c in profiles.items():
        checks[name] = {}
        for limit in (3, 6, 11):
            center = max(abs(evaluate(c, float(j), args.ratio)) for j in range(-limit, limit + 1))
            worst = 0.0
            for j in range(-limit, limit + 1):
                for index in range(1001):
                    message = -1 + 2 * index / 1000
                    worst = max(worst, abs(evaluate(c, j + message / args.ratio, args.ratio) - message))
            checks[name][str(limit)] = {'integer_center_residual': center,
                                       'max_scalar_residual_on_bands': worst}
    print(json.dumps({'degree': 22, 'K': 12, 'double_angle': 3,
                      'ratio_for_validation': args.ratio, 'precision_decimal_digits': args.precision,
                      'basis': 'Chebyshev((t-1/4)/12), before sqrt_2pi scaling',
                      'coefficients': coefficients, 'scalar_checks': checks}, indent=2))


if __name__ == '__main__':
    main()
