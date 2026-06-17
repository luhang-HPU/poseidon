#pragma once

#include <complex>
#include <tuple>
#include <vector>

using namespace std;

namespace poseidon
{
enum PolynomialBasisType
{
    Chebyshev,
    Monomial
};

class Polynomial
{
public:
    Polynomial() = default;

    inline Polynomial(const vector<complex<double>> &data, int a, int b, int max_deg,
                      PolynomialBasisType basis_type, bool lead = false)
        : data_(std::move(data)), a_(a), b_(b), max_deg_(max_deg), basis_type_(basis_type),
          lead_(lead){};

    Polynomial(const Polynomial &copy) = default;
    Polynomial(Polynomial &&source) = default;
    Polynomial &operator=(const Polynomial &assign) = default;
    Polynomial &operator=(Polynomial &&assign) = default;

    inline vector<complex<double>> &data() noexcept { return data_; }
    inline const vector<complex<double>> &data() const noexcept { return data_; }
    inline auto &a() noexcept { return a_; }
    inline const auto a() const noexcept { return a_; }
    inline auto &b() noexcept { return b_; }
    inline const auto b() const noexcept { return b_; }

    inline auto &max_degree() noexcept { return max_deg_; }
    inline const auto max_degree() const noexcept { return max_deg_; }

    inline const auto degree() const noexcept { return data_.size() - 1; }

    inline auto &basis_type() noexcept { return basis_type_; }
    inline const auto basis_type() const noexcept { return basis_type_; }

    inline auto &lead() noexcept { return lead_; }
    inline const auto lead() const noexcept { return lead_; }

    inline bool& is_even() noexcept { return is_even_; }
    inline const bool is_even() const noexcept { return is_even_; }

    inline bool& is_odd() noexcept { return is_odd_; }
    inline const bool is_odd() const noexcept { return is_odd_; }

    inline int& level() noexcept { return level_; }
    inline const int level() const noexcept { return level_; }

    inline double& scale() noexcept { return scale_; }
    inline const double scale() const noexcept { return scale_; }

private:
    vector<complex<double>> data_{};
    int a_ = 0;
    int b_ = 0;
    int max_deg_ = 0;
    PolynomialBasisType basis_type_ = Monomial;
    bool lead_ = false;

    bool is_even_ = true;
    bool is_odd_ = true;

    // member level_ / scale_ used for simulation
    int level_ = -1;
    double scale_ = -1.0;
};

class PolynomialVector
{
public:
    PolynomialVector() = default;

    PolynomialVector(const vector<Polynomial> &polys, const vector<vector<int>> &indexs,
                     bool lead = true)
        : poly_vector_(polys), poly_index_(indexs)
    {
    }
    PolynomialVector(const PolynomialVector &copy) = default;
    PolynomialVector(PolynomialVector &&source) = default;
    PolynomialVector &operator=(const PolynomialVector &assign) = default;
    PolynomialVector &operator=(PolynomialVector &&assign) = default;

    inline vector<Polynomial> &polys() noexcept { return poly_vector_; }
    inline auto const &polys() const noexcept { return poly_vector_; }

    inline const vector<vector<int>> &index() const noexcept { return poly_index_; }
    inline vector<vector<int>> &index() noexcept { return poly_index_; }

    inline const auto &index_vector() const noexcept { return poly_index_; }

    inline Polynomial& operator[](int i) noexcept { return poly_vector_[i]; }
    inline const Polynomial& operator[](int i) const noexcept { return poly_vector_[i]; }

    inline const bool is_even() const noexcept
    {
        bool is_even = true;
        for (auto &poly : poly_vector_)
        {
            is_even = is_even && poly.is_even();
        }
        return is_even;
    }
    inline const bool is_odd() const noexcept
    {
        bool is_odd = true;
        for (auto &poly : poly_vector_)
        {
            is_odd = is_odd && poly.is_odd();
        }
        return is_odd;
    }

    inline int size() const noexcept { return poly_vector_.size(); }


private:
    vector<Polynomial> poly_vector_;
    vector<vector<int>> poly_index_;
};

tuple<Polynomial, Polynomial> split_coeffs(const Polynomial &coeffs, int split);

void split_coeffs_poly_vector(const PolynomialVector &polys, PolynomialVector &coeffsq,
                              PolynomialVector &coeffsr, int split);

}  // namespace poseidon
