#pragma once

#include "src/basics/util/defines.h"
#include "src/util/exception.h"
#include <cmath>
#include <random>

namespace poseidon
{
namespace util
{
class ClippedNormalDistribution
{
public:
    using result_type = double;

    using param_type = ClippedNormalDistribution;

    ClippedNormalDistribution(result_type mean, result_type standard_deviation,
                              result_type max_deviation);

    template <typename RNG>
    POSEIDON_NODISCARD inline result_type operator()(RNG &engine, const param_type &parm) noexcept
    {
        param(parm);
        return operator()(engine);
    }

    template <typename RNG> POSEIDON_NODISCARD inline result_type operator()(RNG &engine) noexcept
    {
        result_type mean = normal_.mean();
        while (true)
        {
            result_type value = normal_(engine);
            result_type deviation = std::abs(value - mean);
            if (deviation <= max_deviation_)
            {
                return value;
            }
        }
    }

    POSEIDON_NODISCARD inline result_type mean() const noexcept { return normal_.mean(); }

    POSEIDON_NODISCARD inline result_type standard_deviation() const noexcept
    {
        return normal_.stddev();
    }

    POSEIDON_NODISCARD inline result_type max_deviation() const noexcept { return max_deviation_; }

    POSEIDON_NODISCARD inline result_type min() const noexcept
    {
        return normal_.mean() - max_deviation_;
    }

    POSEIDON_NODISCARD inline result_type max() const noexcept
    {
        return normal_.mean() + max_deviation_;
    }

    POSEIDON_NODISCARD inline param_type param() const noexcept { return *this; }

    inline void param(const param_type &parm) noexcept { *this = parm; }

    inline void reset() noexcept { normal_.reset(); }

private:
    std::normal_distribution<result_type> normal_;

    result_type max_deviation_;
};
}  // namespace util
}  // namespace poseidon
