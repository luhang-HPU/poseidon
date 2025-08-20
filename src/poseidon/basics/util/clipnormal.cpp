#include "poseidon/basics/util/clipnormal.h"
#include <stdexcept>

using namespace std;

namespace poseidon
{
namespace util
{
ClippedNormalDistribution::ClippedNormalDistribution(result_type mean,
                                                     result_type standard_deviation,
                                                     result_type max_deviation)
    : normal_(mean, standard_deviation), max_deviation_(max_deviation)
{
    // Verify arguments.
    if (standard_deviation < 0)
    {
        POSEIDON_THROW(invalid_argument_error, "standard_deviation");
    }
    if (max_deviation < 0)
    {
        POSEIDON_THROW(invalid_argument_error, "max_deviation");
    }
}
}  // namespace util
}  // namespace poseidon
