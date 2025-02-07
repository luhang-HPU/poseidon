#include "homomorphic_linear_transform.h"

namespace poseidon
{
bool is_in_slice_int(int x, const vector<int> &slice)
{
    for (int i : slice)
    {
        if (i == x)
        {
            return true;
        }
    }
    return false;
}
}  // namespace poseidon
