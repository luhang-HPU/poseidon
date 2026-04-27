#include "test_ckks_dag_common.h"

int main()
{
    return ckks_dag::run_example({24, 64.0, "manual-parallel 24-branch"});
}
