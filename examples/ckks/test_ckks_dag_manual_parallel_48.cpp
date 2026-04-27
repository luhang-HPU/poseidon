#include "test_ckks_dag_common.h"

int main()
{
    return ckks_dag::run_example({48, 128.0, "manual-parallel 48-branch"});
}
