#include "test_ckks_dag_48_common.h"

int main() {
  ckks_dag48::run_example(ckks_dag48::ExecutionMode::ManualParallel);
  return 0;
}
