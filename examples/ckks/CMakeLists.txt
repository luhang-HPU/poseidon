cmake_minimum_required(VERSION 3.12)

set(CKKS_DAG_TARGETS
    test_ckks_dag_single_thread_24_parallel
    test_ckks_dag_manual_parallel_24
    test_ckks_dag_single_thread_48_parallel
    test_ckks_dag_manual_parallel_48
)

foreach(ckks_example_target IN LISTS CKKS_DAG_TARGETS)
    add_executable(${ckks_example_target} "${ckks_example_target}.cpp")
    target_link_libraries(${ckks_example_target} poseidon_shared)
endforeach()
