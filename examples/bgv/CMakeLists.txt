cmake_minimum_required(VERSION 3.12)

#test bgv test_bgv_basic
add_executable(test_bgv_basic test_bgv_basic.cpp)
target_link_libraries(test_bgv_basic poseidon_shared)

add_executable(test_bgv_load test_bgv_load.cpp)
target_link_libraries(test_bgv_load poseidon_shared)