cmake_minimum_required(VERSION 3.12)

file(GLOB CKKS_EXAMPLE_SOURCES CONFIGURE_DEPENDS "*.cpp")

foreach(ckks_example_source IN LISTS CKKS_EXAMPLE_SOURCES)
    get_filename_component(ckks_example_target "${ckks_example_source}" NAME_WE)
    add_executable(${ckks_example_target} "${ckks_example_source}")
    target_link_libraries(${ckks_example_target} poseidon_shared)
endforeach()
