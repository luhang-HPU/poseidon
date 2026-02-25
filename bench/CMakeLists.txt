cmake_minimum_required(VERSION 3.13)
project(POSEIDONBench VERSION 4.1.1 LANGUAGES CXX)

# Must define these variables and include macros
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(POSEIDON_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/../thirdparty)
set(THIRDPARTY_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/thirdparty")

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(PoseidonMacros)
include(FetchContent)
mark_as_advanced(FETCHCONTENT_BASE_DIR)
mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
mark_as_advanced(FETCHCONTENT_QUIET)
message(STATUS "Benchmark: download ...")
poseidon_fetch_thirdparty_content(ExternalBenchmark)
add_executable(poseidonbench)
# If we're targeting WASM, add the appropriate link flags
if(EMSCRIPTEN)
    set_target_properties(poseidonbench PROPERTIES LINK_FLAGS "-flto -O3 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s MAXIMUM_MEMORY=4GB")
endif()
target_sources(poseidonbench
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/keygen.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
        ${CMAKE_CURRENT_LIST_DIR}/bfv.cpp
        ${CMAKE_CURRENT_LIST_DIR}/bgv.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ckks.cpp
)

target_link_libraries(poseidonbench PUBLIC poseidon_shared benchmark::benchmark)
