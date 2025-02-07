set(POSEIDON_USE_STD_BYTE OFF)
set(POSEIDON_USE_SHARED_MUTEX OFF)
set(POSEIDON_USE_IF_CONSTEXPR OFF)
set(POSEIDON_USE_MAYBE_UNUSED OFF)
set(POSEIDON_USE_NODISCARD OFF)
set(POSEIDON_USE_STD_FOR_EACH_N OFF)
set(CMAKE_CXX_STANDARD 14)
set(POSEIDON_LANG_FLAG "-std=c++14")
if(POSEIDON_USE_CXX17)
    set(POSEIDON_USE_STD_BYTE ON)
    set(POSEIDON_USE_SHARED_MUTEX ON)
    set(POSEIDON_USE_IF_CONSTEXPR ON)
    set(POSEIDON_USE_MAYBE_UNUSED ON)
    set(POSEIDON_USE_NODISCARD ON)
    set(POSEIDON_USE_STD_FOR_EACH_N ON)
    set(POSEIDON_LANG_FLAG "-std=c++17")
    set(CMAKE_CXX_STANDARD 17)
endif()

# In some non-MSVC compilers std::for_each_n is not available even when compiling as C++17
if(POSEIDON_USE_STD_FOR_EACH_N)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)

    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${POSEIDON_LANG_FLAG}")
        check_cxx_source_compiles("
            #include <algorithm>
            int main() {
                int a[1]{ 0 };
                volatile auto fun = std::for_each_n(a, 1, [](auto b) {});
                return 0;
            }"
            USE_STD_FOR_EACH_N
        )
        if(NOT USE_STD_FOR_EACH_N EQUAL 1)
            set(POSEIDON_USE_STD_FOR_EACH_N OFF)
            message(STATUS "STD_FOR_EACH_N: ${POSEIDON_USE_STD_FOR_EACH_N}")
        endif()
        unset(USE_STD_FOR_EACH_N CACHE)
    endif()

    cmake_pop_check_state()
endif()
