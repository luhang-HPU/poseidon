#pragma once

#if POSEIDON_COMPILER == POSEIDON_COMPILER_GCC

// We require GCC >= 6
#if (__GNUC__ < 6) || not defined(__cplusplus)
#pragma GCC error "POSEIDON requires __GNUC__ >= 6"
#endif

// Read in config.h
#include "src/util/config.h"

#if (__GNUC__ == 6) && defined(POSEIDON_USE_IF_CONSTEXPR)
#pragma GCC error                                                                                  \
    "g++-6 cannot compile Poseidon as C++17; set CMake build option `POSEIDON_USE_CXX17' to OFF"
#endif

#define POSEIDON_FORCE_INLINE inline __attribute__((always_inline))

#ifdef POSEIDON_USE_ALIGNED_ALLOC
#include <cstdlib>
#define POSEIDON_MALLOC(size)                                                                      \
    static_cast<poseidon_byte *>((((size)&63) == 0) ? ::aligned_alloc(64, (size))                  \
                                                    : std::malloc((size)))
#define POSEIDON_FREE(ptr) std::free(ptr)
#endif

// Are intrinsics enabled?
#ifdef POSEIDON_USE_INTRIN
#if defined(__aarch64__)
#include <arm_neon.h>
#elif defined(EMSCRIPTEN)
#include <wasm_simd128.h>
#else
#include <x86intrin.h>
#endif

#ifdef POSEIDON_USE___BUILTIN_CLZLL
#define POSEIDON_MSB_INDEX_UINT64(result, value)                                                   \
    {                                                                                              \
        *result = 63UL - static_cast<unsigned long>(__builtin_clzll(value));                       \
    }
#endif

#ifdef POSEIDON_USE___INT128
__extension__ typedef __int128 int128_t;
__extension__ typedef unsigned __int128 uint128_t;
#define POSEIDON_MULTIPLY_UINT64_HW64(operand1, operand2, hw64)                                    \
    do                                                                                             \
    {                                                                                              \
        *hw64 = static_cast<unsigned long long>(                                                   \
            ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64));        \
    } while (false);

#define POSEIDON_MULTIPLY_UINT64(operand1, operand2, result128)                                    \
    do                                                                                             \
    {                                                                                              \
        uint128_t product = static_cast<uint128_t>(operand1) * operand2;                           \
        result128[0] = static_cast<unsigned long long>(product);                                   \
        result128[1] = static_cast<unsigned long long>(product >> 64);                             \
    } while (false)

#define POSEIDON_DIVIDE_UINT128_UINT64(numerator, denominator, result)                             \
    do                                                                                             \
    {                                                                                              \
        uint128_t n, q;                                                                            \
        n = (static_cast<uint128_t>(numerator[1]) << 64) | (static_cast<uint128_t>(numerator[0])); \
        q = n / denominator;                                                                       \
        n -= q * denominator;                                                                      \
        numerator[0] = static_cast<std::uint64_t>(n);                                              \
        numerator[1] = 0;                                                                          \
        result[0] = static_cast<std::uint64_t>(q);                                                 \
        result[1] = static_cast<std::uint64_t>(q >> 64);                                           \
    } while (false)
#endif

// GCC intrinsics for _addcarry_u64 is disabled, for it compiles to slower code than
// add_uint64_generic.
//#ifdef POSEIDON_USE__ADDCARRY_U64
//#define POSEIDON_ADD_CARRY_UINT64(operand1, operand2, carry, result) _addcarry_u64(carry,
// operand1, operand2, result) #endif

#ifdef POSEIDON_USE_SUBBORROW_U64
#if ((__GNUC__ == 7) && (__GNUC_MINOR__ >= 2)) || (__GNUC__ >= 8)
// The inverted arguments problem was fixed in GCC-7.2
// (https://patchwork.ozlabs.org/patch/784309/)
#define POSEIDON_SUB_BORROW_UINT64(operand1, operand2, borrow, result)                             \
    _subborrow_u64(borrow, operand1, operand2, result)
#else
// Warning: Note the inverted order of operand1 and operand2
#define POSEIDON_SUB_BORROW_UINT64(operand1, operand2, borrow, result)                             \
    _subborrow_u64(borrow, operand2, operand1, result)
#endif  //(__GNUC__ == 7) && (__GNUC_MINOR__ >= 2)
#endif

#endif  // POSEIDON_USE_INTRIN

#endif
