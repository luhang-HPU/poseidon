#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "src/basics/util/common.h"
#include <string.h>

#if (POSEIDON_SYSTEM == POSEIDON_SYSTEM_WINDOWS)
#include <Windows.h>
#endif

using namespace std;

namespace poseidon
{
namespace util
{
void poseidon_memzero(void *data, size_t size)
{
#if (POSEIDON_SYSTEM == POSEIDON_SYSTEM_WINDOWS)
    SecureZeroMemory(data, size);
#elif defined(POSEIDON_USE_MEMSET_S)
    if (size > 0U && memset_s(data, static_cast<rsize_t>(size), 0, static_cast<rsize_t>(size)) != 0)
    {
        throw runtime_error("error calling memset_s");
    }
#elif defined(POSEIDON_USE_EXPLICIT_BZERO)
    explicit_bzero(data, size);
#elif defined(POSEIDON_USE_EXPLICIT_MEMSET)
    explicit_memset(data, 0, size);
#else
    volatile poseidon_byte *data_ptr = reinterpret_cast<poseidon_byte *>(data);
    while (size--)
    {
        *data_ptr++ = poseidon_byte{};
    }
#endif
}
}  // namespace util
}  // namespace poseidon
