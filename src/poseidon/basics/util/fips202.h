#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif

    void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#if defined(__cplusplus)
}
#endif
