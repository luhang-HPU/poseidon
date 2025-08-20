#pragma once

#include "poseidon/basics/util/defines.h"
#include <cstdint>

namespace poseidon
{
/**
Holds Poseidon version information. A SEALVersion contains four values:

    1. The major version number;
    2. The minor version number;
    3. The patch version number;
    4. The tweak version number.

Two versions of the library with the same major and minor versions are fully
compatible with each other. They are guaranteed to have the same public API.
Changes in the patch version number indicate totally internal changes, such
as bug fixes that require no changes to the public API. The tweak version
number is currently not used, and is expected to be 0.
*/
struct PoseidonVersion
{
    /**
    Holds the major version number.
    */
    std::uint8_t major = POSEIDON_VERSION_MAJOR;

    /**
    Holds the minor version number.
    */
    std::uint8_t minor = POSEIDON_VERSION_MINOR;

    /**
    Holds the patch version number.
    */
    std::uint8_t patch = POSEIDON_VERSION_PATCH;

    std::uint8_t tweak = 0;
};
}  // namespace poseidon
