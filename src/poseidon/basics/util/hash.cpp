#include "poseidon/basics/util/hash.h"

using namespace std;

namespace poseidon
{
namespace util
{
// Required for C++14 compliance: static constexpr member variables are not necessarily inlined so
// need to ensure symbol is created.
constexpr size_t HashFunction::hash_block_uint64_count;

// Required for C++14 compliance: static constexpr member variables are not necessarily inlined so
// need to ensure symbol is created.
constexpr size_t HashFunction::hash_block_byte_count;

// Required for C++14 compliance: static constexpr member variables are not necessarily inlined so
// need to ensure symbol is created.
constexpr HashFunction::hash_block_type HashFunction::hash_zero_block;
}  // namespace util
}  // namespace poseidon
