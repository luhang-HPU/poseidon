#pragma once

#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"

#include "poseidon/basics/memorymanager.h"
#include "poseidon/basics/util/iterator.h"
#include <cstdint>

namespace poseidon
{
namespace util
{
void add_plain_without_scaling_variant(const Plaintext &plain,
                                       const CrtContext::ContextData &context_data,
                                       RNSIter destination);

void sub_plain_without_scaling_variant(const Plaintext &plain,
                                       const CrtContext::ContextData &context_data,
                                       RNSIter destination);

void multiply_add_plain_with_scaling_variant(const Plaintext &plain,
                                             const CrtContext::ContextData &context_data,
                                             RNSIter destination);

void multiply_sub_plain_with_scaling_variant(const Plaintext &plain,
                                             const CrtContext::ContextData &context_data,
                                             RNSIter destination);
}  // namespace util
}  // namespace poseidon
