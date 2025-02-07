#pragma once

#include "src/basics/util/defines.h"

#if defined(POSEIDON_USE_ZLIB) || defined(POSEIDON_USE_ZSTD)
#include "src/basics/dynarray.h"
#include "src/basics/memorymanager.h"
#include <ios>
#include <iostream>

namespace poseidon
{
namespace util
{
namespace ztools
{
/**
Compresses data in the given buffer, completes the given POSEIDONHeader by writing in the size of
the output and setting the compression mode to compr_mode_type::zlib and finally writes the
POSEIDONHeader followed by the compressed data in the given stream.

@param[in] in The buffer to compress
@param[in] in_size The size of the buffer to compress in bytes
@param[out] header A pointer to a POSEIDONHeader instance matching the output of the compression
@param[out] out_stream The stream to write to
@param[in] pool The MemoryPoolHandle pointing to a valid memory pool
@throws std::invalid_argument if pool is uninitialized
@throws std::logic_error if compression failed
*/
void zlib_write_header_deflate_buffer(DynArray<poseidon_byte> &in, void *header_ptr,
                                      std::ostream &out_stream, MemoryPoolHandle pool);

int zlib_deflate_array_inplace(DynArray<poseidon_byte> &in, MemoryPoolHandle pool);

int zlib_inflate_stream(std::istream &in_stream, std::streamoff in_size, std::ostream &out_stream,
                        MemoryPoolHandle pool);

/**
Compresses data in the given buffer, completes the given POSEIDONHeader by writing in the size of
the output and setting the compression mode to compr_mode_type::zstd and finally writes the
POSEIDONHeader followed by the compressed data in the given stream.

@param[in] in The buffer to compress
@param[in] in_size The size of the buffer to compress in bytes
@param[out] header A pointer to a POSEIDONHeader instance matching the output of the compression
@param[out] out_stream The stream to write to
@param[in] pool The MemoryPoolHandle pointing to a valid memory pool
@throws std::invalid_argument if pool is uninitialized
@throws std::logic_error if compression failed
*/
void zstd_write_header_deflate_buffer(DynArray<poseidon_byte> &in, void *header_ptr,
                                      std::ostream &out_stream, MemoryPoolHandle pool);

unsigned zstd_deflate_array_inplace(DynArray<poseidon_byte> &in, MemoryPoolHandle pool);

unsigned zstd_inflate_stream(std::istream &in_stream, std::streamoff in_size,
                             std::ostream &out_stream, MemoryPoolHandle pool);

template <typename SizeT> POSEIDON_NODISCARD SizeT zlib_deflate_size_bound(SizeT in_size)
{
    return util::add_safe<SizeT>(in_size, in_size >> 12, in_size >> 14, in_size >> 25, SizeT(17));
}

template <typename SizeT> POSEIDON_NODISCARD SizeT zstd_deflate_size_bound(SizeT in_size)
{
    return util::add_safe<SizeT>(
        in_size, in_size >> 8,
        (in_size < (SizeT(128) << 10)) ? (((SizeT(128) << 10) - in_size) >> 11) : SizeT(0));
}
}  // namespace ztools
}  // namespace util
}  // namespace poseidon

#endif
