#pragma once

#include "src/basics/util/defines.h"
#include "src/basics/version.h"
#include "src/util/exception.h"
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>

namespace poseidon
{
/**
A type to describe the compression algorithm applied to serialized data.
Ciphertext and key data consist of a large number of 64-bit words storing
integers modulo prime numbers much smaller than the word size, resulting in
a large number of zero bytes in the output. Any compression algorithm should
be able to clean up these zero bytes and hence compress both ciphertext and
key data.
*/
enum class compr_mode_type : std::uint8_t
{
    // No compression is used.
    none = 0,
#ifdef POSEIDON_USE_ZLIB
    // Use ZLIB compression
    zlib = 1,
#endif
#ifdef POSEIDON_USE_ZSTD
    // Use Zstandard compression
    zstd = 2,
#endif
};

/**
Class to provide functionality for serialization. Most users of the library
should never have to call these functions explicitly, as they are called
internally by functions such as Ciphertext::save and Ciphertext::load.
*/
class Serialization
{
public:
    /**
    The compression mode used by default; prefer Zstandard
    */
#if defined(POSEIDON_USE_ZLIB)
    static constexpr compr_mode_type compr_mode_default = compr_mode_type::zlib;
#else
    static constexpr compr_mode_type compr_mode_default = compr_mode_type::none;
#endif
    /**
    The magic value indicating a Poseidon header.
    */
    static constexpr std::uint16_t poseidon_magic = 0xA15E;

    /**
    The size in bytes of the PoseidonHeader.
    */
    static constexpr std::uint8_t poseidon_header_size = 0x10;

    /**
    Struct to contain metadata for serialization comprising the following fields:

    1. a magic number identifying this is a PoseidonHeader struct (2 bytes)
    2. size in bytes of the PoseidonHeader struct (1 byte)
    3. Poseidon's major version number (1 byte)
    4. Poseidon's minor version number (1 byte)
    5. a compr_mode_type indicating whether data after the header is compressed (1 byte)
    6. reserved for future use and data alignment (2 bytes)
    7. the size in bytes of the entire serialized object, including the header (8 bytes)
    */
    struct PoseidonHeader
    {
        std::uint16_t magic = poseidon_magic;

        std::uint8_t header_size = poseidon_header_size;

        std::uint8_t version_major = static_cast<std::uint8_t>(POSEIDON_VERSION_MAJOR);

        std::uint8_t version_minor = static_cast<std::uint8_t>(POSEIDON_VERSION_MINOR);

        compr_mode_type compr_mode = compr_mode_type::none;

        std::uint16_t reserved = 0;

        std::uint64_t size = 0;
    };

    static_assert(sizeof(PoseidonHeader) == poseidon_header_size, "");

    /**
    Returns true if the given byte corresponds to a supported compression mode.

    @param[in] compr_mode The compression mode to validate
    */
    POSEIDON_NODISCARD static bool IsSupportedComprMode(std::uint8_t compr_mode) noexcept
    {
        switch (compr_mode)
        {
        case static_cast<std::uint8_t>(compr_mode_type::none):
            /* fall through */
#ifdef POSEIDON_USE_ZLIB
        case static_cast<std::uint8_t>(compr_mode_type::zlib):
            /* fall through */
#endif
            return true;
        }
        return false;
    }

    /**
    Returns true if the given value corresponds to a supported compression mode.

    @param[in] compr_mode The compression mode to validate
    */
    POSEIDON_NODISCARD static inline bool IsSupportedComprMode(compr_mode_type compr_mode) noexcept
    {
        return IsSupportedComprMode(static_cast<uint8_t>(compr_mode));
    }

    /**
    Returns an upper bound on the output size of data compressed according to
    a given compression mode with given input size. If compr_mode is
    compr_mode_type::none, the return value is exactly in_size.

    @param[in] in_size The input size to a compression algorithm
    @param[in] in_size The compression mode
    @throws std::invalid_argument if the compression mode is not supported
    */
    POSEIDON_NODISCARD static std::size_t ComprSizeEstimate(std::size_t in_size,
                                                            compr_mode_type compr_mode);

    /**
    Returns true if the PoseidonHeader has a version number compatible with this version of
    Poseidon.

    @param[in] header The PoseidonHeader
    */
    POSEIDON_NODISCARD static bool IsCompatibleVersion(const PoseidonHeader &header) noexcept
    {
        // Exact same version
        if (header.version_major == POSEIDON_VERSION_MAJOR &&
            header.version_minor == POSEIDON_VERSION_MINOR)
        {
            return true;
        }

        // // Different major versions not supported
        // if (header.version_major != POSEIDON_VERSION_MAJOR && header.version_major != 3)
        // {
        //     return false;
        // }

        // // Support Poseidon 3.4 and above
        // if (header.version_major == 3 && header.version_minor >= 4)
        // {
        //     return true;
        // }

        return false;
    }

    /**
    Returns true if the given PoseidonHeader is valid for this version of Poseidon.

    @param[in] header The PoseidonHeader
    */
    POSEIDON_NODISCARD static bool IsValidHeader(const PoseidonHeader &header) noexcept
    {
        if (header.magic != poseidon_magic)
        {
            return false;
        }
        if (header.header_size != poseidon_header_size)
        {
            return false;
        }
        if (!IsCompatibleVersion(header))
        {
            return false;
        }
        if (!IsSupportedComprMode(static_cast<uint8_t>(header.compr_mode)))
        {
            return false;
        }
        return true;
    }

    /**
    Saves a PoseidonHeader to a given stream. The output is in binary format and
    not human-readable. The output stream must have the "binary" flag set.

    @param[in] header The PoseidonHeader to save to the stream
    @param[out] stream The stream to save the PoseidonHeader to
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff SaveHeader(const PoseidonHeader &header, std::ostream &stream);

    /**
    Loads a PoseidonHeader from a given stream.

    @param[in] stream The stream to load the PoseidonHeader from
    @param[in] header The PoseidonHeader to populate with the loaded data
    @param[in] try_upgrade_if_invalid If the loaded PoseidonHeader is invalid,
    attempt to identify its format and upgrade to the current PoseidonHeader version
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff LoadHeader(std::istream &stream, PoseidonHeader &header,
                                     bool try_upgrade_if_invalid = true);

    /**
    Saves a PoseidonHeader to a given memory location. The output is in binary
    format and is not human-readable.

    @param[out] out The memory location to write the PoseidonHeader to
    @param[in] size The number of bytes available in the given memory location
    @throws std::invalid_argument if out is null or if size is too small to
    contain a PoseidonHeader
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff SaveHeader(const PoseidonHeader &header, poseidon_byte *out,
                                     std::size_t size);

    /**
    Loads a PoseidonHeader from a given memory location.

    @param[in] in The memory location to load the PoseidonHeader from
    @param[in] size The number of bytes available in the given memory location
    @param[in] try_upgrade_if_invalid If the loaded PoseidonHeader is invalid,
    attempt to identify its format and upgrade to the current PoseidonHeader version
    @throws std::invalid_argument if in is null or if size is too small to
    contain a PoseidonHeader
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff LoadHeader(const poseidon_byte *in, std::size_t size,
                                     PoseidonHeader &header, bool try_upgrade_if_invalid = true);

    /**
    Evaluates save_members and compresses the output according to the given
    compr_mode_type. The resulting data is written to stream and is prepended
    by the given compr_mode_type and the total size of the data to facilitate
    deserialization. In typical use-cases save_members would be a function
    that serializes the member variables of an object to the given stream.

    For any given compression mode, raw_size must be the exact right size
    (in bytes) of what save_members writes to a stream in the uncompressed
    mode plus the size of PoseidonHeader. Otherwise the behavior of Save is
    unspecified.

    @param[in] save_members A function taking an std::ostream reference as an
    argument, possibly writing some number of bytes into it
    @param[in] raw_size The exact uncompressed output size of save_members
    plus the size of PoseidonHeader
    @param[out] stream The stream to write to
    @param[in] compr_mode The desired compression mode
    @param[in] clear_buffers Whether internal buffers should be cleared
    @throws std::invalid_argument if save_members is invalid
    @throws std::invalid_argument if raw_size is smaller than PoseidonHeader size
    @throws std::logic_error if the data to be saved is invalid, if compression
    mode is not supported, or if compression failed
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff Save(std::function<void(std::ostream &)> save_members,
                               std::streamoff raw_size, std::ostream &stream,
                               compr_mode_type compr_mode, bool clear_buffers);

    /**
    Deserializes data from stream that was serialized by Save. Once stream has
    been decompressed (depending on compression mode), load_members is applied
    to the decompressed stream. In typical use-cases load_members would be
    a function that deserializes the member variables of an object from the
    given stream.

    @param[in] load_members A function taking an std::istream reference and
    a SEALVersion struct as arguments, possibly reading some number of bytes
    from the std::istream, possibly depending on the SEALVersion object
    @param[in] stream The stream to read from
    @param[in] clear_buffers Whether internal buffers should be cleared
    @throws std::invalid_argument if load_members is invalid
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff Load(std::function<void(std::istream &, PoseidonVersion)> load_members,
                               std::istream &stream, bool clear_buffers);

    /**
    Evaluates save_members and compresses the output according to the given
    compr_mode_type. The resulting data is written to a given memory location
    and is prepended by the given compr_mode_type and the total size of the
    data to facilitate deserialization. In typical use-cases save_members would
    be a function that serializes the member variables of an object to the
    given stream.

    For any given compression mode, raw_size must be the exact right size
    (in bytes) of what save_members writes to a stream in the uncompressed
    mode plus the size of PoseidonHeader. Otherwise the behavior of Save is
    unspecified.

    @param[in] save_members A function that takes an std::ostream reference as
    an argument and writes some number of bytes into it
    @param[in] raw_size The exact uncompressed output size of save_members
    plus the size of PoseidonHeader
    @param[out] out The memory location to write to
    @param[in] size The number of bytes available in the given memory location
    @param[in] compr_mode The desired compression mode
    @param[in] clear_buffers Whether internal buffers should be cleared
    @throws std::invalid_argument if save_members is invalid, if raw_size or
    size is smaller than PoseidonHeader size, or if out is null
    @throws std::logic_error if the data to be saved is invalid, if compression
    mode is not supported, or if compression failed
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff Save(std::function<void(std::ostream &)> save_members,
                               std::streamoff raw_size, poseidon_byte *out, std::size_t size,
                               compr_mode_type compr_mode, bool clear_buffers);

    /**
    Deserializes data from a memory location that was serialized by Save.
    Once the data has been decompressed (depending on compression mode),
    load_members is applied to the decompressed stream. In typical use-cases
    load_members would be a function that deserializes the member variables
    of an object from the given stream.

    @param[in] load_members A function that takes an std::istream reference as
    a SEALVersion struct as arguments, possibly reading some number of bytes
    from the std::istream, possibly depending on the SEALVersion object
    @param[in] in The memory location to read from
    @param[in] size The number of bytes available in the given memory location
    @param[in] clear_buffers Whether internal buffers should be cleared
    @throws std::invalid_argument if load_members is invalid, if in is null,
    or if size is too small to contain a PoseidonHeader
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    static std::streamoff Load(std::function<void(std::istream &, PoseidonVersion)> load_members,
                               const poseidon_byte *in, std::size_t size, bool clear_buffers);

private:
    Serialization() = delete;
};

}  // namespace poseidon
