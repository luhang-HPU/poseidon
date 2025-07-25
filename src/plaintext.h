#pragma once

#include "basics/dynarray.h"
#include "basics/memorymanager.h"
#include "basics/util/common.h"
#include "basics/util/defines.h"
#include "basics/util/polycore.h"
#include "poseidon_context.h"
#include "rns_poly.h"
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <string>

#ifdef POSEIDON_USE_MSGSL
#include "gsl/span"
#endif

namespace poseidon
{
/**
Class to store a plaintext element. The data for the plaintext is a polynomial
with coefficients modulo the plaintext modulus. The degree of the plaintext
polynomial must be one less than the degree of the polynomial modulus. The
backing array always allocates one 64-bit word per each coefficient of the
polynomial.

@par Memory Management
The coefficient count of a plaintext refers to the number of word-size
coefficients in the plaintext, whereas its capacity refers to the number of
word-size coefficients that fit in the current memory allocation. In high-
performance applications unnecessary re-allocations should be avoided by
reserving enough memory for the plaintext to begin with either by providing
the desired capacity to the constructor as an extra argument, or by calling
the reserve function at any time.

When the scheme is scheme_type::bfv each coefficient of a plaintext is a 64-bit
word, but when the scheme is scheme_type::ckks the plaintext is by default
stored in an NTT transformed form with respect to each of the primes in the
coefficient modulus. Thus, the size of the allocation that is needed is the
size of the coefficient modulus (number of primes) times the degree of the
polynomial modulus. In addition, a valid ckks plaintext also store the parms_id
for the corresponding encryption parameters.

@par Thread Safety
In general, reading from plaintext is thread-safe as long as no other thread
is concurrently mutating it. This is due to the underlying data structure
storing the plaintext not being thread-safe.

@see Ciphertext for the class that stores ciphertexts.
*/
class Plaintext
{
public:
    using pt_coeff_type = std::uint64_t;

    /**
    Constructs an empty plaintext allocating no memory.

    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if pool is uninitialized
    */
    Plaintext(MemoryPoolHandle pool = MemoryManager::GetPool()) : data_(std::move(pool)) {}

    /**
    Constructs a plaintext representing a constant polynomial 0. The coefficient
    count of the polynomial is set to the given value. The capacity is set to
    the same value.

    @param[in] coeff_count The number of (zeroed) coefficients in the plaintext
    polynomial
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if coeff_count is negative
    @throws std::invalid_argument if pool is uninitialized
    */
    explicit Plaintext(std::size_t coeff_count, MemoryPoolHandle pool = MemoryManager::GetPool())
        : coeff_count_(coeff_count), data_(coeff_count_, std::move(pool))
    {
    }

    /**
    Constructs a plaintext representing a constant polynomial 0. The coefficient
    count of the polynomial and the capacity are set to the given values.

    @param[in] capacity The capacity
    @param[in] coeff_count The number of (zeroed) coefficients in the plaintext
    polynomial
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if capacity is less than coeff_count
    @throws std::invalid_argument if coeff_count is negative
    @throws std::invalid_argument if pool is uninitialized
    */
    explicit Plaintext(std::size_t capacity, std::size_t coeff_count,
                       MemoryPoolHandle pool = MemoryManager::GetPool())
        : coeff_count_(coeff_count), data_(capacity, coeff_count_, std::move(pool))
    {
    }
#ifdef POSEIDON_USE_MSGSL
    /**
    Constructs a plaintext representing a polynomial with given coefficient
    values. The coefficient count of the polynomial is set to the number of
    coefficient values provided, and the capacity is set to the given value.

    @param[in] coeffs Desired values of the plaintext coefficients
    @param[in] capacity The capacity
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if capacity is less than the size of coeffs
    @throws std::invalid_argument if pool is uninitialized
    */
    explicit Plaintext(gsl::span<const pt_coeff_type> coeffs, std::size_t capacity,
                       MemoryPoolHandle pool = MemoryManager::GetPool())
        : coeff_count_(coeffs.size()), data_(coeffs, capacity, std::move(pool))
    {
    }

    /**
    Constructs a plaintext representing a polynomial with given coefficient
    values. The coefficient count of the polynomial is set to the number of
    coefficient values provided, and the capacity is set to the same value.

    @param[in] coeffs Desired values of the plaintext coefficients
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if pool is uninitialized
    */
    explicit Plaintext(gsl::span<const pt_coeff_type> coeffs,
                       MemoryPoolHandle pool = MemoryManager::GetPool())
        : coeff_count_(coeffs.size()), data_(coeffs, std::move(pool))
    {
    }
#endif
    /**
    Constructs a plaintext from a given hexadecimal string describing the
    plaintext polynomial.

    The string description of the polynomial must adhere to the format returned
    by to_string(),
    which is of the form "7FFx^3 + 1x^1 + 3" and summarized by the following
    rules:
    1. Terms are listed in order of strictly decreasing exponent
    2. Coefficient values are non-negative and in hexadecimal format (upper
    and lower case letters are both supported)
    3. Exponents are positive and in decimal format
    4. Zero coefficient terms (including the constant term) may be (but do
    not have to be) omitted
    5. Term with the exponent value of one must be exactly written as x^1
    6. Term with the exponent value of zero (the constant term) must be written
    as just a hexadecimal number without exponent
    7. Terms must be separated by exactly <space>+<space> and minus is not
    allowed
    8. Other than the +, no other terms should have whitespace

    @param[in] hex_poly The formatted polynomial string specifying the plaintext
    polynomial
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if hex_poly does not adhere to the expected
    format
    @throws std::invalid_argument if pool is uninitialized
    */
    Plaintext(const std::string &hex_poly, MemoryPoolHandle pool = MemoryManager::GetPool())
        : data_(std::move(pool))
    {
        operator=(hex_poly);
    }

    /**
    Creates a new plaintext by copying a given one.

    @param[in] copy The plaintext to copy from
    */
    Plaintext(const Plaintext &copy) = default;

    /**
    Creates a new plaintext by moving a given one.

    @param[in] source The plaintext to move from
    */
    Plaintext(Plaintext &&source) = default;

    /**
    Creates a new plaintext by copying a given one.

    @param[in] copy The plaintext to copy from
    @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
    @throws std::invalid_argument if pool is uninitialized
    */
    Plaintext(const Plaintext &copy, MemoryPoolHandle pool) : Plaintext(std::move(pool))
    {
        *this = copy;
    }

    /**
    Allocates enough memory to accommodate the backing array of a plaintext
    with given capacity.

    @param[in] capacity The capacity
    @throws std::invalid_argument if capacity is negative
    @throws std::logic_error if the plaintext is NTT transformed
    */
    void reserve(std::size_t capacity)
    {
        if (is_ntt_form())
        {
            throw std::logic_error("cannot reserve for an NTT transformed Plaintext");
        }
        data_.reserve(capacity);
        coeff_count_ = data_.size();
    }

    /**
    Allocates enough memory to accommodate the backing array of the current
    plaintext and copies it over to the new location. This function is meant
    to reduce the memory use of the plaintext to smallest possible and can be
    particularly important after modulus switching.
    */
    inline void shrink_to_fit() { data_.shrink_to_fit(); }

    /**
    Resets the plaintext. This function releases any memory allocated by the
    plaintext, returning it to the memory pool.
    */
    inline void release() noexcept
    {
        // parms_id_ = parms_id_zero;
        coeff_count_ = 0;
        scale_ = 1.0;
        data_.release();
    }

    /**
    Resizes the plaintext to have a given coefficient count. The plaintext
    is automatically reallocated if the new coefficient count does not fit in
    the current capacity.

    @param[in] coeff_count The number of coefficients in the plaintext polynomial
    @throws std::invalid_argument if coeff_count is negative
    @throws std::logic_error if the plaintext is NTT transformed
    */
    void resize(const PoseidonContext &context, parms_id_type parms_id, size_t size);

    inline void resize(std::size_t coeff_count)
    {
        data_.resize(coeff_count);
        coeff_count_ = coeff_count;
    }

    /**
    Copies a given plaintext to the current one.

    @param[in] assign The plaintext to copy from
    */
    Plaintext &operator=(const Plaintext &assign);

    /**
    Moves a given plaintext to the current one.

    @param[in] assign The plaintext to move from
    */
    Plaintext &operator=(Plaintext &&assign) = default;

    /**
    Sets the value of the current plaintext to the polynomial represented by
    the given hexadecimal string.

    The string description of the polynomial must adhere to the format returned
    by to_string(), which is of the form "7FFx^3 + 1x^1 + 3" and summarized
    by the following rules:
    1. Terms are listed in order of strictly decreasing exponent
    2. Coefficient values are non-negative and in hexadecimal format (upper
    and lower case letters are both supported)
    3. Exponents are positive and in decimal format
    4. Zero coefficient terms (including the constant term) may be (but do
    not have to be) omitted
    5. Term with the exponent value of one must be exactly written as x^1
    6. Term with the exponent value of zero (the constant term) must be
    written as just a hexadecimal number without exponent
    7. Terms must be separated by exactly <space>+<space> and minus is not
    allowed
    8. Other than the +, no other terms should have whitespace

    @param[in] hex_poly The formatted polynomial string specifying the plaintext
    polynomial
    @throws std::invalid_argument if hex_poly does not adhere to the expected
    format
    @throws std::invalid_argument if the coefficients of hex_poly are too wide
    */
    Plaintext &operator=(const std::string &hex_poly);

    /**
    Sets the value of the current plaintext to a given constant polynomial and
    sets the parms_id to parms_id_zero, effectively marking the plaintext as
    not NTT transformed. The coefficient count is set to one.

    @param[in] const_coeff The constant coefficient
    */
    Plaintext &operator=(pt_coeff_type const_coeff)
    {
        data_.resize(1);
        data_[0] = const_coeff;
        coeff_count_ = 1;
        // parms_id_ = parms_id_zero;
        return *this;
    }
#ifdef POSEIDON_USE_MSGSL
    /**
    Sets the coefficients of the current plaintext to given values and sets
    the parms_id to parms_id_zero, effectively marking the plaintext as not
    NTT transformed.

    @param[in] coeffs Desired values of the plaintext coefficients
    */
    Plaintext &operator=(gsl::span<const pt_coeff_type> coeffs)
    {
        data_ = coeffs;
        coeff_count_ = coeffs.size();
        parms_id_ = parms_id_zero;
        return *this;
    }
#endif
    /**
    Sets a given range of coefficients of a plaintext polynomial to zero; does
    nothing if length is zero.

    @param[in] start_coeff The index of the first coefficient to set to zero
    @param[in] length The number of coefficients to set to zero
    @throws std::out_of_range if start_coeff + length - 1 is not within [0, coeff_count)
    */
    inline void set_zero(std::size_t start_coeff, std::size_t length)
    {
        if (!length)
        {
            return;
        }
        if (start_coeff + length - 1 >= coeff_count_)
        {
            throw std::out_of_range("length must be non-negative and start_coeff + length - 1 must "
                                    "be within [0, coeff_count)");
        }
        std::fill_n(data_.begin() + start_coeff, length, pt_coeff_type(0));
    }

    /**
    Sets the plaintext polynomial coefficients to zero starting at a given index.

    @param[in] start_coeff The index of the first coefficient to set to zero
    @throws std::out_of_range if start_coeff is not within [0, coeff_count)
    */
    inline void set_zero(std::size_t start_coeff)
    {
        if (start_coeff >= coeff_count_)
        {
            throw std::out_of_range("start_coeff must be within [0, coeff_count)");
        }
        std::fill(data_.begin() + start_coeff, data_.end(), pt_coeff_type(0));
    }

    /**
    Sets the plaintext polynomial to zero.
    */
    inline void set_zero() { std::fill(data_.begin(), data_.end(), pt_coeff_type(0)); }

    /**
    Returns a reference to the backing DynArray object.
    */
    POSEIDON_NODISCARD inline const auto &dyn_array() const noexcept { return data_; }

    /**
    Returns a pointer to the beginning of the plaintext polynomial.
    */
    POSEIDON_NODISCARD inline pt_coeff_type *data() { return data_.begin(); }

    /**
    Returns a const pointer to the beginning of the plaintext polynomial.
    */
    POSEIDON_NODISCARD inline const pt_coeff_type *data() const { return data_.cbegin(); }
#ifdef POSEIDON_USE_MSGSL
    /**
    Returns a span pointing to the beginning of the text polynomial.
    */
    POSEIDON_NODISCARD inline gsl::span<pt_coeff_type> data_span()
    {
        return gsl::span<pt_coeff_type>(data_.begin(), coeff_count_);
    }

    /**
    Returns a span pointing to the beginning of the text polynomial.
    */
    POSEIDON_NODISCARD inline gsl::span<const pt_coeff_type> data_span() const
    {
        return gsl::span<const pt_coeff_type>(data_.cbegin(), coeff_count_);
    }
#endif
    /**
    Returns a pointer to a given coefficient of the plaintext polynomial.

    @param[in] coeff_index The index of the coefficient in the plaintext polynomial
    @throws std::out_of_range if coeff_index is not within [0, coeff_count)
    */
    POSEIDON_NODISCARD inline pt_coeff_type *data(std::size_t coeff_index)
    {
        if (!coeff_count_)
        {
            return nullptr;
        }
        if (coeff_index >= coeff_count_)
        {
            throw std::out_of_range("coeff_index must be within [0, coeff_count)");
        }
        return data_.begin() + coeff_index;
    }

    /**
    Returns a const pointer to a given coefficient of the plaintext polynomial.

    @param[in] coeff_index The index of the coefficient in the plaintext polynomial
    */
    POSEIDON_NODISCARD inline const pt_coeff_type *data(std::size_t coeff_index) const
    {
        if (!coeff_count_)
        {
            return nullptr;
        }
        if (coeff_index >= coeff_count_)
        {
            throw std::out_of_range("coeff_index must be within [0, coeff_count)");
        }
        return data_.cbegin() + coeff_index;
    }

    /**
    Returns a const reference to a given coefficient of the plaintext polynomial.

    @param[in] coeff_index The index of the coefficient in the plaintext polynomial
    @throws std::out_of_range if coeff_index is not within [0, coeff_count)
    */
    POSEIDON_NODISCARD inline const pt_coeff_type &operator[](std::size_t coeff_index) const
    {
        return data_.at(coeff_index);
    }

    /**
    Returns a reference to a given coefficient of the plaintext polynomial.

    @param[in] coeff_index The index of the coefficient in the plaintext polynomial
    @throws std::out_of_range if coeff_index is not within [0, coeff_count)
    */
    POSEIDON_NODISCARD inline pt_coeff_type &operator[](std::size_t coeff_index)
    {
        return data_.at(coeff_index);
    }

    /**
    Returns whether or not the plaintext has the same semantic value as a given
    plaintext. Leading zero coefficients are ignored by the comparison.

    @param[in] compare The plaintext to compare against
    */
    POSEIDON_NODISCARD inline bool operator==(const Plaintext &compare) const
    {
        std::size_t sig_coeff_count = significant_coeff_count();
        std::size_t sig_coeff_count_compare = compare.significant_coeff_count();
        bool parms_id_compare = ((is_ntt_form() && compare.is_ntt_form()) ||
                                 (!is_ntt_form() && !compare.is_ntt_form())) &&
                                (parms_id_ == compare.parms_id_);
        return parms_id_compare && (sig_coeff_count == sig_coeff_count_compare) &&
               std::equal(data_.cbegin(), data_.cbegin() + sig_coeff_count, compare.data_.cbegin(),
                          compare.data_.cbegin() + sig_coeff_count) &&
               std::all_of(data_.cbegin() + sig_coeff_count, data_.cend(),
                           util::is_zero<pt_coeff_type>) &&
               std::all_of(compare.data_.cbegin() + sig_coeff_count, compare.data_.cend(),
                           util::is_zero<pt_coeff_type>) &&
               util::are_approximate(scale_, compare.scale_);
    }

    /**
    Returns whether or not the plaintext has a different semantic value than
    a given plaintext. Leading zero coefficients are ignored by the comparison.

    @param[in] compare The plaintext to compare against
    */
    POSEIDON_NODISCARD inline bool operator!=(const Plaintext &compare) const
    {
        return !operator==(compare);
    }

    /**
    Returns whether the current plaintext polynomial has all zero coefficients.
    */
    POSEIDON_NODISCARD inline bool is_zero() const
    {
        return !coeff_count_ ||
               std::all_of(data_.cbegin(), data_.cend(), util::is_zero<pt_coeff_type>);
    }

    /**
    Returns the capacity of the current allocation.
    */
    POSEIDON_NODISCARD inline std::size_t capacity() const noexcept { return data_.capacity(); }

    /**
    Returns the coefficient count of the current plaintext polynomial.
    */
    POSEIDON_NODISCARD inline std::size_t coeff_count() const noexcept { return coeff_count_; }

    /**
    Returns the significant coefficient count of the current plaintext polynomial.
    */
    POSEIDON_NODISCARD inline std::size_t significant_coeff_count() const
    {
        if (!coeff_count_)
        {
            return 0;
        }
        return util::get_significant_uint64_count_uint(data_.cbegin(), coeff_count_);
    }

    /**
    Returns the non-zero coefficient count of the current plaintext polynomial.
    */
    POSEIDON_NODISCARD inline std::size_t nonzero_coeff_count() const
    {
        if (!coeff_count_)
        {
            return 0;
        }
        return util::get_nonzero_uint64_count_uint(data_.cbegin(), coeff_count_);
    }

    /**
    Returns a human-readable string description of the plaintext polynomial.

    The returned string is of the form "7FFx^3 + 1x^1 + 3" with a format
    summarized by the following:
    1. Terms are listed in order of strictly decreasing exponent
    2. Coefficient values are non-negative and in hexadecimal format (hexadecimal
    letters are in upper-case)
    3. Exponents are positive and in decimal format
    4. Zero coefficient terms (including the constant term) are omitted unless
    the polynomial is exactly 0 (see rule 9)
    5. Term with the exponent value of one is written as x^1
    6. Term with the exponent value of zero (the constant term) is written as
    just a hexadecimal number without x or exponent
    7. Terms are separated exactly by <space>+<space>
    8. Other than the +, no other terms have whitespace
    9. If the polynomial is exactly 0, the string "0" is returned

    @throws std::invalid_argument if the plaintext is in NTT transformed form
    */
    POSEIDON_NODISCARD inline std::string to_string() const
    {
        if (is_ntt_form())
        {
            throw std::invalid_argument("cannot convert NTT transformed plaintext to string");
        }
        return util::poly_to_hex_string(data_.cbegin(), coeff_count_, 1);
    }

    /**
    Returns an upper bound on the size of the plaintext, as if it was written
    to an output stream.

    @param[in] compr_mode The compression mode
    @throws std::invalid_argument if the compression mode is not supported
    @throws std::logic_error if the size does not fit in the return type
    */
    POSEIDON_NODISCARD inline std::streamoff
    save_size(compr_mode_type compr_mode = Serialization::compr_mode_default) const
    {
        std::size_t members_size = Serialization::ComprSizeEstimate(
            util::add_safe(sizeof(parms_id_),
                           sizeof(std::uint64_t),  // coeff_count_
                           sizeof(scale_),
                           util::safe_cast<std::size_t>(data_.save_size(compr_mode_type::none))),
            compr_mode);

        return util::safe_cast<std::streamoff>(
            util::add_safe(sizeof(Serialization::PoseidonHeader), members_size));
    }

    /**
    Saves the plaintext to an output stream. The output is in binary format
    and not human-readable. The output stream must have the "binary" flag set.

    @param[out] stream The stream to save the plaintext to
    @param[in] compr_mode The desired compression mode
    @throws std::invalid_argument if the compression mode is not supported
    @throws std::logic_error if the data to be saved is invalid, or if
    compression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff save(std::ostream &stream,
                               compr_mode_type compr_mode = Serialization::compr_mode_default) const
    {
        return Serialization::Save(std::bind(&Plaintext::save_members, this, std::placeholders::_1),
                                   save_size(compr_mode_type::none), stream, compr_mode, false);
    }

    /**
    Loads a plaintext from an input stream overwriting the current plaintext.
    No checking of the validity of the plaintext data against encryption
    parameters is performed. This function should not be used unless the
    plaintext comes from a fully trusted source.

    @param[in] context The PoseidonContext
    @param[in] stream The stream to load the plaintext from
    @throws std::invalid_argument if the encryption parameters are not valid
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff unsafe_load(const PoseidonContext &context, std::istream &stream)
    {
        return Serialization::Load(std::bind(&Plaintext::load_members, this, context,
                                             std::placeholders::_1, std::placeholders::_2),
                                   stream, false);
    }

    /**
    Loads a plaintext from an input stream overwriting the current plaintext.
    The loaded plaintext is verified to be valid for the given PoseidonContext.

    @param[in] context The PoseidonContext
    @param[in] stream The stream to load the plaintext from
    @throws std::invalid_argument if the encryption parameters are not valid
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff load(const PoseidonContext &context, std::istream &stream)
    {
        Plaintext new_data(pool());
        auto in_size = new_data.unsafe_load(context, stream);
        std::swap(*this, new_data);
        return in_size;
    }

    /**
    Saves the plaintext to a given memory location. The output is in binary
    format and not human-readable.

    @param[out] out The memory location to write the plaintext to
    @param[in] size The number of bytes available in the given memory location
    @param[in] compr_mode The desired compression mode
    @throws std::invalid_argument if out is null or if size is too small to
    contain a PoseidonHeader, or if the compression mode is not supported
    @throws std::logic_error if the data to be saved is invalid, or if
    compression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff save(poseidon_byte *out, std::size_t size,
                               compr_mode_type compr_mode = Serialization::compr_mode_default) const
    {
        return Serialization::Save(std::bind(&Plaintext::save_members, this, std::placeholders::_1),
                                   save_size(compr_mode_type::none), out, size, compr_mode, false);
    }

    /**
    Loads a plaintext from a given memory location overwriting the current
    plaintext. No checking of the validity of the plaintext data against
    encryption parameters is performed. This function should not be used
    unless the plaintext comes from a fully trusted source.

    @param[in] context The PoseidonContext
    @param[in] in The memory location to load the plaintext from
    @param[in] size The number of bytes available in the given memory location
    @throws std::invalid_argument if the encryption parameters are not valid
    @throws std::invalid_argument if in is null or if size is too small to
    contain a PoseidonHeader
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff unsafe_load(const PoseidonContext &context, const poseidon_byte *in,
                                      std::size_t size)
    {
        return Serialization::Load(std::bind(&Plaintext::load_members, this, context,
                                             std::placeholders::_1, std::placeholders::_2),
                                   in, size, false);
    }

    /**
    Loads a plaintext from an input stream overwriting the current plaintext.
    The loaded plaintext is verified to be valid for the given PoseidonContext.

    @param[in] context The PoseidonContext
    @param[in] in The memory location to load the PublicKey from
    @param[in] size The number of bytes available in the given memory location
    @throws std::invalid_argument if the encryption parameters are not valid
    @throws std::invalid_argument if in is null or if size is too small to
    contain a PoseidonHeader
    @throws std::logic_error if the data cannot be loaded by this version of
    Poseidon, if the loaded data is invalid, or if decompression failed
    @throws std::runtime_error if I/O operations failed
    */
    inline std::streamoff load(const PoseidonContext &context, const poseidon_byte *in,
                               std::size_t size)
    {
        Plaintext new_data(pool());
        auto in_size = new_data.unsafe_load(context, in, size);
        std::swap(*this, new_data);
        return in_size;
    }

    /**
    Returns whether the plaintext is in NTT form.
    */
    POSEIDON_NODISCARD inline bool is_ntt_form() const noexcept
    {
        return (parms_id_ != parms_id_zero);
    }

    /**
    Returns a reference to the scale. This is only needed when using the ckks encryption scheme. The
    user should have little or no reason to ever change the scale by hand.
    */
    POSEIDON_NODISCARD inline double &scale() noexcept { return scale_; }

    /**
    Returns a constant reference to the scale. This is only needed when using the ckks encryption
    scheme.
    */
    POSEIDON_NODISCARD inline const double &scale() const noexcept { return scale_; }

    POSEIDON_NODISCARD inline const parms_id_type &parms_id() const noexcept { return parms_id_; }

    POSEIDON_NODISCARD inline parms_id_type &parms_id() noexcept { return parms_id_; }

    POSEIDON_NODISCARD inline bool is_valid(const PoseidonContext &context) const noexcept
    {
        auto &map = context.crt_context()->context_data_map();
        return map.find(parms_id_) != map.end();
    }

    /**
    Returns the currently used MemoryPoolHandle.
    */
    POSEIDON_NODISCARD inline MemoryPoolHandle pool() const noexcept { return data_.pool(); }

    // POSEIDON_NODISCARD inline const RNSPoly &operator[] (std::size_t poly_index) const{
    //      return  polys_[poly_index];
    // }

    POSEIDON_NODISCARD inline RNSPoly &poly() { return polys_; }

    POSEIDON_NODISCARD inline const RNSPoly &poly() const { return polys_; }

    POSEIDON_NODISCARD inline bool is_valid() const { return (coeff_count_ != 0); }

    POSEIDON_NODISCARD inline bool &need_reszie() { return need_resize_; }

    POSEIDON_NODISCARD inline const bool &need_resize() const { return need_resize_; }

private:
    void save_members(std::ostream &stream) const;
    void load_members(const PoseidonContext &context, std::istream &stream,
                      PoseidonVersion version);

    std::size_t coeff_count_ = 0;  // degree
    double scale_ = 1.0;  // for ckks
    parms_id_type parms_id_ = parms_id_zero;
    DynArray<pt_coeff_type> data_;

    // SecretKey needs access to save_members/load_members
    friend class SecretKey;
    RNSPoly polys_;
    std::shared_ptr<CrtContext> crt_context_{nullptr};
    bool need_resize_ = false;
};
}  // namespace poseidon
