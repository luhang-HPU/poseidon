#include "ciphertext.h"
#include "basics/util/defines.h"
#include "basics/util/pointer.h"
#include "basics/util/polyarithsmallmod.h"
#include "basics/util/rlwe.h"
#include <algorithm>

using namespace std;
using namespace poseidon::util;

namespace poseidon
{
Ciphertext &Ciphertext::operator=(const Ciphertext &assign)
{
    // Check for self-assignment
    if (this == &assign)
    {
        return *this;
    }

    // Copy over fields
    parms_id_ = assign.parms_id_;
    is_ntt_form_ = assign.is_ntt_form_;
    scale_ = assign.scale_;
    correction_factor_ = assign.correction_factor_;
    crt_context_ = assign.crt_context_;

    // Then resize
    resize_internal(assign.size_, assign.poly_modulus_degree_, assign.coeff_modulus_size_);
    copy(assign.data_.cbegin(), assign.data_.cend(), data_.begin());
    polys_.resize(assign.size_);
    for (auto i = 0; i < assign.size_ && !assign.polys_.empty(); ++i)
    {
        polys_[i] = RNSPoly(crt_context_, data(i), parms_id_);
        polys_[i].set_hardware_id(0);
    }

    return *this;
}

void Ciphertext::reserve(const PoseidonContext &context, parms_id_type parms_id,
                         size_t size_capacity)
{
    auto context_data_ptr = context.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }

    // Need to set parms_id first
    auto &parms = context_data_ptr->parms();
    auto poly_modulus_degree = context_data_ptr->parms().degree();
    auto coeff_modulus_size = context_data_ptr->coeff_modulus().size();
    parms_id_ = parms.parms_id();
    if (!this->crt_context_)
    {
        this->crt_context_ = context.crt_context();
    }
    reserve_internal(size_capacity, poly_modulus_degree, coeff_modulus_size);
}

void Ciphertext::reserve_internal(size_t size_capacity, size_t poly_modulus_degree,
                                  size_t coeff_modulus_size)
{
    if (size_capacity < POSEIDON_CIPHERTEXT_SIZE_MIN ||
        size_capacity > POSEIDON_CIPHERTEXT_SIZE_MAX)
    {
        POSEIDON_THROW(invalid_argument_error, "invalid size_capacity");
    }

    size_t new_data_capacity = mul_safe(size_capacity, poly_modulus_degree, coeff_modulus_size);
    size_t new_data_size = min<size_t>(new_data_capacity, data_.size());

    // First reserve, then resize
    data_.reserve(new_data_capacity);
    data_.resize(new_data_size);

    // Set the size
    size_ = min<size_t>(size_capacity, size_);
    poly_modulus_degree_ = poly_modulus_degree;
    coeff_modulus_size_ = coeff_modulus_size;
}

void Ciphertext::resize(const PoseidonContext &context, parms_id_type parms_id, size_t size)
{
    auto context_data_ptr = context.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }
    // Need to set parms_id first
    auto &parms = context_data_ptr->parms();
    auto poly_modulus_degree = context_data_ptr->parms().degree();
    auto coeff_modulus_size = context_data_ptr->coeff_modulus().size();
    auto old_size = polys_.size();
    auto old_coeff_modulus_size = coeff_modulus_size_;

    parms_id_ = parms.parms_id();
    if (!this->crt_context_)
    {
        this->crt_context_ = context.crt_context();
    }

    resize_internal(size, poly_modulus_degree, coeff_modulus_size);

    if (old_size == size && old_coeff_modulus_size == coeff_modulus_size_)
    {
        return;
    }
    else
    {
        polys_.resize(size);
        for (auto i = 0; i < size; ++i)
        {
            auto hardware_id = polys_[i].hardware_id();
            polys_[i] = RNSPoly(context, data(i), parms_id_);
            polys_[i].set_hardware_id(hardware_id);
        }
    }
}

void Ciphertext::resize_internal(size_t size, size_t poly_modulus_degree, size_t coeff_modulus_size)
{
    if ((size < POSEIDON_CIPHERTEXT_SIZE_MIN && size != 0) || size > POSEIDON_CIPHERTEXT_SIZE_MAX)
    {
        POSEIDON_THROW(invalid_argument_error, "invalid size");
    }

    // Resize the data
    size_t new_data_size = mul_safe(size, poly_modulus_degree, coeff_modulus_size);
    data_.resize(new_data_size);

    // Set the size parameters
    size_ = size;
    poly_modulus_degree_ = poly_modulus_degree;
    coeff_modulus_size_ = coeff_modulus_size;
}

void Ciphertext::expand_seed(const PoseidonContext &context,
                             const UniformRandomGeneratorInfo &prng_info, PoseidonVersion version)
{
    // Set up a PRNG from the given info and sample the second polynomial
    auto prng = prng_info.make_prng();
    if (!prng)
    {
        throw logic_error("unsupported prng_type");
    }

    sample_poly_uniform(prng, context, parms_id_, data(1));
}

streamoff Ciphertext::save_size(compr_mode_type compr_mode) const
{
    // We need to consider two cases: seeded and unseeded; these have very
    // different size characteristics and we need the exact size when
    // compr_mode is compr_mode_type::none.
    size_t data_size;
    if (has_seed_marker())
    {
        // Create a temporary aliased DynArray of smaller size
        DynArray<ct_coeff_type> alias_data(
            Pointer<ct_coeff_type>::Aliasing(const_cast<ct_coeff_type *>(data_.cbegin())),
            data_.size() / 2, false, data_.pool());

        data_size =
            add_safe(safe_cast<size_t>(alias_data.save_size(compr_mode_type::none)),  // data_(0)
                     static_cast<size_t>(
                         UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none)));  // seed
    }
    else
    {
        data_size = safe_cast<size_t>(data_.save_size(compr_mode_type::none));  // data_
    }

    size_t members_size =
        Serialization::ComprSizeEstimate(add_safe(sizeof(parms_id_type),  // parms_id_
                                                  sizeof(poseidon_byte),  // is_ntt_form_
                                                  sizeof(uint64_t),       // size_
                                                  sizeof(uint64_t),       // poly_modulus_degree_
                                                  sizeof(uint64_t),       // coeff_modulus_size_
                                                  sizeof(double),         // scale_
                                                  sizeof(uint64_t),       // correction_factor_
                                                  data_size),
                                         compr_mode);

    return safe_cast<streamoff>(add_safe(sizeof(Serialization::PoseidonHeader), members_size));
}

void Ciphertext::save_members(ostream &stream) const
{
    auto old_except_mask = stream.exceptions();
    try
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        stream.exceptions(ios_base::badbit | ios_base::failbit);

        stream.write(reinterpret_cast<const char *>(&parms_id_), sizeof(parms_id_type));
        poseidon_byte is_ntt_form_byte = static_cast<poseidon_byte>(is_ntt_form_);
        stream.write(reinterpret_cast<const char *>(&is_ntt_form_byte), sizeof(poseidon_byte));
        uint64_t size64 = safe_cast<uint64_t>(size_);
        stream.write(reinterpret_cast<const char *>(&size64), sizeof(uint64_t));
        uint64_t poly_modulus_degree64 = safe_cast<uint64_t>(poly_modulus_degree_);
        stream.write(reinterpret_cast<const char *>(&poly_modulus_degree64), sizeof(uint64_t));
        uint64_t coeff_modulus_size64 = safe_cast<uint64_t>(coeff_modulus_size_);
        stream.write(reinterpret_cast<const char *>(&coeff_modulus_size64), sizeof(uint64_t));
        stream.write(reinterpret_cast<const char *>(&scale_), sizeof(double));
        stream.write(reinterpret_cast<const char *>(&correction_factor_), sizeof(uint64_t));

        if (has_seed_marker())
        {
            UniformRandomGeneratorInfo info;
            size_t info_size =
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            info.load(reinterpret_cast<const poseidon_byte *>(data(1) + 1), info_size);

            size_t data_size = data_.size();
            size_t half_size = data_size / 2;
            // Save_members must be a const method.
            // Create an alias of data_; must be handled with care.
            DynArray<ct_coeff_type> alias_data(data_.pool_);
            alias_data.size_ = half_size;
            alias_data.capacity_ = half_size;
            auto alias_ptr =
                util::Pointer<ct_coeff_type>::Aliasing(const_cast<ct_coeff_type *>(data_.cbegin()));
            swap(alias_data.data_, alias_ptr);
            alias_data.save(stream, compr_mode_type::none);

            // Save the UniformRandomGeneratorInfo
            info.save(stream, compr_mode_type::none);
        }
        else
        {
            // Save the DynArray
            data_.save(stream, compr_mode_type::none);
        }
    }
    catch (const ios_base::failure &)
    {
        stream.exceptions(old_except_mask);
        throw runtime_error("I/O error");
    }
    catch (...)
    {
        stream.exceptions(old_except_mask);
        throw;
    }
    stream.exceptions(old_except_mask);
}

void Ciphertext::load_members(const PoseidonContext &context, istream &stream,
                              POSEIDON_MAYBE_UNUSED PoseidonVersion version)
{
    Ciphertext new_data(data_.pool());

    auto old_except_mask = stream.exceptions();
    try
    {
        // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
        stream.exceptions(ios_base::badbit | ios_base::failbit);

        parms_id_type parms_id{};
        stream.read(reinterpret_cast<char *>(&parms_id), sizeof(parms_id_type));
        poseidon_byte is_ntt_form_byte;
        stream.read(reinterpret_cast<char *>(&is_ntt_form_byte), sizeof(poseidon_byte));
        uint64_t size64 = 0;
        stream.read(reinterpret_cast<char *>(&size64), sizeof(uint64_t));
        uint64_t poly_modulus_degree64 = 0;
        stream.read(reinterpret_cast<char *>(&poly_modulus_degree64), sizeof(uint64_t));
        uint64_t coeff_modulus_size64 = 0;
        stream.read(reinterpret_cast<char *>(&coeff_modulus_size64), sizeof(uint64_t));
        double scale = 0;
        stream.read(reinterpret_cast<char *>(&scale), sizeof(double));
        uint64_t correction_factor = 1;
        stream.read(reinterpret_cast<char *>(&correction_factor), sizeof(uint64_t));
        // Set values already at this point for the metadata validity check
        new_data.parms_id_ = parms_id;
        new_data.is_ntt_form_ = (is_ntt_form_byte == poseidon_byte{}) ? false : true;
        new_data.size_ = safe_cast<size_t>(size64);
        new_data.poly_modulus_degree_ = safe_cast<size_t>(poly_modulus_degree64);
        new_data.coeff_modulus_size_ = safe_cast<size_t>(coeff_modulus_size64);
        new_data.scale_ = scale;
        new_data.correction_factor_ = correction_factor;
        // TODO too many shared_ptr<context> poseidon data structure to remove
        new_data.crt_context_ = context.crt_context();

        // Compute the total uint64 count required and reserve memory.
        // Note that this must be done after the metadata is checked for validity.
        auto total_uint64_count =
            mul_safe(new_data.size_, new_data.poly_modulus_degree_, new_data.coeff_modulus_size_);

        // Reserve memory for the entire (expected) ciphertext data
        new_data.data_.reserve(total_uint64_count);

        // Load the data. Note that we are supplying also the expected maximum
        // size of the loaded DynArray. This is an important security measure to
        // prevent a malformed DynArray from causing arbitrarily large memory
        // allocations.
        new_data.data_.load(stream, total_uint64_count);

        // Expected buffer size in the seeded case
        auto seeded_uint64_count = poly_modulus_degree64 * coeff_modulus_size64;

        // This is the case where we need to expand a seed, otherwise full
        // ciphertext data was already (possibly) loaded and we are done
        if (unsigned_eq(new_data.data_.size(), seeded_uint64_count))
        {
            // Single polynomial size data was loaded, so we are in the seeded
            // ciphertext case. Next load the UniformRandomGeneratorInfo.
            UniformRandomGeneratorInfo prng_info;

            prng_info.load(stream);

            // Set up a UniformRandomGenerator and expand
            new_data.data_.resize(total_uint64_count);
            new_data.expand_seed(context, prng_info, version);
        }

        new_data.polys_.resize(new_data.size_);
        for (auto i = 0; i < new_data.size_; ++i)
        {
            new_data.polys_[i] =
                RNSPoly(new_data.crt_context_, new_data.data(i), new_data.parms_id_);
        }
    }
    catch (const ios_base::failure &)
    {
        stream.exceptions(old_except_mask);
        throw runtime_error("I/O error");
    }
    catch (...)
    {
        stream.exceptions(old_except_mask);
        throw;
    }
    stream.exceptions(old_except_mask);

    swap(*this, new_data);

    // BGV Ciphertext are converted to NTT form.
    if (context.crt_context()->key_context_data()->parms().scheme() == SchemeType::BGV &&
        !this->is_ntt_form() && this->data())
    {
        ntt_negacyclic_harvey(*this, this->size(), context.crt_context()->small_ntt_tables());
        this->is_ntt_form() = true;
    }
}
}  // namespace poseidon
