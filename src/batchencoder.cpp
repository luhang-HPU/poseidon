#include "batchencoder.h"
#include "basics/util/common.h"
#include <algorithm>
#include <limits>
#include <random>
#include <stdexcept>

using namespace std;
using namespace poseidon::util;

namespace poseidon
{
BatchEncoder::BatchEncoder(const PoseidonContext &context) : context_(context)
{
    // Verify parameters
    auto &crt_context = *context_.crt_context().get();
    auto &context_data = *crt_context.first_context_data();
    if (context_data.parms().scheme() != BFV && context_data.parms().scheme() != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "unsupported scheme");
    }

    // Set the slot count
    slots_ = context_data.parms().degree();

    // Reserve space for all of the primitive roots
    roots_of_unity_ = allocate_uint(slots_, pool_);

    // Fill the vector of roots of unity with all distinct odd powers of generator.
    // These are all the primitive (2*slots_)-th roots of unity in integers modulo
    // parms.plain_modulus().
    populate_roots_of_unity_vector(crt_context);

    // Populate matrix representation index map
    populate_matrix_reps_index_map();
}

void BatchEncoder::populate_roots_of_unity_vector(const CrtContext &crt_context)
{

    uint64_t root = crt_context.plain_ntt_tables()->get_root();
    auto &modulus = crt_context.first_context_data()->parms().plain_modulus();

    uint64_t generator_sq = multiply_uint_mod(root, root, modulus);
    roots_of_unity_[0] = root;

    for (size_t i = 1; i < slots_; i++)
    {
        roots_of_unity_[i] = multiply_uint_mod(roots_of_unity_[i - 1], generator_sq, modulus);
    }
}

void BatchEncoder::populate_matrix_reps_index_map()
{
    int logn = get_power_of_two(slots_);
    matrix_reps_index_map_ = allocate<size_t>(slots_, pool_);

    // Copy from the matrix to the value vectors
    size_t row_size = slots_ >> 1;
    size_t m = slots_ << 1;
    uint64_t gen = 5;
    uint64_t pos = 1;
    for (size_t i = 0; i < row_size; i++)
    {
        // Position in normal bit order
        uint64_t index1 = (pos - 1) >> 1;
        uint64_t index2 = (m - pos - 1) >> 1;

        // Set the bit-reversed locations
        matrix_reps_index_map_[i] = safe_cast<size_t>(util::reverse_bits(index1, logn));
        matrix_reps_index_map_[row_size | i] = safe_cast<size_t>(util::reverse_bits(index2, logn));

        // Next primitive root
        pos *= gen;
        pos &= (m - 1);
    }
}

void BatchEncoder::reverse_bits(uint64_t *input)
{
#ifdef POSEIDON_DEBUG
    if (input == nullptr)
    {
        POSEIDON_THROW(invalid_argument_error, "input cannot be null");
    }
#endif
    auto &context_data = *context_.crt_context()->first_context_data();
    size_t coeff_count = context_data.parms().degree();
    int logn = get_power_of_two(coeff_count);
    for (size_t i = 0; i < coeff_count; i++)
    {
        uint64_t reversed_i = util::reverse_bits(i, logn);
        if (i < reversed_i)
        {
            swap(input[i], input[reversed_i]);
        }
    }
}

void BatchEncoder::encode(const vector<uint64_t> &values_matrix, Plaintext &destination) const
{
    auto crt_context = context_.crt_context();
    auto &context_data = *crt_context->first_context_data();
    // Validate input parameters
    size_t values_matrix_size = values_matrix.size();
    if (values_matrix_size > slots_)
    {
        POSEIDON_THROW(invalid_argument_error, "values_matrix size is too large");
    }
#ifdef POSEIDON_DEBUG
    uint64_t modulus = context_data.parms().plain_modulus().value();
    for (auto v : values_matrix)
    {
        // Validate the i-th input
        if (v >= modulus)
        {
            POSEIDON_THROW(invalid_argument_error, "input value is larger than plain_modulus");
        }
    }
#endif
    // Set destination to full size
    destination.resize(slots_);
    destination.parms_id() = parms_id_zero;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slots_; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = 0;
    }

    // Transform destination using inverse of negacyclic NTT
    // Note: We already performed bit-reversal when reading in the matrix
    inverse_ntt_negacyclic_harvey(destination.data(), *crt_context->plain_ntt_tables());
}

void BatchEncoder::encode(const vector<int64_t> &values_matrix, Plaintext &destination) const
{
    auto crt_context = context_.crt_context();
    auto &context_data = *crt_context->first_context_data();
    uint64_t modulus = context_data.parms().plain_modulus().value();
    // Validate input parameters
    if (values_matrix.empty())
    {
        POSEIDON_THROW(invalid_argument_error, "values_matrix is empty");
    }

    size_t values_matrix_size = values_matrix.size();
    if (values_matrix_size > slots_)
    {
        POSEIDON_THROW(invalid_argument_error, "values_matrix size is too large");
    }
#ifdef POSEIDON_DEBUG
    uint64_t plain_modulus_div_two = modulus >> 1;
    for (auto v : values_matrix)
    {
        // Validate the i-th input
        if (unsigned_gt(llabs(v), plain_modulus_div_two))
        {
            POSEIDON_THROW(invalid_argument_error, "input value is larger than plain_modulus");
        }
    }
#endif
    // Set destination to full size
    destination.resize(slots_);
    destination.parms_id() = parms_id_zero;

    // First write the values to destination coefficients.
    // Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) =
            (values_matrix[i] < 0) ? (modulus + static_cast<uint64_t>(values_matrix[i]))
                                   : static_cast<uint64_t>(values_matrix[i]);
    }
    for (size_t i = values_matrix_size; i < slots_; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = 0;
    }

    // Transform destination using inverse of negacyclic NTT
    // Note: We already performed bit-reversal when reading in the matrix
    inverse_ntt_negacyclic_harvey(destination.data(), *crt_context->plain_ntt_tables());
}
#undef POSEIDON_USE_MSGSL
#ifdef POSEIDON_USE_MSGSL
void BatchEncoder::encode(gsl::span<const uint64_t> values_matrix, Plaintext &destination) const
{
    auto &context_data = *context_.first_context_data();

    // Validate input parameters
    size_t values_matrix_size = static_cast<size_t>(values_matrix.size());
    if (values_matrix_size > slots_)
    {
        POSEIDON_THROW(invalid_argument_error, "values_matrix size is too large");
    }
#ifdef POSEIDON_DEBUG
    uint64_t modulus = context_data.parms().plain_modulus().value();
    for (auto v : values_matrix)
    {
        // Validate the i-th input
        if (v >= modulus)
        {
            POSEIDON_THROW(invalid_argument_error, "input value is larger than plain_modulus");
        }
    }
#endif
    // Set destination to full size
    destination.resize(slots_);
    destination.parms_id() = parms_id_zero;

    // First write the values to destination coefficients. Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = values_matrix[i];
    }
    for (size_t i = values_matrix_size; i < slots_; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = 0;
    }

    // Transform destination using inverse of negacyclic NTT
    // Note: We already performed bit-reversal when reading in the matrix
    inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
}

void BatchEncoder::encode(gsl::span<const int64_t> values_matrix, Plaintext &destination) const
{
    auto &context_data = *context_.first_context_data();
    uint64_t modulus = context_data.parms().plain_modulus().value();

    // Validate input parameters
    size_t values_matrix_size = static_cast<size_t>(values_matrix.size());
    if (values_matrix_size > slots_)
    {
        POSEIDON_THROW(invalid_argument_error, "values_matrix size is too large");
    }
#ifdef POSEIDON_DEBUG
    uint64_t plain_modulus_div_two = modulus >> 1;
    for (auto v : values_matrix)
    {
        // Validate the i-th input
        if (unsigned_gt(llabs(v), plain_modulus_div_two))
        {
            POSEIDON_THROW(invalid_argument_error, "input value is larger than plain_modulus");
        }
    }
#endif
    // Set destination to full size
    destination.resize(slots_);
    destination.parms_id() = parms_id_zero;

    // First write the values to destination coefficients. Read in top row, then bottom row.
    for (size_t i = 0; i < values_matrix_size; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) =
            (values_matrix[i] < 0) ? (modulus + static_cast<uint64_t>(values_matrix[i]))
                                   : static_cast<uint64_t>(values_matrix[i]);
    }
    for (size_t i = values_matrix_size; i < slots_; i++)
    {
        *(destination.data() + matrix_reps_index_map_[i]) = 0;
    }

    // Transform destination using inverse of negacyclic NTT
    // Note: We already performed bit-reversal when reading in the matrix
    inverse_ntt_negacyclic_harvey(destination.data(), *context_data.plain_ntt_tables());
}
#endif
void BatchEncoder::decode(const Plaintext &plain, vector<uint64_t> &destination,
                          MemoryPoolHandle pool) const
{

    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(metadata_error, "plain cannot be in NTT form");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    auto crt_context = context_.crt_context();
    auto &context_data = *crt_context->first_context_data();

    // Set destination size
    destination.resize(slots_);

    // Never include the leading zero coefficient (if present)
    size_t plain_coeff_count = min(plain.coeff_count(), slots_);

    auto temp_dest(allocate_uint(slots_, pool));

    // Make a copy of poly
    set_uint(plain.data(), plain_coeff_count, temp_dest.get());
    set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

    // Transform destination using negacyclic NTT.
    ntt_negacyclic_harvey(temp_dest.get(), *crt_context->plain_ntt_tables());

    // Read top row, then bottom row
    for (size_t i = 0; i < slots_; i++)
    {
        destination[i] = temp_dest[matrix_reps_index_map_[i]];
    }
}

void BatchEncoder::decode(const Plaintext &plain, vector<int64_t> &destination,
                          MemoryPoolHandle pool) const
{
    if (!plain.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "plain is empty");
    }
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(metadata_error, "plain cannot be in NTT form");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }
    auto crt_context = context_.crt_context();
    auto &context_data = *crt_context->first_context_data();
    uint64_t modulus = context_data.parms().plain_modulus().value();

    // Set destination size
    destination.resize(slots_);

    // Never include the leading zero coefficient (if present)
    size_t plain_coeff_count = min(plain.coeff_count(), slots_);

    auto temp_dest(allocate_uint(slots_, pool));

    // Make a copy of poly
    set_uint(plain.data(), plain_coeff_count, temp_dest.get());
    set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

    // Transform destination using negacyclic NTT.
    ntt_negacyclic_harvey(temp_dest.get(), *crt_context->plain_ntt_tables());

    // Read top row, then bottom row
    uint64_t plain_modulus_div_two = modulus >> 1;
    for (size_t i = 0; i < slots_; i++)
    {
        uint64_t curr_value = temp_dest[matrix_reps_index_map_[i]];
        destination[i] = (curr_value > plain_modulus_div_two)
                             ? (static_cast<int64_t>(curr_value) - static_cast<int64_t>(modulus))
                             : static_cast<int64_t>(curr_value);
    }
}
#ifdef POSEIDON_USE_MSGSL
void BatchEncoder::decode(const Plaintext &plain, gsl::span<uint64_t> destination,
                          MemoryPoolHandle pool) const
{
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "plain cannot be in NTT form");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    auto &context_data = *context_.first_context_data();

    if (unsigned_gt(destination.size(), numeric_limits<int>::max()) ||
        unsigned_neq(destination.size(), slots_))
    {
        POSEIDON_THROW(invalid_argument_error, "destination has incorrect size");
    }

    // Never include the leading zero coefficient (if present)
    size_t plain_coeff_count = min(plain.coeff_count(), slots_);

    auto temp_dest(allocate_uint(slots_, pool));

    // Make a copy of poly
    set_uint(plain.data(), plain_coeff_count, temp_dest.get());
    set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

    // Transform destination using negacyclic NTT.
    ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

    // Read top row, then bottom row
    for (size_t i = 0; i < slots_; i++)
    {
        destination[i] = temp_dest[matrix_reps_index_map_[i]];
    }
}

void BatchEncoder::decode(const Plaintext &plain, gsl::span<int64_t> destination,
                          MemoryPoolHandle pool) const
{
    if (plain.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error, "plain cannot be in NTT form");
    }
    if (!pool)
    {
        POSEIDON_THROW(invalid_argument_error, "pool is uninitialized");
    }

    auto &context_data = *context_.first_context_data();
    uint64_t modulus = context_data.parms().plain_modulus().value();

    if (unsigned_gt(destination.size(), numeric_limits<int>::max()) ||
        unsigned_neq(destination.size(), slots_))
    {
        POSEIDON_THROW(invalid_argument_error, "destination has incorrect size");
    }

    // Never include the leading zero coefficient (if present)
    size_t plain_coeff_count = min(plain.coeff_count(), slots_);

    auto temp_dest(allocate_uint(slots_, pool));

    // Make a copy of poly
    set_uint(plain.data(), plain_coeff_count, temp_dest.get());
    set_zero_uint(slots_ - plain_coeff_count, temp_dest.get() + plain_coeff_count);

    // Transform destination using negacyclic NTT.
    ntt_negacyclic_harvey(temp_dest.get(), *context_data.plain_ntt_tables());

    // Read top row, then bottom row
    uint64_t plain_modulus_div_two = modulus >> 1;
    for (size_t i = 0; i < slots_; i++)
    {
        uint64_t curr_value = temp_dest[matrix_reps_index_map_[i]];
        destination[i] = (curr_value > plain_modulus_div_two)
                             ? (static_cast<int64_t>(curr_value) - static_cast<int64_t>(modulus))
                             : static_cast<int64_t>(curr_value);
    }
}
#endif
}  // namespace poseidon
