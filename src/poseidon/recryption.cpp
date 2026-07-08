#include "poseidon/recryption.h"
#include "poseidon/basics/util/common.h"
#include "poseidon/basics/util/numth.h"
#include "poseidon/basics/util/polyarithsmallmod.h"
#include "poseidon/basics/util/polycore.h"
#include "poseidon/basics/util/rns.h"
#include "poseidon/basics/util/uintarith.h"
#include "poseidon/basics/util/uintcore.h"
#include "poseidon/basics/memorymanager.h"
#include "poseidon/keygenerator.h"
#include "poseidon/encryptor.h"
#include "poseidon/util/exception.h"
#include "poseidon/util/pke_params_defines.h"
#include <algorithm>
#include <map>
#include <gmpxx.h>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <tuple>

namespace poseidon
{

namespace
{
using poseidon::util::allocate_uint;
using poseidon::util::set_uint;

uint64_t plaintext_modulus_value(const PoseidonContext &context)
{
    return context.parameters_literal()->plain_modulus().value();
}

const char *scheme_name(const PoseidonContext &context)
{
    switch (context.parameters_literal()->scheme())
    {
    case BFV:
        return "BFV";
    case BGV:
        return "BGV";
    default:
        return "BFV/BGV";
    }
}

mpz_class uint_array_to_mpz(const std::uint64_t *value, std::size_t size)
{
    mpz_class result;
    mpz_import(result.get_mpz_t(), size, -1, sizeof(std::uint64_t), 0, 0, value);
    return result;
}

mpz_class uint64_to_mpz(std::uint64_t value)
{
    mpz_class result;
    mpz_import(result.get_mpz_t(), 1, -1, sizeof(std::uint64_t), 0, 0, &value);
    return result;
}

std::int64_t checked_mpz_to_int64(const mpz_class &value, const char *name)
{
    if (!value.fits_slong_p())
    {
        std::ostringstream ss;
        ss << name << " does not fit in signed 64 bits";
        POSEIDON_THROW(invalid_argument_error, ss.str());
    }
    return static_cast<std::int64_t>(value.get_si());
}

std::int64_t positive_mod(std::int64_t value, std::uint64_t modulus)
{
    auto remainder = value % static_cast<std::int64_t>(modulus);
    if (remainder < 0)
    {
        remainder += static_cast<std::int64_t>(modulus);
    }
    return remainder;
}

std::int64_t checked_add_mul(std::int64_t value, std::int64_t multiplier,
                             std::uint64_t factor)
{
    __int128 wide = static_cast<__int128>(value) +
                    static_cast<__int128>(multiplier) * static_cast<__int128>(factor);
    if (wide > std::numeric_limits<std::int64_t>::max() ||
        wide < std::numeric_limits<std::int64_t>::min())
    {
        POSEIDON_THROW(invalid_argument_error, "recryption coefficient overflow");
    }
    return static_cast<std::int64_t>(wide);
}

std::uint64_t checked_power_u64(std::uint64_t base, std::uint32_t exponent)
{
    std::uint64_t result = 1;
    for (std::uint32_t i = 0; i < exponent; ++i)
    {
        if (base != 0 && result > std::numeric_limits<std::uint64_t>::max() / base)
        {
            POSEIDON_THROW(invalid_argument_error, "BGV plaintext-space parameter overflow");
        }
        result *= base;
    }
    return result;
}

void add_bfv_full_slot_galois_steps(std::vector<int> &steps, int full_step, int slots)
{
    auto add_unique = [&steps](int step)
    {
        if (std::find(steps.begin(), steps.end(), step) == steps.end())
        {
            steps.push_back(step);
        }
    };

    if (slots <= 0)
    {
        add_unique(full_step);
        return;
    }

    full_step &= (slots - 1);
    const int row_slots = slots >> 1;
    if (full_step == 0)
    {
        add_unique(0);
        return;
    }
    if (full_step == row_slots)
    {
        add_unique(0);
        return;
    }
    if (full_step > row_slots)
    {
        add_unique(0);
        add_unique(full_step - row_slots);
        return;
    }

    add_unique(full_step);
}

std::vector<std::size_t> batch_encoder_matrix_index_map(std::size_t slots)
{
    const int logn = util::get_power_of_two(slots);
    const std::size_t row_size = slots >> 1;
    const std::size_t m = slots << 1;
    std::uint64_t pos = 1;
    std::vector<std::size_t> index_map(slots);
    for (std::size_t i = 0; i < row_size; ++i)
    {
        const auto index1 = (pos - 1) >> 1;
        const auto index2 = (m - pos - 1) >> 1;
        index_map[i] = util::safe_cast<std::size_t>(util::reverse_bits(index1, logn));
        index_map[row_size | i] =
            util::safe_cast<std::size_t>(util::reverse_bits(index2, logn));
        pos *= 5;
        pos &= (m - 1);
    }
    return index_map;
}

void add_bfv_rotated_matrix_entry(std::map<int, std::vector<std::uint64_t>> &rotated_rows,
                                  std::size_t row, std::size_t col, std::size_t slots,
                                  std::uint64_t value, const Modulus &plain_modulus)
{
    const auto half_slots = slots >> 1;
    const auto row_swaps_halves = row >= half_slots;
    const auto col_half = col >= half_slots;
    const auto col_index = col & (half_slots - 1);
    const auto row_index = row & (half_slots - 1);
    const auto rotated_index = (col_index + half_slots - row_index) & (half_slots - 1);
    const auto rotated_half = row_swaps_halves ? !col_half : col_half;
    const auto rotated_row = rotated_index + (rotated_half ? half_slots : 0);

    auto &values = rotated_rows[static_cast<int>(rotated_row)];
    if (values.empty())
    {
        values.assign(slots, 0);
    }
    values[row] = util::add_uint_mod(values[row], value, plain_modulus);
}

void encode_bfv_rotated_rows_matrix(const BatchEncoder &encoder,
                                    const std::map<int, std::vector<std::uint64_t>> &rotated_rows,
                                    std::uint32_t level, std::uint32_t log_bsgs_ratio,
                                    MatrixPlain &plain_mat, std::vector<int> &rotate_index)
{
    auto parms_id_map = encoder.context().crt_context()->parms_id_map();
    if (parms_id_map.find(level) == parms_id_map.end())
    {
        POSEIDON_THROW(invalid_argument_error, "invalid recryption linear-map level");
    }

    const auto slots = encoder.slot_count();
    const auto log_slots = util::get_power_of_two(slots);
    const auto n1 =
        find_best_bsgs_ratio(rotated_rows, static_cast<int>(slots),
                             static_cast<int>(log_bsgs_ratio));

    plain_mat.n1 = static_cast<std::uint32_t>(n1);
    plain_mat.log_slots = static_cast<std::uint32_t>(log_slots);
    plain_mat.level = level;
    plain_mat.scale = 1.0;

    add_matrix_rot_to_list(rotated_rows, rotate_index, n1, static_cast<int>(slots), false);
    add_matrix_rot_to_list(rotated_rows, plain_mat.rot_index, n1, static_cast<int>(slots), false);
    auto bsgs = bsgs_index(rotated_rows, static_cast<int>(slots), n1);
    const auto &index_map = std::get<0>(bsgs);
    std::vector<std::uint64_t> values(slots);
    const auto slot_mask = static_cast<int>(slots - 1);
    for (const auto &j : index_map)
    {
        const auto rot = j.first;
        for (auto i : j.second)
        {
            const auto row = (j.first + i) & slot_mask;
            values = matrix_operations::rotate_slots_vec(rotated_rows.at(row), -rot);
            encoder.encode(values, plain_mat.plain_vec[row]);
        }
    }
}

std::uint64_t negate_mod(std::uint64_t value, const Modulus &plain_modulus)
{
    return value == 0 ? 0 : plain_modulus.value() - value;
}

std::vector<std::uint64_t> ntt_root_powers(std::size_t slots, const Modulus &plain_modulus,
                                           bool inverse)
{
    const auto log_slots = util::get_power_of_two(slots);
    std::uint64_t root = 0;
    if (!util::try_minimal_primitive_root(2 * slots, plain_modulus, root))
    {
        POSEIDON_THROW(invalid_argument_error,
                       "plaintext modulus does not support BFV/BGV batching roots");
    }
    if (inverse && !util::try_invert_uint_mod(root, plain_modulus, root))
    {
        POSEIDON_THROW(invalid_argument_error, "cannot invert batching root");
    }

    std::vector<std::uint64_t> powers(slots, 1);
    std::uint64_t power = root;
    if (!inverse)
    {
        for (std::size_t i = 1; i < slots; ++i)
        {
            powers[util::reverse_bits(i, log_slots)] = power;
            power = util::multiply_uint_mod(power, root, plain_modulus);
        }
    }
    else
    {
        for (std::size_t i = 1; i < slots; ++i)
        {
            powers[util::reverse_bits(i - 1, log_slots) + 1] = power;
            power = util::multiply_uint_mod(power, root, plain_modulus);
        }
    }
    powers[0] = 1;
    return powers;
}

std::map<int, std::vector<std::uint64_t>>
build_dwt_layer_rotated_rows(std::size_t slots, std::size_t gap, std::size_t m,
                             std::uint64_t &root_index,
                             const std::vector<std::uint64_t> &roots,
                             const Modulus &plain_modulus, bool inverse)
{
    std::map<int, std::vector<std::uint64_t>> rows;

    std::size_t offset = 0;
    for (std::size_t i = 0; i < m; ++i)
    {
        const auto r = roots[++root_index];
        for (std::size_t j = 0; j < gap; ++j)
        {
            const auto x = offset + j;
            const auto y = x + gap;
            if (!inverse)
            {
                add_bfv_rotated_matrix_entry(rows, x, x, slots, 1, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, x, y, slots, r, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, y, x, slots, 1, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, y, y, slots, negate_mod(r, plain_modulus),
                                             plain_modulus);
            }
            else
            {
                add_bfv_rotated_matrix_entry(rows, x, x, slots, 1, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, x, y, slots, 1, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, y, x, slots, r, plain_modulus);
                add_bfv_rotated_matrix_entry(rows, y, y, slots, negate_mod(r, plain_modulus),
                                             plain_modulus);
            }
        }
        offset += gap << 1;
    }
    return rows;
}

std::map<int, std::vector<std::uint64_t>>
build_permutation_rotated_rows(std::size_t slots,
                               const std::vector<std::size_t> &source_for_row,
                               const Modulus &plain_modulus)
{
    std::map<int, std::vector<std::uint64_t>> rows;
    for (std::size_t row = 0; row < slots; ++row)
    {
        add_bfv_rotated_matrix_entry(rows, row, source_for_row[row], slots, 1, plain_modulus);
    }
    return rows;
}

void append_rotated_rows_matrix(const BatchEncoder &encoder,
                                const std::map<int, std::vector<std::uint64_t>> &rows,
                                std::uint32_t level, std::uint32_t log_bsgs_ratio,
                                LinearMatrixGroup &group)
{
    MatrixPlain matrix;
    encode_bfv_rotated_rows_matrix(encoder, rows, level, log_bsgs_ratio, matrix,
                                   group.rot_index());
    group.data().push_back(matrix);
}

void build_bfv_batch_encoder_group(const PoseidonContext &context, const BatchEncoder &encoder,
                                   std::uint32_t level, bool coeff_to_slot,
                                   std::uint32_t log_bsgs_ratio, LinearMatrixGroup &group)
{
    const auto slots = encoder.slot_count();
    const auto &plain_modulus = context.parameters_literal()->plain_modulus();
    const auto index_map = batch_encoder_matrix_index_map(slots);
    std::vector<std::size_t> inverse_index_map(slots, 0);
    for (std::size_t i = 0; i < slots; ++i)
    {
        inverse_index_map[index_map[i]] = i;
    }

    group.data().clear();
    group.rot_index().clear();
    group.set_step(0);

    if (coeff_to_slot)
    {
        const auto roots = ntt_root_powers(slots, plain_modulus, false);
        std::uint64_t root_index = 0;
        std::size_t gap = slots >> 1;
        std::size_t m = 1;
        for (; m < (slots >> 1); m <<= 1)
        {
            append_rotated_rows_matrix(encoder,
                                       build_dwt_layer_rotated_rows(slots, gap, m, root_index,
                                                                    roots, plain_modulus, false),
                                       level, log_bsgs_ratio, group);
            gap >>= 1;
        }
        append_rotated_rows_matrix(encoder,
                                   build_dwt_layer_rotated_rows(slots, gap, m, root_index,
                                                                roots, plain_modulus, false),
                                   level, log_bsgs_ratio, group);
        append_rotated_rows_matrix(encoder,
                                   build_permutation_rotated_rows(slots, index_map,
                                                                  plain_modulus),
                                   level, log_bsgs_ratio, group);
    }
    else
    {
        append_rotated_rows_matrix(encoder,
                                   build_permutation_rotated_rows(slots, inverse_index_map,
                                                                  plain_modulus),
                                   level, log_bsgs_ratio, group);

        const auto roots = ntt_root_powers(slots, plain_modulus, true);
        std::uint64_t root_index = 0;
        std::size_t gap = 1;
        std::size_t m = slots >> 1;
        for (; m > 1; m >>= 1)
        {
            append_rotated_rows_matrix(encoder,
                                       build_dwt_layer_rotated_rows(slots, gap, m, root_index,
                                                                    roots, plain_modulus, true),
                                       level, log_bsgs_ratio, group);
            gap <<= 1;
        }
        append_rotated_rows_matrix(encoder,
                                   build_dwt_layer_rotated_rows(slots, gap, m, root_index,
                                                                roots, plain_modulus, true),
                                   level, log_bsgs_ratio, group);

        std::uint64_t inv_slots = 0;
        if (!util::try_invert_uint_mod(slots % plain_modulus.value(), plain_modulus, inv_slots))
        {
            POSEIDON_THROW(invalid_argument_error,
                           "slot count is not invertible modulo plaintext");
        }
        std::map<int, std::vector<std::uint64_t>> scale_diag;
        scale_diag[0] = std::vector<std::uint64_t>(slots, inv_slots);
        append_rotated_rows_matrix(encoder, scale_diag, level, log_bsgs_ratio, group);
    }
}
}  // namespace

RecryptionData::RecryptionData(const PoseidonContext &context) : context_(context)
{
    validate_context();
    parameters_.plain_base = plaintext_modulus_value(context_);
    parameters_.r = 1;
    recompute_derived_parameters();
}

void RecryptionData::set_plain_base(uint64_t plain_base, uint32_t r)
{
    if (plain_base < 2)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption plaintext base must be >= 2");
    }
    if (r == 0)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption plaintext exponent r must be >= 1");
    }
    parameters_.plain_base = plain_base;
    parameters_.r = r;
    recompute_derived_parameters();
}

void RecryptionData::set_auxiliary_exponents(uint32_t e, uint32_t e_prime)
{
    if (e <= e_prime)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires e > e_prime");
    }

    parameters_.e = e;
    parameters_.e_prime = e_prime;
    recompute_derived_parameters();
}

void RecryptionData::set_linear_maps(const LinearMatrixGroup &first_map,
                                     const LinearMatrixGroup &second_map)
{
    first_map_ = std::make_shared<LinearMatrixGroup>(first_map);
    second_map_ = std::make_shared<LinearMatrixGroup>(second_map);
}

void RecryptionData::validate_context() const
{
    const auto scheme = context_.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption.cpp is for BFV/BGV bootstrapping");
    }

    if (plaintext_modulus_value(context_) < 2)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption requires plaintext modulus >= 2");
    }
}

void RecryptionData::recompute_derived_parameters()
{
    const auto p = parameters_.plain_base == 0 ? plaintext_modulus_value(context_)
                                               : parameters_.plain_base;
    parameters_.p_power_r = checked_power(p, parameters_.r);

    if (parameters_.e_prime != 0)
    {
        parameters_.p_power_e_prime = checked_power(p, parameters_.e_prime);
    }
    else
    {
        parameters_.p_power_e_prime = 0;
    }

    if (parameters_.e != 0)
    {
        const auto p_power_e = checked_power(p, parameters_.e);
        if (p_power_e == std::numeric_limits<uint64_t>::max())
        {
            POSEIDON_THROW(invalid_argument_error, "p^e overflows uint64_t");
        }
        parameters_.bootstrap_modulus = p_power_e + 1;
    }
    else
    {
        parameters_.bootstrap_modulus = 0;
    }
}

uint64_t RecryptionData::checked_power(uint64_t base, uint32_t exponent)
{
    uint64_t result = 1;
    for (uint32_t i = 0; i < exponent; i++)
    {
        if (base != 0 && result > std::numeric_limits<uint64_t>::max() / base)
        {
            POSEIDON_THROW(invalid_argument_error, "recryption parameter overflow");
        }
        result *= base;
    }
    return result;
}

Recryptor::Recryptor(const PoseidonContext &context, EvaluatorBase &evaluator,
                     const RecryptionData &data)
    : context_(context), evaluator_(evaluator), data_(data)
{
    validate_context();
}

RecryptionKey create_recryption_key(const PoseidonContext &context,
                                    const SecretKey &original_secret_key,
                                    const PublicKey &original_public_key,
                                    const SecretKey &bootstrap_secret_key,
                                    const PublicKey &bootstrap_public_key)
{
    RecryptionKey result;
    KeyGenerator original_keygen(context, original_secret_key);
    result.bootstrap_switch_key =
        original_keygen.create_switch_key(original_secret_key, bootstrap_public_key);

    Plaintext bootstrap_secret_rns = bootstrap_secret_key.data();
    auto key_context = context.crt_context()->key_context_data();
    if (!key_context)
    {
        POSEIDON_THROW(invalid_argument_error, "missing key context data");
    }
    auto degree = key_context->parms().degree();
    auto key_modulus_size = key_context->coeff_modulus().size();
    if (bootstrap_secret_rns.is_ntt_form())
    {
        RNSIter secret_iter(bootstrap_secret_rns.data(), degree);
        util::inverse_ntt_negacyclic_harvey(
            secret_iter, key_modulus_size, context.crt_context()->small_ntt_tables());
        bootstrap_secret_rns.parms_id() = parms_id_zero;
    }

    Plaintext bootstrap_secret_plain(degree);
    const auto first_modulus = key_context->coeff_modulus()[0].value();
    const auto plain_modulus = context.parameters_literal()->plain_modulus().value();
    for (std::size_t i = 0; i < degree; ++i)
    {
        const auto coeff = bootstrap_secret_rns.data()[i];
        if (coeff > first_modulus / 2)
        {
            const auto magnitude = (first_modulus - coeff) % plain_modulus;
            bootstrap_secret_plain.data()[i] =
                magnitude == 0 ? 0 : plain_modulus - magnitude;
        }
        else
        {
            bootstrap_secret_plain.data()[i] = coeff % plain_modulus;
        }
    }

    Encryptor encryptor(context, original_public_key);
    encryptor.encrypt(bootstrap_secret_plain, result.encrypted_bootstrap_secret);
    return result;
}

RecryptionKey create_recryption_key(const PoseidonContext &context,
                                    const SecretKey &original_secret_key,
                                    const PublicKey &original_public_key,
                                    const SecretKey &bootstrap_secret_key,
                                    const PublicKey &bootstrap_public_key,
                                    const GaloisKeys &linear_map_galois_keys)
{
    auto result = create_recryption_key(context, original_secret_key, original_public_key,
                                        bootstrap_secret_key, bootstrap_public_key);
    result.linear_map_galois_keys = linear_map_galois_keys;
    return result;
}

RecryptionKey create_recryption_key(const PoseidonContext &context,
                                    const SecretKey &original_secret_key,
                                    const PublicKey &original_public_key,
                                    const SecretKey &bootstrap_secret_key,
                                    const PublicKey &bootstrap_public_key,
                                    const GaloisKeys &linear_map_galois_keys,
                                    const RelinKeys &relin_keys)
{
    auto result = create_recryption_key(context, original_secret_key, original_public_key,
                                        bootstrap_secret_key, bootstrap_public_key,
                                        linear_map_galois_keys);
    result.relin_keys = relin_keys;
    return result;
}

std::vector<int> bgv_recryption_required_galois_steps(const RecryptionData &data)
{
    if (!data.has_linear_maps())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "cannot collect BGV recryption Galois steps without linear maps");
    }

    const auto slots = data.first_map().data().empty()
                           ? 0
                           : static_cast<int>(std::int64_t{1}
                                              << data.first_map().data().front().log_slots);
    std::vector<int> steps;
    auto add_step = [&steps, slots](int step) { add_bfv_full_slot_galois_steps(steps, step, slots); };
    auto collect = [&add_step](const LinearMatrixGroup &group)
    {
        for (const auto &matrix : group.data())
        {
            for (auto step : matrix.rot_index)
            {
                add_step(step);
            }
        }
        for (auto step : group.rot_index())
        {
            add_step(step);
        }
    };
    collect(data.first_map());
    collect(data.second_map());
    if (std::find(steps.begin(), steps.end(), 0) == steps.end())
    {
        steps.push_back(0);
    }
    return steps;
}

void bgv_build_thin_recryption_maps(const PoseidonContext &context, const BatchEncoder &encoder,
                                    std::uint32_t level, LinearMatrixGroup &coeff_to_slot,
                                    LinearMatrixGroup &slot_to_coeff,
                                    std::uint32_t log_bsgs_ratio)
{
    const auto scheme = context.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "thin recryption maps are only valid for BFV/BGV");
    }
    if (encoder.slot_count() != context.parameters_literal()->degree())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "thin recryption maps require full-slot BFV/BGV batching");
    }

    build_bfv_batch_encoder_group(context, encoder, level, false, log_bsgs_ratio, coeff_to_slot);
    build_bfv_batch_encoder_group(context, encoder, level, true, log_bsgs_ratio, slot_to_coeff);
}

void bgv_initialize_plaintext_space(const PoseidonContext &context, Ciphertext &ciph)
{
    bgv_initialize_plaintext_space(context, ciph, plaintext_modulus_value(context));
}

void bgv_initialize_plaintext_space(const PoseidonContext &context, Ciphertext &ciph,
                                    std::uint64_t plain_base)
{
    const auto scheme = context.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "plaintext-space metadata is only valid for BFV/BGV");
    }
    ciph.bgv_plaintext_space() = plain_base;
    ciph.bgv_int_factor() = 1;
}

void bgv_reduce_plaintext_space(Ciphertext &ciph, std::uint64_t new_plaintext_space)
{
    if (new_plaintext_space < 2)
    {
        POSEIDON_THROW(invalid_argument_error, "new BGV plaintext space must be >= 2");
    }
    if (ciph.bgv_plaintext_space() == 0)
    {
        POSEIDON_THROW(invalid_argument_error, "BGV plaintext-space metadata is not initialized");
    }

    const auto reduced = std::gcd(ciph.bgv_plaintext_space(), new_plaintext_space);
    if (reduced < 2)
    {
        POSEIDON_THROW(invalid_argument_error, "new BGV plaintext space is coprime to current");
    }
    ciph.bgv_plaintext_space() = reduced;
    ciph.bgv_int_factor() %= reduced;
}

std::uint32_t bgv_effective_plain_exponent(const PoseidonContext &context,
                                           const Ciphertext &ciph)
{
    return bgv_effective_plain_exponent(context, ciph, plaintext_modulus_value(context));
}

std::uint32_t bgv_effective_plain_exponent(const PoseidonContext &,
                                           const Ciphertext &ciph,
                                           std::uint64_t plain_base)
{
    const auto p = plain_base;
    auto p_power = std::uint64_t{1};
    for (std::uint32_t exponent = 0; exponent < 64; ++exponent)
    {
        if (p_power == ciph.bgv_plaintext_space())
        {
            return exponent;
        }
        if (p != 0 && p_power > std::numeric_limits<std::uint64_t>::max() / p)
        {
            break;
        }
        p_power *= p;
    }
    POSEIDON_THROW(invalid_argument_error,
                   "BGV plaintext space is not a power of the context plaintext modulus");
}

void bgv_divide_by_plain_base(const PoseidonContext &context, Ciphertext &ciph)
{
    bgv_divide_by_plain_base(context, ciph, plaintext_modulus_value(context));
}

void bgv_divide_by_plain_base(const PoseidonContext &context, Ciphertext &ciph,
                              std::uint64_t plain_base)
{
    const auto scheme = context.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "divide_by_plain_base is only valid for BFV/BGV");
    }
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ciphertext is empty");
    }
    const auto p = plain_base;
    if (ciph.bgv_plaintext_space() == 0)
    {
        bgv_initialize_plaintext_space(context, ciph, p);
    }
    if (ciph.bgv_plaintext_space() % p != 0 || ciph.bgv_plaintext_space() <= p)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "BGV divide_by_plain_base requires plaintext space p^r with r > 1");
    }

    auto context_data = context.crt_context()->get_context_data(ciph.parms_id());
    if (!context_data)
    {
        POSEIDON_THROW(invalid_argument_error, "ciphertext has invalid parms_id");
    }

    const auto &coeff_modulus = context_data->coeff_modulus();
    const auto coeff_count = ciph.poly_modulus_degree();
    const auto coeff_modulus_size = ciph.coeff_modulus_size();

    for (std::size_t part = 0; part < ciph.size(); ++part)
    {
        RNSIter part_iter(ciph.data(part), coeff_count);
        for (std::size_t mod_index = 0; mod_index < coeff_modulus_size; ++mod_index)
        {
            std::uint64_t p_inverse = 0;
            if (!util::try_invert_uint_mod(p % coeff_modulus[mod_index].value(),
                                           coeff_modulus[mod_index].value(), p_inverse))
            {
                POSEIDON_THROW(invalid_argument_error,
                               "plaintext base is not invertible modulo coefficient modulus");
            }
            util::multiply_poly_scalar_coeffmod(part_iter[mod_index], coeff_count, p_inverse,
                                                coeff_modulus[mod_index], part_iter[mod_index]);
        }
    }

    ciph.bgv_plaintext_space() /= p;
    ciph.bgv_int_factor() %= ciph.bgv_plaintext_space();
}

void bgv_multiply_by_plain_base(const PoseidonContext &context, EvaluatorBase &evaluator,
                                Ciphertext &ciph, std::uint32_t exponent)
{
    bgv_multiply_by_plain_base(context, evaluator, ciph, plaintext_modulus_value(context),
                               exponent);
}

void bgv_multiply_by_plain_base(const PoseidonContext &context, EvaluatorBase &evaluator,
                                Ciphertext &ciph, std::uint64_t plain_base,
                                std::uint32_t exponent)
{
    const auto scheme = context.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "multiply_by_plain_base is only valid for BFV/BGV");
    }
    if (exponent == 0)
    {
        return;
    }
    if (ciph.bgv_plaintext_space() == 0)
    {
        bgv_initialize_plaintext_space(context, ciph, plain_base);
    }

    const auto p = plain_base;
    auto multiplier = checked_power_u64(p, exponent);
    Plaintext scalar_plain(1);
    scalar_plain.data()[0] = multiplier % context.parameters_literal()->plain_modulus().value();
    evaluator.multiply_plain(ciph, scalar_plain, ciph);

    for (std::uint32_t i = 0; i < exponent; ++i)
    {
        if (ciph.bgv_plaintext_space() > std::numeric_limits<std::uint64_t>::max() / p)
        {
            POSEIDON_THROW(invalid_argument_error, "BGV plaintext space overflow");
        }
        ciph.bgv_plaintext_space() *= p;
    }
}

void bgv_extract_digits_thin_basic(const PoseidonContext &context, EvaluatorBase &evaluator,
                                   const Ciphertext &ciph, std::vector<Ciphertext> &digits,
                                   std::uint32_t digit_count)
{
    bgv_extract_digits_thin_basic(context, evaluator, ciph, plaintext_modulus_value(context),
                                  digits, digit_count);
}

void bgv_extract_digits_thin_basic(const PoseidonContext &context, EvaluatorBase &evaluator,
                                   const Ciphertext &ciph, std::uint64_t plain_base,
                                   std::vector<Ciphertext> &digits,
                                   std::uint32_t digit_count)
{
    const auto scheme = context.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "digit extraction is only valid for BFV/BGV");
    }
    const auto p = plain_base;
    const auto effective_r = bgv_effective_plain_exponent(context, ciph, p);
    if (digit_count == 0 || digit_count > effective_r)
    {
        digit_count = effective_r;
    }
    if (digit_count == 0)
    {
        digits.clear();
        return;
    }
    if (p != 2 && p != 3 && digit_count > 1)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "basic BGV digit extraction for p>3 currently supports only r=1; "
                       "HElib's interpolation/Chen-Han digit polynomial is still needed for "
                       "multiple digits");
    }

    digits.assign(digit_count, Ciphertext{});
    for (std::uint32_t i = 0; i < digit_count; ++i)
    {
        Ciphertext tmp = ciph;
        for (std::uint32_t j = 0; j < i; ++j)
        {
            Ciphertext p_power = digits[j];
            if (p == 2)
            {
                evaluator.square(p_power, p_power);
            }
            else
            {
                POSEIDON_THROW(invalid_argument_error,
                               "p>3 digit extraction requires HElib-style digit polynomial");
            }
            evaluator.sub(tmp, p_power, tmp);
            bgv_divide_by_plain_base(context, tmp, p);
        }
        digits[i] = tmp;
    }
}

void Recryptor::recrypt(const Ciphertext &ciph, Ciphertext &result,
                        const RecryptionKey &recryption_key) const
{
    if (!recryption_key.has_encrypted_bootstrap_secret())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption key must contain encrypted_bootstrap_secret");
    }

    if (context_.parameters_literal()->scheme() == BGV &&
        data_.parameters().plain_base != plaintext_modulus_value(context_))
    {
        bgv_modulus_raise_to_top(ciph, result);
        return;
    }

    if (!data_.has_linear_maps())
    {
        std::ostringstream ss;
        ss << scheme_name(context_)
           << " public recryption has preprocess+compose and thin digit extraction, "
              "but RecryptionData does not contain HElib-style first/second EvalMap matrices";
        POSEIDON_THROW(invalid_argument_error, ss.str());
    }
    if (!recryption_key.has_linear_map_galois_keys())
    {
        std::ostringstream ss;
        ss << scheme_name(context_)
           << " public recryption needs Galois keys for first/second EvalMap matrices";
        POSEIDON_THROW(invalid_argument_error, ss.str());
    }
    if (!recryption_key.has_relin_keys())
    {
        std::ostringstream ss;
        ss << scheme_name(context_)
           << " public recryption needs relinearization keys after encrypted digit extraction";
        POSEIDON_THROW(invalid_argument_error, ss.str());
    }

    Ciphertext coeffs;
    apply_linear_map(ciph, data_.second_map(), recryption_key.linear_map_galois_keys,
                     coeffs);

    Ciphertext composed;
    preprocess_and_compose(coeffs, recryption_key, composed);

    Ciphertext slots;
    apply_linear_map(composed, data_.first_map(), recryption_key.linear_map_galois_keys,
                     slots);

    Ciphertext digit_extracted;
    thin_digit_extract_after_compose(slots, recryption_key.relin_keys, digit_extracted);
    result = std::move(digit_extracted);
}

RecryptionPreprocessResult
Recryptor::preprocess(const Ciphertext &ciph, const KSwitchKeys &recryption_key) const
{
    ensure_ciphertext_can_bootstrap(ciph);

    if (ciph.size() != 2)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption preprocess expects a size-2 ciphertext; relinearize first");
    }

    Ciphertext working = ciph;
    if (working.level() > 2)
    {
        const auto &level_to_id = context_.crt_context()->parms_id_map();
        auto target = level_to_id.find(2);
        if (target == level_to_id.end())
        {
            POSEIDON_THROW(invalid_argument_error,
                           "cannot find level-2 parameters for recryption preprocess");
        }
        evaluator_.drop_modulus(working, working, target->second);
    }

    evaluator_.switch_key(working, working, recryption_key);

    if (context_.parameters_literal()->scheme() == BGV && working.is_ntt_form())
    {
        evaluator_.ntt_inv(working, working);
    }

    RecryptionPreprocessResult preprocess_result;
    raw_mod_switch(working, data_.parameters().bootstrap_modulus,
                   preprocess_result.raw_parts);
    preprocess_result.divisible_parts = preprocess_result.raw_parts;
    std::vector<RecryptionRawPart> v_parts;
    make_divisible(preprocess_result.divisible_parts, v_parts);
    preprocess_result.divided_parts = preprocess_result.divisible_parts;
    divide_by_p_power_e_prime(preprocess_result.divided_parts);

    return preprocess_result;
}

void Recryptor::preprocess_and_compose(const Ciphertext &ciph,
                                       const RecryptionKey &recryption_key,
                                       Ciphertext &result) const
{
    if (!recryption_key.has_encrypted_bootstrap_secret())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption key must contain encrypted_bootstrap_secret");
    }

    auto preprocessed = preprocess(ciph, recryption_key.bootstrap_switch_key);
    if (preprocessed.divided_parts.size() != 2)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption compose expects exactly two preprocessed parts");
    }

    const auto &encrypted_bootstrap_secret = recryption_key.encrypted_bootstrap_secret;
    auto context_data = context_.crt_context()->get_context_data(encrypted_bootstrap_secret.parms_id());
    if (!context_data)
    {
        POSEIDON_THROW(invalid_argument_error, "encrypted bootstrap secret has invalid parms_id");
    }

    const auto coeff_count = encrypted_bootstrap_secret.poly_modulus_degree();
    const auto plain_base = data_.parameters().plain_base;
    const auto plain_modulus = plaintext_modulus_value(context_);
    auto encode_raw_part = [&](const RecryptionRawPart &part)
    {
        Plaintext plain(coeff_count);
        const auto count = std::min<std::size_t>(coeff_count, part.coeffs.size());
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto reduced = positive_mod(part.coeffs[i], plain_modulus);
            plain.data()[i] = static_cast<std::uint64_t>(reduced);
        }
        return plain;
    };

    auto z0_plain = encode_raw_part(preprocessed.divided_parts[0]);
    auto z1_plain = encode_raw_part(preprocessed.divided_parts[1]);
    Ciphertext working = encrypted_bootstrap_secret;

    if (working.is_ntt_form())
    {
        evaluator_.ntt_fwd(z1_plain, z1_plain, working.parms_id());
    }
    evaluator_.multiply_plain(working, z1_plain, result);

    if (context_.parameters_literal()->scheme() == BGV && !result.is_ntt_form())
    {
        evaluator_.ntt_fwd(result, result);
    }
    evaluator_.add_plain(result, z0_plain, result);
    result.bgv_plaintext_space() =
        checked_power_u64(plain_base, data_.parameters().e - data_.parameters().e_prime +
                                          data_.parameters().r);
    result.bgv_int_factor() = 1;
}

void Recryptor::thin_digit_extract_after_compose(const Ciphertext &composed,
                                                 Ciphertext &result) const
{
    const auto &params = data_.parameters();
    if (params.e < params.e_prime)
    {
        POSEIDON_THROW(invalid_argument_error, "invalid recryption digit range");
    }

    const auto p = params.plain_base;
    const auto bot_high = params.e - params.e_prime;
    auto top_high = bot_high + params.r - 1;
    if (p == 2 && params.r > 2 && top_high + 1 > 2)
    {
        top_high--;
    }

    std::vector<Ciphertext> digits;
    bgv_extract_digits_thin_basic(context_, evaluator_, composed, p, digits, top_high + 1);
    if (digits.empty())
    {
        POSEIDON_THROW(invalid_argument_error, "digit extraction produced no digits");
    }

    if (top_high >= digits.size())
    {
        top_high = static_cast<std::uint32_t>(digits.size() - 1);
    }
    if (bot_high > top_high)
    {
        POSEIDON_THROW(invalid_argument_error, "digit extraction did not produce requested digits");
    }

    result = digits[top_high];
    for (std::int64_t j = static_cast<std::int64_t>(top_high) - 1;
         j >= static_cast<std::int64_t>(bot_high); --j)
    {
        bgv_multiply_by_plain_base(context_, evaluator_, result, p, 1);
        evaluator_.add(result, digits[static_cast<std::size_t>(j)], result);
    }
    if (p == 2 && bot_high > 0)
    {
        evaluator_.add(result, digits[bot_high - 1], result);
    }
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        result[i].negate();
    }

    if (params.r > params.e_prime)
    {
        const auto top_low = params.r - 1 - params.e_prime;
        if (top_low >= digits.size())
        {
            POSEIDON_THROW(invalid_argument_error,
                           "digit extraction did not produce low digits");
        }
        Ciphertext low = digits[top_low];
        for (std::int64_t j = static_cast<std::int64_t>(top_low) - 1; j >= 0; --j)
        {
            bgv_multiply_by_plain_base(context_, evaluator_, low, p, 1);
            evaluator_.add(low, digits[static_cast<std::size_t>(j)], low);
        }
        if (params.e_prime > 0)
        {
            bgv_multiply_by_plain_base(context_, evaluator_, low, p, params.e_prime);
        }
        evaluator_.add(result, low, result);
    }
    bgv_reduce_plaintext_space(result, params.p_power_r);
}

void Recryptor::apply_linear_map_for_bgv_recryption(const Ciphertext &ciph,
                                                    const LinearMatrixGroup &map,
                                                    const GaloisKeys &galois_keys,
                                                    Ciphertext &result) const
{
    apply_linear_map(ciph, map, galois_keys, result);
}

void Recryptor::thin_digit_extract_after_compose(const Ciphertext &composed,
                                                 const RelinKeys &relin_keys,
                                                 Ciphertext &result) const
{
    thin_digit_extract_after_compose(composed, result);
    if (result.size() > 2)
    {
        evaluator_.relinearize(result, result, relin_keys);
    }
}

void Recryptor::validate_context() const
{
    const auto scheme = context_.parameters_literal()->scheme();
    if (scheme != BFV && scheme != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "recryption.cpp is for BFV/BGV bootstrapping");
    }
}

void Recryptor::ensure_ciphertext_can_bootstrap(const Ciphertext &ciph) const
{
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "recryption input ciphertext is empty");
    }

    const auto &params = data_.parameters();
    if (params.e == 0 || params.e_prime == 0 || params.bootstrap_modulus == 0)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "recryption auxiliary exponents are not initialized");
    }
}

void Recryptor::raw_mod_switch(const Ciphertext &ciph, std::uint64_t q,
                               std::vector<RecryptionRawPart> &destination) const
{
    if (q <= 1)
    {
        POSEIDON_THROW(invalid_argument_error, "raw mod-switch target q must be greater than 1");
    }
    if (ciph.is_ntt_form())
    {
        POSEIDON_THROW(invalid_argument_error,
                       "raw mod-switch expects coefficient-form BFV/BGV ciphertexts");
    }

    const auto context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    if (!context_data)
    {
        POSEIDON_THROW(invalid_argument_error, "ciphertext has invalid parms_id");
    }

    const auto &params = data_.parameters();
    if (std::gcd(q, params.p_power_r) != 1)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "raw mod-switch target q must be coprime to p^r");
    }

    const auto coeff_count = ciph.poly_modulus_degree();
    const auto coeff_modulus_size = ciph.coeff_modulus_size();
    const auto &coeff_modulus = context_data->coeff_modulus();
    const auto base_q = context_data->rns_tool()->base_q();

    mpz_class Q = 1;
    for (const auto &modulus : coeff_modulus)
    {
        Q *= uint64_to_mpz(modulus.value());
    }
    mpz_class Q_half = Q / 2;

    mpz_class q_mod_p_mpz = Q % uint64_to_mpz(params.p_power_r);
    std::uint64_t q_mod_p = static_cast<std::uint64_t>(q_mod_p_mpz.get_ui());
    std::uint64_t Q_inv_mod_p = 0;
    if (!util::try_invert_uint_mod(q_mod_p, params.p_power_r, Q_inv_mod_p))
    {
        POSEIDON_THROW(invalid_argument_error, "Q is not invertible modulo p^r");
    }

    destination.resize(ciph.size());
    for (std::size_t part = 0; part < ciph.size(); ++part)
    {
        auto &out = destination[part].coeffs;
        out.assign(coeff_count, 0);

        auto composed(allocate_uint(coeff_count * coeff_modulus_size,
                                    MemoryManager::GetPool()));
        set_uint(ciph.data(part), coeff_count * coeff_modulus_size, composed.get());
        if (coeff_modulus_size > 1)
        {
            base_q->compose_array(composed.get(), coeff_count, MemoryManager::GetPool());
        }

        for (std::size_t j = 0; j < coeff_count; ++j)
        {
            const std::uint64_t *coeff =
                coeff_modulus_size == 1 ? composed.get() + j
                                        : composed.get() + (j * coeff_modulus_size);
            mpz_class c = coeff_modulus_size == 1
                              ? uint64_to_mpz(*coeff)
                              : uint_array_to_mpz(coeff, coeff_modulus_size);
            if (c > Q_half)
            {
                c -= Q;
            }

            mpz_class cq = c * uint64_to_mpz(q);
            mpz_class X;
            mpz_class Y;
            mpz_fdiv_qr(X.get_mpz_t(), Y.get_mpz_t(), cq.get_mpz_t(), Q.get_mpz_t());
            if (Y > Q_half)
            {
                Y -= Q;
                X += 1;
            }

            mpz_class y_mod_p;
            mpz_class p2r_mpz = uint64_to_mpz(params.p_power_r);
            mpz_mod(y_mod_p.get_mpz_t(), Y.get_mpz_t(), p2r_mpz.get_mpz_t());
            auto delta_product = static_cast<unsigned __int128>(y_mod_p.get_ui()) *
                                 static_cast<unsigned __int128>(Q_inv_mod_p);
            auto delta = static_cast<std::int64_t>(delta_product % params.p_power_r);
            if (static_cast<std::uint64_t>(delta) > params.p_power_r / 2)
            {
                delta -= static_cast<std::int64_t>(params.p_power_r);
            }

            mpz_class x = X + static_cast<long>(delta);
            if (x > uint64_to_mpz(q / 2))
            {
                x -= uint64_to_mpz(q);
            }
            else if (x < -uint64_to_mpz(q / 2))
            {
                x += uint64_to_mpz(q);
            }
            out[j] = checked_mpz_to_int64(x, "raw mod-switch coefficient");
        }
    }
}

void Recryptor::make_divisible(std::vector<RecryptionRawPart> &parts,
                               std::vector<RecryptionRawPart> &v_parts) const
{
    const auto &params = data_.parameters();
    const auto p2e_prime = params.p_power_e_prime;
    const auto q = params.bootstrap_modulus;
    if (p2e_prime == 1)
    {
        v_parts.assign(parts.size(), {});
        for (std::size_t i = 0; i < parts.size(); ++i)
        {
            v_parts[i].coeffs.assign(parts[i].coeffs.size(), 0);
        }
        return;
    }
    if (q % p2e_prime != 1)
    {
        POSEIDON_THROW(invalid_argument_error, "bootstrap modulus q must equal 1 modulo p^e'");
    }

    v_parts.resize(parts.size());
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        v_parts[i].coeffs.assign(parts[i].coeffs.size(), 0);
        for (std::size_t j = 0; j < parts[i].coeffs.size(); ++j)
        {
            auto z_mod = positive_mod(parts[i].coeffs[j], p2e_prime);
            std::int64_t v = 0;
            if (static_cast<std::uint64_t>(z_mod) > p2e_prime / 2)
            {
                v = static_cast<std::int64_t>(p2e_prime) - z_mod;
            }
            else
            {
                v = -z_mod;
            }

            parts[i].coeffs[j] = checked_add_mul(parts[i].coeffs[j], v, q);
            if (positive_mod(parts[i].coeffs[j], p2e_prime) != 0)
            {
                POSEIDON_THROW(invalid_argument_error, "make_divisible failed sanity check");
            }
            v_parts[i].coeffs[j] = v;
        }
    }
}

void Recryptor::divide_by_p_power_e_prime(std::vector<RecryptionRawPart> &parts) const
{
    const auto divisor = static_cast<std::int64_t>(data_.parameters().p_power_e_prime);
    if (divisor <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "invalid p^e' divisor");
    }

    for (auto &part : parts)
    {
        for (auto &coeff : part.coeffs)
        {
            if (coeff % divisor != 0)
            {
                POSEIDON_THROW(invalid_argument_error, "coefficient is not divisible by p^e'");
            }
            coeff /= divisor;
        }
    }
}

void Recryptor::apply_linear_map(const Ciphertext &ciph, const LinearMatrixGroup &map,
                                 const GaloisKeys &galois_keys, Ciphertext &result) const
{
    if (map.data().empty())
    {
        POSEIDON_THROW(invalid_argument_error, "BGV recryption linear map is empty");
    }

    Ciphertext current;
    evaluator_.multiply_by_diag_matrix_bsgs(ciph, map.data().front(), current, galois_keys);
    for (std::size_t i = 1; i < map.data().size(); ++i)
    {
        Ciphertext next;
        evaluator_.multiply_by_diag_matrix_bsgs(current, map.data()[i], next, galois_keys);
        current = std::move(next);
    }
    result = std::move(current);
    result.bgv_plaintext_space() = ciph.bgv_plaintext_space();
    result.bgv_int_factor() = ciph.bgv_int_factor();
}

void Recryptor::bgv_modulus_raise_to_top(const Ciphertext &ciph, Ciphertext &result) const
{
    if (context_.parameters_literal()->scheme() != BGV)
    {
        POSEIDON_THROW(invalid_argument_error, "BGV modulus raise is only valid for BGV");
    }
    if (!ciph.is_valid())
    {
        POSEIDON_THROW(invalid_argument_error, "ciphertext is empty");
    }

    auto source_context_data = context_.crt_context()->get_context_data(ciph.parms_id());
    auto target_context_data = context_.crt_context()->first_context_data();
    if (!source_context_data || !target_context_data)
    {
        POSEIDON_THROW(invalid_argument_error, "ciphertext has invalid parms_id");
    }
    if (source_context_data->parms_id() == target_context_data->parms_id())
    {
        result = ciph;
        return;
    }

    Ciphertext coeff_form = ciph;
    const bool was_ntt = coeff_form.is_ntt_form();
    if (was_ntt)
    {
        evaluator_.ntt_inv(coeff_form, coeff_form);
    }

    const auto coeff_count = coeff_form.poly_modulus_degree();
    const auto source_modulus_size = coeff_form.coeff_modulus_size();
    const auto target_modulus_size = target_context_data->coeff_modulus().size();
    const auto &source_moduli = source_context_data->coeff_modulus();
    const auto &target_moduli = target_context_data->coeff_modulus();
    auto source_base = source_context_data->rns_tool()->base_q();

    mpz_class source_q = 1;
    for (const auto &modulus : source_moduli)
    {
        source_q *= uint64_to_mpz(modulus.value());
    }
    const mpz_class source_q_half = source_q / 2;
    mpz_class raise_factor = 1;
    std::uint64_t raise_factor_mod_plain = 1;
    const auto &plain_modulus = context_.parameters_literal()->plain_modulus();
    for (std::size_t i = source_modulus_size; i < target_modulus_size; ++i)
    {
        raise_factor *= uint64_to_mpz(target_moduli[i].value());
        raise_factor_mod_plain = util::multiply_uint_mod(
            raise_factor_mod_plain, target_moduli[i].value() % plain_modulus.value(),
            plain_modulus);
    }

    result.resize(context_, target_context_data->parms_id(), coeff_form.size());
    result.is_ntt_form() = false;
    result.scale() = coeff_form.scale();
    result.correction_factor() = util::multiply_uint_mod(
        coeff_form.correction_factor(), raise_factor_mod_plain, plain_modulus);
    result.bgv_plaintext_space() = coeff_form.bgv_plaintext_space();
    result.bgv_int_factor() = coeff_form.bgv_int_factor();

    for (std::size_t part = 0; part < coeff_form.size(); ++part)
    {
        auto composed(allocate_uint(coeff_count * source_modulus_size,
                                    MemoryManager::GetPool()));
        set_uint(coeff_form.data(part), coeff_count * source_modulus_size, composed.get());
        if (source_modulus_size > 1)
        {
            source_base->compose_array(composed.get(), coeff_count, MemoryManager::GetPool());
        }

        RNSIter target_iter(result.data(part), coeff_count);
        for (std::size_t j = 0; j < coeff_count; ++j)
        {
            const std::uint64_t *source_coeff =
                source_modulus_size == 1 ? composed.get() + j
                                         : composed.get() + (j * source_modulus_size);
            mpz_class centered = source_modulus_size == 1
                                     ? uint64_to_mpz(*source_coeff)
                                     : uint_array_to_mpz(source_coeff, source_modulus_size);
            if (centered > source_q_half)
            {
                centered -= source_q;
            }
            centered *= raise_factor;

            for (std::size_t mod_index = 0; mod_index < target_modulus_size; ++mod_index)
            {
                mpz_class reduced;
                const auto target_modulus = uint64_to_mpz(target_moduli[mod_index].value());
                mpz_mod(reduced.get_mpz_t(), centered.get_mpz_t(), target_modulus.get_mpz_t());
                target_iter[mod_index][j] = static_cast<std::uint64_t>(reduced.get_ui());
            }
        }
    }

    if (was_ntt)
    {
        evaluator_.ntt_fwd(result, result);
    }
}

}  // namespace poseidon
