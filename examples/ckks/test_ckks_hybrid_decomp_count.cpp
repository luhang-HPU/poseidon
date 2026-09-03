#include "poseidon/batchencoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

using namespace poseidon;

namespace
{
using Complex = std::complex<double>;

std::size_t ceil_div(std::size_t numerator, std::size_t denominator)
{
    return (numerator + denominator - 1) / denominator;
}

std::vector<Complex> make_message(std::size_t slot_count, double phase)
{
    std::vector<Complex> result(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        const double x = static_cast<double>(static_cast<int>(i % 17) - 8) / 25.0;
        const double y = static_cast<double>(static_cast<int>(i % 11) - 5) / 30.0;
        result[i] = {x + phase, y - phase / 2.0};
    }
    return result;
}

double max_abs_error(const std::vector<Complex> &expected, const std::vector<Complex> &actual)
{
    double result = 0.0;
    const std::size_t count = std::min(expected.size(), actual.size());
    for (std::size_t i = 0; i < count; ++i)
    {
        result = std::max(result, std::abs(expected[i] - actual[i]));
    }
    return result;
}

bool check_close(const std::string &label, const std::vector<Complex> &expected,
                 const std::vector<Complex> &actual, double tolerance)
{
    if (expected.size() != actual.size())
    {
        std::cerr << label << " size mismatch" << std::endl;
        return false;
    }
    const double error = max_abs_error(expected, actual);
    std::cout << label << " max_abs_error=" << error << " tolerance=" << tolerance << std::endl;
    if (error > tolerance)
    {
        std::cerr << label << " failed" << std::endl;
        return false;
    }
    return true;
}

bool check_equal(const std::string &label, const std::vector<std::uint64_t> &expected,
                 const std::vector<std::uint64_t> &actual)
{
    if (expected.size() != actual.size())
    {
        std::cerr << label << " size mismatch" << std::endl;
        return false;
    }
    for (std::size_t i = 0; i < expected.size(); ++i)
    {
        if (expected[i] != actual[i])
        {
            std::cerr << label << " mismatch at " << i << ": expected=" << expected[i]
                      << " actual=" << actual[i] << std::endl;
            return false;
        }
    }
    std::cout << label << " passed" << std::endl;
    return true;
}

template <typename EvaluatorT>
bool check_integer_keyswitch(const std::string &scheme_label, PoseidonContext &context,
                             EvaluatorT &evaluator, std::size_t q_count, std::size_t p_count)
{
    constexpr std::uint64_t plain_modulus = 65537;
    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(std::vector<int>{1, -1}, galois_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    const std::size_t slot_count = context.parameters_literal()->degree();
    std::vector<std::uint64_t> message(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        message[i] = (i * 7 + 3) % 97;
    }

    Plaintext plain;
    encoder.encode(message, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    Ciphertext multiplied;
    evaluator.multiply_relin(encrypted, encrypted, multiplied, relin_keys);
    Plaintext result_plain;
    std::vector<std::uint64_t> actual;
    decryptor.decrypt(multiplied, result_plain);
    encoder.decode(result_plain, actual);
    auto expected_product = message;
    for (auto &value : expected_product)
    {
        value = value * value % plain_modulus;
    }

    const std::string label = scheme_label + " q=" + std::to_string(q_count) +
                              " p=" + std::to_string(p_count) +
                              " dnum=" + std::to_string(ceil_div(q_count, p_count));
    bool ok = check_equal(label + " multiply_relin", expected_product, actual);

    Ciphertext rotated;
    Ciphertext restored;
    evaluator.rotate_row(encrypted, rotated, 1, galois_keys);
    evaluator.rotate_row(rotated, restored, -1, galois_keys);
    decryptor.decrypt(restored, result_plain);
    encoder.decode(result_plain, actual);
    ok &= check_equal(label + " rotate_row roundtrip", message, actual);
    return ok;
}

bool run_integer_case(SchemeType scheme, std::size_t q_count, std::size_t p_count)
{
    ParametersLiteral parameters{scheme, 13, 12, 0, 5, 0, 65537, {}, {},
                                 poseidon::sec_level_type::none};
    parameters.set_log_modulus(std::vector<std::uint32_t>(q_count, 45),
                               std::vector<std::uint32_t>(p_count, 45));
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    if (context.key_switch_variant() != HYBRID)
    {
        std::cerr << "expected HYBRID integer context" << std::endl;
        return false;
    }

    if (scheme == BFV)
    {
        auto evaluator = PoseidonFactory::get_instance()->create_bfv_evaluator(context);
        return check_integer_keyswitch("BFV", context, *evaluator, q_count, p_count);
    }
    auto evaluator = PoseidonFactory::get_instance()->create_bgv_evaluator(context);
    return check_integer_keyswitch("BGV", context, *evaluator, q_count, p_count);
}

bool run_case(std::size_t expected_decomp_count, std::size_t q_count, std::size_t p_count)
{
    constexpr std::uint32_t log_n = 13;
    constexpr std::uint32_t log_slots = log_n - 1;
    constexpr std::uint32_t log_scale = 35;

    ParametersLiteral parameters{CKKS, log_n, log_slots, log_scale, 5, 0, 0, {}, {},
                                 poseidon::sec_level_type::none};
    parameters.set_log_modulus(std::vector<std::uint32_t>(q_count, 45),
                               std::vector<std::uint32_t>(p_count, 45));

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(parameters);

    if (context.key_switch_variant() != HYBRID)
    {
        std::cerr << "expected HYBRID key switch variant for decomp_count="
                  << expected_decomp_count << std::endl;
        return false;
    }

    const auto key_context_data = context.crt_context()->key_context_data();
    const auto qp_tool = key_context_data->qp_rns_tool();
    const std::size_t actual_q_count = qp_tool->base_q()->size();
    const std::size_t actual_p_count = qp_tool->base_p()->size();
    const std::size_t actual_decomp_count = ceil_div(actual_q_count, actual_p_count);

    std::cout << "case decomp_count=" << expected_decomp_count << " q_count=" << actual_q_count
              << " p_count=" << actual_p_count << " actual_decomp_count="
              << actual_decomp_count << std::endl;

    if (actual_decomp_count != expected_decomp_count)
    {
        std::cerr << "unexpected decomp_count" << std::endl;
        return false;
    }

    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    KeyGenerator keygen(context);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(std::vector<int>{1}, galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    const double scale = std::pow(2.0, log_scale);
    const std::size_t slot_count = parameters.slot();
    const auto msg1 = make_message(slot_count, 0.05);
    const auto msg2 = make_message(slot_count, -0.03);

    Plaintext plain1;
    Plaintext plain2;
    encoder.encode(msg1, scale, plain1);
    encoder.encode(msg2, scale, plain2);

    Ciphertext ct1;
    Ciphertext ct2;
    encryptor.encrypt(plain1, ct1);
    encryptor.encrypt(plain2, ct2);

    Plaintext decoded_plain;
    std::vector<Complex> decoded;
    std::vector<Complex> expected_product(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i)
    {
        expected_product[i] = msg1[i] * msg2[i];
    }
    auto expected_rotated = msg1;
    std::rotate(expected_rotated.begin(), expected_rotated.begin() + 1, expected_rotated.end());

    for (std::size_t current_q_count = q_count; current_q_count > 0; --current_q_count)
    {
        const std::size_t level_decomp_count = ceil_div(current_q_count, p_count);
        const std::string case_label = "q=" + std::to_string(current_q_count) +
                                       " p=" + std::to_string(p_count) +
                                       " dnum=" + std::to_string(level_decomp_count);

        // A 35-bit CKKS scale squares to 70 bits, so multiplication is not a
        // meaningful correctness check after the chain reaches one 45-bit Q.
        if (current_q_count > 1)
        {
            Ciphertext multiplied;
            evaluator->multiply_relin(ct1, ct2, multiplied, relin_keys);
            decryptor.decrypt(multiplied, decoded_plain);
            encoder.decode(decoded_plain, decoded);
            if (!check_close(case_label + " multiply_relin", expected_product, decoded, 2e-3))
            {
                return false;
            }
        }

        Ciphertext rotated;
        evaluator->rotate(ct1, rotated, 1, galois_keys);
        decryptor.decrypt(rotated, decoded_plain);
        encoder.decode(decoded_plain, decoded);
        if (!check_close(case_label + " rotate", expected_rotated, decoded, 2e-3))
        {
            return false;
        }

        if (current_q_count > 1)
        {
            evaluator->drop_modulus_to_next(ct1, ct1);
            evaluator->drop_modulus_to_next(ct2, ct2);
        }
    }

    return true;
}
}  // namespace

int main()
{
    try
    {
        bool all_ok = true;
        // Cover exact division and both non-exact final decomposition shapes
        // (one remaining Q prime and multiple remaining Q primes), for two P sizes.
        std::vector<std::pair<std::size_t, std::size_t>> cases;
        for (std::size_t dnum = 2; dnum <= 16; ++dnum)
        {
            cases.emplace_back(dnum * 2 - 1, 2);  // final group contains one Q
            cases.emplace_back(dnum * 2, 2);      // exact division
        }
        cases.emplace_back(8, 3);   // final group contains multiple Qs
        cases.emplace_back(10, 3);  // final group contains one Q

        for (const auto &[q_count, p_count] : cases)
        {
            if (!run_case(ceil_div(q_count, p_count), q_count, p_count))
            {
                all_ok = false;
            }
        }

        // CKKS and BGV share the NTT-form switch path; BFV has a separate
        // coefficient-form path. Exercise both integer schemes across dnum=2..16.
        std::vector<std::pair<std::size_t, std::size_t>> integer_cases;
        for (std::size_t dnum = 2; dnum <= 16; ++dnum)
        {
            integer_cases.emplace_back(dnum * 2 - 1, 2);
        }
        for (const auto scheme : {BFV, BGV})
        {
            for (const auto &[q_count, p_count] : integer_cases)
            {
                if (!run_integer_case(scheme, q_count, p_count))
                {
                    all_ok = false;
                }
            }
        }

        if (!all_ok)
        {
            std::cerr << "HYBRID software full branch matrix failed" << std::endl;
            return 1;
        }
        std::cout << "HYBRID software full branch matrix passed for CKKS, BFV, and BGV" << std::endl;
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
