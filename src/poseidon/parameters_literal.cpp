#include "parameters_literal.h"
#include "basics/util/numth.h"
#include "util/exception.h"

namespace poseidon
{
using namespace util;
ParametersLiteral::ParametersLiteral(SchemeType type, uint32_t log_n, uint32_t log_slots,
                                     uint32_t log_scale, uint32_t hamming_weight, uint32_t q0_level,
                                     Modulus plain_modulus, const vector<Modulus> &q,
                                     const vector<Modulus> &p, sec_level_type sec_level,
                                     MemoryPoolHandle pool)
    : type_(type), log_n_(log_n), log_slots_(log_slots), q_(q), p_(p), log_scale_(log_scale),
      hamming_weight_(hamming_weight), plain_modulus_(plain_modulus), q0_level_(q0_level),
      pool_(std::move(pool)), sec_level_(sec_level)
{
    compute_params_id();
}

void ParametersLiteral::save_members(std::ostream &stream) const
{
    // TODO: need test
    // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
    auto old_except_mask = stream.exceptions();
    try
    {
        stream.exceptions(ios_base::badbit | ios_base::failbit);
        uint8_t type = static_cast<uint8_t>(type_);
        int sec_level = static_cast<int>(sec_level_);
        uint32_t log_n = static_cast<uint32_t>(log_n_);
        uint32_t log_slots = static_cast<uint32_t>(log_slots_);
        uint32_t log_scale = static_cast<uint32_t>(log_scale_);
        uint32_t hamming_weight = static_cast<uint32_t>(hamming_weight_);
        uint32_t q0_level = static_cast<uint32_t>(q0_level_);

        stream.write(reinterpret_cast<const char *>(&type), sizeof(uint8_t));
        stream.write(reinterpret_cast<const char *>(&sec_level), sizeof(int));
        stream.write(reinterpret_cast<const char *>(&log_n), sizeof(uint32_t));
        stream.write(reinterpret_cast<const char *>(&log_slots), sizeof(uint32_t));
        stream.write(reinterpret_cast<const char *>(&log_scale), sizeof(uint32_t));
        stream.write(reinterpret_cast<const char *>(&hamming_weight), sizeof(uint32_t));
        stream.write(reinterpret_cast<const char *>(&q0_level), sizeof(uint32_t));

        uint64_t q_size64 = static_cast<uint64_t>(q_.size());
        uint64_t p_size64 = static_cast<uint64_t>(p_.size());

        stream.write(reinterpret_cast<const char *>(&q_size64), sizeof(uint64_t));
        stream.write(reinterpret_cast<const char *>(&p_size64), sizeof(uint64_t));
        for (const auto &q : q_)
        {
            q.save(stream, compr_mode_type::none);
        }
        for (const auto &p : p_)
        {
            p.save(stream, compr_mode_type::none);
        }

        // Only BFV and BGV uses plain_modulus but save it in any case for simplicity
        plain_modulus_.save(stream, compr_mode_type::none);
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

void ParametersLiteral::load_members(std::istream &stream)
{
    // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
    auto old_except_mask = stream.exceptions();
    try
    {
        stream.exceptions(ios_base::badbit | ios_base::failbit);

        // Read the scheme identifier
        uint8_t type;
        int sec_level;
        uint32_t log_n;
        uint32_t log_slots;
        uint32_t log_scale;
        uint32_t hamming_weight;
        uint32_t q0_level;

        stream.read(reinterpret_cast<char *>(&type), sizeof(uint8_t));
        stream.read(reinterpret_cast<char *>(&sec_level), sizeof(int));
        stream.read(reinterpret_cast<char *>(&log_n), sizeof(uint32_t));
        stream.read(reinterpret_cast<char *>(&log_slots), sizeof(uint32_t));
        stream.read(reinterpret_cast<char *>(&log_scale), sizeof(uint32_t));
        stream.read(reinterpret_cast<char *>(&hamming_weight), sizeof(uint32_t));
        stream.read(reinterpret_cast<char *>(&q0_level), sizeof(uint32_t));

        uint64_t q_size64;
        uint64_t p_size64;
        vector<Modulus> q;
        vector<Modulus> p;

        stream.read(reinterpret_cast<char *>(&q_size64), sizeof(uint64_t));
        stream.read(reinterpret_cast<char *>(&p_size64), sizeof(uint64_t));
        for (uint64_t i = 0; i < q_size64; i++)
        {
            q.emplace_back();
            q.back().load(stream);
        }

        for (uint64_t i = 0; i < p_size64; i++)
        {
            p.emplace_back();
            p.back().load(stream);
        }
        // Read the plain_modulus
        Modulus plain_modulus;
        plain_modulus.load(stream);

        // This constructor will throw if scheme is invalid
        ParametersLiteral parms(static_cast<SchemeType>(type), log_n, log_slots, log_scale,
                                hamming_weight, q0_level, plain_modulus, q, p,
                                static_cast<poseidon::sec_level_type>(sec_level));

        // Set the loaded parameters
        swap(*this, parms);

        stream.exceptions(old_except_mask);
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

void ParametersLiteral::set_poly_modulus_degree(std::size_t poly_modulus_degree)
{
    if (poly_modulus_degree)
    {
        throw std::logic_error("poly_modulus_degree is not supported for this scheme");
    }

    // Set the degree
    log_n_ = static_cast<uint32_t>(log2(poly_modulus_degree));

    // Re-compute the parms_id
    compute_params_id();
}

void ParametersLiteral::set_plain_modulus(const Modulus &plain_modulus)
{
    if (type_ != BFV && type_ != BGV && !plain_modulus.is_zero())
    {
        throw std::logic_error("plain_modulus is not supported for this scheme");
    }
    plain_modulus_ = plain_modulus;

    // Re-compute the parms_id
    compute_params_id();
}

void ParametersLiteral::set_log_modulus(const vector<uint32_t> &log_q,
                                        const vector<uint32_t> &log_p)
{
    //<prime_size, primes_num>
    auto factor = (uint64_t)2 << log_n_;
    //<prime_size, primes_vector>
    map<uint32_t, vector<Modulus>> primes_map;
    map<uint32_t, int> primes_num_map;
    for (unsigned int i : log_q)
    {
        auto f = primes_num_map.find(i);
        if (f != primes_num_map.end())
        {
            primes_num_map[i] += 1;
        }
        else
        {
            primes_num_map[i] = 1;
        }
    }

    for (unsigned int i : log_p)
    {
        auto f = primes_num_map.find(i);
        if (f != primes_num_map.end())
        {
            primes_num_map[i] += 1;
        }
        else
        {
            primes_num_map[i] = 1;
        }
    }

    for (auto p : primes_num_map)
    {
        // key : p.first--- prime_size  value:p.second--- prime_num
        // primes_map[p.first] = get_primes(factor,p.first,p.second);
        primes_map[p.first] = get_primes_raise_no_check(factor, safe_cast<int>(p.first), p.second);
    }

    p_.clear();
    q_.clear();
    for (auto bit_len : log_q)
    {
        q_.push_back(primes_map[bit_len][0]);
        primes_map[bit_len].erase(primes_map[bit_len].begin());
    }
    for (auto bit_len : log_p)
    {
        p_.push_back(primes_map[bit_len][0]);
        primes_map[bit_len].erase(primes_map[bit_len].begin());
    }
    compute_params_id();
}

void ParametersLiteral::compute_params_id()
{
    auto q_size = q_.size();
    auto p_size = p_.size();
    auto total_uint64_count = add_safe(size_t(1), size_t(1), size_t(1), q_size, p_size, size_t(1),
                                       size_t(1), size_t(1), size_t(1));

    auto parms_data = allocate_uint(total_uint64_count, pool_);
    uint64_t *plain_data_ptr = parms_data.get();

    *plain_data_ptr++ = static_cast<uint64_t>(type_);
    *plain_data_ptr++ = static_cast<uint64_t>(log_n_);
    *plain_data_ptr++ = static_cast<uint64_t>(log_slots_);
    for (const auto &mod : q_)
    {
        *plain_data_ptr++ = mod.value();
    }
    for (const auto &mod : p_)
    {
        *plain_data_ptr++ = mod.value();
    }

    *plain_data_ptr++ = static_cast<uint64_t>(log_scale_);
    *plain_data_ptr++ = static_cast<uint64_t>(hamming_weight_);
    *plain_data_ptr++ = static_cast<uint64_t>(plain_modulus_.value());
    *plain_data_ptr++ = static_cast<uint64_t>(q0_level_);
    HashFunction::hash(parms_data.get(), total_uint64_count, params_id_);
}

const std::map<std::size_t, std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>> &
GetDefaultCoeffModulus128()
{
    static const std::map<std::size_t,
                          std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>>
        default_coeff_modulus_128{
            /*
            Polynomial modulus: 1x^4096 + 1
            Modulus count: 3
            Total bit count: 109 = 2 * 36 + 37
            */
            {4096, {{0xffffee001, 0xffffc4001}, {0x1ffffe0001}, 25}},

            /*
            Polynomial modulus: 1x^8192 + 1
            Modulus count: 5
            Total bit count: 218 = 2 * 43 + 3 * 44
            */
            {8192,
             {{0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001, 0xffffff6c001}, {0xfffffebc001}, 32}},

            /*
            Polynomial modulus: 1x^16384 + 1
            Modulus count: 9
            Total bit count: 438 = 3 * 48 + 6 * 49
            */
            {16384,
             {{0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001, 0x1fffffff68001, 0x1fffffff50001,
               0x1ffffffee8001, 0x1ffffffea0001, 0x1ffffffe88001},
              {0x1ffffffe48001},
              32}},

            /*
            Polynomial modulus: 1x^32768 + 1
            Modulus count: 16
            Total bit count: 881 = 15 * 55 + 56
            */
            {32768,
             {{0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001,
               0x7fffffffaa0001, 0x7fffffffa50001, 0x7fffffff9f0001, 0x7fffffff7e0001,
               0x7fffffff770001, 0x7fffffff380001, 0x7fffffff330001, 0x7fffffff2d0001,
               0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001},
              {0xfffffffff70001},
              40}},

            /*
            Polynomial modulus: 1x^65536 + 1
            Modulus count: 32
            Total bit count: 1857 = 31 * 58 + 59
            */
            {65536,
            {{ 0x3fffffffa320001, 0x3fffffffa800001, 0x3fffffffaa20001, 0x3fffffffaa40001, 0x3fffffffad20001,
               0x3fffffffaf20001, 0x3fffffffb4a0001, 0x3fffffffbb20001, 0x3fffffffbbc0001, 0x3fffffffc600001,
               0x3fffffffc8a0001, 0x3fffffffcb20001, 0x3fffffffcc00001, 0x3fffffffcca0001, 0x3fffffffce80001,
               0x3fffffffd3c0001, 0x3fffffffd900001, 0x3fffffffdc80001, 0x3fffffffdd80001, 0x3fffffffdfe0001,
               0x3fffffffe2c0001, 0x3fffffffe320001, 0x3fffffffe440001, 0x3fffffffe800001, 0x3fffffffea00001,
               0x3fffffffeb00001, 0x3fffffffed00001, 0x3fffffffed60001, 0x3ffffffff040001, 0x3ffffffff3a0001,
               0x3ffffffffbe0001},
              {0x7ffffffffcc0001},
              40}}};

    return default_coeff_modulus_128;
}

const std::map<std::size_t, std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>> &
GetDefaultCoeffModulus192()
{
    static const std::map<std::size_t,
                          std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>>
        default_coeff_modulus_192{
            /*
            Polynomial modulus: 1x^4096 + 1
            Modulus count: 3
            Total bit count: 75 = 3 * 25
            */
            {4096, {{0x1fce001, 0x1fc0001}, {0x1ffc001}, 25}},

            /*
            Polynomial modulus: 1x^8192 + 1
            Modulus count: 4
            Total bit count: 152 = 4 * 38
            */
            {8192, {{0x3ffff54001, 0x3ffff48001, 0x3ffff28001}, {0x3ffffac001}, 32}},

            /*
            Polynomial modulus: 1x^16384 + 1
            Modulus count: 6
            Total bit count: 300 = 6 * 50
            */
            {16384,
             {{0x3ffffffd48001, 0x3ffffffd20001, 0x3ffffffd18001, 0x3ffffffcd0001, 0x3ffffffc70001},
              {0x3ffffffdf0001},
              32}},

            /*
            Polynomial modulus: 1x^32768 + 1
            Modulus count: 11
            Total bit count: 600 = 5 * 54 + 6 * 55
            */
            {32768,
             {{0x3fffffffd60001, 0x3fffffffca0001, 0x3fffffff6d0001, 0x3fffffff5d0001,
               0x3fffffff550001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001,
               0x7fffffffaa0001, 0x7fffffffa50001},
              {0x7fffffffe90001},
              32}}};

    return default_coeff_modulus_192;
}

const std::map<std::size_t, std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>> &
GetDefaultCoeffModulus256()
{
    static const std::map<std::size_t,
                          std::tuple<std::vector<Modulus>, std::vector<Modulus>, std::uint64_t>>
        default_coeff_modulus_256{
            /*
            Polynomial modulus: 1x^4096 + 1
            Modulus count: 1
            Total bit count: 58
            */
            {4096, {{0x3ffffffff040001}, {}, 32}},

            /*
            Polynomial modulus: 1x^8192 + 1
            Modulus count: 3
            Total bit count: 118 = 2 * 39 + 40
            */
            {8192, {{0x7ffffec001, 0x7ffffb0001}, {0xfffffdc001}, 32}},

            /*
            Polynomial modulus: 1x^16384 + 1
            Modulus count: 5
            Total bit count: 237 = 3 * 47 + 2 * 48
            */
            {16384,
             {{0x7ffffffc8001, 0x7ffffff00001, 0x7fffffe70001, 0xfffffffa0001},
              {0xfffffffd8001},
              32}},

            /*
            Polynomial modulus: 1x^32768 + 1
            Modulus count: 9
            Total bit count: 476 = 52 + 8 * 53
            */
            {32768,
             {{0xffffffff00001, 0x1fffffffe30001, 0x1fffffffd10001, 0x1fffffffc50001,
               0x1fffffffbf0001, 0x1fffffffb90001, 0x1fffffffb60001, 0x1fffffffa50001},
              {0x1fffffffd80001},
              40}}};

    return default_coeff_modulus_256;
}

const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>> &
GetDefaultLogCoeffModulus128()
{
    static const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>>
        default_log_coeff_modulus_128{
            /*
            Polynomial modulus: 1x^4096 + 1
            Modulus count: 3
            Total bit count: 109 = 2 * 36 + 37
            */
            {4096, {{36, 36}, {37}, 32}},

            /*
            Polynomial modulus: 1x^8192 + 1
            Modulus count: 5
            Total bit count: 218 = 2 * 43 + 3 * 44
            */
            {8192, {{43, 43, 43, 43}, {44}, 32}},

            /*
            Polynomial modulus: 1x^16384 + 1
            Modulus count: 9
            Total bit count: 438 = 3 * 48 + 6 * 49
            */
            {16384, {{48, 48, 48, 48, 48, 48, 48, 48}, {50}, 40}},

            /*
            Polynomial modulus: 1x^32768 + 1
            Modulus count: 16
            Total bit count: 881 = 15 * 55 + 56
            */
            {32768, {{55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55}, {56}, 40}},

            /*
            Polynomial modulus: 1x^65536 + 1
            Modulus count: 32
            Total bit count: 1857 = 31 * 58 + 59
            */
            {65536, {{58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
                  58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58}, {59}, 40}}};

    return default_log_coeff_modulus_128;
}

const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>> &
GetDefaultLogCoeffModulus192()
{
    static const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>>
        default_log_coeff_modulus_192{
            /*
            Polynomial modulus: 1x^1024 + 1
            Modulus count: 1
            Total bit count: 19
            */
            {1024, {{19}, {}, 25}},

            /*
            Polynomial modulus: 1x^2048 + 1
            Modulus count: 1
            Total bit count: 37
            */
            {2048, {{37}, {}, 25}},

            /*
            Polynomial modulus: 1x^4096 + 1
            Modulus count: 3
            Total bit count: 75 = 3 * 25
            */
            {4096, {{25, 25}, {25}, 25}},

            /*
            Polynomial modulus: 1x^8192 + 1
            Modulus count: 4
            Total bit count: 152 = 4 * 38
            */
            {8192, {{38, 38, 38}, {38}, 32}},

            /*
            Polynomial modulus: 1x^16384 + 1
            Modulus count: 6
            Total bit count: 300 = 6 * 50
            */
            {16384, {{50, 50, 50, 50, 50}, {50}, 32}},

            /*
            Polynomial modulus: 1x^32768 + 1
            Modulus count: 11
            Total bit count: 600 = 5 * 54 + 6 * 55
            */
            {32768, {{54, 54, 54, 54, 54, 55, 55, 55, 55, 55}, {55}, 40}}};

    return default_log_coeff_modulus_192;
}

const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>> &
GetDefaultLogCoeffModulus256()
{
    static const map<size_t, tuple<vector<uint32_t>, vector<uint32_t>, uint32_t>>
        default_log_coeff_modulus_256{/*
                                      Polynomial modulus: 1x^1024 + 1
                                      Modulus count: 1
                                      Total bit count: 14
                                      */
                                      {1024, {{14}, {}, 13}},

                                      /*
                                      Polynomial modulus: 1x^2048 + 1
                                      Modulus count: 1
                                      Total bit count: 29
                                      */
                                      {2048, {{29}, {}, 7}},

                                      /*
                                     Polynomial modulus: 1x^4096 + 1
                                     Modulus count: 1
                                     Total bit count: 58
                                     */
                                      {4096, {{58}, {}, 25}},

                                      /*
                                      Polynomial modulus: 1x^8192 + 1
                                      Modulus count: 3
                                      Total bit count: 118 = 2 * 39 + 40
                                      */
                                      {8192, {{39, 39}, {40}, 30}},

                                      /*
                                       Polynomial modulus: 1x^16384 + 1
                                       Modulus count: 5
                                       Total bit count: 237 = 3 * 47 + 2 * 48
                                       */
                                      {16384, {{47, 47, 47, 48}, {48}, 35}},

                                      /*
                                      Polynomial modulus: 1x^32768 + 1
                                      Modulus count: 9
                                      Total bit count: 476 = 52 + 8 * 53
                                      */
                                      {32768, {{52, 53, 53, 53, 53, 53, 53, 53}, {53}, 40}}};

    return default_log_coeff_modulus_256;
}

ParametersLiteralDefault::ParametersLiteralDefault(SchemeType scheme_type, uint32_t degree,
                                                   sec_level_type sec_level, MemoryPoolHandle pool)
    : ParametersLiteral(sec_level)
{
    pool_ = std::move(pool);
    init(scheme_type, degree, sec_level);
};

void ParametersLiteralDefault::init(SchemeType scheme_type, uint32_t degree,
                                    sec_level_type sec_level)
{
    type_ = scheme_type;
    q0_level_ = 0;
    log_n_ = static_cast<uint32_t>(log2(static_cast<double>(degree)));
    hamming_weight_ = 5;
    if (scheme_type == CKKS)
    {
        log_slots_ = log_n_ - 1;
        plain_modulus_ = 0;

        switch (sec_level_)
        {
        case sec_level_type::none:
            log_scale_ = std::get<2>(GetDefaultLogCoeffModulus128().at(degree));
            set_log_modulus(std::get<0>(GetDefaultLogCoeffModulus128().at(degree)),
                            std::get<1>(GetDefaultLogCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc128:
            log_scale_ = std::get<2>(GetDefaultLogCoeffModulus128().at(degree));
            set_log_modulus(std::get<0>(GetDefaultLogCoeffModulus128().at(degree)),
                            std::get<1>(GetDefaultLogCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc192:
            log_scale_ = std::get<2>(GetDefaultLogCoeffModulus192().at(degree));
            set_log_modulus(std::get<0>(GetDefaultLogCoeffModulus192().at(degree)),
                            std::get<1>(GetDefaultLogCoeffModulus192().at(degree)));
            break;
        case sec_level_type::tc256:
            log_scale_ = std::get<2>(GetDefaultLogCoeffModulus256().at(degree));
            set_log_modulus(std::get<0>(GetDefaultLogCoeffModulus256().at(degree)),
                            std::get<1>(GetDefaultLogCoeffModulus256().at(degree)));
            break;
        default:
            log_scale_ = std::get<2>(GetDefaultLogCoeffModulus128().at(degree));
            set_log_modulus(std::get<0>(GetDefaultLogCoeffModulus128().at(degree)),
                            std::get<1>(GetDefaultLogCoeffModulus128().at(degree)));
        }
    }
    else if (scheme_type == BFV)
    {
        log_slots_ = log_n_;
        if (degree < 65536)
        {
            plain_modulus_ = 65537;
        }
        else
        {
            plain_modulus_ = PlainModulus::Batching(degree, 20);
        }

        switch (sec_level_)
        {
        case sec_level_type::none:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc128:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc192:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus192().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus192().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus192().at(degree)));
            break;
        case sec_level_type::tc256:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus256().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus256().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus256().at(degree)));
            break;
        default:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
        }
    }
    else if (scheme_type == BGV)
    {
        log_slots_ = log_n_;

        if (degree < 65536)
        {
            plain_modulus_ = 65537;
        }
        else
        {
            plain_modulus_ = PlainModulus::Batching(degree, 20);
        }

        switch (sec_level_)
        {
        case sec_level_type::none:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc128:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
            break;
        case sec_level_type::tc192:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus192().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus192().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus192().at(degree)));
            break;
        case sec_level_type::tc256:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus256().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus256().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus256().at(degree)));
            break;
        default:
            log_scale_ = std::get<2>(GetDefaultCoeffModulus128().at(degree));
            set_modulus(std::get<0>(GetDefaultCoeffModulus128().at(degree)),
                        std::get<1>(GetDefaultCoeffModulus128().at(degree)));
        }
    }
}
}  // namespace poseidon
