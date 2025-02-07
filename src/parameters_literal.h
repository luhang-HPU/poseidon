#pragma once

#include "basics/memorymanager.h"
#include "basics/modulus.h"
#include "basics/util/hash.h"
#include "util/defines.h"
#include "util/pke_params_defines.h"
#include <iostream>
#include <vector>

using namespace std;

namespace poseidon
{

using parms_id_type = util::HashFunction::hash_block_type;
const parms_id_type parms_id_zero = util::HashFunction::hash_zero_block;

class ParametersLiteral
{
public:
    inline ParametersLiteral(sec_level_type sec_level = poseidon::sec_level_type::tc128)
        : sec_level_(sec_level)
    {
    }

    ParametersLiteral(SchemeType scheme_type, uint32_t log_n, uint32_t log_slots,
                      uint32_t log_scale, uint32_t hamming_weight, uint32_t q0_level,
                      Modulus plain_modulus, const vector<Modulus> &q, const vector<Modulus> &p,
                      sec_level_type sec_level = poseidon::sec_level_type::none,
                      MemoryPoolHandle pool = MemoryManager::GetPool());

    void set_poly_modulus_degree(std::size_t poly_modulus_degree);
    inline void set_plain_modulus(std::uint64_t plain_modulus)
    {
        set_plain_modulus(Modulus(plain_modulus));
    }
    void set_plain_modulus(const Modulus &plain_modulus);
    void set_log_modulus(const vector<uint32_t> &log_q, const vector<uint32_t> &log_p);
    void set_sec_level(sec_level_type &sec_level) { this->sec_level_ = sec_level; }

    inline void set_modulus(const vector<Modulus> &mod_chain_q, const vector<Modulus> &mod_chain_p)
    {
        this->q_ = mod_chain_q;
        this->p_ = mod_chain_p;
        compute_params_id();
    }

    void compute_params_id();
    POSEIDON_NODISCARD inline uint32_t degree() const { return 1 << log_n_; }

    POSEIDON_NODISCARD inline uint32_t slot() const { return 1 << log_slots_; }

    POSEIDON_NODISCARD inline const parms_id_type &parms_id() const { return params_id_; }

    POSEIDON_NODISCARD inline const SchemeType &scheme() const { return type_; }

    POSEIDON_NODISCARD inline uint32_t log_n() const { return log_n_; }

    POSEIDON_NODISCARD inline uint32_t log_slots() const { return log_slots_; }

    POSEIDON_NODISCARD inline uint32_t hamming_weight() const { return hamming_weight_; }

    POSEIDON_NODISCARD inline uint32_t q0_level() const { return q0_level_; }

    POSEIDON_NODISCARD inline const Modulus &plain_modulus() const { return plain_modulus_; }

    POSEIDON_NODISCARD inline const vector<Modulus> &q() const { return q_; }

    POSEIDON_NODISCARD inline const vector<Modulus> &p() const { return p_; }

    POSEIDON_NODISCARD inline uint32_t log_scale() const { return log_scale_; }

    POSEIDON_NODISCARD inline double scale() const { return pow(2.0, log_scale_); }

    POSEIDON_NODISCARD inline poseidon::sec_level_type sec_level() const { return sec_level_; }

protected:
    SchemeType type_;
    uint32_t log_n_ = 0;
    uint32_t log_slots_ = 0;
    uint32_t log_scale_ = 0;
    uint32_t hamming_weight_ = 0;
    uint32_t q0_level_ = 0;  // merge primes as q0
    Modulus plain_modulus_ = 0;
    vector<Modulus> q_{};
    vector<Modulus> p_{};
    MemoryPoolHandle pool_;
    parms_id_type params_id_ = parms_id_zero;
    poseidon::sec_level_type sec_level_;
};

class ParametersLiteralDefault : public ParametersLiteral
{
private:
    void init(SchemeType scheme_type, uint32_t degree, sec_level_type sec_level);

public:
    ParametersLiteralDefault(SchemeType scheme_type, uint32_t degree,
                             sec_level_type sec_level = poseidon::sec_level_type::tc128,
                             MemoryPoolHandle pool = MemoryManager::GetPool());
};

}  // namespace poseidon

namespace std
{
template <> struct hash<poseidon::parms_id_type>
{
    std::size_t operator()(const poseidon::parms_id_type &params_id) const
    {
        std::uint64_t result = 17;
        result = 31 * result + params_id[0];
        result = 31 * result + params_id[1];
        result = 31 * result + params_id[2];
        result = 31 * result + params_id[3];
        return static_cast<std::size_t>(result);
    }
};

};  // namespace std
