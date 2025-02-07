#pragma once

#include "basics/memorymanager.h"
#include "basics/modulus.h"
#include "basics/util/galois.h"
#include "basics/util/ntt.h"
#include "basics/util/rns.h"
#include "parameters_literal.h"
#include "util/rns_tool_qp.h"
#include <utility>
#include <vector>

namespace poseidon
{
using namespace util;

class CrtContext
{

public:
    class ContextData
    {
        friend class CrtContext;

    public:
        POSEIDON_NODISCARD inline const ParametersLiteral &parms() const noexcept { return parms_; }

        POSEIDON_NODISCARD inline double modulus_data() const { return modulus_data_; }

        POSEIDON_NODISCARD inline const std::uint64_t *total_coeff_modulus() const noexcept
        {
            return total_coeff_modulus_.get();
        }

        POSEIDON_NODISCARD inline const vector<Modulus> &coeff_modulus() const noexcept
        {
            return modulus_;
        }

        POSEIDON_NODISCARD inline const uint32_t &total_coeff_modulus_bit_count() const
        {
            return total_coeff_modulus_bit_count_;
        }

        POSEIDON_NODISCARD inline const std::uint64_t *upper_half_threshold() const noexcept
        {
            return upper_half_threshold_.get();
        }

        POSEIDON_NODISCARD inline const util::RNSTool *rns_tool() const noexcept
        {
            return rns_tool_.get();
        }

        POSEIDON_NODISCARD inline const util::RNSToolQP *qp_rns_tool() const noexcept
        {
            return rns_tool_qp_tool_.get();
        }

        POSEIDON_NODISCARD inline std::shared_ptr<const ContextData>
        next_context_data() const noexcept
        {
            return next_context_data_;
        }

        POSEIDON_NODISCARD inline size_t level() const noexcept { return parms_.q().size() - 1; }

        /**
           Return a pointer to BFV "Delta", i.e. coefficient modulus divided by
           plaintext modulus.
       */
        POSEIDON_NODISCARD inline const util::MultiplyUIntModOperand *
        coeff_div_plain_modulus() const noexcept
        {
            return coeff_div_plain_modulus_.get();
        }

        /**
        Return the threshold for the upper half of integers modulo plain_modulus.
        This is simply (plain_modulus + 1) / 2.
        */
        POSEIDON_NODISCARD inline std::uint64_t plain_upper_half_threshold() const noexcept
        {
            return plain_upper_half_threshold_;
        }

        /**
        Return a pointer to the plaintext upper half increment, i.e. coeff_modulus
        minus plain_modulus. The upper half increment is represented as an integer
        for the full product coeff_modulus if using_fast_plain_lift is false and is
        otherwise represented modulo each of the coeff_modulus primes in order.
        */
        POSEIDON_NODISCARD inline const std::uint64_t *plain_upper_half_increment() const noexcept
        {
            return plain_upper_half_increment_.get();
        }

        /**
        Return the non-RNS form of upper_half_increment which is q mod t.
        */
        POSEIDON_NODISCARD inline std::uint64_t coeff_modulus_mod_plain_modulus() const noexcept
        {
            return coeff_modulus_mod_plain_modulus_;
        }

        POSEIDON_NODISCARD inline bool using_fast_plain_lift() const noexcept
        {
            return using_fast_plain_lift_;
        }

    private:
        ContextData(ParametersLiteral parms, MemoryPoolHandle pool)
            : pool_(std::move(pool)), parms_(std::move(parms))
        {
            if (!pool_)
            {
                throw std::invalid_argument("pool is uninitialized");
            }
        }
        MemoryPoolHandle pool_;
        ParametersLiteral parms_;
        double modulus_data_ = 0;
        std::shared_ptr<const ContextData> next_context_data_{nullptr};
        util::Pointer<util::RNSTool> rns_tool_;
        util::Pointer<util::RNSToolQP> rns_tool_qp_tool_;
        uint32_t total_coeff_modulus_bit_count_ = 0;
        util::Pointer<std::uint64_t> total_coeff_modulus_;
        vector<Modulus> modulus_{};
        bool using_fast_plain_lift_;
        std::uint64_t plain_upper_half_threshold_ = 0;
        std::uint64_t coeff_modulus_mod_plain_modulus_ = 0;
        util::Pointer<std::uint64_t> upper_half_threshold_;
        util::Pointer<std::uint64_t> upper_half_increment_;
        util::Pointer<std::uint64_t> plain_upper_half_increment_;
        util::Pointer<util::MultiplyUIntModOperand> coeff_div_plain_modulus_;
    };

public:
    explicit CrtContext(const std::shared_ptr<const ParametersLiteral> &params,
                        sec_level_type sec_level, MemoryPoolHandle pool = MemoryManager::GetPool());
    POSEIDON_NODISCARD inline const util::NTTTables *small_ntt_tables() const noexcept
    {
        return small_ntt_tables_.get();
    }

    POSEIDON_NODISCARD inline const util::NTTTables *plain_ntt_tables() const noexcept
    {
        return plain_ntt_tables_.get();
    }

    POSEIDON_NODISCARD inline std::shared_ptr<const ContextData>
    get_context_data(parms_id_type parms_id) const
    {
        auto data = context_data_map_.find(parms_id);
        return (data != context_data_map_.end()) ? data->second
                                                 : std::shared_ptr<ContextData>{nullptr};
    }

    POSEIDON_NODISCARD inline std::shared_ptr<const ContextData> key_context_data() const
    {
        auto data = context_data_map_.find(key_parms_id_);
        return (data != context_data_map_.end()) ? data->second
                                                 : std::shared_ptr<ContextData>{nullptr};
    }

    POSEIDON_NODISCARD inline std::shared_ptr<const ContextData> first_context_data() const
    {
        auto data = context_data_map_.find(first_parms_id_);
        return (data != context_data_map_.end()) ? data->second
                                                 : std::shared_ptr<ContextData>{nullptr};
    }

    POSEIDON_NODISCARD inline std::shared_ptr<const ContextData> last_context_data() const
    {
        auto data = context_data_map_.find(last_parms_id_);
        return (data != context_data_map_.end()) ? data->second
                                                 : std::shared_ptr<ContextData>{nullptr};
    }

    POSEIDON_NODISCARD inline const std::unordered_map<parms_id_type,
                                                       std::shared_ptr<const ContextData>>
    context_data_map() const
    {
        return context_data_map_;
    };

    POSEIDON_NODISCARD inline const std::unordered_map<uint32_t, parms_id_type> parms_id_map() const
    {
        return parms_id_map_;
    };

    POSEIDON_NODISCARD inline const parms_id_type &first_parms_id() const noexcept
    {
        return first_parms_id_;
    }

    POSEIDON_NODISCARD inline const parms_id_type &last_parms_id() const noexcept
    {
        return last_parms_id_;
    }

    POSEIDON_NODISCARD inline const parms_id_type &key_parms_id() const noexcept
    {
        return key_parms_id_;
    }

    POSEIDON_NODISCARD inline const util::GaloisTool *galois_tool() const
    {
        return galois_tool_.get();
    }

    POSEIDON_NODISCARD inline double q0() const { return q0_; }

    POSEIDON_NODISCARD inline bool using_keyswitch() const { return using_keyswitch_; }

private:
    CrtContext::ContextData validate(const ParametersLiteral &params,
                                     const vector<Modulus> &modulus_p);
    CrtContext::ContextData validate(const ParametersLiteral &params);
    parms_id_type create_next_context_data(const parms_id_type &id);

    parms_id_type first_parms_id_ = parms_id_zero;
    parms_id_type last_parms_id_ = parms_id_zero;
    parms_id_type key_parms_id_ = parms_id_zero;

    double q0_ = 0;
    uint32_t p_offset_ = 0;
    bool using_keyswitch_ = true;
    Pointer<util::NTTTables> small_ntt_tables_;
    Pointer<util::NTTTables> plain_ntt_tables_;
    MemoryPoolHandle pool_;
    std::unordered_map<parms_id_type, std::shared_ptr<const ContextData>> context_data_map_{};
    std::unordered_map<uint32_t, parms_id_type> parms_id_map_{};
    util::Pointer<util::GaloisTool> galois_tool_;
    sec_level_type sec_level_;
};
}  // namespace poseidon
