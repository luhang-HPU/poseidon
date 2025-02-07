#pragma once

#include "context_data_hardware.h"
#include "src/crt_context.h"

namespace poseidon
{
class HardwareContext
{

public:
    explicit HardwareContext(const shared_ptr<CrtContext> &context);

    POSEIDON_NODISCARD inline const uint64_t *barrett_c() const { return barrett_c_; };
    POSEIDON_NODISCARD inline const uint64_t *barrett_k() const { return barrett_k_; };
    POSEIDON_NODISCARD inline const uint64_t *mods() const { return mods_; };
    POSEIDON_NODISCARD inline const uint64_t *qk_inv() const { return qk_inv_; };
    POSEIDON_NODISCARD inline const uint64_t *inv_dm() const { return inv_dm_; };
    POSEIDON_NODISCARD inline const uint64_t *rou() const { return rou_; };
    POSEIDON_NODISCARD inline const uint64_t *inv_rou() const { return inv_rou_; };
    POSEIDON_NODISCARD inline const std::vector<uint32_t> &primes() const { return primes_; };
    POSEIDON_NODISCARD inline const std::vector<uint64_t> &barrett_reduction_c() const
    {
        return barrett_reduction_c_;
    };

    POSEIDON_NODISCARD inline const std::vector<uint64_t> &barrett_reduction_cc() const
    {
        return barrett_reduction_cc_;
    };

    POSEIDON_NODISCARD inline const std::vector<std::vector<uint32_t>> &rou_src_total() const
    {
        return rou_src_total_;
    };

    POSEIDON_NODISCARD inline const std::vector<std::vector<uint32_t>> &rou_inv_src_total() const
    {
        return rou_inv_src_total_;
    };

    POSEIDON_NODISCARD inline const std::vector<uint32_t> &rou_params() const
    {
        return rou_params_;
    };

    POSEIDON_NODISCARD inline const std::vector<uint32_t> &rou_inv_params() const
    {
        return rou_inv_params_;
    };

    POSEIDON_NODISCARD inline const std::vector<uint32_t> &primes_degree_inv() const
    {
        return primes_degree_inv_;
    };

    POSEIDON_NODISCARD inline const std::vector<uint32_t> &primes_degree_inv_mult_t() const
    {
        return primes_degree_inv_mult_t_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &primes_degree_inv_parms() const
    {
        return primes_degree_inv_parms_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &
    primes_degree_inv_mult_t_parms() const
    {
        return primes_degree_inv_mult_t_parms_;
    };

    POSEIDON_NODISCARD inline size_t coeff_modulus_size_max() const
    {
        return coeff_modulus_size_max_;
    };

    POSEIDON_NODISCARD inline std::shared_ptr<const ContextDataHardware>
    get_context_data(parms_id_type parms_id) const
    {
        auto data = context_data_map_.find(parms_id);
        return (data != context_data_map_.end()) ? data->second
                                                 : std::shared_ptr<ContextDataHardware>{nullptr};
    }

private:
    ContextDataHardware validate(shared_ptr<const CrtContext::ContextData> context,
                                 size_t coeff_modulus_size_max);
    void generate_ckks_global_params();
    void generate_ckks_contextdata();

    void generate_bfv_global_params();
    void generate_bfv_contextdata();

    void generate_bgv_global_params();
    void generate_bgv_contextdata();

    MemoryPoolHandle pool_ = MemoryManager::GetPool();
    shared_ptr<CrtContext> crt_context_{};
    SchemeType scheme_type_;
    std::vector<uint32_t> primes_{};
    size_t coeff_modulus_size_max_ = 0;
    size_t poly_modulus_degree_ = 0;

    // 取模
    std::vector<uint64_t> barrett_reduction_c_{};
    std::vector<uint64_t> barrett_reduction_cc_{};
    //模数链的所有模数
    uint64_t *mods_;
    uint64_t *barrett_c_{};
    uint64_t *barrett_k_{};
    uint64_t *qk_inv_{};
    // inv_degree_modulus
    uint64_t *inv_dm_{};
    uint64_t *rou_{};
    uint64_t *inv_rou_{};
    // ntt
    std::vector<vector<uint32_t>> rou_src_total_{};
    std::vector<vector<uint32_t>> rou_inv_src_total_{};
    std::vector<uint32_t> rou_params_{};
    std::vector<uint32_t> rou_inv_params_{};

    std::vector<uint32_t> primes_degree_inv_{};
    // bfv * need
    std::vector<uint32_t> primes_degree_inv_mult_t_{};

    // hardware need translate
    std::vector<vector<uint32_t>> primes_degree_inv_parms_{};
    std::vector<vector<uint32_t>> primes_degree_inv_mult_t_parms_{};

    std::unordered_map<parms_id_type, std::shared_ptr<const ContextDataHardware>>
        context_data_map_{};
};

}  // namespace poseidon
