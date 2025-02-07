#pragma once

#include "src/crt_context.h"

namespace poseidon
{
class ContextDataHardware
{
    friend class HardwareContext;

public:
    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv0_up_param() const
    {
        return conv0_up_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv0_down_param() const
    {
        return conv0_down_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv1_up_param() const
    {
        return conv1_up_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv1_down_param() const
    {
        return conv1_down_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv2_param() const
    {
        return conv2_down_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &rescale_param() const
    {
        return rescale_param_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &coeff_div_plain_modulus() const
    {
        return coeff_div_plain_modulus_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &neg_prod_b_mod_q_elt() const
    {
        return neg_prod_b_mod_q_elt_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &
    neg_inv_prod_q_mod_m_tilde() const
    {
        return neg_inv_prod_q_mod_m_tilde_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &prod_q_mod_bsk() const
    {
        return prod_q_mod_bsk_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &inv_prod_q_mod_bsk() const
    {
        return inv_prod_q_mod_bsk_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param0_0th() const
    {
        return conv_param0_0th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param1_0th() const
    {
        return conv_param1_0th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param0_1th() const
    {
        return conv_param0_1th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param1_1th() const
    {
        return conv_param1_1th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param0_2th() const
    {
        return conv_param0_2th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param1_2th() const
    {
        return conv_param1_2th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param0_3th() const
    {
        return conv_param0_3th_;
    };

    POSEIDON_NODISCARD inline const std::vector<vector<uint32_t>> &conv_param1_3th() const
    {
        return conv_param1_3th_;
    };

    POSEIDON_NODISCARD inline const parms_id_type &parms_id() const { return parms_id_; };

private:
    ContextDataHardware(shared_ptr<const CrtContext::ContextData> context_data,
                        size_t coeff_modulus_size_max);
    void cal_raise_conv(shared_ptr<const CrtContext::ContextData> context_data,
                        size_t coeff_modulus_size_max);
    void cal_down_conv(shared_ptr<const CrtContext::ContextData> context_data,
                       size_t coeff_modulus_size_max);
    void cal_rescale_conv(shared_ptr<const CrtContext::ContextData> context_data,
                          size_t coeff_modulus_size_max);
    void cal_coeff_div_plain_modulus(shared_ptr<const CrtContext::ContextData> context_data);
    void cal_bfv_multiply_params(const shared_ptr<const CrtContext::ContextData> &context_data,
                                 const vector<uint32_t> &primes, uint32_t rns_q_full_num);
    void conv_param_compute(uint32_t rns_c, uint32_t rns_b, const std::vector<uint32_t> &rns_c_mod,
                            const std::vector<uint32_t> &rns_b_mod,
                            std::vector<std::vector<uint32_t>> &rns_mod_inv,
                            std::vector<std::vector<uint32_t>> &rns_conv_array) const;
    void config_conv_param(const shared_ptr<const CrtContext::ContextData> &context_data,
                           const vector<uint32_t> &primes, uint32_t rns_q_full_num);

    std::shared_ptr<const ContextDataHardware> next_context_data_{nullptr};
    parms_id_type parms_id_ = parms_id_zero;
    // ckks
    size_t poly_modulus_degree_ = 0;
    vector<uint32_t> conv_up_inv_mod_qi_{};
    vector<vector<uint32_t>> conv_up_mod_pi_{};
    vector<uint32_t> conv_down_inv_mod_qi_{};
    vector<vector<uint32_t>> conv_down_mod_pi_{};
    vector<uint32_t> conv_down_p_inv_mod_qi_{};
    vector<uint32_t> rescale_p_inv_mod_qi_{};

    vector<vector<uint32_t>> conv0_up_param_{};
    vector<vector<uint32_t>> conv0_down_param_{};
    vector<vector<uint32_t>> conv1_up_param_{};
    vector<vector<uint32_t>> conv1_down_param_{};
    vector<vector<uint32_t>> conv2_down_param_{};
    vector<vector<uint32_t>> rescale_param_{};

    // bfv
    vector<vector<uint32_t>> coeff_div_plain_modulus_{};
    // bfv multiply
    vector<vector<uint32_t>> neg_prod_b_mod_q_elt_{};
    vector<vector<uint32_t>> neg_inv_prod_q_mod_m_tilde_{};
    vector<vector<uint32_t>> prod_q_mod_bsk_{};
    vector<vector<uint32_t>> inv_prod_q_mod_bsk_{};

    vector<vector<uint32_t>> conv_param0_0th_{};
    vector<vector<uint32_t>> conv_param1_0th_{};
    vector<vector<uint32_t>> conv_param0_1th_{};
    vector<vector<uint32_t>> conv_param1_1th_{};
    vector<vector<uint32_t>> conv_param0_2th_{};
    vector<vector<uint32_t>> conv_param1_2th_{};
    vector<vector<uint32_t>> conv_param0_3th_{};
    vector<vector<uint32_t>> conv_param1_3th_{};
};
}  // namespace poseidon
