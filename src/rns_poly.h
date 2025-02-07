#pragma once

#include "basics/util/polyarithsmallmod.h"
#include "basics/util/polycore.h"
#include "poseidon_context.h"

namespace poseidon
{
enum PolyType
{
    ternary,            // 0 -1 1 for keys
    gaussian,           // [0, q] for a
    centered_binomial,  // for noise
    nothing,
    zero

};
class RNSPoly
{
    friend void compute_ckks_hardware_id(const RNSPoly &poly);

public:
    RNSPoly() = default;
    RNSPoly(const shared_ptr<CrtContext> &context_data, std::uint64_t *data,
            parms_id_type parms_id);
    RNSPoly(const PoseidonContext &context, std::uint64_t *data, parms_id_type parms_id,
            PolyType = nothing, const shared_ptr<UniformRandomGenerator> &prng = nullptr);
    RNSPoly(const PoseidonContext &context, parms_id_type parms_id, PolyType = nothing,
            const shared_ptr<UniformRandomGenerator> &prng = nullptr);
    RNSPoly(const PoseidonContext &context, parms_id_type parms_id, bool enable_rns_p);
    RNSPoly(const RNSPoly &copy) = default;
    RNSPoly(RNSPoly &&source) = default;
    RNSPoly &operator=(const RNSPoly &assign) = default;
    RNSPoly &operator=(RNSPoly &&assign) = default;

    void set_random(const PoseidonContext &context, PolyType random_type,
                    const shared_ptr<UniformRandomGenerator> &prng = nullptr) const;
    void resize(const PoseidonContext &context, parms_id_type parms_id, bool enable_rns_p = false);

    POSEIDON_NODISCARD inline size_t rns_num_q() const { return rns_num_q_; }

    POSEIDON_NODISCARD inline auto const &get() const { return buffer_; }

    POSEIDON_NODISCARD inline size_t rns_num_p() const { return rns_num_p_; }

    POSEIDON_NODISCARD inline size_t rns_num_total() const { return rns_num_total_; }

    POSEIDON_NODISCARD inline size_t poly_degree() const { return poly_degree_; }

    POSEIDON_NODISCARD inline size_t rns_p_offset() const { return rns_p_offset_; }

    inline void set_parms_id(parms_id_type parms_id) { parms_id_ = parms_id; }

    inline const parms_id_type &parms_id() const { return parms_id_; }

    inline ConstPolyIter const_poly_iter() const { return const_poly_iter_; }

    inline PolyIter poly_iter() { return poly_iter_; }

    inline void set_hardware_id(uint32_t id) { this->hardware_id_ = id; }

    inline const uint32_t &hardware_id() { return this->hardware_id_; }

    inline const uint32_t hardware_id() const { return this->hardware_id_; }

    void dot_to_coeff();
    void coeff_to_dot();
    void dot_to_coeff_lazy();
    void coeff_to_dot_lazy();
    POSEIDON_NODISCARD RNSIter operator[](std::size_t rns_index) const;
    POSEIDON_NODISCARD const uint64_t *data() const;
    POSEIDON_NODISCARD uint64_t *data();

    void operator*=(const RNSPoly &poly);
    void operator*=(uint64_t scalar);
    void operator+=(const RNSPoly &poly);
    void operator+=(uint64_t scalar);
    void operator-=(const RNSPoly &poly);
    void negate();

    void copy(const RNSPoly &operand) const;
    void copy(const RNSPoly &operand, size_t rns_num) const;
    void copy(const RNSPoly &operand, size_t operand_rns_idx, size_t rns_num,
              size_t res_rns_idx) const;

    // for drop modulus
    void drop(size_t rns_count, size_t rns_num) const;
    void add(const RNSPoly &operand, RNSPoly &result) const;
    void sub(const RNSPoly &operand, RNSPoly &result) const;
    void multiply(const RNSPoly &operand, RNSPoly &result) const;
    void add_scalar(uint64_t scalar, RNSPoly &result) const;
    void multiply_scalar(uint64_t scalar, RNSPoly &result) const;

    inline void set_context(const std::shared_ptr<CrtContext> &context)
    {
        crt_context_ = context;
        context_data = context->get_context_data(parms_id_);
        key_context_data = context->key_context_data();
    }

private:
    // friendly function only_used by base conv
    inline void set_rns_p(size_t num) { rns_num_p_ = num; }
    std::shared_ptr<CrtContext> crt_context_{nullptr};
    std::shared_ptr<const CrtContext::ContextData> context_data{nullptr};
    std::shared_ptr<const CrtContext::ContextData> key_context_data{nullptr};

    size_t poly_degree_ = 0;
    size_t rns_num_q_ = 0;  // level + 1
    size_t rns_num_p_ = 0;
    size_t rns_num_total_ = 0;
    size_t rns_p_offset_ = 0;

    parms_id_type parms_id_ = parms_id_zero;
    uint64_t *data_ = nullptr;

    DynArray<uint64_t> buffer_;
    PolyIter poly_iter_;
    ConstPolyIter const_poly_iter_;
    MemoryPoolHandle pool_ = MemoryManager::GetPool();
    mutable uint32_t hardware_id_ = 0;
};

}  // namespace poseidon
