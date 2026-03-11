#include "rns_poly.h"
#include "basics/util/rlwe.h"

namespace poseidon
{
RNSPoly::RNSPoly(const PoseidonContext &context, std::uint64_t *data, parms_id_type parms_id,
                 PolyType random_type, const shared_ptr<UniformRandomGenerator> &prng)
    : crt_context_(context.crt_context()), data_(data), parms_id_(parms_id)
{
    if (context.crt_context())
    {
        rns_p_offset_ = context.crt_context()->first_context_data()->coeff_modulus().size();
    }
    context_data = crt_context_->get_context_data(parms_id);
    key_context_data = crt_context_->key_context_data();
    poly_degree_ = context_data->parms().degree();
    rns_num_q_ = context_data->parms().q().size();
    rns_num_p_ = context_data->parms().p().size();
    rns_num_total_ = rns_num_q_ + rns_num_p_;
    poly_iter_ = PolyIter(data, poly_degree_, rns_num_total_);
    const_poly_iter_ = ConstPolyIter(data, poly_degree_, rns_num_total_);
    if (random_type != nothing)
    {
        set_random(context, random_type, prng);
    }
}

RNSPoly::RNSPoly(const shared_ptr<CrtContext> &crt_context, std::uint64_t *data,
                 parms_id_type parms_id)
    : crt_context_(crt_context), data_(data), parms_id_(parms_id)

{
    if (crt_context)
    {
        rns_p_offset_ = crt_context->first_context_data()->coeff_modulus().size();
        context_data = crt_context_->get_context_data(parms_id);
        key_context_data = crt_context_->key_context_data();
        poly_degree_ = context_data->parms().degree();
        rns_num_q_ = context_data->parms().q().size();
        rns_num_p_ = context_data->parms().p().size();
        rns_num_total_ = rns_num_q_ + rns_num_p_;
        poly_iter_ = PolyIter(data, poly_degree_, rns_num_total_);
        const_poly_iter_ = ConstPolyIter(data, poly_degree_, rns_num_total_);
    }
}

RNSPoly::RNSPoly(const PoseidonContext &context, parms_id_type parms_id, PolyType random_type,
                 const shared_ptr<UniformRandomGenerator> &prng)
    : crt_context_(context.crt_context()), parms_id_(parms_id)
{
    if (context.crt_context())
    {
        rns_p_offset_ = context.crt_context()->first_context_data()->coeff_modulus().size();
    }
    resize(context, parms_id);
    if (random_type != nothing)
    {
        set_random(context, random_type, prng);
    }
}

RNSPoly::RNSPoly(const PoseidonContext &context, parms_id_type parms_id, bool enable_rns_p)
    : crt_context_(context.crt_context()), parms_id_(parms_id)
{
    if (context.crt_context())
    {
        rns_p_offset_ = context.crt_context()->first_context_data()->coeff_modulus().size();
    }
    resize(context, parms_id, enable_rns_p);
}

void RNSPoly::resize(const PoseidonContext &context, parms_id_type parms_id, bool enable_rns_p)
{
    auto context_data_ptr = context.crt_context()->get_context_data(parms_id);
    if (!context_data_ptr)
    {
        POSEIDON_THROW(invalid_argument_error, "parms_id is not valid for encryption parameters");
    }

    crt_context_ = context.crt_context();
    // Need to set parms_id first
    context_data = crt_context_->get_context_data(parms_id);
    key_context_data = crt_context_->key_context_data();
    poly_degree_ = context_data->parms().degree();
    rns_num_q_ = context_data->parms().q().size();
    if (enable_rns_p)
    {
        rns_num_p_ = key_context_data->parms().p().size();
    }
    else
    {
        rns_num_p_ = context_data->parms().p().size();
    }
    rns_p_offset_ = context.parameters_literal()->q().size();
    rns_num_total_ = add_safe(rns_num_q_, rns_num_p_);
    size_t new_data_size = mul_safe(poly_degree_, rns_num_total_);

    parms_id_ = parms_id;
    buffer_.resize(new_data_size);

    data_ = buffer_.begin();
    poly_iter_ = PolyIter(data_, poly_degree_, rns_num_total_);
    const_poly_iter_ = ConstPolyIter(data_, poly_degree_, rns_num_total_);
}

void RNSPoly::set_random(const PoseidonContext &context, PolyType random_type,
                         const shared_ptr<UniformRandomGenerator> &prng) const
{

    auto prng_itr = prng;
    if (prng_itr == nullptr)
    {
        prng_itr = context.random_generator()->create();
    }
    if (random_type == ternary)
        sample_poly_ternary(prng_itr, context, parms_id_, data_);
    if (random_type == gaussian)
        sample_poly_uniform(prng_itr, context, parms_id_, data_);
    if (random_type == centered_binomial)
        sample_poly_cbd(prng_itr, context, parms_id_, data_);
    else if (random_type == zero)
        set_zero_uint(mul_safe(rns_num_total_, poly_degree_), data_);
}

void RNSPoly::coeff_to_dot()
{
    auto ntt_table = crt_context_->small_ntt_tables();
    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        ntt_negacyclic_harvey(data_ + i * poly_degree_, ntt_table[i]);
    }

    for (auto i = 0; i < rns_num_p_; ++i)
    {
        ntt_negacyclic_harvey(data_ + (i + rns_num_q_) * poly_degree_,
                              ntt_table[i + rns_p_offset_]);
    }
}

void RNSPoly::coeff_to_dot_lazy()
{
    auto ntt_table = crt_context_->small_ntt_tables();
    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        ntt_negacyclic_harvey_lazy(data_ + i * poly_degree_, ntt_table[i]);
    }

    for (auto i = 0; i < rns_num_p_; ++i)
    {
        ntt_negacyclic_harvey_lazy(data_ + (i + rns_num_q_) * poly_degree_,
                                   ntt_table[i + rns_p_offset_]);
    }
}

void RNSPoly::dot_to_coeff()
{
    auto ntt_table = crt_context_->small_ntt_tables();
    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        inverse_ntt_negacyclic_harvey(data_ + i * poly_degree_, ntt_table[i]);
    }

    for (auto i = 0; i < rns_num_p_; ++i)
    {
        inverse_ntt_negacyclic_harvey(data_ + (i + rns_num_q_) * poly_degree_,
                                      ntt_table[i + rns_p_offset_]);
    }
}

void RNSPoly::dot_to_coeff_lazy()
{
    auto ntt_table = crt_context_->small_ntt_tables();
    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        inverse_ntt_negacyclic_harvey_lazy(data_ + i * poly_degree_, ntt_table[i]);
    }

    for (auto i = 0; i < rns_num_p_; ++i)
    {
        inverse_ntt_negacyclic_harvey_lazy(data_ + (i + rns_num_q_) * poly_degree_,
                                           ntt_table[i + rns_p_offset_]);
    }
}

RNSIter RNSPoly::operator[](std::size_t rns_index) const
{

    if (rns_index >= rns_num_total_)
    {
        throw std::invalid_argument("rns_index is out of range");
    }
    return poly_iter_.data(rns_index);
}

const uint64_t *RNSPoly::data() const { return data_; }

uint64_t *RNSPoly::data() { return data_; }

void RNSPoly::operator*=(const RNSPoly &poly)
{
    if (this->parms_id_ != poly.parms_id_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly *= : param_id not match!");
    }

    if (rns_num_p_ != poly.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly *= : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    for (auto i = 0; i < rns_num_q_; ++i)
    {
        dyadic_product_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_,
                                poly_degree_, modulus_q[i], data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        dyadic_product_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_,
                                poly_degree_, modulus_p[i - rns_num_q_], data_ + i * poly_degree_);
    }
}

void RNSPoly::operator*=(uint64_t scalar)
{
    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    for (auto i = 0; i < rns_num_q_; ++i)
    {
        multiply_poly_scalar_coeffmod(data_ + i * poly_degree_, scalar, poly_degree_, modulus_q[i],
                                      data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        multiply_poly_scalar_coeffmod(data_ + i * poly_degree_, scalar, poly_degree_,
                                      modulus_p[i - rns_num_q_], data_ + i * poly_degree_);
    }
}

void RNSPoly::operator+=(const RNSPoly &poly)
{
    if (this->parms_id_ != poly.parms_id_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly += : param_id not match!");
    }

    if (rns_num_p_ != poly.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly += : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    for (auto i = 0; i < rns_num_q_; ++i)
    {
        add_poly_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_, poly_degree_,
                          modulus_q[i], data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        add_poly_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_, poly_degree_,
                          modulus_p[i - rns_num_q_], data_ + i * poly_degree_);
    }
}

void RNSPoly::operator+=(uint64_t scalar)
{
    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    for (auto i = 0; i < rns_num_q_; ++i)
    {
        add_poly_scalar_coeffmod(data_ + i * poly_degree_, scalar, poly_degree_, modulus_q[i],
                                 data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        add_poly_scalar_coeffmod(data_ + i * poly_degree_, scalar, poly_degree_,
                                 modulus_p[i - rns_num_q_], data_ + i * poly_degree_);
    }
}

void RNSPoly::operator-=(const RNSPoly &poly)
{
    if (this->parms_id_ != poly.parms_id_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly -= : param_id not match!");
    }

    if (rns_num_p_ == poly.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly -= : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    for (auto i = 0; i < rns_num_q_; ++i)
    {
        sub_poly_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_, poly_degree_,
                          modulus_q[i], data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        sub_poly_coeffmod(data_ + i * poly_degree_, poly.data_ + i * poly_degree_, poly_degree_,
                          modulus_p[i - rns_num_q_], data_ + i * poly_degree_);
    }
}

void RNSPoly::negate()
{
    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        negate_poly_coeffmod(data_ + i * poly_degree_, poly_degree_, modulus_q[i],
                             data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        negate_poly_coeffmod(data_ + i * poly_degree_, poly_degree_, modulus_p[i - rns_num_q_],
                             data_ + i * poly_degree_);
    }
}

void RNSPoly::add(const RNSPoly &operand, RNSPoly &result) const
{
    if (this->parms_id_ != operand.parms_id_ || this->parms_id_ != result.parms_id_)
    {
        if ((this->parms_id_ == crt_context_->key_parms_id() &&
             result.parms_id_ == operand.parms_id_) ||
            (operand.parms_id_ == crt_context_->key_parms_id() &&
             this->parms_id_ == result.parms_id_))
        {
            auto &modulus_q = context_data->parms().q();
            auto &modulus_p = key_context_data->parms().p();

            #pragma omp parallel for
            for (int i = 0; i < rns_num_q_; ++i)
            {
                add_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_,
                                  poly_degree_, modulus_q[i], result.data_ + i * poly_degree_);
            }

            if (rns_num_p_ == operand.rns_num_p_ && rns_num_p_ == result.rns_num_p_)
            {
                for (int i = 0; i < rns_num_p_; ++i)
                {
                    dyadic_product_coeffmod(
                        data_ + (rns_p_offset_ + i) * poly_degree_,
                        operand.data_ + (operand.rns_p_offset_ + i) * poly_degree_, poly_degree_,
                        modulus_p[i], result.data_ + (result.rns_p_offset_ + i) * poly_degree_);
                }
            }
            return;
        }
        else
        {
            POSEIDON_THROW(invalid_argument_error, "RNSPoly add : param_id not match!");
        }
    }

    if (rns_num_p_ != operand.rns_num_p_ || rns_num_p_ != result.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly add : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        add_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_, poly_degree_,
                          modulus_q[i], result.data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        add_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_, poly_degree_,
                          modulus_p[i - rns_num_q_], result.data_ + i * poly_degree_);
    }
}
void RNSPoly::sub(const RNSPoly &operand, RNSPoly &result) const
{
    if (this->parms_id_ != operand.parms_id_ || this->parms_id_ != result.parms_id_)
    {
        if ((this->parms_id_ == crt_context_->key_parms_id() &&
             result.parms_id_ == operand.parms_id_) ||
            (operand.parms_id_ == crt_context_->key_parms_id() &&
             this->parms_id_ == result.parms_id_))
        {
            auto &modulus_q = context_data->parms().q();
            auto &modulus_p = key_context_data->parms().p();

            for (int i = 0; i < rns_num_q_; ++i)
            {
                sub_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_,
                                  poly_degree_, modulus_q[i], result.data_ + i * poly_degree_);
            }

            if (rns_num_p_ == operand.rns_num_p_ && rns_num_p_ == result.rns_num_p_)
            {
                for (int i = 0; i < rns_num_p_; ++i)
                {
                    dyadic_product_coeffmod(
                        data_ + (rns_p_offset_ + i) * poly_degree_,
                        operand.data_ + (operand.rns_p_offset_ + i) * poly_degree_, poly_degree_,
                        modulus_p[i], result.data_ + (result.rns_p_offset_ + i) * poly_degree_);
                }
            }
            return;
        }
        else
        {
            POSEIDON_THROW(invalid_argument_error, "RNSPoly sub : param_id not match!");
        }
    }

    if (rns_num_p_ != operand.rns_num_p_ || rns_num_p_ != result.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly sub : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        sub_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_, poly_degree_,
                          modulus_q[i], result.data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        sub_poly_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_, poly_degree_,
                          modulus_p[i - rns_num_q_], result.data_ + i * poly_degree_);
    }
}
void RNSPoly::multiply(const RNSPoly &operand, RNSPoly &result) const
{

    if (this->parms_id_ != operand.parms_id_ || this->parms_id_ != result.parms_id_)
    {
        if ((this->parms_id_ == crt_context_->key_parms_id() &&
             result.parms_id_ == operand.parms_id_) ||
            (operand.parms_id_ == crt_context_->key_parms_id() &&
             this->parms_id_ == result.parms_id_))
        {
            auto &modulus_q = context_data->parms().q();
            auto &modulus_p = key_context_data->parms().p();

            #pragma omp parallel for
            for (int i = 0; i < rns_num_q_; ++i)
            {
                dyadic_product_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_,
                                        poly_degree_, modulus_q[i],
                                        result.data_ + i * poly_degree_);
            }

            if (rns_num_p_ == operand.rns_num_p_ && rns_num_p_ == result.rns_num_p_)
            {
                for (int i = 0; i < rns_num_p_; ++i)
                {
                    dyadic_product_coeffmod(
                        data_ + (rns_p_offset_ + i) * poly_degree_,
                        operand.data_ + (operand.rns_p_offset_ + i) * poly_degree_, poly_degree_,
                        modulus_p[i], result.data_ + (result.rns_p_offset_ + i) * poly_degree_);
                }
            }
            return;
        }
        else
        {
            POSEIDON_THROW(invalid_argument_error, "RNSPoly multiply : param_id not match!");
        }
    }
    if (rns_num_p_ != operand.rns_num_p_ || rns_num_p_ != result.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly multiply : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        dyadic_product_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_,
                                poly_degree_, modulus_q[i], result.data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        dyadic_product_coeffmod(data_ + i * poly_degree_, operand.data_ + i * poly_degree_,
                                poly_degree_, modulus_p[i - rns_num_q_],
                                result.data_ + i * poly_degree_);
    }
}
void RNSPoly::add_scalar(uint64_t scalar, RNSPoly &result) const
{
    if (this->parms_id_ != result.parms_id_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly add_scalar : param_id not match!");
    }
    if (rns_num_p_ != result.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly add_scalar : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        add_poly_scalar_coeffmod(data_ + i * poly_degree_, poly_degree_, scalar, modulus_q[i],
                                 result.data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        add_poly_scalar_coeffmod(data_ + i * poly_degree_, poly_degree_, scalar,
                                 modulus_p[i - rns_num_q_], result.data_ + i * poly_degree_);
    }
}
void RNSPoly::multiply_scalar(uint64_t scalar, RNSPoly &result) const
{
    if (this->parms_id_ != result.parms_id_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly multiply_scalar : param_id not match!");
    }
    if (rns_num_p_ != result.rns_num_p_)
    {
        POSEIDON_THROW(invalid_argument_error, "RNSPoly multiply_scalar : rns_num_p not match!");
    }

    auto &modulus_q = context_data->parms().q();
    auto &modulus_p = key_context_data->parms().p();

    #pragma omp parallel for
    for (auto i = 0; i < rns_num_q_; ++i)
    {
        multiply_poly_scalar_coeffmod(data_ + i * poly_degree_, poly_degree_, scalar, modulus_q[i],
                                      result.data_ + i * poly_degree_);
    }
    for (auto i = rns_num_q_; i < rns_num_q_ + rns_num_p_; ++i)
    {
        multiply_poly_scalar_coeffmod(data_ + i * poly_degree_, poly_degree_, scalar,
                                      modulus_p[i - rns_num_q_], result.data_ + i * poly_degree_);
    }
}

void RNSPoly::copy(const RNSPoly &operand) const
{
    set_poly_array(operand.data_, 1, poly_degree_, rns_num_total_, this->data_);
}

void RNSPoly::copy(const RNSPoly &operand, size_t rns_num) const
{
    if (rns_num > rns_num_total_)
    {
        throw out_of_range("RNSPoly copy error");
    }
    set_poly_array(operand.data_, 1, poly_degree_, rns_num, this->data_);
}

void RNSPoly::copy(const RNSPoly &operand, size_t operand_rns_idx, size_t rns_num,
                   size_t res_rns_idx) const
{
    if (rns_num + res_rns_idx > rns_num_total_)
    {
        throw out_of_range("RNSPoly copy error");
    }

    if (rns_num + operand_rns_idx > rns_num_total_)
    {
        throw out_of_range("RNSPoly copy error");
    }
    set_poly_array(operand.data_ + poly_degree_ * operand_rns_idx, 1, poly_degree_, rns_num,
                   this->data_ + poly_degree_ * res_rns_idx);
}

void RNSPoly::drop(size_t rns_count, size_t rns_num) const
{
    auto new_poly_iter_ = poly_iter_[0] - rns_count;
    set_poly_array(poly_iter_, 1, poly_degree_, rns_num, new_poly_iter_);
}

}  // namespace poseidon
