#include "crt_context.h"

namespace poseidon
{
CrtContext::CrtContext(const std::shared_ptr<const ParametersLiteral> &params,
                       sec_level_type sec_level, MemoryPoolHandle pool)
    : pool_(std::move(pool)), p_offset_(params->q().size()), sec_level_(sec_level)
{
    auto q0_level = params->q0_level();
    q0_ = safe_cast<double>(params->q()[0].value());
    for (auto i = 0; i < q0_level; ++i)
    {
        q0_ *= safe_cast<double>(params->q()[i + 1].value());
    }
    auto plain_value = params->plain_modulus();
    auto scheme_type = params->scheme();
    auto modulus = params->q();
    auto &modulus_p = params->p();
    auto logn = params->log_n();
    modulus.insert(modulus.end(), modulus_p.begin(), modulus_p.end());
    try
    {
        CreateNTTTables(safe_cast<int>(logn), modulus, small_ntt_tables_, pool_);
    }
    catch (const invalid_argument &)
    {
        // POSEIDON_THROW(invalid_argument_error, );
        POSEIDON_THROW(config_error, "invalid modulus");
    }

    if (scheme_type == BFV || scheme_type == BGV)
    {
        try
        {
            CreateNTTTables(safe_cast<int>(logn), vector<Modulus>{plain_value}, plain_ntt_tables_,
                            pool_);
        }
        catch (const invalid_argument &)
        {
            POSEIDON_THROW(config_error, "invalid modulus");
        }
    }

    auto params_copy = *params;
    auto prev_parms_id = parms_id_zero;

    if (params_copy.p().empty())  // no key switch
    {
        using_keyswitch_ = false;
    }
    else
    {
        auto rns_num = add_safe(params_copy.q().size(), params_copy.p().size());
        key_parms_id_ = params_copy.parms_id();
        parms_id_map_.emplace(rns_num - 1, key_parms_id_);
        context_data_map_.emplace(key_parms_id_,
                                  make_shared<const ContextData>(validate(params_copy, modulus_p)));
        params_copy.set_modulus(params->q(), {});
        prev_parms_id = key_parms_id_;
    }

    first_parms_id_ = params_copy.parms_id();
    if (!using_keyswitch_)  // no key switch
    {
        key_parms_id_ = first_parms_id_;
    }
    parms_id_map_.emplace(params_copy.q().size() - 1, first_parms_id_);
    context_data_map_.emplace(first_parms_id_,
                              make_shared<const ContextData>(validate(params_copy, modulus_p)));
    if (prev_parms_id != parms_id_zero)
    {
        const_pointer_cast<ContextData>(context_data_map_.at(prev_parms_id))->next_context_data_ =
            context_data_map_.at(params_copy.parms_id());
    }
    prev_parms_id = params_copy.parms_id();

    while (params_copy.q().size() > 1)
    {
        auto modulus_q = params_copy.q();
        modulus_q.pop_back();
        auto rns_num = modulus_q.size();
        params_copy.set_modulus(modulus_q, {});
        auto parms_id = params_copy.parms_id();
        parms_id_map_.emplace(rns_num - 1, parms_id);
        context_data_map_.emplace(parms_id,
                                  make_shared<const ContextData>(validate(params_copy, modulus_p)));
        const_pointer_cast<ContextData>(context_data_map_.at(prev_parms_id))->next_context_data_ =
            context_data_map_.at(params_copy.parms_id());
        prev_parms_id = params_copy.parms_id();
    }

    last_parms_id_ = prev_parms_id;

    // Create GaloisTool
    galois_tool_ = allocate<GaloisTool>(pool_, logn, pool_);

    // Set the chain_index for each context_data
    size_t parms_count = context_data_map_.size();
    auto context_data_ptr = context_data_map_.at(key_parms_id_);
    while (context_data_ptr)
    {
        // We need to remove constness first to modify this
        const_pointer_cast<ContextData>(context_data_ptr)->chain_index_ = --parms_count;
        context_data_ptr = context_data_ptr->next_context_data_;
    }
}

CrtContext::ContextData CrtContext::validate(const ParametersLiteral &params,
                                             const vector<Modulus> &modulus_p)
{
    auto context_data = CrtContext::ContextData(params, pool_);
    auto scheme_type = params.scheme();
    size_t poly_modulus_degree = params.degree();
    // Compute the product of all coeff moduli
    context_data.modulus_ = params.q();
    if (!params.p().empty())
        context_data.modulus_.insert(context_data.modulus_.end(), params.p().begin(),
                                     params.p().end());
    auto &coeff_modulus = context_data.modulus_;
    auto coeff_modulus_size = context_data.modulus_.size();
    auto &plain_modulus = params.plain_modulus();

    context_data.total_coeff_modulus_ = allocate_uint(coeff_modulus_size, pool_);
    auto coeff_modulus_values(allocate_uint(coeff_modulus_size, pool_));
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        coeff_modulus_values[i] = context_data.modulus_[i].value();
    }
    multiply_many_uint64(coeff_modulus_values.get(), coeff_modulus_size,
                         context_data.total_coeff_modulus_.get(), pool_);
    context_data.total_coeff_modulus_bit_count_ =
        get_significant_bit_count_uint(context_data.total_coeff_modulus_.get(), coeff_modulus_size);

    // std::cout << "poly_modulus_degree" << poly_modulus_degree << std::endl;
    // std::cout << "total_coeff_modulus_bit_count_" << context_data.total_coeff_modulus_bit_count_  << std::endl;
    // std::cout << "MaxBitCount" << CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_) << std::endl;
    // if (context_data.total_coeff_modulus_bit_count_ >
    //     CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_))
    // {
    //     POSEIDON_THROW(
    //         invalid_argument_error,
    //         "parameters are not compliant with HomomorphicEncryption.org security standard");
    // }

    // Compute the upper_half_threshold for this modulus.
    // (total_coeff_modulus + 1) / 2
    context_data.upper_half_threshold_ = allocate_uint(coeff_modulus_size, pool_);
    increment_uint(context_data.total_coeff_modulus(), coeff_modulus_size,
                   context_data.upper_half_threshold_.get());
    right_shift_uint(context_data.upper_half_threshold_.get(), 1, coeff_modulus_size,
                     context_data.upper_half_threshold_.get());

    // Set up RNSBase for coeff_modulus
    // RNSBase's constructor may fail due to:
    //   (1) coeff_mod not coprime
    //   (2) cannot find inverse of punctured products (because of (1))
    Pointer<RNSBase> coeff_modulus_base;
    try
    {
        coeff_modulus_base = allocate<RNSBase>(pool_, coeff_modulus, pool_);
    }
    catch (const invalid_argument &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "RNSBase's constructor  fail!");
        return context_data;
    }

    Pointer<RNSBase> coeff_modulus_q;
    try
    {
        coeff_modulus_q = allocate<RNSBase>(pool_, params.q(), pool_);
    }
    catch (const invalid_argument &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "RNSBase's constructor  fail!");
        return context_data;
    }

    if (scheme_type == BFV || scheme_type == BGV)
    {
        if (plain_modulus.value() >> POSEIDON_PLAIN_MOD_BIT_COUNT_MAX ||
            !(plain_modulus.value() >> (POSEIDON_PLAIN_MOD_BIT_COUNT_MIN - 1)))
        {
            POSEIDON_THROW(config_error, "plain modulus is out of range");
        }

        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            if (!are_coprime(coeff_modulus[i].value(), plain_modulus.value()))
            {
                POSEIDON_THROW(config_error, "plain modulus and coeff_modulus are not coprime ");
            }
        }

        // Check that plain_modulus is smaller than total coeff modulus
        if (!is_less_than_uint(plain_modulus.data(), plain_modulus.uint64_count(),
                               context_data.total_coeff_modulus_.get(), coeff_modulus_size))
        {
            // Parameters are not valid
            POSEIDON_THROW(config_error, "plain modulus is too large ");
        }

        context_data.using_fast_plain_lift_ = true;
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            context_data.using_fast_plain_lift_ &=
                (coeff_modulus[i].value() > plain_modulus.value());
        }

        // Calculate coeff_div_plain_modulus (BFV-"Delta") and the remainder upper_half_increment
        auto temp_coeff_div_plain_modulus = allocate_uint(coeff_modulus_size, pool_);
        context_data.coeff_div_plain_modulus_ =
            allocate<MultiplyUIntModOperand>(coeff_modulus_size, pool_);
        context_data.upper_half_increment_ = allocate_uint(coeff_modulus_size, pool_);
        auto wide_plain_modulus(duplicate_uint_if_needed(
            plain_modulus.data(), plain_modulus.uint64_count(), coeff_modulus_size, false, pool_));
        divide_uint(context_data.total_coeff_modulus_.get(), wide_plain_modulus.get(),
                    coeff_modulus_size, temp_coeff_div_plain_modulus.get(),
                    context_data.upper_half_increment_.get(), pool_);

        // Store the non-RNS form of upper_half_increment for BFV encryption
        context_data.coeff_modulus_mod_plain_modulus_ = context_data.upper_half_increment_[0];

        // Decompose coeff_div_plain_modulus into RNS factors
        coeff_modulus_base->decompose(temp_coeff_div_plain_modulus.get(), pool_);

        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            context_data.coeff_div_plain_modulus_[i].set(temp_coeff_div_plain_modulus[i],
                                                         coeff_modulus_base->base()[i]);
        }

        // Decompose upper_half_increment into RNS factors
        coeff_modulus_base->decompose(context_data.upper_half_increment_.get(), pool_);

        // Calculate (plain_modulus + 1) / 2.
        context_data.plain_upper_half_threshold_ = (plain_modulus.value() + 1) >> 1;

        // Calculate coeff_modulus - plain_modulus.
        context_data.plain_upper_half_increment_ = allocate_uint(coeff_modulus_size, pool_);
        if (context_data.using_fast_plain_lift_)
        {
            // Calculate coeff_modulus[i] - plain_modulus if using_fast_plain_lift
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                context_data.plain_upper_half_increment_[i] =
                    coeff_modulus[i].value() - plain_modulus.value();
            }
        }
    }

    try
    {
        if (scheme_type == CKKS)
            context_data.rns_tool_ = allocate<RNSTool>(pool_, poly_modulus_degree,
                                                       *coeff_modulus_base, Modulus{0}, pool_);
        else
            context_data.rns_tool_ =
                allocate<RNSTool>(pool_, poly_modulus_degree, *coeff_modulus_base,
                                  Modulus{params.plain_modulus()}, pool_);
    }
    catch (const exception &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "failed_creating_rns_tool!");
        return context_data;
    }

    // for GHS & Hybrid
    // P
    if (!modulus_p.empty() && modulus_p.size() != 1)
    {  // not bv & has p

        Pointer<RNSBase> coeff_modulus_p;
        try
        {
            coeff_modulus_p = allocate<RNSBase>(pool_, modulus_p, pool_);
        }
        catch (const invalid_argument &)
        {
            // Parameters are not valid
            POSEIDON_THROW(invalid_argument_error, "modulus_p RNSBase's constructor  fail!");
            return context_data;
        }

        try
        {
            if (scheme_type == CKKS)
                context_data.rns_tool_qp_tool_ =
                    allocate<RNSToolQP>(pool_, poly_modulus_degree, *coeff_modulus_q,
                                        *coeff_modulus_p, Modulus{0}, pool_);
            else
                context_data.rns_tool_qp_tool_ =
                    allocate<RNSToolQP>(pool_, poly_modulus_degree, *coeff_modulus_q,
                                        *coeff_modulus_p, Modulus{params.plain_modulus()}, pool_);
        }
        catch (const exception &)
        {
            // Parameters are not valid
            POSEIDON_THROW(invalid_argument_error, "failed_creating_rns_tool!");
            return context_data;
        }
    }

    return context_data;
}

CrtContext::ContextData CrtContext::validate(const ParametersLiteral &params)
{

    auto context_data = CrtContext::ContextData(params, pool_);
    auto scheme_type = params.scheme();
    size_t poly_modulus_degree = params.degree();
    // Compute the product of all coeff moduli
    context_data.modulus_ = params.q();

    if (!params.p().empty())
        context_data.modulus_.insert(context_data.modulus_.end(), params.p().begin(),
                                     params.p().end());
    auto &coeff_modulus = context_data.modulus_;
    auto coeff_modulus_size = context_data.modulus_.size();
    auto &plain_modulus = params.plain_modulus();

    context_data.total_coeff_modulus_ = allocate_uint(coeff_modulus_size, pool_);
    auto coeff_modulus_values(allocate_uint(coeff_modulus_size, pool_));
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        coeff_modulus_values[i] = context_data.modulus_[i].value();
    }
    multiply_many_uint64(coeff_modulus_values.get(), coeff_modulus_size,
                         context_data.total_coeff_modulus_.get(), pool_);
    context_data.total_coeff_modulus_bit_count_ =
        get_significant_bit_count_uint(context_data.total_coeff_modulus_.get(), coeff_modulus_size);

    // Set up RNSBase for coeff_modulus
    // RNSBase's constructor may fail due to:
    //   (1) coeff_mod not coprime
    //   (2) cannot find inverse of punctured products (because of (1))
    Pointer<RNSBase> coeff_modulus_base;
    try
    {
        coeff_modulus_base = allocate<RNSBase>(pool_, coeff_modulus, pool_);
    }
    catch (const invalid_argument &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "RNSBase's constructor  fail!");
    }

    if (scheme_type == BFV || scheme_type == BGV)
    {
        if (plain_modulus.value() >> POSEIDON_PLAIN_MOD_BIT_COUNT_MAX ||
            !(plain_modulus.value() >> (POSEIDON_PLAIN_MOD_BIT_COUNT_MIN - 1)))
        {
            POSEIDON_THROW(config_error, "plain modulus is out of range");
        }

        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            if (!are_coprime(coeff_modulus[i].value(), plain_modulus.value()))
            {
                POSEIDON_THROW(config_error, "plain modulus and coeff_modulus are not coprime ");
            }
        }

        // Check that plain_modulus is smaller than total coeff modulus
        if (!is_less_than_uint(plain_modulus.data(), plain_modulus.uint64_count(),
                               context_data.total_coeff_modulus_.get(), coeff_modulus_size))
        {
            // Parameters are not valid
            POSEIDON_THROW(config_error, "plain modulus is too large ");
        }

        bool using_fast_plain_lift = true;
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            using_fast_plain_lift &= (coeff_modulus[i].value() > plain_modulus.value());
        }

        // Calculate coeff_div_plain_modulus (BFV-"Delta") and the remainder upper_half_increment
        auto temp_coeff_div_plain_modulus = allocate_uint(coeff_modulus_size, pool_);
        context_data.coeff_div_plain_modulus_ =
            allocate<MultiplyUIntModOperand>(coeff_modulus_size, pool_);
        context_data.upper_half_increment_ = allocate_uint(coeff_modulus_size, pool_);
        auto wide_plain_modulus(duplicate_uint_if_needed(
            plain_modulus.data(), plain_modulus.uint64_count(), coeff_modulus_size, false, pool_));
        divide_uint(context_data.total_coeff_modulus_.get(), wide_plain_modulus.get(),
                    coeff_modulus_size, temp_coeff_div_plain_modulus.get(),
                    context_data.upper_half_increment_.get(), pool_);

        // Store the non-RNS form of upper_half_increment for BFV encryption
        context_data.coeff_modulus_mod_plain_modulus_ = context_data.upper_half_increment_[0];

        // Decompose coeff_div_plain_modulus into RNS factors
        coeff_modulus_base->decompose(temp_coeff_div_plain_modulus.get(), pool_);

        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
            context_data.coeff_div_plain_modulus_[i].set(temp_coeff_div_plain_modulus[i],
                                                         coeff_modulus_base->base()[i]);
        }

        // Decompose upper_half_increment into RNS factors
        coeff_modulus_base->decompose(context_data.upper_half_increment_.get(), pool_);

        // Calculate (plain_modulus + 1) / 2.
        context_data.plain_upper_half_threshold_ = (plain_modulus.value() + 1) >> 1;

        // Calculate coeff_modulus - plain_modulus.
        context_data.plain_upper_half_increment_ = allocate_uint(coeff_modulus_size, pool_);
        if (using_fast_plain_lift)
        {
            // Calculate coeff_modulus[i] - plain_modulus if using_fast_plain_lift
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                context_data.plain_upper_half_increment_[i] =
                    coeff_modulus[i].value() - plain_modulus.value();
            }
        }
    }

    if (context_data.total_coeff_modulus_bit_count_ >
        CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_))
    {
        POSEIDON_THROW(
            invalid_argument_error,
            "parameters are not compliant with HomomorphicEncryption.org security standard");
    }

    // Compute the upper_half_threshold for this modulus.
    // (total_coeff_modulus + 1) / 2
    context_data.upper_half_threshold_ = allocate_uint(coeff_modulus_size, pool_);
    increment_uint(context_data.total_coeff_modulus(), coeff_modulus_size,
                   context_data.upper_half_threshold_.get());
    right_shift_uint(context_data.upper_half_threshold_.get(), 1, coeff_modulus_size,
                     context_data.upper_half_threshold_.get());

    try
    {
        if (scheme_type == CKKS)
            context_data.rns_tool_ = allocate<RNSTool>(pool_, poly_modulus_degree,
                                                       *coeff_modulus_base, Modulus{0}, pool_);
        else
            context_data.rns_tool_ =
                allocate<RNSTool>(pool_, poly_modulus_degree, *coeff_modulus_base,
                                  Modulus{params.plain_modulus()}, pool_);
    }
    catch (const exception &)
    {
        // Parameters are not valid
        POSEIDON_THROW(invalid_argument_error, "failed_creating_rns_tool!");
    }
    return context_data;
}

parms_id_type CrtContext::create_next_context_data(const parms_id_type &id)
{
    return parms_id_zero;
}

}  // namespace poseidon
