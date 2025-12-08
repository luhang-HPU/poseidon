#include "poseidon_context.h"

#ifdef USING_HARDWARE
#include "poseidon_hardware/hardware_drive/hardware_api.h"
#endif

namespace poseidon
{
PoseidonContext::PoseidonContext(const ParametersLiteral &param_literal, bool using_hardware)
    : parameters_literal_(make_shared<const poseidon::ParametersLiteral>(param_literal)),
      sec_level_(param_literal.sec_level()), using_hardware_(using_hardware)
{
#ifdef USING_HARDWARE
    if (using_hardware_)
    {
        HardwareApi::check_hardware();
    }
#endif

    auto base_p_size = param_literal.p().size();
    auto base_q_size = param_literal.q().size();
    auto scheme_type = param_literal.scheme();
    if (base_p_size < 1)
    {
        key_switch_variant_ = none;
    }
    else if (base_p_size == 1)
    {
        key_switch_variant_ = BV;
    }
    else if (base_p_size == base_q_size)
    {
        key_switch_variant_ = GHS;
    }
    else
    {
        key_switch_variant_ = HYBRID;
    }

    crt_context_ = make_shared<poseidon::CrtContext>(parameters_literal_, sec_level_);

    if (using_hardware)
    {
#ifdef USING_HARDWARE
        if (key_switch_variant_ != BV)
        {
            POSEIDON_THROW(invalid_argument_error, "hardware only support BV variant");
        }

        hardware_context_ = make_shared<poseidon::HardwareContext>(crt_context_);
#else
        POSEIDON_THROW(invalid_argument_error, "context: no hardware!");
#endif
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory());
    set_random_generator(rng);
}
}  // namespace poseidon
