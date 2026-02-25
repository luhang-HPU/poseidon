#pragma once

#include "basics/randomgen.h"
#include "crt_context.h"
#include "parameters_literal.h"
#include "util/pke_params_defines.h"

#ifdef USING_HARDWARE
#include "poseidon_hardware/hardware_context.h"
#endif

using namespace std;

namespace poseidon
{
class PoseidonContext
{
public:
    explicit PoseidonContext(const ParametersLiteral &param_literal, bool using_hardware = false);
    PoseidonContext(const PoseidonContext &context) = default;
    ~PoseidonContext() = default;

    POSEIDON_NODISCARD inline shared_ptr<const poseidon::ParametersLiteral>
    parameters_literal() const
    {
        return parameters_literal_;
    }

    POSEIDON_NODISCARD inline KeySwitchVariant key_switch_variant() const
    {
        return key_switch_variant_;
    }

    POSEIDON_NODISCARD inline shared_ptr<CrtContext> crt_context() const { return crt_context_; }

#ifdef USING_HARDWARE
    POSEIDON_NODISCARD inline shared_ptr<HardwareContext> hardware_context() const
    {
        return hardware_context_;
    }
#endif

    POSEIDON_NODISCARD inline bool using_hardware() const { return using_hardware_; }

    inline void
    set_random_generator(std::shared_ptr<UniformRandomGeneratorFactory> random_generator) noexcept
    {
        random_generator_ = std::move(random_generator);
    }
    POSEIDON_NODISCARD inline std::shared_ptr<UniformRandomGeneratorFactory>
    random_generator() const noexcept
    {
        return random_generator_;
    }

private:
    std::shared_ptr<const poseidon::ParametersLiteral> parameters_literal_{nullptr};
    std::shared_ptr<CrtContext> crt_context_{nullptr};

#ifdef USING_HARDWARE
    std::shared_ptr<HardwareContext> hardware_context_{nullptr};
#endif

    std::shared_ptr<UniformRandomGeneratorFactory> random_generator_{nullptr};
    sec_level_type sec_level_ = sec_level_type::none;
    KeySwitchVariant key_switch_variant_ = GHS;
    bool using_hardware_ = false;
};

}  // namespace poseidon
