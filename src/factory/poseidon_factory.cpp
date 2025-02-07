#include "poseidon_factory.h"

#ifdef USING_HARDWARE
#include "poseidon_hardware/evaluator/evaluator_bfv_hardware.h"
#include "poseidon_hardware/evaluator/evaluator_bgv_hardware.h"
#include "poseidon_hardware/evaluator/evaluator_ckks_hardware.h"
#endif

namespace poseidon
{
PoseidonFactory *PoseidonFactory::factory_{nullptr};
std::mutex PoseidonFactory::mtx_;

PoseidonFactory::PoseidonFactory(DEVICE_TYPE type) : device_type_(type) {}

PoseidonFactory *PoseidonFactory::get_instance()
{
    std::lock_guard<std::mutex> lck(mtx_);
    if (factory_ == nullptr)
    {
#ifdef USING_HARDWARE
        factory_ = new PoseidonFactory(DEVICE_TYPE::DEVICE_HARDWARE);
#else
        factory_ = new PoseidonFactory(DEVICE_TYPE::DEVICE_SOFTWARE);
#endif
    }
    return factory_;
}

PoseidonContext
PoseidonFactory::create_poseidon_context(const ParametersLiteral &param_literal) const
{
#ifdef USING_HARDWARE
    if (DEVICE_TYPE::DEVICE_HARDWARE == device_type_)
    {
        return PoseidonContext(param_literal, true);
    }
#endif
    return PoseidonContext(param_literal, false);
}

std::unique_ptr<EvaluatorBfvBase>
PoseidonFactory::create_bfv_evaluator(PoseidonContext &context) const
{
#ifdef USING_HARDWARE
    if (DEVICE_TYPE::DEVICE_HARDWARE == device_type_)
    {
        return std::make_unique<EvaluatorBfvHardware>(context);
    }
#endif
    return std::make_unique<EvaluatorBfvSoftware>(context);
}

std::unique_ptr<EvaluatorBgvBase>
PoseidonFactory::create_bgv_evaluator(PoseidonContext &context) const
{
#ifdef USING_HARDWARE
    if (DEVICE_TYPE::DEVICE_HARDWARE == device_type_)
    {
        return std::make_unique<EvaluatorBgvHardware>(context);
    }
#endif
    return std::make_unique<EvaluatorBgvSoftware>(context);
}

std::unique_ptr<EvaluatorCkksBase>
PoseidonFactory::create_ckks_evaluator(PoseidonContext &context) const
{
#ifdef USING_HARDWARE
    if (DEVICE_TYPE::DEVICE_HARDWARE == device_type_)
    {
        return std::make_unique<EvaluatorCkksHardware>(context);
    }
#endif
    return std::make_unique<EvaluatorCkksSoftware>(context);
}

DEVICE_TYPE PoseidonFactory::get_device_type() const { return device_type_; }

void PoseidonFactory::set_device_type(DEVICE_TYPE type)
{
#ifdef USING_HARDWARE
    if (type != DEVICE_TYPE::DEVICE_SOFTWARE && type != DEVICE_TYPE::DEVICE_HARDWARE)
    {
        POSEIDON_THROW(invalid_argument_error, "device type switch error!");
    }
#else
    if (type != DEVICE_TYPE::DEVICE_SOFTWARE)
    {
        POSEIDON_THROW(invalid_argument_error, "device type only support software!");
    }
#endif
    device_type_ = type;
}

}  // namespace poseidon
