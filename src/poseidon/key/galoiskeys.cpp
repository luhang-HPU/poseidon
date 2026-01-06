#include "galoiskeys.h"
#include "galoiskeys.h"
#ifdef USING_HARDWARE
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon_hardware/hardware_drive/ckks_hardware_api.h"
#endif

namespace poseidon
{
std::streamoff GaloisKeys::load(const PoseidonContext &context, std::istream &stream)
{
    GaloisKeys new_keys;
    new_keys.pool_ = pool_;
    auto in_size = new_keys.unsafe_load(context, stream);
    std::swap(*this, new_keys);

#ifdef USING_HARDWARE
    if (PoseidonFactory::get_instance()->get_device_type() == DEVICE_TYPE::DEVICE_HARDWARE)
    {
        auto literal = context.parameters_literal();
        auto degree = literal->degree();
        auto rns_max = literal->q().size() + literal->p().size();
        auto galois_tool = context.crt_context()->galois_tool();
        HardwareApi::galois_key_config(*this, galois_tool, rns_max, degree);
        HardwareApi::permutation_tables_config(*this, galois_tool, rns_max, degree);
    }
#endif
    return in_size;
}

std::streamoff GaloisKeys::load(const PoseidonContext &context, const poseidon_byte *in,
                                std::size_t size)
{
    GaloisKeys new_keys;
    new_keys.pool_ = pool_;
    auto in_size = new_keys.unsafe_load(context, in, size);
    std::swap(*this, new_keys);
#ifdef USING_HARDWARE
    if (PoseidonFactory::get_instance()->get_device_type() == DEVICE_TYPE::DEVICE_HARDWARE)
    {
        auto literal = context.parameters_literal();
        auto degree = literal->degree();
        auto rns_max = literal->q().size() + literal->p().size();
        auto galois_tool = context.crt_context()->galois_tool();
        HardwareApi::galois_key_config(*this, galois_tool, rns_max, degree);
        HardwareApi::permutation_tables_config(*this, galois_tool, rns_max, degree);
    }
#endif
    return in_size;
}

}  // namespace poseidon
