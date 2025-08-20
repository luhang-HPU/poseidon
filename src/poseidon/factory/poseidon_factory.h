#pragma once

#include "poseidon/evaluator/software/evaluator_bfv_software.h"
#include "poseidon/evaluator/software/evaluator_bgv_software.h"
#include "poseidon/evaluator/software/evaluator_ckks_software.h"
#include "poseidon/poseidon_context.h"
#include <mutex>

namespace poseidon
{

class EvaluatorBfvBase;
class EvaluatorBgvBase;
class EvaluatorCkksBase;

enum DEVICE_TYPE
{
    DEVICE_SOFTWARE = 1,
    DEVICE_HARDWARE = 2
};

class PoseidonFactory
{
public:
    PoseidonFactory(PoseidonFactory &) = delete;
    void operator=(const PoseidonFactory &) = delete;

    static PoseidonFactory *get_instance();

    [[nodiscard]] PoseidonContext
    create_poseidon_context(const ParametersLiteral &param_literal) const;

    [[nodiscard]] std::unique_ptr<EvaluatorBfvBase>
    create_bfv_evaluator(PoseidonContext &context) const;

    [[nodiscard]] std::unique_ptr<EvaluatorBgvBase>
    create_bgv_evaluator(PoseidonContext &context) const;

    [[nodiscard]] std::unique_ptr<EvaluatorCkksBase>
    create_ckks_evaluator(PoseidonContext &context) const;

    DEVICE_TYPE get_device_type() const;
    void set_device_type(DEVICE_TYPE type);

private:
    PoseidonFactory(DEVICE_TYPE type);
    ~PoseidonFactory() = default;

private:
    static PoseidonFactory *factory_;
    static std::mutex mtx_;

    DEVICE_TYPE device_type_;
};

}  // namespace poseidon
