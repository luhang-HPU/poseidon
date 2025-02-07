#pragma once

#include "src/evaluator/evaluator_ckks_base.h"

namespace poseidon
{

class EvaluatorCkksSoftware : public EvaluatorCkksBase
{
public:
    explicit EvaluatorCkksSoftware(PoseidonContext &context) : EvaluatorCkksBase(context) {}
    ~EvaluatorCkksSoftware() = default;
};

}  // namespace poseidon
