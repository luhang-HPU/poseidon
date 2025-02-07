#pragma once

#include "src/evaluator/evaluator_bfv_base.h"

namespace poseidon
{

class EvaluatorBfvSoftware : public EvaluatorBfvBase
{
    using Base = EvaluatorBfvBase;

public:
    explicit EvaluatorBfvSoftware(PoseidonContext &context);
    ~EvaluatorBfvSoftware() = default;

public:
    void read(Plaintext &plain) const override;
    void read(Ciphertext &ciph) const override;
};
}  // namespace poseidon
