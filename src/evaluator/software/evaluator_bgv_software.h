#pragma once

#include "src/evaluator/evaluator_bgv_base.h"

namespace poseidon
{

class EvaluatorBgvSoftware : public EvaluatorBgvBase
{

public:
    explicit EvaluatorBgvSoftware(PoseidonContext &context);
    ~EvaluatorBgvSoftware() = default;

    void read(Plaintext &plain) const override;
    void read(Ciphertext &ciph) const override;
};

}  // namespace poseidon
