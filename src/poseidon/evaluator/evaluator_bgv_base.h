#pragma once

#include "evaluator_base.h"
#include "poseidon/key/keyswitch.h"

namespace poseidon
{
class EvaluatorBgvBase : public EvaluatorBase
{
    using Base = EvaluatorBase;

public:
    explicit EvaluatorBgvBase(const PoseidonContext &context);
    virtual ~EvaluatorBgvBase() = default;

public:
    void drop_modulus(const Ciphertext &ciph, Ciphertext &result, uint32_t level) const;
    void drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const;

public:
    virtual void multiply_by_diag_matrix_bsgs(const Ciphertext &ciph, const MatrixPlain &plain_mat,
                                              Ciphertext &result,
                                              const GaloisKeys &rot_key) const override;
    virtual void ntt_fwd(const Plaintext &plain, Plaintext &result,
                         parms_id_type parms_id = parms_id_zero) const override;
    virtual void ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const override;
    virtual void ntt_inv(const Ciphertext &ciph, Ciphertext &result) const override;
    virtual void square_inplace(Ciphertext &ciph,
                                MemoryPoolHandle pool = MemoryManager::GetPool()) const override;

    virtual void add(const Ciphertext &ciph1, const Ciphertext &ciph2,
                     Ciphertext &result) const override;
    virtual void sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                     Ciphertext &result) const override;
    virtual void add_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const override;
    virtual void sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const override;
    virtual void multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                          Ciphertext &result) const override;
    virtual void relinearize(const Ciphertext &ciph1, Ciphertext &result,
                             const RelinKeys &relin_keys) const override;
    virtual void multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result, const RelinKeys &relin_keys) const override;
    virtual void rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                        const GaloisKeys &galois_keys) const override;
    virtual void rotate_row(const Ciphertext &ciph, Ciphertext &result, int rot_step,
                            const GaloisKeys &galois_keys) const override;
    virtual void rotate_col(const Ciphertext &ciph, Ciphertext &result,
                            const GaloisKeys &galois_keys) const override;
    virtual void drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                              parms_id_type parms_id) const override;
    virtual void rescale(Ciphertext &ciph) const;
    void add_inplace(Ciphertext &ciph1, const Ciphertext &ciph2) const;
    virtual void apply_galois(const Ciphertext &ciph, Ciphertext &destination, std::uint32_t galois_elt,
                      const GaloisKeys &galois_keys,
                      MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    void add_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const;

    void sub_plain_inplace(Ciphertext &ciph, const Plaintext &plain) const;

    void bgv_multiply(Ciphertext &ciph1, const Ciphertext &ciph2, MemoryPoolHandle pool) const;
    void multiply_inplace(Ciphertext &ciph1, const Ciphertext &ciph2,
                          MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    virtual void
    multiply_plain_inplace(Ciphertext &ciph, const Plaintext &plain,
                           MemoryPoolHandle pool = MemoryManager::GetPool()) const override;
    void multiply_plain_ntt(Ciphertext &ciph_ntt, const Plaintext &plain_ntt) const;

    // void multiply_plain_normal(Ciphertext &ciph, const Plaintext &plain,
    //                            MemoryPoolHandle pool) const;

private:
    std::shared_ptr<KSwitchBase> kswitch_{nullptr};
};
}  // namespace poseidon
