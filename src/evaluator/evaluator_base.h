#pragma once

#include "src/advance/homomorphic_linear_transform.h"
#include "src/ciphertext.h"
#include "src/key/galoiskeys.h"
#include "src/key/relinkeys.h"
#include "src/plaintext.h"

namespace poseidon
{

class EvaluatorBase
{
public:
    virtual void read(Plaintext &plain) const = 0;
    virtual void read(Ciphertext &ciph) const = 0;

    virtual void ntt_fwd(const Plaintext &plain, Plaintext &result,
                         parms_id_type id = parms_id_zero) const = 0;
    virtual void ntt_fwd(const Ciphertext &ciph, Ciphertext &result) const = 0;
    virtual void ntt_inv(const Ciphertext &ciph, Ciphertext &result) const = 0;

    virtual void sub_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const = 0;

    virtual void add_plain(const Ciphertext &ciph, const Plaintext &plain,
                           Ciphertext &result) const = 0;
    virtual void multiply_plain(const Ciphertext &ciph, const Plaintext &plain,
                                Ciphertext &result) const = 0;
    virtual void add(const poseidon::Ciphertext &ciph1, const poseidon::Ciphertext &ciph2,
                     poseidon::Ciphertext &result) const = 0;
    virtual void sub(const Ciphertext &ciph1, const Ciphertext &ciph2,
                     Ciphertext &result) const = 0;
    virtual void multiply(const Ciphertext &ciph1, const Ciphertext &ciph2,
                          Ciphertext &result) const = 0;
    virtual void square_inplace(Ciphertext &ciph) const = 0;
    virtual void relinearize(const Ciphertext &ciph, Ciphertext &result,
                             const RelinKeys &relin_keys) const = 0;
    virtual void multiply_relin(const Ciphertext &ciph1, const Ciphertext &ciph2,
                                Ciphertext &result, const RelinKeys &relin_keys) const = 0;
    virtual void rotate(const Ciphertext &ciph, Ciphertext &result, int step,
                        const GaloisKeys &galois_keys) const = 0;
    virtual void rotate_row(const Ciphertext &ciph, Ciphertext &result, int step,
                            const GaloisKeys &galois_keys) const = 0;
    virtual void rotate_col(const Ciphertext &ciph, Ciphertext &result,
                            const GaloisKeys &galois_keys) const = 0;
    virtual void multiply_by_diag_matrix_bsgs(const Ciphertext &ciph, const MatrixPlain &plain_mat,
                                              Ciphertext &result,
                                              const GaloisKeys &rot_key) const = 0;
    virtual void multiply_by_diag_matrix_bsgs_with_mutex(const Ciphertext &ciph,
                                                         MatrixPlain &plain_mat, Ciphertext &result,
                                                         const GaloisKeys &rot_key,
                                                         std::map<int, std::vector<int>> &ref1,
                                                         std::vector<int> &ref2,
                                                         std::vector<int> &ref3) const
    {
    }

    virtual void drop_modulus(const Ciphertext &ciph, Ciphertext &result,
                              parms_id_type parms_id) const = 0;
    virtual void drop_modulus(const Ciphertext &ciph, Ciphertext &result, uint32_t level) const;
    virtual void drop_modulus_to_next(const Ciphertext &ciph, Ciphertext &result) const;
    void transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id,
                                  MemoryPoolHandle pool = MemoryManager::GetPool()) const;
    void transform_to_ntt_inplace(Ciphertext &plain) const;

protected:
    EvaluatorBase(const PoseidonContext &context, MemoryPoolHandle pool = MemoryManager::GetPool());
    virtual ~EvaluatorBase() = default;

    template <typename T, typename S>
    POSEIDON_NODISCARD inline bool are_same_scale(const T &value1, const S &value2) noexcept
    {
        return util::are_approximate<double>(value1.scale(), value2.scale());
    }

protected:
    
    static void ntt_fwd_b(const Plaintext &plain, Plaintext &result);
    static void ntt_fwd_b(const Ciphertext &ciph, Ciphertext &result);
    static void ntt_inv_b(const Plaintext &plain, Plaintext &result);
    static void ntt_inv_b(const Ciphertext &ciph, Ciphertext &result);

protected:
    MemoryPoolHandle pool_;
    PoseidonContext context_;
};
}  // namespace poseidon
