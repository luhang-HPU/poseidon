#include "bench.h"

using namespace benchmark;
using namespace poseidonbench;
using namespace poseidon;
using namespace std;

/**
This file defines benchmarks for CKKS-specific HE primitives.
*/

namespace poseidonbench
{
    void bm_ckks_encrypt_secret(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_pt_ckks(pt, scale);

            state.ResumeTiming();
            bm_env->encryptor()->encrypt_symmetric(pt, ct[2]);
        }
    }

    void bm_ckks_encrypt_public(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_pt_ckks(pt, scale);

            state.ResumeTiming();
            bm_env->encryptor()->encrypt(pt, ct[2]);
        }
    }

    void bm_ckks_decrypt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);

            state.ResumeTiming();
            bm_env->decryptor()->decrypt(ct[0], pt);
        }
    }

    void bm_ckks_encode_double(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<double> &msg = bm_env->msg_double();
        Plaintext &pt = bm_env->pt()[0];
        parms_id_type parms_id = bm_env->context().crt_context()->first_parms_id();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_message_double(msg);

            state.ResumeTiming();
            bm_env->ckks_encoder()->encode(msg, parms_id, scale, pt);
        }
    }

    void bm_ckks_decode_double(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<double> &msg = bm_env->msg_double();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_pt_ckks(pt, scale);

            state.ResumeTiming();
            bm_env->ckks_encoder()->decode(pt, msg);
        }
    }

    void bm_ckks_add_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            bm_env->randomize_ct_ckks(ct[1], scale);
            state.ResumeTiming();
            Ciphertext res;
            bm_env->evaluator()->add(ct[0], ct[1], res);
        }
    }

    void bm_ckks_add_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            bm_env->randomize_pt_ckks(pt, scale);
            state.ResumeTiming();
            bm_env->evaluator()->add_plain(ct[0], pt, ct[2]);
        }
    }

//     void bm_ckks_negate(State &state, shared_ptr<BMEnv> bm_env)
//     {
//         vector<Ciphertext> &ct = bm_env->ct();
//         double scale = bm_env->safe_scale();
//         for (auto _ : state)
//         {
//             state.PauseTiming();
//             bm_env->randomize_ct_ckks(ct[0], scale);

//             state.ResumeTiming();
//             bm_env->evaluator()->negate(ct[0], ct[2]);
//         }
//     }

    void bm_ckks_sub_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            bm_env->randomize_ct_ckks(ct[1], scale);
            state.ResumeTiming();
            bm_env->evaluator()->sub(ct[0], ct[1], ct[2]);
        }
    }

    // void bm_ckks_sub_pt(State &state, shared_ptr<BMEnv> bm_env)
    // {
    //     vector<Ciphertext> &ct = bm_env->ct();
    //     Plaintext &pt = bm_env->pt()[0];
    //     double scale = bm_env->safe_scale();
    //     for (auto _ : state)
    //     {
    //         state.PauseTiming();
    //         bm_env->randomize_ct_ckks(ct[0], scale);
    //         bm_env->randomize_pt_ckks(pt, scale);

    //         state.ResumeTiming();
    //         bm_env->evaluator()->sub_plain(ct[0], pt, ct[2]);
    //     }
    // }

    void bm_ckks_mul_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            bm_env->randomize_ct_ckks(ct[1], scale);

            state.ResumeTiming();
            bm_env->evaluator()->multiply(ct[0], ct[1], ct[2]);
        }
    }

    void bm_ckks_mul_pt(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        Plaintext &pt = bm_env->pt()[0];
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);

            // auto slot_num = ckks_param_literal.slot();
            // vector<complex<double>> msg1;
            // sample_random_complex_vector(msg1, slot_num);
            // bm_env->ckks_encoder()->encode(msg1, ct[0].parms_id(), scale, pt);
            bm_env->randomize_pt_ckks(pt, scale);

            state.ResumeTiming();
            bm_env->evaluator()->multiply_plain(ct[0], pt, ct[2]);
        }
    }

    void bm_ckks_square(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            bm_env->randomize_ct_ckks(ct[1], scale);

            state.ResumeTiming();
            bm_env->evaluator()->square(ct[0], ct[2]);
        }
    }

    void bm_ckks_rescale(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale() * pow(2.0, 20);
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            poseidon::EvaluatorCkksBase* ckks_evaluator =
                dynamic_cast<poseidon::EvaluatorCkksBase*>(bm_env->evaluator().get());
    
            state.ResumeTiming();
            ckks_evaluator->rescale(ct[0], ct[0]);
        }
    }

    void bm_ckks_relinearize(State &state, shared_ptr<BMEnv> bm_env)
    {
        Ciphertext ct;
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            ct.resize(bm_env->context(), size_t(3));
            bm_env->randomize_ct_ckks(ct, scale);

            state.ResumeTiming();
            bm_env->evaluator()->relinearize(ct, ct, bm_env->rlk());
        }
    }

    void bm_ckks_rotate(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0], scale);
            state.ResumeTiming();
            bm_env->evaluator()->rotate(ct[0], ct[2], 1, bm_env->glk());
        }
    }
} // namespace poseidonbench
