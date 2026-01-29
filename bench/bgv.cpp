#include "bench.h"

using namespace benchmark;
using namespace poseidonbench;
using namespace poseidon;
using namespace std;

/**
This file defines benchmarks for BGV-specific HE primitives.
*/

namespace poseidonbench
{
void bm_bgv_encrypt_secret(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->encryptor()->encrypt_symmetric(pt, ct[2]);
    }
}

void bm_bgv_encrypt_public(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->encryptor()->encrypt(pt, ct[2]);
    }
}

void bm_bgv_decrypt(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);

        state.ResumeTiming();
        bm_env->decryptor()->decrypt(ct[0], pt);
    }
}

void bm_bgv_encode_batch(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<uint64_t> &msg = bm_env->msg_uint64();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_message_uint64(msg);

        state.ResumeTiming();
        bm_env->batch_encoder()->encode(msg, pt);
    }
}

void bm_bgv_decode_batch(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<uint64_t> &msg = bm_env->msg_uint64();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->batch_encoder()->decode(pt, msg);
    }
}

void bm_bgv_add_ct(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_ct_bgv(ct[1]);
        state.ResumeTiming();
        Ciphertext res;
        bm_env->evaluator()->add(ct[0], ct[1], res);
    }
}

void bm_bgv_add_pt(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->evaluator()->add_plain(ct[0], pt, ct[2]);
    }
}

void bm_bgv_mul_ct(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_ct_bgv(ct[1]);

        state.ResumeTiming();
        bm_env->evaluator()->multiply(ct[0], ct[1], ct[2]);
    }
}

void bm_bgv_mul_pt(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->evaluator()->multiply_plain(ct[0], pt, ct[2]);
    }
}

void bm_bgv_mul_pt_inplace(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    Plaintext &pt = bm_env->pt()[0];
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_pt_bgv(pt);

        state.ResumeTiming();
        bm_env->evaluator()->multiply_plain_inplace(ct[0], pt);
    }
}

void bm_bgv_square(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->randomize_ct_bgv(ct[1]);

        state.ResumeTiming();
        bm_env->evaluator()->square(ct[0], ct[2]);
    }
}

void bm_bgv_square_inplace(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        ct[2].resize(2);
        bm_env->randomize_ct_bgv(ct[2]);

        state.ResumeTiming();
        bm_env->evaluator()->square_inplace(ct[2]);
    }
}

void bm_bgv_modswitch(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);

        state.ResumeTiming();
        bm_env->evaluator()->drop_modulus_to_next(ct[0], ct[0]);
    }
}

void bm_bgv_relinearize(State &state, shared_ptr<BMEnv> bm_env)
{
    Ciphertext ct;
    for (auto _ : state)
    {
        state.PauseTiming();
        ct.resize(bm_env->context(), size_t(3));
        bm_env->randomize_ct_bgv(ct);

        state.ResumeTiming();
        bm_env->evaluator()->relinearize(ct, ct, bm_env->rlk());
    }
}

void bm_bgv_rotate_rows(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);

        state.ResumeTiming();
        bm_env->evaluator()->rotate_row(ct[0], ct[2], 1, bm_env->glk());
    }
}

void bm_bgv_rotate_cols(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);

        state.ResumeTiming();
        bm_env->evaluator()->rotate_col(ct[0], ct[2], bm_env->glk());
    }
}

void bm_bgv_to_ntt_inplace(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);
        bm_env->evaluator()->transform_from_ntt_inplace(ct[0]);

        state.ResumeTiming();
        bm_env->evaluator()->transform_to_ntt_inplace(ct[0]);
    }
}

void bm_bgv_from_ntt_inplace(State &state, shared_ptr<BMEnv> bm_env)
{
    vector<Ciphertext> &ct = bm_env->ct();
    for (auto _ : state)
    {
        state.PauseTiming();
        bm_env->randomize_ct_bgv(ct[0]);

        state.ResumeTiming();
        bm_env->evaluator()->transform_from_ntt_inplace(ct[0]);
    }
}
}  // namespace poseidonbench
