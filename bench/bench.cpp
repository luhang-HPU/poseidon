#include "bench.h"
#include <iomanip>

using namespace benchmark;
using namespace poseidon;
using namespace poseidonbench;
using namespace std;

namespace poseidonbench
{

#define POSEIDON_BENCHMARK_REGISTER(category, n, log_q, name, func, ...)                                                  \
    RegisterBenchmark(                                                                                                \
        (string("n=") + to_string(n) + string(" / log(q)=") + to_string(log_q) + string(" / " #category " / " #name)) \
            .c_str(),                                                                                                 \
        [=](State &st) { func(st, __VA_ARGS__); })                                                                    \
        ->Unit(benchmark::kMicrosecond)                                                                               \
        ->Iterations(10);

struct ParametersLiteralComparator
{
    bool operator()(const poseidon::ParametersLiteralDefault &a,
                    const poseidon::ParametersLiteralDefault &b) const
    {
        // 按照 log_n 排序，如果相同则按照 scheme 排序
        if (a.log_n() != b.log_n())
        {
            return a.log_n() < b.log_n();
        }
        return static_cast<int>(a.scheme()) < static_cast<int>(b.scheme());
    }
};

void register_bm_family(
    const size_t degree,
    std::map<ParametersLiteralDefault, shared_ptr<BMEnv>, ParametersLiteralComparator> &bm_env_map)
{
    // For BFV benchmark cases
    ParametersLiteralDefault parms_bfv(BFV, degree);
    shared_ptr<BMEnv> bm_env_bfv = bm_env_map.find(parms_bfv)->second;

    // For BGV benchmark cases
    ParametersLiteralDefault parms_bgv(BGV, degree);
    shared_ptr<BMEnv> bm_env_bgv = bm_env_map.find(parms_bgv)->second;

    // For CKKS / KeyGen / Util benchmark cases
    ParametersLiteralDefault parms_ckks(CKKS, degree);
    shared_ptr<BMEnv> bm_env_ckks = bm_env_map.find(parms_ckks)->second;

    // Registration / display order:
    // 1. KeyGen
    // 2. BFV
    // 3. BGV
    // 4. CKKS
    // 5. Util
    int n = static_cast<int>(degree);
    int log_q = static_cast<int>(bm_env_map.find(parms_ckks)
                                     ->second->context()
                                     .crt_context()
                                     ->key_context_data()
                                     ->total_coeff_modulus_bit_count());
    // POSEIDON_BENCHMARK_REGISTER(KeyGen, n, log_q, Secret, bm_keygen_secret, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(KeyGen, n, log_q, Public, bm_keygen_public, bm_env_bfv);
    // if (bm_env_bfv->context().using_keyswitching())
    // {
    //     POSEIDON_BENCHMARK_REGISTER(KeyGen, n, log_q, Relin, bm_keygen_relin, bm_env_bfv);
    //     POSEIDON_BENCHMARK_REGISTER(KeyGen, n, log_q, Galois, bm_keygen_galois, bm_env_bfv);
    // }

    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EncryptSecret, bm_bfv_encrypt_secret, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EncryptPublic, bm_bfv_encrypt_public, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, Decrypt, bm_bfv_decrypt, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EncodeBatch, bm_bfv_encode_batch, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, DecodeBatch, bm_bfv_decode_batch, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateAddCt, bm_bfv_add_ct, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateAddPt, bm_bfv_add_pt, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateNegate, bm_bfv_negate, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSubCt, bm_bfv_sub_ct, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSubPt, bm_bfv_sub_pt, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateMulCt, bm_bfv_mul_ct, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateMulPt, bm_bfv_mul_pt, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateSquare, bm_bfv_square, bm_env_bfv);
    // if (bm_env_bfv->context().first_context_data()->parms().coeff_modulus().size() > 1)
    // {
    //     POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateModSwitchInplace,
    //     bm_bfv_modswitch_inplace, bm_env_bfv);
    // }
    // if (bm_env_bfv->context().using_keyswitching())
    // {
    //     POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateRelinInplace, bm_bfv_relin_inplace,
    //     bm_env_bfv); POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q, EvaluateRotateRows,
    //     bm_bfv_rotate_rows, bm_env_bfv); POSEIDON_BENCHMARK_REGISTER(BFV, n, log_q,
    //     EvaluateRotateCols, bm_bfv_rotate_cols, bm_env_bfv);
    // }

    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EncryptSecret, bm_bgv_encrypt_secret, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EncryptPublic, bm_bgv_encrypt_public, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, Decrypt, bm_bgv_decrypt, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EncodeBatch, bm_bgv_encode_batch, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, DecodeBatch, bm_bgv_decode_batch, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateNegate, bm_bgv_negate, bm_env_bgv);
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateNegateInplace, bm_bgv_negate_inplace,
    // bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddCt, bm_bgv_add_ct,
    // bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddCtInplace,
    // bm_bgv_add_ct_inplace, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddPt,
    // bm_bgv_add_pt, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateAddPtInplace,
    // bm_bgv_add_pt_inplace, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulCt,
    // bm_bgv_mul_ct, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulCtInplace,
    // bm_bgv_mul_ct_inplace, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulPt,
    // bm_bgv_mul_pt, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateMulPtInplace,
    // bm_bgv_mul_pt_inplace, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateSquare,
    // bm_bgv_square, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateSquareInplace,
    // bm_bgv_square_inplace, bm_env_bgv); if
    // (bm_env_bgv->context().first_context_data()->parms().coeff_modulus().size() > 1)
    // {
    //     POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateModSwitchInplace,
    //     bm_bgv_modswitch_inplace, bm_env_bgv);
    // }
    // if (bm_env_bgv->context().using_keyswitching())
    // {
    //     POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRelinInplace, bm_bgv_relin_inplace,
    //     bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateRows,
    //     bm_bgv_rotate_rows, bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q,
    //     EvaluateRotateRowsInplace, bm_bgv_rotate_rows_inplace, bm_env_bgv);
    //     POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateCols, bm_bgv_rotate_cols,
    //     bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateRotateColsInplace,
    //     bm_bgv_rotate_cols_inplace, bm_env_bgv);
    // }
    // POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateToNTTInplace, bm_bgv_to_ntt_inplace,
    // bm_env_bgv); POSEIDON_BENCHMARK_REGISTER(BGV, n, log_q, EvaluateFromNTTInplace,
    // bm_bgv_from_ntt_inplace, bm_env_bgv);

    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EncryptSecret, bm_ckks_encrypt_secret, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EncryptPublic, bm_ckks_encrypt_public, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, Decrypt, bm_ckks_decrypt, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EncodeDouble, bm_ckks_encode_double, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, DecodeDouble, bm_ckks_decode_double, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateAddCt, bm_ckks_add_ct, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateAddPt, bm_ckks_add_pt, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateNegate, bm_ckks_negate, bm_env_ckks);
    POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSubCt, bm_ckks_sub_ct, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSubPt, bm_ckks_sub_pt, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateMulCt, bm_ckks_mul_ct, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateMulPt, bm_ckks_mul_pt, bm_env_ckks);
    // POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateSquare, bm_ckks_square, bm_env_ckks);
    // if (bm_env_ckks->context().first_context_data()->parms().coeff_modulus().size() > 1)
    // {
    //     POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRescaleInplace, bm_ckks_rescale_inplace,
    //     bm_env_ckks);
    // }
    // if (bm_env_ckks->context().using_keyswitching())
    // {
    //     POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRelinInplace, bm_ckks_relin_inplace,
    //     bm_env_ckks); POSEIDON_BENCHMARK_REGISTER(CKKS, n, log_q, EvaluateRotate, bm_ckks_rotate,
    //     bm_env_ckks);
    // }
    // POSEIDON_BENCHMARK_REGISTER(UTIL, n, log_q, NTTForward, bm_util_ntt_forward, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(UTIL, n, log_q, NTTInverse, bm_util_ntt_inverse, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(UTIL, n, 0, NTTForwardLowLevel, bm_util_ntt_forward_low_level,
    // bm_env_bfv); POSEIDON_BENCHMARK_REGISTER(UTIL, n, 0, NTTInverseLowLevel,
    // bm_util_ntt_inverse_low_level, bm_env_bfv); POSEIDON_BENCHMARK_REGISTER(UTIL, n, 0,
    // NTTForwardLowLevelLazy, bm_util_ntt_forward_low_level_lazy, bm_env_bfv);
    // POSEIDON_BENCHMARK_REGISTER(UTIL, n, 0, NTTInverseLowLevelLazy,
    // bm_util_ntt_inverse_low_level_lazy, bm_env_bfv);
}

} // namespace poseidonbench

int main(int argc, char **argv)
{
    Initialize(&argc, argv);
    cout << "Running precomputations ..." << endl;

    vector<size_t> bm_parms_vec = {4096, 8192, 16384, 32768};
    std::map<ParametersLiteralDefault, shared_ptr<BMEnv>, ParametersLiteralComparator> bm_env_map;

    for (auto &i : bm_parms_vec)
    {
        ParametersLiteralDefault parms_bfv(BFV, i);
        ParametersLiteralDefault parms_bgv(BGV, i);
        ParametersLiteralDefault parms_ckks(CKKS, i);
        // EncryptionParameters parms_bfv(scheme_type::bfv);
        // parms_bfv.set_poly_modulus_degree(i.first);
        // parms_bfv.set_coeff_modulus(i.second);
        // parms_bfv.set_plain_modulus(PlainModulus::Batching(i.first, 20));
        // EncryptionParameters parms_bgv(scheme_type::bgv);
        // parms_bgv.set_poly_modulus_degree(i.first);
        // parms_bgv.set_coeff_modulus(i.second);
        // parms_bgv.set_plain_modulus(PlainModulus::Batching(i.first, 20));
        // EncryptionParameters parms_ckks(scheme_type::ckks);
        // parms_ckks.set_poly_modulus_degree(i.first);
        // parms_ckks.set_coeff_modulus(i.second);

        if (bm_env_map.emplace(make_pair(parms_bfv, make_shared<BMEnv>(parms_bfv))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
        if (bm_env_map.emplace(make_pair(parms_bgv, make_shared<BMEnv>(parms_bgv))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
        if (bm_env_map.emplace(make_pair(parms_ckks, make_shared<BMEnv>(parms_ckks))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
    }

    cout << "[" << setw(7) << right << (poseidon::MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB] "
         << "Total allocation from the memory pool" << endl;

    // For each parameter set in bm_parms_vec, register a family of benchmark cases.
    for (auto &i : bm_parms_vec)
    {
        poseidonbench::register_bm_family(i, bm_env_map);
    }

    RunSpecifiedBenchmarks();

    // After running all benchmark cases, we print again the total memory consumption by SEAL memory pool.
    // This value should be larger than the previous amount but not by much.
    cout << "[" << setw(7) << right << (poseidon::MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB] "
         << "Total allocation from the memory pool" << endl;
}
