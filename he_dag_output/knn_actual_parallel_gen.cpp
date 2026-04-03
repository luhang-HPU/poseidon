#include "poseidon/util/thread_pool.h"
#include <cstddef>
#include <thread>

namespace poseidon_codegen {

// Generated from examples/ckks/knn.cpp:main.
// This prototype emits a conservative schedule skeleton for the extracted HE calls.
template <typename SetupFn>
void run_main_parallel(SetupFn &&emit_serial_statement,
                           std::size_t he_dag_threads = std::thread::hardware_concurrency())
{
    poseidon::ThreadPool pool(he_dag_threads == 0 ? 1 : he_dag_threads);

    // layer 0
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(kgen.create_public_key(public_key);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(kgen.create_relin_keys(relin_keys);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(kgen.create_galois_keys(step, rot_keys);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(cmp_top_k, scale, encode_and_encrypt__3__plain);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(encode_and_encrypt__3__plain, ciph_top_k);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->sub(ciph_data[i + 10], ciph_query[i], ciph_data[i + 10]);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->add(ciph_distance_2, ciph_data[i + dimension], ciph_distance_2);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ciph_tmp = ciph_result;)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(accumulate_top_n_block__17__zero, ciph_tmp.parms_id(), ciph_tmp.scale(), accumulate_top_n_block__17__plain_zero);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(accumulate_top_n_block__17__plain_zero, ciph_result);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(vec_tmp, ciph_top_k.parms_id(), scale * scale / ciph_top_k.scale(), match_scale__23__plt_tmp);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(vec_mask, ciph_result.parms_id(), scale, pl_mask);)stmt");
    });
    pool.wait_all();

    // layer 1
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->add(ciph_result, accumulate_top_n_block__17__ciph_rotate_sum, ciph_result);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->rotate(accumulate_top_n_block__17__ciph_rotate_sum, accumulate_top_n_block__17__ciph_rotate_sum, 100, rot_keys);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_plain(ciph_top_k, match_scale__23__plt_tmp, ciph_top_k);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(} { ckks_encoder.encode(vec_tmp, ciph_result.parms_id(), scale * scale / ciph_result.scale(), match_scale__23__plt_tmp);)stmt");
    });
    pool.wait_all();

    // layer 2
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i], relin_keys);)stmt");

    // layer 3
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin(ciph_data[i + 10], ciph_data[i + 10], ciph_data[i + 10], relin_keys);)stmt");

    // layer 4
    emit_serial_statement(R"stmt(ckks_eva->evaluate_poly_vector(ciph_tmp, ciph_tmp, polys, ciph_tmp.scale(), relin_keys, ckks_encoder);)stmt");

    // layer 5
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->add(accumulate_top_n_block__17__ciph_rotate_sum, ciph_tmp, accumulate_top_n_block__17__ciph_rotate_sum);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(} } ckks_eva->add(ciph_result, accumulate_top_n_block__17__ciph_rotate_sum, ciph_result);)stmt");
    });
    pool.wait_all();

    // layer 6
    emit_serial_statement(R"stmt(ckks_eva->rescale(ciph_top_k, ciph_top_k);)stmt");

    // layer 7
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);)stmt");

    // layer 8
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_data[i + 10], ciph_data[i + 10], scale);)stmt");

    // layer 9
    emit_serial_statement(R"stmt(ckks_eva->evaluate_poly_vector(ciph_tmp, ciph_tmp, polys_1, ciph_tmp.scale(), relin_keys, ckks_encoder);)stmt");

    // layer 10
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->add(ciph_distance_1, ciph_data[i], ciph_distance_1);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->add_const(ciph_tmp, 0.5, ciph_tmp, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_plain(ciph_result, match_scale__23__plt_tmp, ciph_result);)stmt");
    });
    pool.wait_all();

    // layer 11
    emit_serial_statement(R"stmt(ckks_eva->rescale(ciph_result, ciph_result);)stmt");

    // layer 12
    emit_serial_statement(R"stmt(ckks_eva->multiply_const(ciph_result, 0.014, scale, ciph_result, ckks_encoder);)stmt");

    // layer 13
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);)stmt");

    // layer 14
    emit_serial_statement(R"stmt(ciph_result = ciph_result;)stmt");

    // layer 15
    emit_serial_statement(R"stmt(ckks_eva->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys, ckks_encoder);)stmt");

    // layer 16
    emit_serial_statement(R"stmt(ckks_eva->multiply_plain(ciph_result, pl_mask, ciph_result);)stmt");

    // layer 17
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);)stmt");

    // layer 18
    emit_serial_statement(R"stmt(dec.decrypt(ciph_result, decrypt_and_decode__36__plain);)stmt");

}

}  // namespace poseidon_codegen
