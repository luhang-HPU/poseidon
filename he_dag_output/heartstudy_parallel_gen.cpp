#include "poseidon/util/thread_pool.h"
#include <cstddef>
#include <thread>

namespace poseidon_codegen {

// Generated from examples/ckks/test_ckks_heartstudy.cpp:main.
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
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_age, ckks_param_literal.scale(), plain_age);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_sbp, ckks_param_literal.scale(), plain_sbp);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_dbp, ckks_param_literal.scale(), plain_dbp);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_chl, ckks_param_literal.scale(), plain_chl);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_weight, ckks_param_literal.scale(), plain_weight);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_encoder.encode(message_height, ckks_param_literal.scale(), plain_height);)stmt");
    });
    pool.wait_all();

    // layer 1
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_age, cipher_age);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_sbp, cipher_sbp);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_dbp, cipher_dbp);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_chl, cipher_chl);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_weight, cipher_weight);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(enc.encrypt(plain_height, cipher_height);)stmt");
    });
    pool.wait_all();

    // layer 2
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_age, coef_age, scale, cipher_age, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_sbp, coef_sbp, scale, cipher_sbp, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_dbp, coef_dbp, scale, cipher_dbp, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_chl, coef_chl, scale, cipher_chl, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_weight, coef_weight, scale, cipher_weight, ckks_encoder);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_height, coef_height, scale, cipher_height, ckks_encoder);)stmt");
    });
    pool.wait_all();

    // layer 3
    emit_serial_statement(R"stmt(ckks_eva->add(cipher_age, cipher_sbp, cipher_x);)stmt");

    // layer 4
    emit_serial_statement(R"stmt(ckks_eva->add(cipher_x, cipher_dbp, cipher_x);)stmt");

    // layer 5
    emit_serial_statement(R"stmt(ckks_eva->add(cipher_x, cipher_chl, cipher_x);)stmt");

    // layer 6
    emit_serial_statement(R"stmt(ckks_eva->add(cipher_x, cipher_weight, cipher_x);)stmt");

    // layer 7
    emit_serial_statement(R"stmt(ckks_eva->add(cipher_x, cipher_height, cipher_x);)stmt");

    // layer 8
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(cipher_x, cipher_x, scale);)stmt");

    // layer 9
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin_dynamic(cipher_x, cipher_x, cipher_x_square, relin_keys);)stmt");

    // layer 10
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(cipher_x_square, cipher_x_square, scale);)stmt");

    // layer 11
    emit_serial_statement(R"stmt(ckks_eva->multiply_const(cipher_x_square, taylor_coef_9, scale, cipher_result, ckks_encoder);)stmt");

    // layer 12
    emit_serial_statement(R"stmt(ckks_eva->add_const(cipher_result, taylor_coef_7, cipher_result, ckks_encoder);)stmt");

    // layer 13
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);)stmt");

    // layer 14
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);)stmt");

    // layer 15
    emit_serial_statement(R"stmt(ckks_eva->add_const(cipher_result, taylor_coef_5, cipher_result, ckks_encoder);)stmt");

    // layer 16
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);)stmt");

    // layer 17
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);)stmt");

    // layer 18
    emit_serial_statement(R"stmt(ckks_eva->add_const(cipher_result, taylor_coef_3, cipher_result, ckks_encoder);)stmt");

    // layer 19
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);)stmt");

    // layer 20
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);)stmt");

    // layer 21
    emit_serial_statement(R"stmt(ckks_eva->add_const(cipher_result, taylor_coef_1, cipher_result, ckks_encoder);)stmt");

    // layer 22
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x, cipher_result, relin_keys);)stmt");

    // layer 23
    emit_serial_statement(R"stmt(ckks_eva->add_const(cipher_result, taylor_coef_0, cipher_result, ckks_encoder);)stmt");

    // layer 24
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->read(cipher_result);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(dec.decrypt(cipher_result, plain_result);)stmt");
    });
    pool.wait_all();

}

}  // namespace poseidon_codegen
