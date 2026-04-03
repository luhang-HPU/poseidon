#include "poseidon/util/thread_pool.h"
#include <cstddef>
#include <thread>

namespace poseidon_codegen {

// Generated from examples/ckks/knn.cpp:sub_and_square.
// This prototype emits a conservative schedule skeleton for the extracted HE calls.
template <typename SetupFn>
void run_sub_and_square_parallel(SetupFn &&emit_serial_statement,
                           std::size_t he_dag_threads = std::thread::hardware_concurrency())
{
    poseidon::ThreadPool pool(he_dag_threads == 0 ? 1 : he_dag_threads);

    // layer 0
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva->sub(ciph_data[i + 10], ciph_query[i], ciph_data[i + 10]);)stmt");
    });
    pool.wait_all();

    // layer 1
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i], relin_keys);)stmt");

    // layer 2
    emit_serial_statement(R"stmt(ckks_eva->multiply_relin(ciph_data[i + 10], ciph_data[i + 10], ciph_data[i + 10], relin_keys);)stmt");

    // layer 3
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);)stmt");

    // layer 4
    emit_serial_statement(R"stmt(ckks_eva->rescale_dynamic(ciph_data[i + 10], ciph_data[i + 10], scale);)stmt");

}

}  // namespace poseidon_codegen
