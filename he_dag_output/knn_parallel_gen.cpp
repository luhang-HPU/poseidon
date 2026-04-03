#include "poseidon/util/thread_pool.h"
#include <cstddef>
#include <thread>

namespace poseidon_codegen {

// Generated from tools/he_dag/samples/knn_ckks_demo.cpp:knn_ckks_demo.
// This prototype emits a conservative schedule skeleton for the extracted HE calls.
template <typename SetupFn>
void run_knn_ckks_demo_parallel(SetupFn &&emit_serial_statement,
                           std::size_t he_dag_threads = std::thread::hardware_concurrency())
{
    poseidon::ThreadPool pool(he_dag_threads == 0 ? 1 : he_dag_threads);

    // layer 0
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva.sub(query, train0, diff0);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva.sub(query, train1, diff1);)stmt");
    });
    pool.wait_all();

    // layer 1
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva.multiply(diff0, diff0, sq0);)stmt");
    });
    pool.enqueue([&]() {
        emit_serial_statement(R"stmt(ckks_eva.multiply(diff1, diff1, sq1);)stmt");
    });
    pool.wait_all();

    // layer 2
    emit_serial_statement(R"stmt(ckks_eva.rotate(sq0, rot0, 1, galois_keys);)stmt");

    // layer 3
    emit_serial_statement(R"stmt(ckks_eva.add(rot0, sq1, total);)stmt");

}

}  // namespace poseidon_codegen
