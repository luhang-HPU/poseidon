#include "poseidon/util/thread_pool.h"
#include <cstddef>
#include <thread>

namespace poseidon_codegen {

// Generated from examples/ckks/knn.cpp:sign_2.
// This prototype emits a conservative schedule skeleton for the extracted HE calls.
template <typename SetupFn>
void run_sign_2_parallel(SetupFn &&emit_serial_statement,
                           std::size_t he_dag_threads = std::thread::hardware_concurrency())
{
    poseidon::ThreadPool pool(he_dag_threads == 0 ? 1 : he_dag_threads);

    // layer 0
    emit_serial_statement(R"stmt(ciph_result = ciph;)stmt");

    // layer 1
    emit_serial_statement(R"stmt(eva->evaluate_poly_vector(ciph_result, ciph_result, polys, ciph_result.scale(), relin_keys, encoder);)stmt");

}

}  // namespace poseidon_codegen
