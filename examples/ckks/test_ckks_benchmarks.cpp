#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/examples.h"
#include "poseidon/util/random_sample.h"

#include <condition_variable>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace poseidon;
using namespace poseidon::util;

namespace
{

struct BenchmarkConfig
{
    std::size_t iterations = 10;
    std::size_t threads = std::thread::hardware_concurrency() == 0
                              ? static_cast<std::size_t>(4)
                              : static_cast<std::size_t>(std::thread::hardware_concurrency());
    std::uint32_t degree = 16384;
};

struct BenchmarkFixture
{
    PoseidonContext context;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    std::vector<std::complex<double>> values1;
    std::vector<std::complex<double>> values2;
    double scale = 0.0;
    Plaintext plain1;
    Plaintext plain2;
    Ciphertext cipher1;
    Ciphertext cipher2;
    Ciphertext cipher_mul;
};

struct WorkerState
{
    explicit WorkerState(const BenchmarkFixture &fixture)
        : context(fixture.context),
          pool(MemoryPoolHandle::New()),
          encoder(context),
          encryptor(context, fixture.public_key, fixture.secret_key),
          decryptor(context, fixture.secret_key),
          evaluator(PoseidonFactory::get_instance()->create_ckks_evaluator(context)),
          plain1(fixture.plain1),
          plain2(fixture.plain2),
          cipher1(fixture.cipher1),
          cipher2(fixture.cipher2),
          cipher_mul(fixture.cipher_mul)
    {}

    PoseidonContext context;
    MemoryPoolHandle pool;
    CKKSEncoder encoder;
    Encryptor encryptor;
    Decryptor decryptor;
    std::unique_ptr<EvaluatorCkksBase> evaluator;
    Plaintext plain1;
    Plaintext plain2;
    Plaintext plain_tmp;
    Ciphertext cipher1;
    Ciphertext cipher2;
    Ciphertext cipher_mul;
    Ciphertext cipher_tmp;
    Ciphertext cipher_tmp2;
    std::vector<std::complex<double>> decoded;
};

struct ParallelGate
{
    explicit ParallelGate(std::size_t expected_threads) : expected_threads(expected_threads) {}

    void mark_ready()
    {
        std::lock_guard<std::mutex> lock(mutex);
        ++ready_threads;
        condition.notify_all();
    }

    void wait_until_all_ready()
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&]() { return ready_threads == expected_threads; });
    }

    void release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        started = true;
        condition.notify_all();
    }

    void wait_for_release()
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&]() { return started; });
    }

    std::size_t expected_threads;
    std::size_t ready_threads = 0;
    bool started = false;
    std::mutex mutex;
    std::condition_variable condition;
};

using BenchFn = std::function<void(WorkerState &)>;

[[noreturn]] void print_usage_and_exit(const char *program)
{
    std::cerr << "Usage: " << program
              << " [--iterations N] [--threads N] [--degree N] [--help]" << std::endl;
    std::exit(0);
}

std::size_t parse_positive_size(const std::string &flag, const char *value)
{
    std::size_t parsed = 0;

    try
    {
        parsed = static_cast<std::size_t>(std::stoull(value));
    }
    catch (const std::exception &)
    {
        throw std::invalid_argument("invalid numeric value for " + flag);
    }

    if (parsed == 0)
    {
        throw std::invalid_argument(flag + " must be greater than zero");
    }

    return parsed;
}

BenchmarkConfig parse_args(int argc, char *argv[])
{
    BenchmarkConfig config;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            print_usage_and_exit(argv[0]);
        }

        if (i + 1 >= argc)
        {
            throw std::invalid_argument("missing value for " + arg);
        }

        if (arg == "--iterations")
        {
            config.iterations = parse_positive_size(arg, argv[++i]);
        }
        else if (arg == "--threads")
        {
            config.threads = parse_positive_size(arg, argv[++i]);
        }
        else if (arg == "--degree")
        {
            config.degree = static_cast<std::uint32_t>(parse_positive_size(arg, argv[++i]));
        }
        else
        {
            throw std::invalid_argument("unknown argument: " + arg);
        }
    }

    return config;
}

void print_metric(const std::string &name, double value_ms)
{
    std::cout << std::fixed << std::setprecision(6) << name << " TIME: " << value_ms << " ms"
              << std::endl;
}

double elapsed_ms(const std::chrono::high_resolution_clock::time_point &begin,
                  const std::chrono::high_resolution_clock::time_point &end)
{
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - begin).count();
}

double run_single_thread_benchmark(const BenchmarkFixture &fixture, std::size_t iterations,
                                   const BenchFn &bench_fn)
{
    WorkerState state(fixture);
    bench_fn(state);

    const auto begin = std::chrono::high_resolution_clock::now();
    for (std::size_t i = 0; i < iterations; ++i)
    {
        bench_fn(state);
    }
    const auto end = std::chrono::high_resolution_clock::now();

    return elapsed_ms(begin, end) / static_cast<double>(iterations);
}

double run_parallel_benchmark(const BenchmarkFixture &fixture, std::size_t iterations,
                              std::size_t thread_count, const BenchFn &bench_fn)
{
    ParallelGate gate(thread_count);
    std::vector<std::thread> workers;
    std::vector<std::exception_ptr> errors(thread_count);
    workers.reserve(thread_count);

    for (std::size_t thread_id = 0; thread_id < thread_count; ++thread_id)
    {
        workers.emplace_back([&, thread_id]() {
            std::unique_ptr<WorkerState> state;

            try
            {
                state = std::make_unique<WorkerState>(fixture);
                bench_fn(*state);
            }
            catch (...)
            {
                errors[thread_id] = std::current_exception();
            }

            gate.mark_ready();
            gate.wait_for_release();

            if (errors[thread_id])
            {
                return;
            }

            try
            {
                for (std::size_t i = 0; i < iterations; ++i)
                {
                    bench_fn(*state);
                }
            }
            catch (...)
            {
                errors[thread_id] = std::current_exception();
            }
        });
    }

    gate.wait_until_all_ready();
    const auto begin = std::chrono::high_resolution_clock::now();
    gate.release();

    for (auto &worker : workers)
    {
        worker.join();
    }

    const auto end = std::chrono::high_resolution_clock::now();

    for (const auto &error : errors)
    {
        if (error)
        {
            std::rethrow_exception(error);
        }
    }

    const auto total_ops = static_cast<double>(iterations) * static_cast<double>(thread_count);
    return elapsed_ms(begin, end) / total_ops;
}

BenchmarkFixture create_fixture(const BenchmarkConfig &config)
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);

    const auto setup_begin = std::chrono::high_resolution_clock::now();
    ParametersLiteralDefault params(CKKS, config.degree, poseidon::sec_level_type::tc128);
    BenchmarkFixture fixture{PoseidonFactory::get_instance()->create_poseidon_context(params)};
    const auto context_ready = std::chrono::high_resolution_clock::now();

    KeyGenerator keygen(fixture.context);
    keygen.create_public_key(fixture.public_key);
    fixture.secret_key = keygen.secret_key();
    keygen.create_relin_keys(fixture.relin_keys);
    keygen.create_galois_keys(fixture.galois_keys);
    const auto keys_ready = std::chrono::high_resolution_clock::now();

    CKKSEncoder encoder(fixture.context);
    Encryptor encryptor(fixture.context, fixture.public_key, fixture.secret_key);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(fixture.context);

    fixture.scale = fixture.context.parameters_literal()->scale();
    const auto slot_count = static_cast<int>(fixture.context.parameters_literal()->slot());

    sample_random_complex_vector(fixture.values1, slot_count);
    sample_random_complex_vector(fixture.values2, slot_count);

    encoder.encode(fixture.values1, fixture.scale, fixture.plain1);
    encoder.encode(fixture.values2, fixture.scale, fixture.plain2);
    encryptor.encrypt(fixture.plain1, fixture.cipher1, MemoryPoolHandle::New());
    encryptor.encrypt(fixture.plain2, fixture.cipher2, MemoryPoolHandle::New());
    evaluator->multiply_relin_dynamic(fixture.cipher1, fixture.cipher2, fixture.cipher_mul,
                                      fixture.relin_keys);
    const auto data_ready = std::chrono::high_resolution_clock::now();

    print_metric("Setup/Context", elapsed_ms(setup_begin, context_ready));
    print_metric("Setup/KeyGeneration", elapsed_ms(context_ready, keys_ready));
    print_metric("Setup/DataPreparation", elapsed_ms(keys_ready, data_ready));

    return fixture;
}

void run_benchmark_pair(const BenchmarkFixture &fixture, const BenchmarkConfig &config,
                        const std::string &name, const BenchFn &bench_fn)
{
    print_metric("SingleThread/" + name, run_single_thread_benchmark(fixture, config.iterations, bench_fn));
    print_metric("Parallel/" + name,
                 run_parallel_benchmark(fixture, config.iterations, config.threads, bench_fn));
}

void bench_encoder(const BenchmarkFixture &fixture, const BenchmarkConfig &config)
{
    print_example_banner("CKKS Benchmarks: Encoder");

    run_benchmark_pair(fixture, config, "Encoder/Encode",
                       [&](WorkerState &state) {
                           state.encoder.encode(fixture.values1, fixture.scale, state.plain_tmp,
                                                state.pool);
                       });

    run_benchmark_pair(fixture, config, "Encoder/Decode",
                       [&](WorkerState &state) {
                           state.encoder.decode(state.plain1, state.decoded, state.pool);
                       });
}

void bench_cryptor(const BenchmarkFixture &fixture, const BenchmarkConfig &config)
{
    print_example_banner("CKKS Benchmarks: Cryptor");

    run_benchmark_pair(fixture, config, "Encryptor/Encrypt",
                       [&](WorkerState &state) {
                           state.encryptor.encrypt(state.plain1, state.cipher_tmp, state.pool);
                       });

    run_benchmark_pair(fixture, config, "Decryptor/Decrypt",
                       [&](WorkerState &state) {
                           state.decryptor.decrypt(state.cipher1, state.plain_tmp);
                       });
}

void bench_evaluator(const BenchmarkFixture &fixture, const BenchmarkConfig &config)
{
    print_example_banner("CKKS Benchmarks: Evaluator");

    run_benchmark_pair(fixture, config, "Evaluator/Add",
                       [&](WorkerState &state) {
                           state.evaluator->add(state.cipher1, state.cipher2, state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/Sub",
                       [&](WorkerState &state) {
                           state.evaluator->sub(state.cipher1, state.cipher2, state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/AddPlain",
                       [&](WorkerState &state) {
                           state.evaluator->add_plain(state.cipher1, state.plain2, state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/MultiplyPlain",
                       [&](WorkerState &state) {
                           state.evaluator->multiply_plain(state.cipher1, state.plain2,
                                                           state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/Rotate",
                       [&](WorkerState &state) {
                           state.evaluator->rotate(state.cipher1, state.cipher_tmp, 1,
                                                   fixture.galois_keys);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/Conjugate",
                       [&](WorkerState &state) {
                           state.evaluator->conjugate(state.cipher1, fixture.galois_keys,
                                                      state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/DropModulusToNext",
                       [&](WorkerState &state) {
                           state.evaluator->drop_modulus_to_next(state.cipher1, state.cipher_tmp);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/NTTInvNTTFwd",
                       [&](WorkerState &state) {
                           state.evaluator->ntt_inv(state.cipher1, state.cipher_tmp);
                           state.evaluator->ntt_fwd(state.cipher_tmp, state.cipher_tmp2);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/MultiplyRelinDynamic",
                       [&](WorkerState &state) {
                           state.evaluator->multiply_relin_dynamic(state.cipher1, state.cipher2,
                                                                   state.cipher_tmp,
                                                                   fixture.relin_keys);
                       });

    run_benchmark_pair(fixture, config, "Evaluator/Rescale",
                       [&](WorkerState &state) {
                           state.evaluator->rescale(state.cipher_mul, state.cipher_tmp);
                       });
}

void print_configuration(const BenchmarkConfig &config)
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << std::endl;
    std::cout << "Benchmark configuration:" << std::endl;
    std::cout << "  degree      : " << config.degree << std::endl;
    std::cout << "  iterations  : " << config.iterations << std::endl;
    std::cout << "  threads     : " << config.threads << std::endl;
    std::cout << std::endl;
    std::cout << "Note: all non-setup TIME values are average milliseconds per operation."
              << std::endl;
}

}  // namespace

int main(int argc, char *argv[])
{
    try
    {
        const auto config = parse_args(argc, argv);
        print_configuration(config);

        const auto fixture = create_fixture(config);

        bench_encoder(fixture, config);
        bench_cryptor(fixture, config);
        bench_evaluator(fixture, config);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Benchmark failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
