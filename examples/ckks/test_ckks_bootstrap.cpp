
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <csignal>
#include <cstdlib>
#include <exception>
#include <execinfo.h>
#include <unistd.h>

#include "spdlog/spdlog.h"

using namespace poseidon;

namespace
{
void print_stacktrace()
{
    void *frames[128];
    auto size = backtrace(frames, 128);

    std::cerr << "\n========== STACKTRACE ==========\n";
    backtrace_symbols_fd(frames, size, STDERR_FILENO);
    std::cerr << "================================\n";
}

void crash_handler(int sig)
{
    std::cerr << "\nCaught signal: " << sig << std::endl;
    print_stacktrace();

    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

void install_crash_handler()
{
    std::signal(SIGSEGV, crash_handler);
    std::signal(SIGABRT, crash_handler);
    std::signal(SIGFPE, crash_handler);
    std::signal(SIGILL, crash_handler);
    std::signal(SIGBUS, crash_handler);
}
}  // namespace

int run_bootstrap_test()
{
    spdlog::set_level(spdlog::level::debug);

    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 40, 1, 1, 0, {}, {}};
    /*vector<uint32_t> log_q_tmp{32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
                               32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};
    vector<uint32_t> log_p_tmp{32};*/

    ckks_param_literal.set_log_modulus(std::vector<uint32_t>(30, 40), std::vector<uint32_t>{40});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    std::vector<std::complex<double>> vec_result;
    int mat_size = 1 << ckks_param_literal.log_slots();

    // create message
    vector<complex<double>> message1;
    sample_random_complex_vector(message1, mat_size);
    for (auto &m : message1)
    {
        m = sin(m);
    }

    // init Plaintext and Ciphertext
    Plaintext plain, plain_res;
    Ciphertext cipher;
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);
    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    // encode && encrypt
    ckks_encoder.encode(message1, (int64_t)1 << 40, plain);
    enc.encrypt(plain, cipher);

    // evaluate
    auto start = chrono::high_resolution_clock::now();
    ckks_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    ckks_eva->rescale_dynamic(cipher, cipher, (int64_t)1 << 40);

    spdlog::debug("bootstrap start, level = {}", cipher.level());

    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 40, 1, 9, 3, 16, 0, 30);
    ckks_eva->bootstrap(cipher, cipher, relin_keys, rot_keys, ckks_encoder, eval_mod_poly);
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    std::cout << "Bootstrap TIME: " << duration.count() << " microseconds" << std::endl;

    spdlog::debug("bootstrap end, level = {}", cipher.level());

    // decode && decrypt
    dec.decrypt(cipher, plain_res);
    ckks_encoder.decode(plain_res, vec_result);
    for (int i = 0; i < 10; i++)
    {
        message1[i] *= message1[i];
        printf("source vec[%d] : %0.10f + %0.10f I \n", i, (real(message1[i])), imag(message1[i]));
        printf("result vec[%d] : %0.10f + %0.10f I \n", i, (real(vec_result[i])),
               imag(vec_result[i]));
    }
    GetPrecisionStats(vec_result, message1);
    return 0;
}

int main()
{
    install_crash_handler();

    try
    {
        return run_bootstrap_test();
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nUncaught exception: " << e.what() << std::endl;
        print_stacktrace();
        throw;
    }
    catch (...)
    {
        std::cerr << "\nUncaught unknown exception" << std::endl;
        print_stacktrace();
        throw;
    }
}
