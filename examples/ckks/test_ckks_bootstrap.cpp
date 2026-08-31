#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <csignal>
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

    // Optimal config found by parameter search (see git history / gen_cfgs.py experiment):
    // modulus chain bottom -> top: q0(60) | residual 40x3 | SlotsToCoeffs 40x3 | EvalMod 60x12 |
    // CoeffsToSlots 56x6, log_p = single 60-bit prime.
    // The EvalMod scaling factor (2^60) must match q0 so that q_div ~= 1, and the primes of the
    // levels consumed by EvalMod must be 60-bit (each multiplication 2^120 -> rescale by 2^60).
    // Message scale 2^40 <= q0/message_ratio = 2^48 leaves room for the ScaleDown scale-up (2^8).
    // log_message_ratio = 12 is the sweet spot: 8->16.2, 9->17.7, 10->20.1, 11->21.7, 12->23.9,
    // 13->23.5, 14->22.9 bits precision. Measured: ~23.9 bits avg / 21.3 bits min.
    ParametersLiteral ckks_param_literal{CKKS, 13, 13 - 1, 40, 1, 0, 0, {}, {}};
    vector<uint32_t> log_q_opt;
    log_q_opt.push_back(60);                              // q0 (ModRaise base)
    for (int i = 0; i < 3; i++) log_q_opt.push_back(40);  // residual (post-bootstrap working)
    for (int i = 0; i < 3; i++) log_q_opt.push_back(40);  // SlotsToCoeffs section
    for (int i = 0; i < 12; i++) log_q_opt.push_back(60); // EvalMod section
    for (int i = 0; i < 6; i++) log_q_opt.push_back(56);  // CoeffsToSlots section

    ckks_param_literal.set_log_modulus(log_q_opt, std::vector<uint32_t>{60});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    std::vector<std::complex<double>> vec_result;
    int mat_size = 1 << ckks_param_literal.log_slots();

    // create message
    vector<complex<double>> message1;
    sample_random_complex_vector(message1, mat_size);

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

    ckks_eva->set_decryptor(&dec);
    ckks_eva->set_encoder(&ckks_encoder);
    ckks_eva->set_encryptor(&enc);

    // encode && encrypt at 2^40 (aligned with the 40-bit working primes;
    // 2^40 < q0/message_ratio = 2^48 so the bootstrap scale-up factor is 2^8)
    ckks_encoder.encode(message1, (int64_t)1 << 40, plain);
    enc.encrypt(plain, cipher);

    // evaluate
    auto start = chrono::high_resolution_clock::now();

    spdlog::debug("bootstrap start, level = {}", cipher.level());

    // EvalMod: scaling factor 2^60 ~= q0 (q_div ~= 1), log_message_ratio = 12 (search optimum)
    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 60, 1, 12, 3, 16, 0, 30);
    ckks_eva->bootstrap(cipher, cipher, relin_keys, rot_keys, ckks_encoder, eval_mod_poly);
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    std::cout << "Bootstrap TIME: " << duration.count() << " microseconds" << std::endl;

    spdlog::debug("bootstrap end, level = {}", cipher.level());

    // decode && decrypt
    dec.decrypt(cipher, plain_res);
    ckks_encoder.decode(plain_res, vec_result);
    // bootstrap is a refresh: the output message should equal the input message
    // (the legacy test squared the ciphertext before bootstrapping; this version encrypts
    // the message directly, so compare against the message itself)
    for (int i = 0; i < 10; i++)
    {
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
