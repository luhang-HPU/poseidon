
#include "src/advance/homomorphic_dft.h"
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 32, 1, 1, 0, {}, {}};
    vector<uint32_t> log_q_tmp{32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
                               32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};
    vector<uint32_t> log_p_tmp{32};

    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

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
    std::cout << "bootstraping start..." << std::endl;
    ckks_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    ckks_eva->rescale_dynamic(cipher, cipher, (int64_t)1 << 45);

    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 40, 1,
                              9, 3, 16, 0, 30);
    ckks_eva->bootstrap(cipher, cipher, relin_keys,rot_keys, ckks_encoder, eval_mod_poly);
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    std::cout << "EXP TIME: " << duration.count() << " microseconds" << std::endl;

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
