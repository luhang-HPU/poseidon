
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

    uint32_t q0_bit = 63;
    auto q_def = 45;
    ParametersLiteral ckks_param_literal{CKKS, 12, 11, 40, 1, 1, 0, {}, {}};
    vector<uint32_t> log_q_tmp{31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31,
                               31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31};
    vector<uint32_t> log_p_tmp{31};

    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    auto q0 = context.crt_context()->q0();
    // init random data
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

    // EvalMod
    auto level_start = ckks_param_literal.q().size() - 1;

    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << (q0_bit - 25), level_start - 6,
                              8, 3, 16, 0, 30);

    auto sc_fac = eval_mod_poly.sc_fac();
    double k = eval_mod_poly.k();
    auto q_diff = eval_mod_poly.q_diff();
    // If the scale used during the EvalMod step is smaller than Q0, then we cannot increase the
    // scale during the EvalMod step to get message free division by message_ratio, and we need to
    // do this division (totally or partly) during the CoeffstoSlots step

    auto coeffs_to_slots_scaling = 1.0;
    coeffs_to_slots_scaling *= eval_mod_poly.q_div() / (k * sc_fac * q_diff);

    auto slots_to_coeffs_scaling = ckks_param_literal.scale();
    slots_to_coeffs_scaling = slots_to_coeffs_scaling / ((double)eval_mod_poly.scaling_factor() /
                                                         (double)eval_mod_poly.message_ratio());

    HomomorphicDFTMatrixLiteral d(0, ckks_param_literal.log_n(), ckks_param_literal.log_slots(),
                                  level_start, vector<uint32_t>(3, 1), true,
                                  coeffs_to_slots_scaling, false, 1);
    HomomorphicDFTMatrixLiteral x(1, ckks_param_literal.log_n(), ckks_param_literal.log_slots(), 7,
                                  vector<uint32_t>(3, 1), true, slots_to_coeffs_scaling, false, 1);
    LinearMatrixGroup mat_group;
    LinearMatrixGroup mat_group_dec;
    d.create(mat_group, ckks_encoder, 2);
    x.create(mat_group_dec, ckks_encoder, 1);
    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(mat_group.rot_index(), rot_keys);
    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    // encode && encrypt
    ckks_encoder.encode(message1, (int64_t)1 << q_def, plain);
    enc.encrypt(plain, cipher);

    // evaluate
    // scale the message1 to delta = q / message_ratio
    auto start = chrono::high_resolution_clock::now();
    std::cout << "bootstraping start..." << std::endl;
    ckks_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    ckks_eva->rescale_dynamic(cipher, cipher, (int64_t)1 << q_def);

    ckks_eva->bootstrap(cipher, cipher, eval_mod_poly, mat_group, mat_group_dec, relin_keys,
                        rot_keys, ckks_encoder);
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
