
#include "src/advance/homomorphic_dft.h"
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{

    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 40, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{40, 40, 40, 40, 40, 40, 40, 40, 40, 40};
    vector<uint32_t> log_p_tmp{40};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // init random data
    std::vector<std::complex<double>> vec;
    std::vector<std::complex<double>> vec_result, vec_result1;
    std::vector<vector<std::complex<double>>> mat;
    int mat_size = 1 << ckks_param_literal.log_slots();
    mat.resize(mat_size);
    // create message
    vector<complex<double>> message1;
    vector<complex<double>> message_tmp(mat_size);
    vector<complex<double>> message_sum(mat_size << 1, 0.0);
    sample_random_complex_vector(message1, mat_size);

    // init Plaintext and Ciphertext
    Plaintext plain1, plain2, plain_res;
    Ciphertext cipher1, cipher2, cipher_res, cipher_res1;
    PublicKey public_key;
    GaloisKeys rot_keys;

    auto level_start = log_q_tmp.size() - 1;
    CKKSEncoder ckks_encoder(context);
    HomomorphicDFTMatrixLiteral d(0, ckks_param_literal.log_n(), ckks_param_literal.log_slots(),
                                  level_start, vector<uint32_t>(3, 1), true, 1.0, false, 1);
    HomomorphicDFTMatrixLiteral x(1, ckks_param_literal.log_n(), ckks_param_literal.log_slots(),
                                  level_start - 3, vector<uint32_t>(3, 1), true, 1.0, false, 1);

    LinearMatrixGroup mat_group1;
    LinearMatrixGroup mat_group2;

    d.create(mat_group1, ckks_encoder, 1);
    x.create(mat_group2, ckks_encoder, 1);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_galois_keys(rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    Plaintext plaintext, plaintext2, plaintext3;
    vector<complex<double>> message2;
    double scale = std::pow(2.0, 40);
    ckks_encoder.encode(message1, scale, plaintext);
    Ciphertext ct, ct2;
    enc.encrypt(plaintext, ct);
    ckks_eva->coeff_to_slot(ct, mat_group1, cipher_res, cipher_res1, rot_keys, ckks_encoder);
    ckks_eva->slot_to_coeff(cipher_res, cipher_res1, mat_group2, cipher_res, rot_keys,
                            ckks_encoder);
    ckks_eva->read(cipher_res);

    dec.decrypt(cipher_res, plaintext2);
    ckks_encoder.decode(plaintext2, message2);

    auto ntt_inv = message2;
    for (auto i = 0; i < 8; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message1[i].real(), message1[i].imag());
        printf("resu  vec[%d]   : %.10lf + %.10lf I\n", i, message2[i].real(), message2[i].imag());
    }

    util::GetPrecisionStats(message1, message2);

    return 0;
}
