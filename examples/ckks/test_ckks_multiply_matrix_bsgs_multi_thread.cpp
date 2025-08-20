#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);

    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 14, 14 - 1, 20, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 30};
    vector<uint32_t> log_p_tmp{30};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    // init random data
    int mat_size = 1 << ckks_param_literal.log_slots();
    std::vector<vector<std::complex<double>>> mat(mat_size, vector<complex<double>>(mat_size, 0));
    std::vector<vector<std::complex<double>>> mat_t(mat_size);
    std::vector<vector<std::complex<double>>> mat_t1;
    // create message
    vector<complex<double>> message1(mat_size, 0);
    message1[1] = 1;

    // init Plaintext and Ciphertext
    Plaintext plain1, plain2;
    Ciphertext cipher1, cipher2, cipher_res;
    PublicKey public_key;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);
    // GenMatrices
    MatrixPlain matrix_plain;

    for (int i = 0; i < mat_size; i++)
    {
        sample_random_complex_vector2(mat[i], mat_size);
    }
    auto &modulus = context.crt_context()->first_context_data()->coeff_modulus();
    int level = modulus.size() - 1;
    matrix_operations::transpose_matrix(mat, mat_t1);
    for (int i = 0; i < mat.size(); i++)
    {
        matrix_operations::diagonal(mat_t1, i, mat_t[i]);
    }

    std::map<int, vector<int>> ref1;
    vector<int> ref2;
    vector<int> ref3;

    std::thread t1(gen_matrix_form_bsgs_multi_thread<std::complex<double>>, std::ref(matrix_plain),
                   std::ref(matrix_plain.rot_index), std::ref(ckks_encoder), mat_t, level,
                   safe_cast<double>(modulus.back().value()), 1, ckks_param_literal.log_slots(),
                   std::ref(ref1), std::ref(ref2), std::ref(ref3));
    {
        std::unique_lock<std::mutex> lck(matrix_plain.mtx_precompute);
        if (!matrix_plain.is_precompute)
        {
            matrix_plain.cv_precompute.wait(lck, [&matrix_plain]()
                                            { return matrix_plain.is_precompute; });
        }
    }

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_galois_keys(rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    Plaintext plaintext, plaintext2;
    double scale = std::pow(2.0, 40);
    ckks_encoder.encode(message1, scale, plaintext);
    vector<complex<double>> message2;

    Ciphertext ct, ct2;
    enc.encrypt(plaintext, ct);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    Timestacs timestacs;
    timestacs.start();

    ckks_eva->multiply_by_diag_matrix_bsgs_with_mutex(ct, matrix_plain, cipher_res, rot_keys, ref1,
                                                      ref2, ref3);

    timestacs.end();
    timestacs.print_time("PIR TIME : ");
    ckks_eva->read(cipher_res);
    dec.decrypt(cipher_res, plaintext2);

    ckks_encoder.decode(plaintext2, message2);
    for (int i = 0; i < 8; i++)
    {
        printf("result vec[%d] : %0.10f + %0.10f I \n", i, real(mat[1][i]), imag(mat[1][i]));
        printf("result vec[%d] : %0.10f + %0.10f I \n", i, real(message2[i]), imag(message2[i]));
    }

    t1.join();

    return 0;
}
