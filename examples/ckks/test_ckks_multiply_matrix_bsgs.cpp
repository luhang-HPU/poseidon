#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;
#define HARDWARE
int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 14, 14 - 1, 20, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{30, 30, 30, 30, 30, 30, 30};
    vector<uint32_t> log_p_tmp{30};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // init random data
    int mat_size = 1 << ckks_param_literal.log_slots();
    std::vector<vector<std::complex<double>>> mat(mat_size, vector<complex<double>>(mat_size, 0));
    std::vector<vector<std::complex<double>>> mat_diag(mat_size);
    std::vector<vector<std::complex<double>>> mat_transpose;
    // create message
    vector<complex<double>> message1(mat_size, 0);
    message1[1] = 1;

    // init Plaintext and Ciphertext
    Plaintext plain1, plain2;
    Ciphertext cipher1, cipher2, cipher_res;
    PublicKey public_key;
    GaloisKeys rot_keys;
    vector<uint32_t> rot_elemt;
    CKKSEncoder ckks_encoder(context);
    // GenMatrices
    MatrixPlain matrix_plain;

    for (int i = 0; i < mat_size; i++)
    {
        sample_random_complex_vector2(mat[i], mat_size);
    }
    auto &modulus = context.crt_context()->first_context_data()->coeff_modulus();
    int level = modulus.size() - 1;
    matrix_operations::transpose_matrix(mat, mat_transpose);
    for (int i = 0; i < mat.size(); i++)
    {
        matrix_operations::diagonal(mat_transpose, i, mat_diag[i]);
    }

    gen_matrix_form_bsgs(matrix_plain, matrix_plain.rot_index, ckks_encoder, mat_diag, level,
                         safe_cast<double>(modulus.back().value()), 1,
                         ckks_param_literal.log_slots());

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
    Timestacs timestacs;
    timestacs.start();

    ckks_eva->multiply_by_diag_matrix_bsgs(ct, matrix_plain, cipher_res, rot_keys);

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

    return 0;
}
