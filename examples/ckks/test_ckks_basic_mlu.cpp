#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;

void matrix()
{
    ParametersLiteralDefault ckks_param_literal(CKKS, 4096, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);
    double const_num = 5.0;

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
    ckks_encoder.encode(message1, scale, plaintext);
    vector<complex<double>> message2;

    Ciphertext ct, ct2;
    enc.encrypt(plaintext, ct);
    Timestacs timestacs;
    timestacs.start();
    ckks_eva->multiply_by_diag_matrix_bsgs(ct, matrix_plain, cipher_res, rot_keys);
    timestacs.end();
    std::cout << "Matrix Time: " << timestacs.microseconds() / 1.0 << " us" << std::endl;
}

void sigmoid()
{
    ParametersLiteralDefault ckks_param_literal(CKKS, 8192, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);
    double const_num = 5.0;

    PublicKey public_key;
    RelinKeys relin_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> msg1, msg2, msg_expect, msg_res;

    sample_random_complex_vector(msg1, slot_num);
    sample_random_complex_vector(msg2, slot_num);

    Timestacs timestacs;
    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2, ct_res;

    // encode
    encoder.encode(msg1, scale, plt1);
    encoder.encode(msg2, scale, plt2);

    // encrypt
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    // sigmoid_approx
    timestacs.start();
    ckks_eva->sigmoid_approx(ct1, ct_res, encoder, relin_keys);
    timestacs.end();
    std::cout << "Sigmoid Time: " << timestacs.microseconds() / 1.0 << " us" << std::endl;

    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);
}

void conv()
{
    ParametersLiteralDefault ckks_param_literal(CKKS, 8192, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);
    double const_num = 5.0;

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> msg1, msg2, msg_expect, msg_res;

    sample_random_complex_vector(msg1, slot_num);
    sample_random_complex_vector(msg2, slot_num);

    Timestacs timestacs;
    Plaintext plt1, plt2, plt_res;
    Ciphertext ct1, ct2, ct_res;

    // encode
    encoder.encode(msg1, scale, plt1);
    encoder.encode(msg2, scale, plt2);

    // encrypt
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    // sigmoid_approx
    timestacs.start();
    ckks_eva->conv(ct1, ct2, ct_res, 1, encoder, encryptor, galois_keys, relin_keys);
    timestacs.end();
    std::cout << "Conv Time: " << timestacs.microseconds() / 1.0 << " us" << std::endl;
    timestacs.end();
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);
}

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault ckks_param_literal(CKKS, 4096, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 19);
    double const_num = 5.0;

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> msg1, msg2, msg_expect, msg_res;

    sample_random_complex_vector(msg1, slot_num);
    sample_random_complex_vector(msg2, slot_num);

    Timestacs timestacs, timestacs_total;
    uint64_t total_time = 0;
    uint64_t encode_time = 0;
    uint64_t decode_time = 0;
    uint64_t encrypt_time = 0;
    uint64_t decrypt_time = 0;
    uint64_t multiply_time = 0;
    uint64_t rotate_time = 0;
    uint64_t kswitch_time = 0;

    timestacs_total.start();
    for (auto i = 0; i < 100; i++)
    {
        Plaintext plt1, plt2, plt_res;
        Ciphertext ct1, ct2, ct_res;

        // encode
        timestacs.start();
        encoder.encode(msg1, scale, plt1);
        timestacs.end();
        encode_time += timestacs.microseconds();
        encoder.encode(msg2, scale, plt2);

        // encrypt
        timestacs.start();
        encryptor.encrypt(plt1, ct1);
        timestacs.end();
        encrypt_time += timestacs.microseconds();
        encryptor.encrypt(plt2, ct2);

        // MULTIPLY_RELIN_DYNAMIC
        timestacs.start();
        ckks_eva->multiply_relin_dynamic(ct1, ct2, ct_res, relin_keys);
        timestacs.end();
        multiply_time += timestacs.microseconds();
        ckks_eva->rescale(ct_res, ct_res);

        // rotate
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        rotate_time += timestacs.microseconds();

        // kswitch
        timestacs.start();
        ckks_eva->rotate(ct_res, ct_res, 1, galois_keys);
        timestacs.end();
        kswitch_time += timestacs.microseconds();

        // decrypt
        timestacs.start();
        decryptor.decrypt(ct_res, plt_res);
        timestacs.end();
        decrypt_time += timestacs.microseconds();

        // decod
        timestacs.start();
        encoder.decode(plt_res, msg_res);
        timestacs.end();
        decode_time += timestacs.microseconds();
    }
    timestacs_total.end();

    matrix();
    total_time = timestacs_total.microseconds();
    std::cout << "Multiply Time: " << multiply_time / 100.0 << " us" << std::endl;
    std::cout << "Rotate Time: " << rotate_time / 100.0 << " us" << std::endl;
    std::cout << "KSwitch Time: " << kswitch_time / 100.0 << " us" << std::endl;
    std::cout << "degree: " << 4096 << std::endl;
    std::cout << "depth: " << 3 << std::endl
              << std::endl;

    sigmoid();
    conv();
    std::cout << "degree: " << 8192 << std::endl;
    std::cout << "depth: " << 5 << std::endl
              << std::endl;

    std::cout << "Encode Time: " << encode_time / 100.0 << " us" << std::endl;
    std::cout << "Encrypt Time: " << encrypt_time / 100.0 << " us" << std::endl;    
    std::cout << "Decrypt Time: " << decrypt_time / 100.0 << " us" << std::endl;
    std::cout << "Decode Time: " << decode_time / 100.0 << " us" << std::endl;
    std::cout << "Total Average Time: " << total_time / 100.0 << " us" << std::endl;
    return 0;
}
