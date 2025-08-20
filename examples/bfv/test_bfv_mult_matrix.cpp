#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;

int main()
{
    cout << BANNER << std::endl;
    cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    cout << "" << std::endl;

    ParametersLiteralDefault bfv_param_literal(BFV, 8192, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    auto bfv_eva = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    Encryptor enc(context, public_key);
    Decryptor dec(context, keygen.secret_key());

    // init Plaintext and Ciphertext
    Plaintext plt, plt_res;
    Ciphertext ct, ct_res;
    int mat_size = bfv_param_literal.slot();
    auto level = bfv_param_literal.q().size() - 1;
    vector<uint64_t> msg(mat_size, 1);
    sample_random_vector(msg, mat_size, 10);
    vector<uint64_t> vec_result(mat_size, 0);
    std::vector<vector<uint64_t>> mat_t1(mat_size);
    std::vector<vector<uint64_t>> mat(mat_size, vector<uint64_t>(mat_size, 0));
    for (int i = 0; i < mat_size; i++)
    {
        sample_random_vector(mat[i], mat_size, i);
    }

    // GenMatrices
    vector<uint64_t> msg_tmp;
    MatrixPlain matrix_plain;
    auto coeff_mod = bfv_param_literal.plain_modulus();
    matrix_operations::matrix_vector_multiply_mod(mat, msg, msg_tmp, coeff_mod.value());
    matrix_operations::rotate_slots_matrix(mat, mat_t1);
    gen_matrix_form_bsgs(matrix_plain, matrix_plain.rot_index, encoder, mat_t1, level, 1,
                         bfv_param_literal.log_slots());

    // init keys
    vector<int> rot_index_tmp;
    for (auto index : matrix_plain.rot_index)
    {
        if (index >= mat_size / 2)
            rot_index_tmp.push_back(index - mat_size / 2);
        else
            rot_index_tmp.push_back(index);
    }
    rot_index_tmp.push_back(0);
    keygen.create_galois_keys(rot_index_tmp, galois_keys);

    // encode
    encoder.encode(msg, plt);
    enc.encrypt(plt, ct);

    auto start = chrono::high_resolution_clock::now();
    Timestacs timestacs;
    timestacs.start();
    bfv_eva->multiply_by_diag_matrix_bsgs(ct, matrix_plain, ct_res, galois_keys);
    timestacs.end();
    timestacs.print_time("MULT MATRIX : ");
    bfv_eva->read(ct_res);

    // decode & decrypt
    dec.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, vec_result);
    for (int i = 0; i < 4; i++)
    {
        printf("soft vec[%d]   : %ld  \n", i, msg_tmp[i]);
        printf("result vec[%d] : %ld  \n", i, vec_result[i]);
    }
}