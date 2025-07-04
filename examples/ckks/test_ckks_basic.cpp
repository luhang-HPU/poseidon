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

    ParametersLiteralDefault ckks_param_literal(CKKS, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    CKKSEncoder enc(context);
    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> message1, message2;
    vector<complex<double>> message_want(slot_num);
    vector<complex<double>> message_res;

    sample_random_complex_vector(message1, slot_num);
    sample_random_complex_vector(message2, slot_num);
    for (size_t i = 0; i < message2.size(); ++i)
    {
        message2[i] = message2[i] + message2[i];
    }

    Plaintext plaintext, plaintext2, plaintext_res;
    double scale = std::pow(2.0, 48);
    enc.encode(message1, scale, plaintext);
    enc.encode(message2, scale, plaintext2);

    Ciphertext ct, ct1, ct2, ct_res;
    encryptor.encrypt(plaintext, ct);
    encryptor.encrypt(plaintext, ct1);
    encryptor.encrypt(plaintext2, ct2);

    Timestacs timestacs;
//     // DROP MODULUS
//     print_example_banner("Example: Drop Modulus in CKKS");
//     timestacs.start();
//     ckks_eva->drop_modulus_to_next(ct, ct_res);
//     timestacs.end();
//     ckks_eva->read(ct_res);

//     timestacs.print_time("Drop Modulus TIME: ");
//     decryptor.decrypt(ct_res, plaintext_res);
//     enc.decode(plaintext_res, message_res);

//     for (auto i = 0; i < 4; i++)
//     {
//         printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
//                message_want[i].imag());
//         printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
//                message_res[i].imag());
//     }
//     util::GetPrecisionStats(message_want, message_res);

    // ADD
    print_example_banner("Example: ADD / ADD in CKKS");
    timestacs.start();
    ckks_eva->add(ct, ct2, ct);
    timestacs.end();
    ckks_eva->read(ct);

    timestacs.print_time("ADD TIME: ");
    decryptor.decrypt(ct, plaintext_res);
    enc.decode(plaintext_res, message_res);
    message_want = message1;
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] += message2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);
    message1 = message_res;

    // NTT
    print_example_banner("Example: NTT / NTT in CKKS");
    timestacs.start();
    ckks_eva->ntt_inv(ct, ct1);
    ckks_eva->ntt_fwd(ct1, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);

    timestacs.print_time("ADD TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // SUB
    print_example_banner("Example: SUB / SUB in CKKS");
    timestacs.start();
    ckks_eva->sub(ct, ct2, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("SUB TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    message_want = message1;
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = message1[i] - message2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // ROTATE
    print_example_banner("Example: ROTATE / ROTATE in CKKS");
    timestacs.start();
    ckks_eva->rotate(ct, ct_res, 1, galois_keys);
    timestacs.end();
    ckks_eva->read(ct_res);

    timestacs.print_time("ROTATE TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = message1[i];
    }
    std::rotate(message_want.begin(), message_want.begin() + 1, message_want.end());

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // CONJUGATE
    print_example_banner("Example: CONJUGATE / CONJUGATE in CKKS");
    timestacs.start();
    ckks_eva->conjugate(ct, galois_keys, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);

    timestacs.print_time("CONJUGATE TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = std::conj(message1[i]);
    }

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // ADD
    print_example_banner("Example: ADD_PLAIN / ADD_PLAIN in CKKS");
    timestacs.start();
    ckks_eva->add_plain(ct, plaintext_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("ADD_PLAIN TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] += message1[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // MULT_PLAIN
    print_example_banner("Example: MULT_PLAIN / MULT_PLAIN in CKKS");
    timestacs.start();
    ckks_eva->multiply_plain(ct, plaintext_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("MULT_PLAIN TIME: ");

    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] *= message1[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // RESCALE
    print_example_banner("Example: RESCALE / RESCALE in CKKS");
    timestacs.start();
    ckks_eva->rescale(ct_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);

    timestacs.print_time("RESCALE TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // MULTIPLY_RELIN_DYNAMIC
    print_example_banner("Example: MULTIPLY_RELIN_DYNAMIC / MULTIPLY_RELIN_DYNAMIC in CKKS");
    timestacs.start();
    ckks_eva->multiply_relin_dynamic(ct_res, ct2, ct_res, relin_keys);
    timestacs.end();
    ckks_eva->rescale(ct_res, ct_res);
    ckks_eva->read(ct_res);

    timestacs.print_time("MULTIPLY_RELIN_DYNAMIC TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] *= message2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // MULT_CONST
    print_example_banner("Example: MULT_CONST_DIRECT/ MULT_CONST_DIRECT in CKKS");
    timestacs.start();
    ckks_eva->multiply_const_direct(ct_res, 2, ct_res, enc);
    ckks_eva->read(ct_res);

    timestacs.end();
    timestacs.print_time("MULT_CONST_DIRECT TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] *= 2;
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // MULT_CONST
    print_example_banner("Example: MULT_CONST / MULT_CONST in CKKS");
    timestacs.start();
    ckks_eva->multiply_const(ct_res, 5.0, 1.0, ct_res, enc);
    ckks_eva->read(ct_res);

    timestacs.end();
    timestacs.print_time("MULT_CONST TIME: ");
    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] *= 5;
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    return 0;
}
