#include "../poseidon_hardware/hardware_drive/ckks_hardware_api.h"
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"
#include <fstream>
#include <iomanip>
using namespace poseidon;
using namespace poseidon::util;
// #define HARDWARE
int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    ParametersLiteral ckks_param_literal{CKKS, 13, 13 - 1, 40, 5, 0, 0, {}, {}};
    vector<Modulus> log_q_tmp{0x000007fffffc8001, 0x000007fffffd8001, 0x00000fffffebc001,
                              0x00000ffffff6c001};
    vector<Modulus> log_p_tmp{0x00000fffffffc001};
    ckks_param_literal.set_modulus(log_q_tmp, log_p_tmp);
    //初始化模数，等context里包含的参数
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

    Timestacs timestacs;
#ifdef HARDWARE
    int rns_max = 5;
    int degree = 8192;
    timestacs.start();
    CKKSHardwareApi::ckks_relin_key_config(relin_keys, rns_max, degree);
    timestacs.end();
    timestacs.print_time("relin_key: ");
    auto galois_tool = context.crt_context()->galois_tool();
    timestacs.start();
    CKKSHardwareApi::ckks_galois_key_config(galois_keys, galois_tool, rns_max, degree);
    timestacs.end();
    timestacs.print_time("galois_keys: ");
    timestacs.start();
    CKKSHardwareApi::permutation_tables_config(galois_keys, galois_tool, rns_max, degree);
    timestacs.end();
    timestacs.print_time("permutation: ");
#endif

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());
    // vector<complex<double>> message1 = {{1.0,1.0}, {2.0,2.0}, {3.0,3.0}, {4.0,4.0}};
    // vector<complex<double>> message2 = {{1.0,1.0}, {2.0,2.0}, {3.0,3.0}, {4.0,4.0}};
    auto slot_num = ckks_param_literal.slot();
    vector<complex<double>> message1, message2;
    sample_random_complex_vector(message1, slot_num);
    sample_random_complex_vector(message2, slot_num);
    vector<complex<double>> message_want(slot_num);
    vector<complex<double>> message_res, message_res1;

    Plaintext plaintext1, plaintext2, plaintext_res, plaintext_res1, plaintext_res2;
    double scale = std::pow(2.0, 35);
    enc.encode(message1, scale, plaintext1);
    enc.encode(message2, scale, plaintext2);

    Ciphertext ct1, ct2, ct_res, ct_res1, ct_res2;
    encryptor.encrypt(plaintext1, ct1);
    encryptor.encrypt(plaintext2, ct2);
    encryptor.encrypt(plaintext2, ct_res);
    encryptor.encrypt(plaintext2, ct_res1);
    encryptor.encrypt(plaintext2, ct_res2);

    print_example_banner("Example: MULTIPLY_RELIN / MULTIPLY_RELIN in ckks");

    timestacs.start();
    ckks_eva->multiply_relin(ct1, ct2, ct_res, relin_keys);
    timestacs.end();
    timestacs.print_time("mult: ");
    ckks_eva->rescale(ct_res, ct_res);

    ckks_eva->multiply(ct1, ct2, ct_res1);
    ckks_eva->relinearize(ct_res1, ct_res1, relin_keys);
    ckks_eva->rescale(ct_res1, ct_res1);

    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);

    decryptor.decrypt(ct_res1, plaintext_res1);
    enc.decode(plaintext_res1, message_res1);

    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = message2[i] * message1[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
        printf("result1_data[%d] : %.10lf + %.10lf I\n", i, message_res1[i].real(),
               message_res[i].imag());
    }

    // //CONJUGATE
    //     print_example_banner("Example: CONJUGATE / CONJUGATE in ckks");

    //     timestacs.start();
    //     ckks_eva->conjugate(ct2, galois_keys, ct_res2);
    //     timestacs.end();
    //     timestacs.print_time("CONJUGATE: ");

    //     decryptor.decrypt(ct_res2, plaintext_res);
    //     enc.decode(plaintext_res, message_res);
    //     for (auto i = 0; i < slot_num; i++)
    //     {
    //         message_want[i] = std::conj(message2[i]);
    //     }

    //     for (auto i = 0; i < 4; i++)
    //     {
    //         printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
    //                message_want[i].imag());
    //         printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
    //                message_res[i].imag());
    //     }
    //     util::GetPrecisionStats(message_want, message_res);

    // ROTATE
    print_example_banner("Example: ROTATE / ROTATE in ckks");
    timestacs.start();
    ckks_eva->rotate(ct1, ct_res, -1, galois_keys);
    timestacs.end();
    timestacs.print_time("ROTATE: ");

    decryptor.decrypt(ct_res, plaintext_res);
    enc.decode(plaintext_res, message_res);
    for (auto i = 0; i < slot_num; i++)
    {
        message_want[i] = message1[i];
    }
    std::rotate(message_want.begin(), message_want.begin() + slot_num - 1, message_want.end());

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
               message_want[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
               message_res[i].imag());
    }
    util::GetPrecisionStats(message_want, message_res);

    // //ROTATE
    //     print_example_banner("Example: SQRT / SQRT in ckks");
    //     timestacs.start();
    //     ckks_eva->square_inplace(ct1);
    //     timestacs.end();
    //     timestacs.print_time("SQRT: ");

    //     decryptor.decrypt(ct1, plaintext_res);
    //     enc.decode(plaintext_res, message_res);
    //     for (auto i = 0; i < slot_num; i++)
    //     {
    //         message_want[i] = message1[i]*message1[i];
    //     }

    //     for (auto i = 0; i < 4; i++)
    //     {
    //         printf("source_data[%d] : %.10lf + %.10lf I\n", i, message_want[i].real(),
    //                message_want[i].imag());
    //         printf("result_data[%d] : %.10lf + %.10lf I\n", i, message_res[i].real(),
    //                message_res[i].imag());
    //     }
    //     util::GetPrecisionStats(message_want, message_res);

    return 0;
}
