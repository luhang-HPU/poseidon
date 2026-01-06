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
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault ckks_param_literal(CKKS, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 48);
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

    Plaintext plt1, plt2, plt_res;
    encoder.encode(msg1, scale, plt1);
    encoder.encode(msg2, scale, plt2);

    Ciphertext ct1, ct2, ct_res;
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    Timestacs timestacs;

    // DROP MODULUS
    print_example_banner("Example: Drop Modulus in CKKS");
    timestacs.start();
    ckks_eva->drop_modulus_to_next(ct1, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("Drop Modulus TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    msg_expect = msg1;
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // ADD
    print_example_banner("Example: ADD / ADD in CKKS");
    timestacs.start();
    ckks_eva->add(ct1, ct2, ct1);
    timestacs.end();
    ckks_eva->read(ct1);
    timestacs.print_time("ADD TIME: ");
    decryptor.decrypt(ct1, plt_res);
    encoder.decode(plt_res, msg_res);

    msg_expect = msg1;
    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] += msg2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);
    msg1 = msg_res;

    // NTT
    print_example_banner("Example: NTT / NTT in CKKS");
    timestacs.start();
    Ciphertext ct_tmp;
    ckks_eva->ntt_inv(ct1, ct_tmp);
    ckks_eva->ntt_fwd(ct_tmp, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("ADD TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // SUB
    print_example_banner("Example: SUB / SUB in CKKS");
    timestacs.start();
    ckks_eva->sub(ct1, ct2, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("SUB TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    msg_expect = msg1;
    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] = msg1[i] - msg2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // ROTATE
    print_example_banner("Example: ROTATE / ROTATE in CKKS");
    timestacs.start();
    ckks_eva->rotate(ct1, ct_res, 1, galois_keys);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("ROTATE TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] = msg1[i];
    }
    std::rotate(msg_expect.begin(), msg_expect.begin() + 1, msg_expect.end());

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // CONJUGATE
    print_example_banner("Example: CONJUGATE / CONJUGATE in CKKS");
    timestacs.start();
    ckks_eva->conjugate(ct1, galois_keys, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("CONJUGATE TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] = std::conj(msg1[i]);
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // ADD
    print_example_banner("Example: ADD_PLAIN / ADD_PLAIN in CKKS");
    timestacs.start();
    ckks_eva->add_plain(ct1, plt_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("ADD_PLAIN TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] += msg1[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // MULT_PLAIN
    print_example_banner("Example: MULT_PLAIN / MULT_PLAIN in CKKS");
    timestacs.start();
    ckks_eva->multiply_plain(ct1, plt_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("MULT_PLAIN TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] *= msg1[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // RESCALE
    print_example_banner("Example: RESCALE / RESCALE in CKKS");
    timestacs.start();
    ckks_eva->rescale(ct_res, ct_res);
    timestacs.end();
    ckks_eva->read(ct_res);
    timestacs.print_time("RESCALE TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // MULTIPLY_RELIN_DYNAMIC
    print_example_banner("Example: MULTIPLY_RELIN_DYNAMIC / MULTIPLY_RELIN_DYNAMIC in CKKS");
    timestacs.start();
    ckks_eva->multiply_relin_dynamic(ct_res, ct2, ct_res, relin_keys);
    timestacs.end();
    ckks_eva->rescale(ct_res, ct_res);
    ckks_eva->read(ct_res);
    timestacs.print_time("MULTIPLY_RELIN_DYNAMIC TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] *= msg2[i];
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // MULT_CONST
    print_example_banner("Example: MULT_CONST_DIRECT/ MULT_CONST_DIRECT in CKKS");
    timestacs.start();
    ckks_eva->multiply_const_direct(ct_res, 2, ct_res, encoder);
    ckks_eva->read(ct_res);

    timestacs.end();
    timestacs.print_time("MULT_CONST_DIRECT TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);
    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] *= 2;
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    // MULT_CONST
    print_example_banner("Example: MULT_CONST / MULT_CONST in CKKS");
    timestacs.start();
    ckks_eva->multiply_const(ct_res, const_num, 1.0, ct_res, encoder);
    ckks_eva->read(ct_res);
    timestacs.end();
    timestacs.print_time("MULT_CONST TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] *= const_num;
    }
    for (auto i = 0; i < 4; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
               msg_expect[i].imag());
        printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
    }
    util::GetPrecisionStats(msg_expect, msg_res);

    return 0;
}
