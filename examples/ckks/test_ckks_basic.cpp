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

    ParametersLiteralDefault ckks_param_literal(CKKS, 4096, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_HARDWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, 35);
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
    msg_expect.resize(slot_num);

    Plaintext plt1, plt2, plt_res;
    encoder.encode(msg1, scale, plt1);
    encoder.encode(msg2, scale, plt2);

    Ciphertext ct1, ct2, ct_res;
    encryptor.encrypt(plt1, ct1);
    encryptor.encrypt(plt2, ct2);

    Timestacs timestacs;

    

    // ROTATE
    print_example_banner("Example: ROTATE / ROTATE in CKKS");
    timestacs.start();
    ckks_eva->rotate(ct1, ct_res, 111, galois_keys);
    timestacs.end();
    timestacs.print_time("ROTATE TIME: ");
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] = msg1[i];
    }
    std::rotate(msg_expect.begin(), msg_expect.begin() + 111, msg_expect.end());

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

    // MULTIPLY
    print_example_banner("Example: MULTIPLY / MULTIPLY in CKKS");
    timestacs.start();
    ckks_eva->multiply(ct1, ct2, ct_res);
    timestacs.end();
    timestacs.print_time("MULTIPLY TIME: ");
    

    // RELINEARIZE
    print_example_banner("Example: RELINEARIZE / RELINEARIZE in CKKS");
    timestacs.start();
    ckks_eva->relinearize(ct_res, ct_res, relin_keys);
    timestacs.end();
    timestacs.print_time("RELINEARIZE TIME: ");
    ckks_eva->rescale(ct_res, ct_res);
    decryptor.decrypt(ct_res, plt_res);
    encoder.decode(plt_res, msg_res);

    for (auto i = 0; i < slot_num; i++)
    {
        msg_expect[i] = msg1[i] * msg2[i];
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
