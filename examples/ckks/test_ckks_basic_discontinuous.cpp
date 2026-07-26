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

    ParametersLiteralDefault ckks_param_literal(CKKS, 32768, poseidon::sec_level_type::tc128);
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

    // ADD
    {
        print_example_banner("Example: ADD in CKKS");
        timestacs.start();
        ckks_eva->add(ct1, ct2, ct_res);
        timestacs.end();
        timestacs.print_time("ADD TIME: ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        msg_expect.clear();
        msg_expect.resize(msg_res.size());
        for (auto i = 0; i < slot_num; i++)
        {
            msg_expect[i] = msg1[i] + msg2[i];
        }
        for (auto i = 0; i < 4; i++)
        {
            printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
                   msg_expect[i].imag());
            printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
        }
        util::GetPrecisionStats(msg_expect, msg_res);
    }

    // SUB
    {
        print_example_banner("Example: SUB in CKKS");
        timestacs.start();
        ckks_eva->sub(ct1, ct2, ct_res);
        timestacs.end();
        timestacs.print_time("SUB TIME: ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

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
    }

    // MULTIPLY_RELIN_DYNAMIC
    {
        print_example_banner("Example: MULTIPLY_RELIN_DYNAMIC in CKKS");
        timestacs.start();
        ckks_eva->multiply_relin_dynamic(ct1, ct2, ct_res, relin_keys);
        timestacs.end();
        timestacs.print_time("MULTIPLY_RELIN_DYNAMIC TIME: ");
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
    }

    // RESCALE
    {
        print_example_banner("Example: RESCALE in CKKS");
        timestacs.start();
        ckks_eva->rescale(ct_res, ct_res);
        timestacs.end();
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
    }

    // ADD_PLAIN
    {
        print_example_banner("Example: ADD_PLAIN in CKKS");
        timestacs.start();
        ckks_eva->add_plain(ct1, plt2, ct_res);
        timestacs.end();
        timestacs.print_time("ADD_PLAIN TIME: ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        msg_expect.clear();
        msg_expect.resize(msg_res.size());
        for (auto i = 0; i < slot_num; i++)
        {
            msg_expect[i] = msg1[i] + msg2[i];
        }
        for (auto i = 0; i < 4; i++)
        {
            printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
                   msg_expect[i].imag());
            printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
        }
        util::GetPrecisionStats(msg_expect, msg_res);
    }

    // MULT_PLAIN
    {
        print_example_banner("Example: MULT_PLAIN in CKKS");
        timestacs.start();
        ckks_eva->multiply_plain(ct1, plt2, ct_res);
        timestacs.end();
        timestacs.print_time("MULT_PLAIN TIME: ");
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
    }

    // NTT & INTT
    {
        print_example_banner("Example: NTT / INTT in CKKS");
        timestacs.start();
        ckks_eva->ntt_inv(ct1, ct_res);
        ckks_eva->ntt_fwd(ct_res, ct_res);
        timestacs.end();
        timestacs.print_time("NTT / INTT TIME: ");
        decryptor.decrypt(ct_res, plt_res);
        encoder.decode(plt_res, msg_res);

        for (auto i = 0; i < slot_num; i++)
        {
            msg_expect[i] = msg1[i];
        }
        for (auto i = 0; i < 4; i++)
        {
            printf("source_data[%d] : %.10lf + %.10lf I\n", i, msg_expect[i].real(),
                   msg_expect[i].imag());
            printf("result_data[%d] : %.10lf + %.10lf I\n", i, msg_res[i].real(), msg_res[i].imag());
        }
        util::GetPrecisionStats(msg_expect, msg_res);
    }

    // ROTATE
    {
        print_example_banner("Example: ROTATE in CKKS");
        timestacs.start();
        ckks_eva->rotate(ct1, ct_res, 1, galois_keys);
        timestacs.end();
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
    }

    // CONJUGATE
    {
        print_example_banner("Example: CONJUGATE in CKKS");
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
    }

    return 0;
}
