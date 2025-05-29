#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;

void test_rotate(Ciphertext ciph, const GaloisKeys &rot_key)
{

}

void test_multiply()
{

}

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 11;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> log_q(10, 32);
    vector<uint32_t> log_p(1, 60);
    ckks_param_literal.set_log_modulus(log_q, log_p);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    double scale = std::pow(2.0, q_def);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys conj_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // init keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);


    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);


    std::vector<std::complex<double>> message = {{9.0, 0.0}, {10.0, 0.0} ,{11.0, 0.0}};
    Plaintext plt;
    Ciphertext ciph;
    ckks_encoder.encode(message, scale, plt);
    enc.encrypt(plt, ciph);

    // test decryption
    Plaintext plt_res;
    for (auto i = 0; i < 5; ++i)
    {
        std::cout << " i = " << i << std::endl;
        dec.decrypt(ciph, plt_res);
        std::vector<std::complex<double>> vec;
        ckks_encoder.decode(plt_res, vec);
        std::cout << "expected result: " << vec[0] << "  " << vec[1] << "  " << vec[2] << std::endl;
    }

    // test rotation
    {
        Ciphertext ciph_rotate = ciph;
        for (auto i = 0; i < 20; ++i)
        {
            ckks_eva->rotate(ciph_rotate, ciph_rotate, -1, rot_keys);
        }


        dec.decrypt(ciph_rotate, plt_res);
        std::vector<std::complex<double>> vec;
        ckks_encoder.decode(plt_res, vec);
        std::cout << "expected result: " << vec[0+20] << "  " << vec[1+20] << "  " << vec[2+20] << std::endl;
    }

    // test multiplication
    {
        std::vector<std::complex<double>> vec_one = {{1.0, 0.0}, {1.0, 0.0}, {1.0, 0.0}};
        Plaintext plt_one;
        Ciphertext ciph_one;
        ckks_encoder.encode(vec_one, scale, plt_one);
        enc.encrypt(plt_one, ciph_one);

        Ciphertext ciph_res;
        ckks_eva->multiply_relin(ciph, ciph_one, ciph_res, relin_keys);
        ckks_eva->rescale(ciph_res, ciph_res);

        dec.decrypt(ciph_res, plt_res);
        std::vector<std::complex<double>> vec;
        ckks_encoder.decode(plt_res, vec);
        std::cout << "expected result: " << vec[0+20] << "  " << vec[1+20] << "  " << vec[2+20] << std::endl;
    }



    return 0;
}