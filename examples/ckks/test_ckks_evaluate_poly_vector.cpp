#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"
#include "src/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;
double fii(double x)
{
    // return  1 / (exp(-x) + 1);
    return sin(6.283185307179586 * x);
}
int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, 32, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
                               32, 32, 32, 32, 32, 32, 32, 32, 32, 50};
    vector<uint32_t> log_p_tmp{50};

    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // init random data
    int mat_size = 1 << ckks_param_literal.log_slots();
    // create message
    vector<complex<double>> message;
    sample_random_complex_vector(message, mat_size);
    for (int i = 0; i < mat_size; i++)
    {
        message[i] = complex<double>(0.79 - (double)i / mat_size, 0.38 - (double)(i) / mat_size);
    }
    for (int i = 0; i < message.size(); i++)
    {
        message[i].imag(0);
    }
    vector<complex<double>> message1(message.size());
    for (size_t i = 0; i < (context.parameters_literal()->degree() >> 1); i++)
    {
        message1[i].real(fii(message[i].real()));
    }

    // poly init
    auto a = -4.0;
    auto b = 4.0;
    auto deg = 64;
    printf("Evaluation of the function f(x) for even slots and g(x) for odd slots in the range "
           "[%0.2f, %0.2f] (degree of approximation: %d)\n",
           a, b, deg);
    auto approx_f = util::approximate(fii, a, b, deg);
    approx_f.lead() = true;
    vector<Polynomial> poly_v{approx_f};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idx_f(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < (context.parameters_literal()->degree() >> 1); i++)
    {
        // Index with all even slots
        idx_f[i] = i;
    }

    // Assigns index of all even slots to poly[0] = f(x)
    slots_index[0] = idx_f;

    PolynomialVector polys(poly_v, slots_index);
    PublicKey public_key;
    RelinKeys relin_keys;
    CKKSEncoder ckks_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    Plaintext plaintext1, plaintext2;
    vector<complex<double>> message2;
    double scale = std::pow(2.0, 32);
    ckks_encoder.encode(message, scale, plaintext1);
    Ciphertext ct1, ct2;
    enc.encrypt(plaintext1, ct1);

    ckks_eva->multiply_const(ct1, (2.0 / (double)(b - a)), scale, ct1, ckks_encoder);
    ckks_eva->rescale_dynamic(ct1, ct1, ct1.scale());
    ckks_eva->read(ct1);
    Timestacs time;
    time.start();
    ckks_eva->evaluate_poly_vector(ct1, ct2, polys, ct1.scale(), relin_keys, ckks_encoder);
    time.end();
    printf("ct1 scale : %.10lf\n", ct1.scale());
    time.print_time("evaluate_poly_vector time :");
    ckks_eva->read(ct2);
    dec.decrypt(ct2, plaintext2);
    ckks_encoder.decode(plaintext2, message2);

    for (auto i = 0; i < 8; i++)
    {
        printf("source_data[%d] : %.10lf + %.10lf I\n", i, message1[i].real(), message1[i].imag());
        printf("result  vec[%d] : %.10lf + %.10lf I\n", i, message2[i].real(), message2[i].imag());
    }

    util::GetPrecisionStats(message1, message2);

    return 0;
}
