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

    ParametersLiteral ckks_param_literal{CKKS, 15, 14, 40, 5, 0, 0, {}, {}};
    vector<uint32_t> log_q_tmp{40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40};
    vector<uint32_t> log_p_tmp{40};
    ckks_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // =====================init data ============================
    auto vec_size = ckks_param_literal.slot();
    double age, sbp, dbp, chl, weight, height;
    age = 26;
    sbp = 100;
    dbp = 70;
    chl = 100;
    weight = 71;
    height = 180;

    std::cout << "The default parameter: " << std::endl;
    std::cout << "age: 26" << std::endl;
    std::cout << "systolic blood pressure: 100" << std::endl;
    std::cout << "diastolic blood pressure: 70" << std::endl;
    std::cout << "total cholesterol: 100" << std::endl;
    std::cout << "weight(kg): 71" << std::endl;
    std::cout << "height(kg): 180" << std::endl;

    // create message
    vector<complex<double>> message_age, message_sbp, message_dbp, message_chl, message_weight,
        message_height, vec_result;
    message_age.resize(vec_size);
    message_sbp.resize(vec_size);
    message_dbp.resize(vec_size);
    message_chl.resize(vec_size);
    message_weight.resize(vec_size);
    message_height.resize(vec_size);

    // message下标为0的地址存储对应身体数据的原始值
    message_age[0] = age;
    message_sbp[0] = sbp;
    message_dbp[0] = dbp;
    message_chl[0] = chl;
    message_weight[0] = weight;
    message_height[0] = height;

    // coef存储对应系数
    double coef_age = 0.072;
    double coef_sbp = 0.013;
    double coef_dbp = -0.029;
    double coef_chl = 0.008;
    double coef_weight = -0.053;
    double coef_height = 0.021;

    // taylor展开的系数
    double taylor_coef_0 = 1.0 / 2;
    double taylor_coef_1 = 1.0 / 4;
    double taylor_coef_3 = -1.0 / 48;
    double taylor_coef_5 = 1.0 / 480;
    double taylor_coef_7 = -17.0 / 80640;
    double taylor_coef_9 = 31.0 / 1451520;

    // init Plaintext and Ciphertext
    Plaintext plain_age, plain_sbp, plain_dbp, plain_chl, plain_weight, plain_height, plain_result;
    Ciphertext cipher_age, cipher_sbp, cipher_dbp, cipher_chl, cipher_weight, cipher_height,
        cipher_x, cipher_x_square, cipher_result;
    PublicKey public_key;
    RelinKeys relin_keys;
    CKKSEncoder ckks_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());

    // encode
    ckks_encoder.encode(message_age, ckks_param_literal.scale(), plain_age);
    ckks_encoder.encode(message_sbp, ckks_param_literal.scale(), plain_sbp);
    ckks_encoder.encode(message_dbp, ckks_param_literal.scale(), plain_dbp);
    ckks_encoder.encode(message_chl, ckks_param_literal.scale(), plain_chl);
    ckks_encoder.encode(message_weight, ckks_param_literal.scale(), plain_weight);
    ckks_encoder.encode(message_height, ckks_param_literal.scale(), plain_height);

    // encrypt
    enc.encrypt(plain_age, cipher_age);
    enc.encrypt(plain_sbp, cipher_sbp);
    enc.encrypt(plain_dbp, cipher_dbp);
    enc.encrypt(plain_chl, cipher_chl);
    enc.encrypt(plain_weight, cipher_weight);
    enc.encrypt(plain_height, cipher_height);

    // calculate
    auto start = chrono::high_resolution_clock::now();

    // 计算 x = 0.072∙Age+0.013∙SBP-0.029∙DBP+0.008∙CHL-0.053∙weight+0.021∙height
    auto scale = ckks_param_literal.scale();
    ckks_eva->multiply_const(cipher_age, coef_age, scale, cipher_age, ckks_encoder);
    ckks_eva->multiply_const(cipher_sbp, coef_sbp, scale, cipher_sbp, ckks_encoder);
    ckks_eva->multiply_const(cipher_dbp, coef_dbp, scale, cipher_dbp, ckks_encoder);
    ckks_eva->multiply_const(cipher_chl, coef_chl, scale, cipher_chl, ckks_encoder);
    ckks_eva->multiply_const(cipher_weight, coef_weight, scale, cipher_weight, ckks_encoder);
    ckks_eva->multiply_const(cipher_height, coef_height, scale, cipher_height, ckks_encoder);

    ckks_eva->add(cipher_age, cipher_sbp, cipher_x);
    ckks_eva->add(cipher_x, cipher_dbp, cipher_x);
    ckks_eva->add(cipher_x, cipher_chl, cipher_x);
    ckks_eva->add(cipher_x, cipher_weight, cipher_x);
    ckks_eva->add(cipher_x, cipher_height, cipher_x);
    ckks_eva->rescale_dynamic(cipher_x, cipher_x, scale);

    // 计算e^x/(e^x+1)
    ckks_eva->multiply_relin_dynamic(cipher_x, cipher_x, cipher_x_square, relin_keys);
    ckks_eva->rescale_dynamic(cipher_x_square, cipher_x_square, scale);

    ckks_eva->multiply_const(cipher_x_square, taylor_coef_9, scale, cipher_result, ckks_encoder);
    ckks_eva->add_const(cipher_result, taylor_coef_7, cipher_result, ckks_encoder);

    ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);
    ckks_eva->add_const(cipher_result, taylor_coef_5, cipher_result, ckks_encoder);

    ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);
    ckks_eva->add_const(cipher_result, taylor_coef_3, cipher_result, ckks_encoder);

    ckks_eva->rescale_dynamic(cipher_result, cipher_result, scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relin_keys);
    ckks_eva->add_const(cipher_result, taylor_coef_1, cipher_result, ckks_encoder);

    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x, cipher_result, relin_keys);
    ckks_eva->add_const(cipher_result, taylor_coef_0, cipher_result, ckks_encoder);

    ckks_eva->read(cipher_result);
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    std::cout << "EXP TIME: " << duration.count() << " microseconds" << std::endl;

    // decode & decrypt
    dec.decrypt(cipher_result, plain_result);
    ckks_encoder.decode(plain_result, vec_result);
    printf("answer after FHE = %.8f \n", real(vec_result[0]));

    // expected answer
    double x = coef_age * age + coef_sbp * sbp + coef_dbp * dbp + coef_chl * chl +
               coef_weight * weight + coef_height * height;

    printf("expected answer = %.8f \n", exp(x) / (exp(x) + 1));

    return 0;
}
