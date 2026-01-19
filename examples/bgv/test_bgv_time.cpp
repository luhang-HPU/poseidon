#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;
using namespace poseidon::util;


void benchEncoder(BatchEncoder &encoder, uint64_t plain_modulus) {
    size_t slot_count = encoder.slot_count();
    
    // 构造测试数据
    vector<uint64_t> values;
    values.reserve(slot_count);
    for (size_t i = 0; i < slot_count; i++) {
        values.push_back(static_cast<uint64_t>(rand()) % plain_modulus);
    }

    // --- Benchmark Encode ---
    Plaintext pt;
    auto start_encode = chrono::high_resolution_clock::now();
    std::cout << "[POSEIDON] Starting Encoder Benchmarks..." << std::endl;
    int iterations = 1000; 
    for (int i = 0; i < iterations; i++) {
        encoder.encode(values, pt);
    }
    
    auto end_encode = chrono::high_resolution_clock::now();
    cout << "Encode avg time: " 
         << chrono::duration<double, micro>(end_encode - start_encode).count() / iterations 
         << " us" << endl;

    // --- Benchmark Decode ---
    vector<uint64_t> result;
    auto start_decode = chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        encoder.decode(pt, result);
    }
    
    auto end_decode = chrono::high_resolution_clock::now();
    cout << "Decode avg time: " 
         << chrono::duration<double, micro>(end_decode - start_decode).count() / iterations 
         << " us" << endl;
}

void benchNTT(PoseidonContext &context, BatchEncoder &encoder, size_t degree) {

    auto evaluator = PoseidonFactory::get_instance()->create_bfv_evaluator(context);
    KeyGenerator keygen(context);
    // 生成必要的密钥
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // 准备数据
    size_t slot_count = encoder.slot_count();
    vector<uint64_t> vector_data(slot_count, 1.0);
    
    Plaintext pt_plain;
    encoder.encode(vector_data, pt_plain);

    Encryptor encryptor(context, keygen.secret_key());
    Ciphertext ct1, ct2;
    encryptor.encrypt_symmetric(pt_plain, ct1);
    encryptor.encrypt_symmetric(pt_plain, ct2);
    
    std::cout << "[POSEIDON] Starting NTT / INTT Benchmarks..." << std::endl;
    int N = 100; // 迭代次数
    Ciphertext res;
    // --- NTT / INTT ---
    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        evaluator->ntt_fwd(ct1, res);
    }
    cout << "Ciphertext NTT Time: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        evaluator->ntt_inv(res, ct1);
    }
    cout << "Ciphertext INTT Time: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;
}

void benchEvaluator(PoseidonContext &context, BatchEncoder &encoder) {
  
    auto evaluator = PoseidonFactory::get_instance()->create_bgv_evaluator(context);
    KeyGenerator keygen(context);

    // 生成必要的密钥
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // 准备数据
    size_t slot_count = encoder.slot_count();
    vector<uint64_t> vector_data(slot_count, 1.0);
    
    Plaintext pt_plain;
    encoder.encode(vector_data, pt_plain); 

    Encryptor encryptor(context, keygen.secret_key()); // 使用私钥对称加密生成随机密文模拟
    Ciphertext ct1, ct2;
    encryptor.encrypt_symmetric(pt_plain, ct1);
    encryptor.encrypt_symmetric(pt_plain, ct2);

    std::cout << "[POSEIDON] Starting Evaluator Benchmarks..." << std::endl;

    int N = 100; // 迭代次数

    // --- 1. Add / Plaintext (对应 Scalar/Vector/Plaintext) --
    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->add_plain(ct1, pt_plain, ct1);
    }
    cout << "Add_Plain: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 2. Add / Ciphertext ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        auto st = chrono::high_resolution_clock::now();
        evaluator->add(ct1, ct2, ct1);
    }
    cout << "Add_Cipher: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 3. Mul / Plaintext ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->multiply_plain(ct1, pt_plain, res);
    }
    cout << "Mul_Plain: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 4. Mul / Ciphertext (Without Relinearization) ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->multiply(ct1, ct2, res); // 结果 Size 会变为 3
    }
    cout << "Mul_Cipher: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 5. MulRelin / Ciphertext ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->multiply_relin(ct1, ct2, res, relin_keys);
    }
    cout << "Mul_Relin: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 6. Rescale ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->drop_modulus_to_next(ct1, res);
    }
    cout << "Drop_Modulus_to_next: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 7. Rotate rol ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->rotate_row(ct1, res, 1, gal_keys);
    }
    cout << "Rotate_Row: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;

    // --- 8. Rotate col ---
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        Ciphertext res;
        evaluator->rotate_col(ct1, res, gal_keys);
    }
    cout << "Rotate_Col: " << chrono::duration<double, micro>(chrono::high_resolution_clock::now() - start).count() / N << " us" << endl;
}



ParametersLiteral auto_generate_bgv_params(uint32_t level) {
    uint32_t log_n;
    // uint32_t plain_modulus;
    
    // 1. 根据要求绑定 Degree (log_n)
    if (level <= 2) {
        log_n = 13;      // 8192
        // plain_modulus = 1032193;
    } else if (level <= 4) {
        log_n = 14;      // 16384
        // plain_modulus = 786433;
    } else if (level <= 10) {
        log_n = 15;      // 32768
        // plain_modulus = 786433;
    } else {
        log_n = 16;      // 65536
        // plain_modulus = 1032193;
    }

    // 2. 自动化装配 log_q_tmp (交替 50, 51 逻辑)
    // 第一个是 50，后面跟 level 个模数
    std::vector<uint32_t> log_q;
    for (uint32_t i = 0; i < level; ++i) {
        // 实现你注释中的交替：51, 50, 51, 50...
        log_q.push_back((i % 2 == 0) ? 50 : 51);
    }
    // 4. 设置模数链
    std::vector<uint32_t> log_p = {60};

    // --- 打印输出区域 ---
    std::cout << "========================================" << std::endl;
    std::cout << "[POSEIDON] Auto-Configuration Details:" << std::endl;
    std::cout << "  - Target Level: " << level << std::endl;
    std::cout << "  - log_n (Degree): " << log_n << " (" << (1 << log_n) << ")" << std::endl;
    
    // 打印 Q 链
    std::cout << "  - log_q [" << log_q.size() << " primes]: { ";
    for (size_t i = 0; i < log_q.size(); ++i) {
        std::cout << log_q[i] << (i == log_q.size() - 1 ? "" : ", ");
    }
    std::cout << " }" << std::endl;

    // 打印 P 链
    std::cout << "  - log_p [" << log_p.size() << " primes]: { ";
    for (size_t i = 0; i < log_p.size(); ++i) {
        std::cout << log_p[i] << (i == log_p.size() - 1 ? "" : ", ");
    }
    std::cout << " }" << std::endl;
    std::cout << "========================================" << std::endl;
    // -------------------

    // 3. 构造 ParametersLiteral
    // 参数含义: 方案, log_n, log_slots, scale, (此后的参数通常为默认或 0)
    // ParametersLiteral literal{BFV, log_n, log_n - 1, 40, 5, 0, 0, {}, {}};
    ParametersLiteralDefault bgv_param_literal(BGV, 1 << log_n, poseidon::sec_level_type::tc128);
    // ParametersLiteral bgv_param_literal{BGV, log_n, log_n, 0, 5, 0, plain_modulus, {}, {}};
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    bgv_param_literal.set_log_modulus(log_q, log_p);

    return bgv_param_literal;
}

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    #ifdef POSEIDON_USE_OPENMP
    std::cout << "DEBUG: OpenMP Macro is defined!" << std::endl;
    #endif
    std::cout << "" << std::endl;

    for (int i = 2; i < 12; i += 2) {
        // 测试不同乘法深度下的参数生成
        ParametersLiteral bgv_param_literal = auto_generate_bgv_params(i);
        auto context = PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
        
        auto coeff_modulus = context.crt_context()->first_context_data()->coeff_modulus();
        std::cout << "coeff modulus size: " << coeff_modulus.size() << endl;
        BatchEncoder encoder(context);
        // benchEncoder(encoder, bgv_param_literal.plain_modulus().value());
        benchNTT(context, encoder, bgv_param_literal.degree());
        benchEvaluator(context, encoder);
    }

    return 0;
}
