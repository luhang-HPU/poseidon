#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/basics/randomtostd.h"
#include <fstream>

using namespace poseidon;
using namespace poseidon::util;



struct regevParam
{
    int n;
    int q;
    double std_dev;
    int m;
    regevParam()
    {
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000;
    }
    regevParam(int n, int q, double std_dev, int m)
        : n(n), q(q), std_dev(std_dev), m(m)
    {
    }
};

// struct regevCiphertext{
//     NativeVector a;
//     NativeInteger b;
// };

typedef std::vector<int> regevSK;

struct regevCiphertext
{
    std::vector<int> a;
    int b;
};

inline long power(long x, long y, long m)
{
    if (y == 0)
        return 1;
    long p = power(x, y / 2, m) % m;
    p = (p * p) % m;

    return (y % 2 == 0) ? p : (x * p) % m;
}

inline long modInverse(long a, long m)
{
    return power(a, m - 2, m);
}

vector<vector<int>> generateMatrixU_transpose(int n, const int q = 65537)
{
    cout << "Generating MatrixU ... " << n << endl;
    vector<vector<int>> U(n, vector<int>(n));
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            if (i == 0)
            {
                // U[0][j]=g^jmodq
                U[i][j] = (int)power(3, j, q);
            }
            else if (i == n / 2)
            {
                // U[n/2][j]=U[0][j]^−1modq
                U[i][j] = (int)modInverse(U[0][j], q);
            }
            else
            {
                // U[i][j]=(U[i−1][j])^3modq
                U[i][j] = (int)power(U[i - 1][j], 3, q);
            }
        }
    }
    cout << "Generation MatrixU finished. " << endl;
    return U;
}

void writeUtemp(const vector<uint64_t> U_temp, const int i)
{
    ofstream datafile;
    datafile.open("../data/U_temp/" + to_string(i) + ".txt");

    for (size_t i = 0; i < U_temp.size(); i++)
    {
        datafile << U_temp[i] << "\n";
    }
    datafile.close();
}

Ciphertext slotToCoeff_WOPrepreocess(std::unique_ptr<EvaluatorBfvBase> &evaluator,
                                     std::unique_ptr<EvaluatorBfvBase> &evaluator_coeff,
                                     vector<Ciphertext> &ct_sqrt_list,
                                     const GaloisKeys &gal_keys,
                                     BatchEncoder &batch_encoder,
                                     const int sq_rt = 128, const int degree = 32768, const int q = 65537, const int scalar = 1)
{

    // 生成明文矩阵，通过生成元生成
    vector<vector<int>> U = generateMatrixU_transpose(degree, q);

    vector<Ciphertext> result(sq_rt);
    for (int iter = 0; iter < sq_rt; iter++)
    {
        for (int j = 0; j < (int)ct_sqrt_list.size(); j++)
        {
            // result[iter]=j∑​  (ct_sqrt_list[j]⊗Uiter,j​)
            // 计算矩阵 U 的一列
            vector<uint64_t> U_tmp(degree);
            for (int i = 0; i < degree; i++)
            {
                int row_index = (i - iter) % (degree / 2) < 0 ? (i - iter) % (degree / 2) + degree / 2 : (i - iter) % (degree / 2);
                row_index = i < degree / 2 ? row_index : row_index + degree / 2;
                int col_index = (i + j * sq_rt) % (degree / 2);
                if (j < (int)ct_sqrt_list.size() / 2)
                { // first half
                    col_index = i < degree / 2 ? col_index : col_index + degree / 2;
                }
                else
                {
                    col_index = i < degree / 2 ? col_index + degree / 2 : col_index;
                }
                U_tmp[i] = (U[row_index][col_index] * scalar) % q;
            }
            writeUtemp(U_tmp, j * sq_rt + iter);

            Plaintext U_plain;
            batch_encoder.encode(U_tmp, U_plain);
            evaluator->transform_to_ntt_inplace(U_plain, ct_sqrt_list[j].parms_id());

            if (j == 0)
            {
                evaluator->multiply_plain(ct_sqrt_list[j], U_plain, result[iter]);
            }
            else
            {
                Ciphertext temp;
                evaluator->multiply_plain(ct_sqrt_list[j], U_plain, temp);
                evaluator->add(result[iter], temp, result[iter]);
            }
        }
    }

    for (int i = 0; i < (int)result.size(); i++)
    {
        evaluator->transform_from_ntt_inplace(result[i]);
    }

    for (int iter = sq_rt - 1; iter > 0; iter--)
    {
        evaluator_coeff->rotate_row(result[iter], result[iter], 1, gal_keys);
        evaluator->add(result[iter - 1], result[iter], result[iter - 1]);
    }

    return result[0];
}

vector<regevCiphertext> extractRLWECiphertextToLWECiphertext(Ciphertext &rlwe_ct, const int ring_dim = 32768,
                                                             const int n = 1024, const int p = 65537, const uint64_t big_prime = 1152921504589938689)
{
    vector<regevCiphertext> results(ring_dim);

    // 随机数生成器初始化
    prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = std::make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint32_t> dist(0, 100);

    // 处理每个多项式系数
    for (int cnt = 0; cnt < ring_dim; cnt++)
    {
        // NativeVector 其实就是 uint64_t  创建了一个 长度为 n 的 NativeVector 对象
        // results[cnt].a = NativeVector(n);
        results[cnt].a = vector<int>(n);
        int ind = 0;
        // 处理负循环部分   从当前位置向前取系数
        for (int i = cnt; i >= 0 && ind < n; i--)
        {
            // 将大模数域的值缩放到小模数域  temp_f = (rlwe_ct.data(1)[i] * p) / big_prime
            float temp_f = ((float)rlwe_ct.data(1)[i]) * ((float)p) / ((long double)big_prime);
            // 提取小数部分用于随机舍入
            uint32_t decimal = (temp_f - ((int)temp_f)) * 100;
            float rounding = dist(engine) < decimal ? 1 : 0; // 随机舍入决策

            // 应用舍入并取模
            long temp = ((int)(temp_f + rounding)) % p;
            results[cnt].a[ind] = temp < 0 ? p + temp : temp; // 处理负数

            ind++;
        }

        // 处理正循环部分, 从环末尾向前取系数（取负）
        for (int i = ring_dim - 1; i > ring_dim - n + cnt && ind < n; i--)
        {
            float temp_f = ((float)rlwe_ct.data(1)[i]) * ((float)p) / ((long double)big_prime);
            uint32_t decimal = (temp_f - ((int)temp_f)) * 100;
            float rounding = dist(engine) < decimal ? 1 : 0;

            long temp = ((int)(temp_f + rounding)) % p;
            results[cnt].a[ind] = -temp < 0 ? p - temp : -temp;

            ind++;
        }

        // 处理RLWE密文的第一个多项式（对应LWE的b部分）
        float temp_f = ((float)rlwe_ct.data(0)[cnt]) * ((float)p) / ((long double)big_prime);
        uint32_t decimal = temp_f - ((int)temp_f) * 100; // 提取小数部分
        float rounding = dist(engine) < decimal ? 1 : 0; // 随机舍入

        long temp = ((int)(temp_f + rounding)) % p;
        results[cnt].b = temp % ((int)p); // 存储到LWE密文的b部分
    }

    return results;
}

// 将 LWE 的密钥 加密 为 BFV 密文
Ciphertext encryptLWEskUnderBFV(const PoseidonContext& context, const size_t& degree,
                                const PublicKey& BFVpk, const SecretKey& BFVsk,
                                const regevSK& regSk, const regevParam& params) { 
    Ciphertext switchingKey(context);

    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    encryptor.set_secret_key(BFVsk);

    int tempn = 1;
    for(tempn = 1; tempn < params.n; tempn *= 2){}

    vector<uint64_t> skInt(degree);
    for(size_t i = 0; i < degree; i++){
        auto tempindex = i%uint64_t(tempn);
        if(int(tempindex) >= params.n) {
            skInt[i] = 0;
        } else {
            // skInt[i] = uint64_t(regSk[tempindex].ConvertToInt() % params.q);
        }
    }
    Plaintext plaintext;
    batch_encoder.encode(skInt, plaintext);
    encryptor.encrypt_symmetric(plaintext, switchingKey);

    return switchingKey;
}

// assume lwe_sk_len is a power of 2, and has a square root
// 同态计算: ∑(aᵢ · sᵢ) + b
Ciphertext evaluatePackedLWECiphertext(const PoseidonContext& seal_context, std::unique_ptr<EvaluatorBfvBase> &evaluator, vector<regevCiphertext>& lwe_ct_list,
                                       const vector<Ciphertext>& lwe_sk_sqrt_list, const GaloisKeys& gal_keys, const int lwe_sk_len,
                                       const vector<uint64_t>& q_shift_constant, const int degree = 32768,
                                       const bool gateEval = false, const int q = 65537) {
    BatchEncoder batch_encoder(seal_context);

    // rotate sqrt(degree), and get sqrt(degree)'s lwe_sk_encrypted
    // 计算密钥长度的平方根  
    int sq_rt = sqrt(lwe_sk_len);
    // 将 LWE 密钥长度划分为 sq_rt 个分块
    vector<Ciphertext> result(sq_rt);
        
    for (int iter = 0; iter < sq_rt; iter++) {
        for (int j = 0; j < (int) lwe_sk_sqrt_list.size(); j++) {
            vector<uint64_t> lwe_ct_tmp(degree);
            for (int i = 0; i < degree; i++) {
                // 把 LWE 的 a 向量按位放入批次槽（slot）里，使得 batch_encoder 编码后不同槽代表不同 LWE 分量。
                int ct_index = (i-iter) % (degree/2) < 0 ? (i-iter) % (degree/2) + degree/2 : (i-iter) % (degree/2);
                ct_index = i < degree/2 ? ct_index : ct_index + degree/2;
                // 从 a 向量中选取某一列索引（把 lwe_sk_len 展开为 sq_rt × sq_rt 网格）。
                int col_index = (i + j*sq_rt) % lwe_sk_len;
                // 从 LWE 密文的 a 部分取出整数，填入批次向量。
                // lwe_ct_tmp[i] = lwe_ct_list[ct_index].a[col_index].ConvertToInt();
            }

            // 编码为明文并转换到NTT域
            Plaintext lwe_ct_pl;
            batch_encoder.encode(lwe_ct_tmp, lwe_ct_pl);
            evaluator->transform_to_ntt_inplace(lwe_ct_pl, lwe_sk_sqrt_list[j].parms_id());

            // 对每个分块密钥 lwe_sk_sqrt_list[j] 与刚构造的明文做乘法（multiply_plain），得到密文（在 NTT 域），并把这些乘积累加到 result[iter] 中。
            // 第一次 j==0 时直接写入 result[iter]，之后 add_inplace 累加。
            if (j == 0) {
                evaluator->multiply_plain(lwe_sk_sqrt_list[j], lwe_ct_pl, result[iter]);
            } else {
                Ciphertext temp;
                evaluator->multiply_plain(lwe_sk_sqrt_list[j], lwe_ct_pl, temp);
                evaluator->add_inplace(result[iter], temp);
            }

        }
    }

    // 从NTT域转换回系数域 接下来要做行旋转与加法，旋转在系数域
    for (int i = 0; i < (int) result.size(); i++) {
        evaluator->transform_from_ntt_inplace(result[i]);
    }

    // sum up all sq_rt tmp results to the first one, each first rotate left one and add to the previous tmp result
    // 结果合并 - 旋转累加   最终结果在 result[0] 中
    for (int iter = sq_rt-1; iter > 0; iter--) {
        evaluator->rotate_row(result[iter], result[iter], 1, gal_keys);
        evaluator->add_inplace(result[iter-1], result[iter]);
    }

    // 处理LWE密文的b部分
    // 所有 b 值收集为向量 b_parts，编码为明文 lwe_b_pl
    vector<uint64_t> b_parts(degree);
    for(int i = 0; i < degree; i++){
        // b_parts[i] = lwe_ct_list[i].b.ConvertToInt();  // 提取所有b值 
    }

    Plaintext lwe_b_pl;
    batch_encoder.encode(b_parts, lwe_b_pl);
    // LWE 的原式通常是 a·s + b  之前累加得到的是 a·s 的负值，则需要 negate
    // evaluator->negate_inplace(result[0]);        // 取负
    evaluator->add_plain_inplace(result[0], lwe_b_pl);   // 加上b部分

    if (gateEval) {
        Plaintext q_shift_pl;
        batch_encoder.encode(q_shift_constant, q_shift_pl);
        evaluator->add_plain_inplace(result[0], q_shift_pl);
    }

    return result[0];
}


int main()
{
    cout << BANNER << std::endl;
    cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    cout << "" << std::endl;

    int ring_dim = 32768; // 多项式深度为 32768
    int plain_modulus = 65537;
    int n = 1024;

    ParametersLiteralDefault bfv_params(BFV, 32768, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bfv_params);
    cout << "primitive root: " << context.crt_context()->plain_ntt_tables()->get_root() << endl;
    auto evaluator = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    // auto coeff_modulus = CoeffModulus::Create(32768, {55, 60, 60, 60, 60, 60,
    //                                                      60, 60, 60, 60, 50, 60});
    // // 设置系数模数
    // bfv_params.set_coeff_modulus(coeff_modulus);
    // // 设置明文模数 bootstrap_param.ciphertextSpacePrime
    // bfv_params.set_plain_modulus(plain_modulus);

    vector<uint32_t> log_q_tmp{55, 60, 60, 60, 60, 60, 60, 60, 60, 60, 50, 60};
    vector<uint32_t> log_p_tmp{60};
    
    bfv_params.set_log_modulus(log_q_tmp, log_p_tmp);
    bfv_params.set_plain_modulus(plain_modulus);                                                  

    // 密钥生成，目前有些混乱
    KeyGenerator keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    SecretKey bfv_secret_key = keygen.secret_key();

    PublicKey bfv_public_key;
    keygen.create_public_key(bfv_public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // 旋转密钥
    GaloisKeys gal_keys, gal_keys_coeff;
    vector<int> rot_steps = {1};
    for (int i = 0; i < n;)
    {
        rot_steps.push_back(i);
        i += sqrt(n);
    }
    keygen.create_galois_keys(rot_steps, gal_keys);


    BatchEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    // init Plaintext and Ciphertext
    Plaintext plt, plt_res;
    Ciphertext ct, ct_res;
    int mat_size = bfv_params.slot();
    auto level = bfv_params.q().size() - 1;
    vector<uint64_t> msg(mat_size, 1);

    // encode
    encoder.encode(msg, plt);
    encryptor.encrypt(plt, ct);
    vector<Ciphertext> ct_sqrt_list;
    Ciphertext ciph_coeff;


    // ————————————————————————————————————————————丢模数—————————————————————————————————————————————————
    // 裁剪系数模的上下文（降阶）
    auto coeff_modulus_q_last = log_q_tmp;
    // 新的系数模数链将包含原始链的前两个模数和最后一个模数 即{q0, q1, q2, q3, q4}，删除后，新的链为：{q0, q1, q4}
    coeff_modulus_q_last.erase(coeff_modulus_q_last.begin() + 2, coeff_modulus_q_last.end());
    ParametersLiteralDefault parms_last = bfv_params;
    parms_last.set_log_modulus(coeff_modulus_q_last, log_p_tmp);
    PoseidonContext context_last = PoseidonFactory::get_instance()->create_poseidon_context(parms_last);

    // 重新创建一个系数模链较短的 SEALContext。
    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_q_last.size() * ring_dim); // 总大小 = 模数个数 × 环维度
    sk_last.parms_id() = context_last.crt_context()->key_parms_id();
    // 源：原始密钥起始位置  每个多项式的系数数量  要复制的模数数量（除了最后一个）目标：新密钥起始位置
    util::set_poly(bfv_secret_key.data().data(), ring_dim, log_q_tmp.size(), sk_last.data().data());
    // 复制最后一个模数对应的密钥数据
    util::set_poly(
        bfv_secret_key.data().data() + ring_dim * (log_p_tmp.size() - 1), ring_dim, 1,
        sk_last.data().data() + ring_dim * (log_p_tmp.size() - 1));

    // 生成旋转密钥
    vector<int> rot_steps_coeff = {1};
    for (int i = 0; i < ring_dim / 2;)
    {
        if (find(rot_steps_coeff.begin(), rot_steps_coeff.end(), i) == rot_steps_coeff.end())
        {
            rot_steps_coeff.push_back(i);
        }
        i += sqrt(ring_dim / 2);
    }
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(rot_steps_coeff, gal_keys_coeff);


    
    // 卷积计算

    // 模数切换     根据论文  是不是应该最后一个模数设置为 2^17 
    for (auto cipher : ct_sqrt_list) {
        evaluator->drop_modulus(cipher, cipher, context.crt_context()->last_parms_id());
    }
    

    // 计算完以后先将 模数降至最后一层

    // S2C
    Ciphertext coeff = slotToCoeff_WOPrepreocess(evaluator, evaluator, ct_sqrt_list, galois_keys, encoder);

    // RLWE -> LWE   只需传入一个密文
    std::vector<regevCiphertext> lwe_ct = extractRLWECiphertextToLWECiphertext(ciph_coeff);

    // LWE -> RLWE  重打包，恢复大模数Q
    auto lwe_params = regevParam(n, plain_modulus, 1.3, ring_dim);
    // auto lwe_sk = regevGenerateSecretKey(lwe_params);
    int sq_sk = sqrt(n);
    Ciphertext lwe_sk_encrypted = encryptLWEskUnderBFV(context, ring_dim, bfv_public_key, bfv_secret_key, lwe_sk, lwe_params);
    evaluator->rotate_col(lwe_sk_encrypted, lwe_sk_encrypted, gal_keys);
    for (int i = 0; i < sq_sk; i++) {
        // evaluator->rotate_row(lwe_sk_encrypted, sq_sk * i, gal_keys, lwe_sk_sqrt_list[i]);
        evaluator->transform_to_ntt_inplace(lwe_sk_sqrt_list[i]);
    }
    // Ciphertext result = evaluatePackedLWECiphertext(seal_context, lwe_ct_list, lwe_sk_sqrt_list, gal_keys, n, q_shift_constant, ring_dim, gateEval);

}