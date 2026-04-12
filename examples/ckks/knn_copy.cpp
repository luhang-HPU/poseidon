
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/precision.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/util/thread_pool.h"
#include "poseidon/util/json.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <filesystem>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace std;

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

#define DEBUG_LRTRAIN

std::filesystem::path current_path(__FILE__);
int data_nums = 100;
int dimension = 10;
int N = 16384;
int NUM = 128;
int num_threads = 8;

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);
std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);

void read_jsonl_query(const std::string &file, std::vector<std::vector<std::complex<double>>> &query)
{
    std::ifstream infile(file);
    if (!infile.is_open())
    {
        POSEIDON_THROW(config_error, "cannot open file ：" + file);
    }

    // 读取整个文件内容
    std::stringstream buffer;
    buffer << infile.rdbuf();
    json j_all = json::parse(buffer.str());
    infile.close();

    query.clear();
    // 获取 query 数组
    std::vector<double> real_vec = j_all["query"].get<std::vector<double>>();

    // 生成 10 行，每行复制对应实数 100 次，转为复数
    for (int i = 0; i < 10; ++i)
    {
        std::vector<std::complex<double>> row(10000, std::complex<double>(real_vec[i] / 40, 0.0));
        query.push_back(row);
    }
}

void read_jsonl_data(const std::string &file, std::vector<std::vector<std::complex<double>>> &matrix_data)
{
    std::ifstream infile(file);
    if (!infile.is_open())
    {
        throw std::runtime_error("cannot open file: " + file);
    }

    json j_all;
    infile >> j_all;

    // 读取二维数组
    if (!j_all.contains("data") || !j_all["data"].is_array())
    {
        throw std::runtime_error("Invalid JSON: 'data' field missing or not an array");
    }

    const auto &data_array = j_all["data"];
    size_t num_rows = data_array.size();
    if (num_rows == 0)
        return;

    size_t num_cols = data_array[0].size();

    for (size_t row = 0; row < num_rows; ++row)
    {
        const auto &row_data = data_array[row];
        if (!row_data.is_array() || row_data.size() != num_cols)
        {
            throw std::runtime_error("Inconsistent row size in JSON data");
        }

        // 每行复制100次
        for (int copy = 0; copy < 100; ++copy)
        {
            // 计算复制后的目标行索引 = 原始行索引 * 100 + 复制次数
            size_t target_row = row + copy * 100;

            for (size_t col = 0; col < num_cols; ++col)
            {
                matrix_data[col][target_row] = std::complex<double>(row_data[col].get<double>() / 40, 0.0);
            }
        }
    }

    for (size_t row = 0; row < num_rows; ++row)
    {
        const auto &row_data = data_array[row];
        if (!row_data.is_array() || row_data.size() != num_cols)
        {
            throw std::runtime_error("Inconsistent row size in JSON data");
        }

        // 每行复制100次
        for (int copy = 0; copy < 100; ++copy)
        {
            // 计算复制后的目标行索引 = 原始行索引 * 100 + 复制次数
            size_t target_row = row * 100 + copy;

            for (size_t col = 0; col < num_cols; ++col)
            {
                matrix_data[col + 10][target_row] = std::complex<double>(row_data[col].get<double>() / 40, 0.0);
            }
        }
    }
}

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale)
{
    Plaintext plain;
    Ciphertext ciph;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
    return ciph;
}

std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale)
{
    std::vector<Ciphertext> vec_ciph;
    for (int i = 0; i < message.size(); ++i)
    {
        Plaintext plain;
        Ciphertext ciph;
        encoder.encode(message[i], scale, plain);
        encryptor.encrypt(plain, ciph);
        vec_ciph.push_back(ciph);
    }
    return vec_ciph;
}

std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph)
{
    Plaintext plain;
    decryptor.decrypt(ciph, plain);
    std::vector<std::complex<double>> message;
    encoder.decode(plain, message);
    return message;
}

void encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                        std::vector<std::complex<double>> &message, double scale, Ciphertext &ciph)
{
    Plaintext plain;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
}

// std::vector<Ciphertext> encode_and_encrypt_mt(const CKKSEncoder &encoder, const Encryptor &encryptor,
//                                               std::vector<std::vector<std::complex<double>>> &message,
//                                               double scale)
// {
//     ThreadPool thread_pool(num_threads);
//     std::vector<Ciphertext> vec_ciph;
//     vec_ciph.resize(message.size());
//     const int work_load = (message.size() + num_threads - 1) / num_threads;
//     for (int w = 0; w < num_threads; ++w)
//     {
//         int start = w * work_load;
//         int end = std::min<int>(start + work_load, message.size());

//         if (end > start)
//         {
//             thread_pool.enqueue(
//                 [&](size_t s, size_t e)
//                 {
//                     for (size_t i = s; i < e; ++i)
//                     {
//                         encode_and_encrypt(encoder, encryptor, message[i], scale, vec_ciph[i]);
//                     }
//                 },
//                 start, end);
//         }
//     }
//     return vec_ciph;
// }

std::vector<Ciphertext> encode_and_encrypt_mt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                              std::vector<std::vector<std::complex<double>>> &message,
                                              double scale)
{
    size_t num_messages = message.size();
    std::vector<Ciphertext> vec_ciph(num_messages);

    #pragma omp parallel for num_threads(num_threads)
    for (int i = 0; i < static_cast<int>(num_messages); ++i)
    {
        // 每个线程处理 message 的不同索引，不存在写冲突
        encode_and_encrypt(encoder, encryptor, message[i], scale, vec_ciph[i]);
    }

    return vec_ciph;
}


void sub_and_square(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
                    std::vector<Ciphertext> &ciph_data, const std::vector<Ciphertext> &ciph_query, const poseidon::RelinKeys &relin_keys, const double scale)
{
    std::vector<Ciphertext> vec_ciph;
    vec_ciph.resize(ciph_data.size());

    ThreadPool thread_pool(num_threads);
    const int work_load = (ciph_query.size() + num_threads - 1) / num_threads;

    for (int w = 0; w < num_threads; ++w)
    {
        int start = w * work_load;
        int end = std::min<int>(start + work_load, ciph_query.size());

        if (end > start)
        {
            thread_pool.enqueue(
                [&](size_t s, size_t e)
                {
                    for (size_t i = s; i < e; ++i)
                    {
                        ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);
                        ckks_eva->sub(ciph_data[i + 10], ciph_query[i], ciph_data[i + 10]);

                        ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i], relin_keys);
                        ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);

                        ckks_eva->multiply_relin(ciph_data[i + 10], ciph_data[i + 10], ciph_data[i + 10], relin_keys);
                        ckks_eva->rescale_dynamic(ciph_data[i + 10], ciph_data[i + 10], scale);
                    }
                },
                start, end);
        }
    }
}

// void sub_and_square(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
//                     std::vector<Ciphertext> &ciph_data, 
//                     const std::vector<Ciphertext> &ciph_query, 
//                     const poseidon::RelinKeys &relin_keys, 
//                     const double scale)
// {
//     // 获取需要迭代的次数（基于查询向量的大小）
//     int query_size = static_cast<int>(ciph_query.size());

//     // 使用 OpenMP 并行化循环
//     // num_threads 为您之前定义的线程数变量
//     #pragma omp parallel for num_threads(num_threads)
//     for (int i = 0; i < query_size; ++i)
//     {
//         // 计算 ciph_data[i] 部分
//         ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);
//         ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i], relin_keys);
//         ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);

//         // 计算 ciph_data[i + 10] 部分
//         // 注意：需确保 ciph_data 的长度至少为 ciph_query.size() + 10
//         ckks_eva->sub(ciph_data[i + 10], ciph_query[i], ciph_data[i + 10]);
//         ckks_eva->multiply_relin(ciph_data[i + 10], ciph_data[i + 10], ciph_data[i + 10], relin_keys);
//         ckks_eva->rescale_dynamic(ciph_data[i + 10], ciph_data[i + 10], scale);
//     }
// }


void match_param_id(Ciphertext &ciph1, Ciphertext &ciph2,
                    std::shared_ptr<EvaluatorCkksBase> eva)
{
    if (ciph1.level() > ciph2.level())
    {
        eva->drop_modulus(ciph1, ciph1, ciph2.parms_id());
    }
    else if (ciph1.level() < ciph2.level())
    {
        eva->drop_modulus(ciph2, ciph2, ciph1.parms_id());
    }
}

void match_scale(Ciphertext &ciph1, Ciphertext &ciph2,
                 const CKKSEncoder &encoder,
                 std::shared_ptr<EvaluatorCkksBase> eva,
                 double scale)
{
    if (!util::are_approximate(ciph1.scale(), ciph2.scale()))
    {
        ciph1.scale() = ciph2.scale();
        std::vector<std::complex<double>> vec_tmp(NUM, {1.0, 0.0});
        Plaintext plt_tmp;

        // for ciph_1
        {
            encoder.encode(vec_tmp, ciph2.parms_id(), scale * scale / ciph2.scale(), plt_tmp);
            eva->multiply_plain(ciph2, plt_tmp, ciph2);
            eva->rescale(ciph2, ciph2);
        }

        // for ciph_2
        {
            encoder.encode(vec_tmp, ciph1.parms_id(), scale * scale / ciph1.scale(), plt_tmp);
            eva->multiply_plain(ciph1, plt_tmp, ciph1);
            eva->rescale(ciph1, ciph1);
        }
    }
}

// sign_1 第一次sign 近似拟合
Ciphertext sign_1(const Ciphertext &ciph,
                  const PolynomialVector &polys_1,
                  const PolynomialVector &polys_2,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys, encoder);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys, encoder);
    eva->add_const(ciph_result, 0.5, ciph_result, encoder);
    return ciph_result;
}

// sign_2 第二次拟合
Ciphertext sign_2(const Ciphertext &ciph,
                  const PolynomialVector &polys,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys, ciph_result.scale(), relin_keys, encoder);
    return ciph_result;
}

void writePredictions(const std::vector<int> &data, std::string predictions_file)
{
    try
    {
        std::filesystem::create_directories(std::filesystem::path(predictions_file).parent_path());
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        std::cerr << "创建目录失败: " << e.what() << std::endl;
        return;
    }

    // 打开文件（使用trunc模式确保覆盖原有内容）
    std::ofstream out_file(predictions_file, std::ios::trunc);
    if (!out_file.is_open())
    {
        std::cerr << "无法打开文件: " << predictions_file << std::endl;
        return;
    }

    // 写入JSON格式内容
    out_file << "{ \"answer\": [ ";
    for (size_t i = 0; i < 10; ++i)
    {
        if (i < data.size())
        {
            out_file << data[i];
        }
        else
        {
            out_file << 100;
        }

        if (i != 9)
        {
            out_file << ", ";
        }
    }
    out_file << " ] }";

    // 关闭文件
    out_file.close();
}

Ciphertext accumulate_top_n_block(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                                  const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                                  const GaloisKeys rot_keys)
{
    if (n <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "n cannot be negative");
    }

    Ciphertext ciph_rotate_sum = ciph;

    std::vector<std::complex<double>> zero = {{0.0, 0.0}};
    Plaintext plain_zero;
    Ciphertext ciph_sum;
    encoder.encode(zero, ciph.parms_id(), ciph.scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_sum);

    int cnt = 0;
    int bottom_nth = 0;
    const int const_n = n;
    while (n > 1)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
            ckks_eva->rotate(ciph_rotate_sum, ciph_rotate_sum, 100, rot_keys);
            n--;
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, n * 100, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

// 生成n个范围在0.9到1.1之间的随机数
std::vector<double> generateRandomNumbers(int n) {
    std::vector<double> result;
    if (n <= 0) {
        return result; // 如果n为非正数，返回空向量
    }
    
    // 使用当前时间作为随机数种子，确保每次运行生成不同序列
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Mersenne Twister随机数生成器
    std::mt19937 generator(seed);
    
    // 定义0.9到1.1之间的均匀分布
    std::uniform_real_distribution<double> distribution(0.9, 1.1);
    
    // 生成n个随机数
    for (int i = 0; i < n; ++i) {
        result.push_back(distribution(generator));
    }
    
    return result;
}

int main(int argc, char *argv[])
{
    util::Timestacs timer;
    util::Timestacs timer_init;
    util::Timestacs timer_calculate;
    timer.start();
    timer_init.start();
    // 参数设置
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 15;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(18, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
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
    vector<int> step = {100, 200, 300, 600, 1200, 2500, 5000};
    kgen.create_galois_keys(step, rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // 多项式构建
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;
    }
    slots_index[0] = idxF;

    vector<complex<double>> buffer = {0, 3.816912, 0, -9.226954, 0, 11.954844, 0, -5.516258};
    Polynomial approxF(buffer, 0, 0, 7, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    PolynomialVector polys(poly_v, slots_index);

    buffer = {0, 2.5390678487943066, 0, -15.36649590685934, 0, 72.05487340640471, 0, -229.83084441307128, 0, 510.7603223522984,
              0, -810.2812835443851, 0, 932.3382320828513, 0, -783.7465043857175, 0, 480.4851545467111, 0, -212.16308093582333,
              0, 65.63925462800184, 0, -13.490628831305791, 0, 1.6532569365778251, 0, -0.091371472313767};
    Polynomial approxF_1(buffer, 0, 0, 27, Monomial);
    approxF_1.lead() = true;
    vector<Polynomial> poly_v_1{approxF_1};
    PolynomialVector polys_1(poly_v_1, slots_index);

    buffer = {0.5, 0.197, 0, -0.004};
    Polynomial approxF_2(buffer, 0, 0, 3, Monomial);
    approxF_2.lead() = true;
    vector<Polynomial> poly_v_2{approxF_2};
    PolynomialVector polys_2(poly_v_2, slots_index);

    vector<vector<complex<double>>> query(10, vector<complex<double>>(N, {0.0, 0.0}));
    vector<vector<complex<double>>> data(20, vector<complex<double>>(N, {0.0, 0.0}));

    // 提交使用 参数解析,读入文件路径
    // std::string dataset_file;
    // std::string predictions_file;
    // for (int i = 1; i < argc; i++) {
    //     if (std::string(argv[i]) == "--dataset") {
    //         dataset_file = argv[++i];
    //     } else if (std::string(argv[i]) == "--predictions") {
    //         predictions_file = argv[++i];
    //     }
    // }
    // read_jsonl_query(dataset_file, query);
    // read_jsonl_data(dataset_file, data);
    std::string predictions_file = current_path.parent_path().string() + "/" + "predictions.jsonl";
    read_jsonl_query(current_path.parent_path().string() + "/" + "train.jsonl", query);
    read_jsonl_data(current_path.parent_path().string() + "/" + "train.jsonl", data);

    timer_init.end();
    timer_calculate.start();

    vector<Ciphertext> ciph_query = encode_and_encrypt_mt(ckks_encoder, enc, query, scale);
    vector<Ciphertext> ciph_data = encode_and_encrypt_mt(ckks_encoder, enc, data, scale);

    // 比较数组
    std::vector<std::complex<double>> cmp_top_k(N, {0.0, 0.0});
    for (size_t i = 0; i < data_nums; i++)
    {
        cmp_top_k[i].real(10.5);
    }
    Ciphertext ciph_top_k = encode_and_encrypt(ckks_encoder, enc, cmp_top_k, scale);

    sub_and_square(ckks_eva, ciph_data, ciph_query, relin_keys, scale);
    Ciphertext ciph_distance_1 = ciph_data[0];
    Ciphertext ciph_distance_2 = ciph_data[dimension];
    for (size_t i = 1; i < dimension; i++)
    {
        ckks_eva->add(ciph_distance_1, ciph_data[i], ciph_distance_1);
        ckks_eva->add(ciph_distance_2, ciph_data[i + dimension], ciph_distance_2);
    }

    Ciphertext ciph_result;
    ckks_eva->sub_dynamic(ciph_distance_1, ciph_distance_2, ciph_result, ckks_encoder);

    Ciphertext ciph_tmp = sign_1(ciph_result, polys, polys_1, ckks_encoder, ckks_eva, relin_keys);
    ciph_result = accumulate_top_n_block(ciph_tmp, 100, ckks_encoder, enc, ckks_eva, rot_keys);

    match_param_id(ciph_result, ciph_top_k, ckks_eva);
    match_scale(ciph_result, ciph_top_k, ckks_encoder, ckks_eva, scale);

    ckks_eva->sub_dynamic(ciph_top_k, ciph_result, ciph_result, ckks_encoder);

    ckks_eva->multiply_const(ciph_result, 0.014, scale, ciph_result, ckks_encoder);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);

    ciph_result = sign_2(ciph_result, polys_2, ckks_encoder, ckks_eva, relin_keys);

    Plaintext pl_mask;
    std::vector<double> ran = generateRandomNumbers(data_nums);
    vector<complex<double>> vec_mask(N, {0.0, 0.0});
    for (size_t i = 0; i < data_nums; i++)
    {
        vec_mask[i] = ran[i];
    }
    ckks_encoder.encode(vec_mask, ciph_result.parms_id(), scale, pl_mask);    
    ckks_eva->multiply_plain(ciph_result, pl_mask, ciph_result);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);
    std::cout << "ciph_result.coeff_modulus_size() - 1: " << ciph_result.coeff_modulus_size() - 1 << std::endl;

    // 查询方
    auto result_index = decrypt_and_decode(ckks_encoder, dec, ciph_result);
    std::vector<int> result;
    for (size_t i = 0; i < 100; ++i)
    {
        if (std::round(result_index[i].real()) == 1)
        {
            result.push_back(i + 1);
        }
    }

    writePredictions(result, predictions_file);

    timer_calculate.end();
    timer.end();
    timer_init.print_time_ms("Init time: ");
    timer_calculate.print_time_ms("Calculate time: ");
    timer.print_time_ms("All time: ");
    return 0;
}
