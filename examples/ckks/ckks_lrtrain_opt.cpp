#include "src/ckks_encoder.h"
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/evaluator/evaluator_ckks_base.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/plaintext.h"
#include "src/poseidon_context.h"
#include "src/util/debug.h"
#include "src/util/precision.h"
#include "src/util/random_sample.h"

#include "batch_handler.h"

#include <fstream>
#include <filesystem>
#include <unistd.h>

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

#define DEBUG_LRTRAIN

const int EPOCHS = 5;
const double learning_rate = 0.95;
int m = 5;      // row size of train set
int n = 3;      // column size of train set

namespace check
{
template <typename T> void print_vector(const std::vector<T> &vec, const std::string &comment = "")
{
    ofstream of("output.txt", ios::app);
    of << comment << "  print vector: " << std::endl;
    for (auto value : vec)
    {
        of << value << std::endl;
    }
    of << std::endl;
}

template <typename T> void print_matrix(const std::vector<std::vector<T>> &matrix, const std::string& comment = "")
{
    ofstream of("output.txt", ios::app);
    of << comment << "  print matrix: " << std::endl;
    for (auto row : matrix)
    {
        for (auto value : row)
        {
            of << value << " ";
        }
        of << std::endl;
    }
}

long get_process_memory(int pid)
{
    std::string filename = "/proc/" + to_string(pid) + "/status";

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "cannot open file: " << filename << std::endl;
        return -1;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("VmRSS:") != std::string::npos) {
            std::istringstream iss(line);
            std::string label;
            long rss;
            iss >> label >> rss;
            return rss;
        }
    }

    file.close();
    return -1;
}

}  // namespace check

void read_file(std::vector<std::complex<double>> &matrix, const std::string& file);
void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string& file);

double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y);
double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder);

/*
 * calculate the transpose matrix @x_transpose and diagonal matrix @x_diag
 */
void preprocess(int block_size,
                int block_num,
                std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag);

/*
 * ciph.slot[0] = slot[0] + slot[1] + ... + slot[n-1]
 * ciph.slot[x] = 0 , x != 0
 */
Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys &rot_keys);

/*
 * return the sery expansion of (exp(x) / (1 + exp(x)))
 */
double sigmoid(double x);
Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys);

/*
 * get @ret = 2^x
 * where @min <= 2^x <= @max
 * */
int get_size(int min, int max);

/*
 * accumulate all the slot into first block_size slot
 * [slot[0], ... , slot[block_size], slot[block_size+1], ... slot[block_size+block_size], ...]
 *  ==>
 * [(slot[0] + slot[block_size] + ...), (slot[1] + slot[block_size + 1] + ...), ..., (slot[block_size-1] + slot[block_size - 1 + block_size] + ...), ....]
 */
Ciphertext accumulate_block_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size);

Ciphertext accumulate_slot_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size, int block_num);

/*
 * batch the first @cnt items of @vec
 * into @return vector with block size @block_size
 */
std::vector<std::complex<double>> vector_to_block_message(const std::vector<std::complex<double>> &vec, int cnt, int block_size);

int main()
{
    auto pid = getpid();
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 15;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> log_q(44, 32);
    vector<uint32_t> log_p(1, 60);
    ckks_param_literal.set_log_modulus(log_q, log_p);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    auto slot_size = 1 << ckks_param_literal.log_slots();
    int block_size = get_size(n, slot_size);
    int block_num = (int)std::ceil((double)m / block_size);
    double scale = std::pow(2.0, q_def);

    std::cout << "matrix size: " << m << "*" << n << std::endl;
    std::cout << "block size: " << block_size << std::endl;
    std::cout << "block num: " << block_num << std::endl;

    // input of trainning set
    vector<vector<complex<double>>> x(m, vector<complex<double>>(n, {0.0, 0.0}));
    // output
    vector<complex<double>> y(m, {0.0, 0.0});
    // weight
    vector<complex<double>> weight(n, {0.0, 0.0});
    // transposed matrix of input
    vector<vector<complex<double>>> x_transpose(n, vector<complex<double>>(m, {0.0, 0.0}));
    // diagonal transposed matrix of input
    vector<vector<complex<double>>> x_diag(block_num * block_size, vector<complex<double>>(block_size, {0.0, 0.0}));

    std::filesystem::path current_path(__FILE__);
    read_file(x,current_path.parent_path().string() + "/x_train.txt");
    read_file(y,current_path.parent_path().string() + "/y_train.txt");

    // init weight randomly
    srand(0);
    for (int i = 0; i < n; ++i)
    {
        weight[i].imag(0);
        double sum = 0;
        for (int j = 0; j < 200; ++j)
            sum += rand() / (RAND_MAX + 1.0);
        sum -= 100;
        sum /= sqrt(200.0 * n / 12);
        weight[i].real(sum);
    }
    auto expected_weight = weight;

    preprocess(block_size, block_num, x, x_transpose, x_diag);

    // batching x_diag
    std::vector<std::complex<double>> block_x_diag;
    for (const auto &vec : x_diag)
    {
        std::copy(vec.begin(), vec.begin() + block_size, std::back_inserter(block_x_diag));
    }
    // batching x_transpose
    std::vector<std::vector<std::complex<double>>> block_x_transpose;
    for (auto vec : x_transpose)
    {
        block_x_transpose.push_back(vector_to_block_message(vec, m, block_size));
    }
    // batching weight
    std::vector<std::complex<double>> block_weight;
    {
        /*
         * fulfill the weight vector to size @block_size with zero
         * weight_extend = [weight, 0, 0 ...]
         */
        auto weight_extend = weight;
        if (weight_extend.size() < block_size)
        {
            weight_extend.insert(weight_extend.end(), block_size - weight_extend.size(), {0.0, 0.0});
        }

        // concatenate the weight with the weight
        // weight_concat = [weight_extend , weight_extend]
        auto weight_concat = weight_extend;
        std::copy(weight_concat.begin(), weight_concat.end(), std::back_inserter(weight_concat));

        for (auto i = 0; i < block_size; ++i)
        {
            block_weight.insert(block_weight.end(), weight_concat.begin() + i, weight_concat.begin() + i + block_size);
        }

        while (block_weight.size() < slot_size)
        {
            block_weight.insert(block_weight.end(), block_weight.begin(), block_weight.end());
        }
    }
    // batching y
    std::vector<std::complex<double>> block_y = vector_to_block_message(y, m, block_size);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys conj_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // init keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    std::cout << "Before create galois keys : " << check::get_process_memory(pid) << std::endl;
    kgen.create_galois_keys(rot_keys);
    std::cout << "After create galois keys : " << check::get_process_memory(pid) << std::endl;

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    BatchHandler batch_handler(slot_size, (int)log_degree, block_size, m, n);
    std::vector<Ciphertext> ciph_x_transpose;
    for (auto &vec : block_x_transpose)
    {
        ciph_x_transpose.emplace_back(batch_handler.encode_and_encrypt(ckks_encoder, enc, vec, scale));
    }
    Ciphertext ciph_x_diag = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_x_diag, scale);
    Ciphertext ciph_weight = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_weight, scale);
    Ciphertext ciph_y = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_y, scale);

    for (auto &ciph : ciph_x_transpose)
    {
        auto message_x_transpose = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph);
        check::print_vector(message_x_transpose);
    }

    std::cout << "After encode and encrypt : " << check::get_process_memory(pid) << std::endl;
    vector<complex<double>> buffer(4, 0);
    buffer[0] = 0.5;
    buffer[1] = 0.197;
    buffer[3] = -0.004;

    Polynomial approxF(buffer, 0, 0, 4, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;  // Index with all even slots
    }
    slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v, slots_index);

    for (auto epoch = 0; epoch < EPOCHS; ++epoch)
    {
        util::Timestacs timer;
        timer.start();
        std::cout << "epoch " << epoch << " start..." << std::endl;

        Ciphertext ciph_product;
        Ciphertext ciph_x_diag_tmp = ciph_x_diag;
        if (ciph_x_diag_tmp.level() != ciph_weight.level())
        {
            ckks_eva->drop_modulus(ciph_x_diag_tmp, ciph_x_diag_tmp, ciph_weight.parms_id());
        }
        ckks_eva->multiply_relin(ciph_x_diag_tmp, ciph_weight, ciph_product, relin_keys);
        ckks_eva->rescale_dynamic(ciph_product, ciph_product, scale);
        ciph_product = accumulate_block_matrix(ckks_eva, rot_keys, ciph_product, block_size);

#ifdef DEBUG_LRTRAIN
        // check theta^T * x
        std::vector<double> expected_dot_product;
        {
            for (auto i = 0; i < m; ++i)
            {
                double _sum = 0.0;
                for (auto j = 0; j < n; ++j)
                {
                    _sum += x[i][j].real() * expected_weight[j].real();
                }
                expected_dot_product.push_back(_sum);
            }

            auto fhe_dot_product = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_product);

            std::cout << "fhe value  |  expected value" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << fhe_dot_product[i % block_size + i / block_size * block_size * block_size].real() << " " << expected_dot_product[i] << std::endl;
            }
        }
#endif

        // calculate sigmoid(theta^T x)
        Ciphertext ciph_sigmoid =
            sigmoid_approx(ciph_product, polys, ckks_encoder, ckks_eva, relin_keys);

#ifdef DEBUG_LRTRAIN
        // check sigmoid
        std::vector<double> expected_sigmoid(m, 0.0);
        {
            auto fhe_sigmoid = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_sigmoid);
            std::cout << "fhe sigmoid  |  expected sigmoid" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                expected_sigmoid[i] = sigmoid(expected_dot_product[i]);
                std::cout << fhe_sigmoid[i / block_size * block_size * block_size + (i % block_size)].real() << " " << expected_sigmoid[i] << std::endl;
            }
        }
#endif

        // calculate gradient
        auto ciph_y_tmp = ciph_y;
        if (ciph_y_tmp.level() != ciph_sigmoid.level())
        {
            ckks_eva->drop_modulus(ciph_y_tmp, ciph_y_tmp, ciph_sigmoid.parms_id());
        }

        // TODO scale loss
        ciph_y_tmp.scale() = ciph_sigmoid.scale();
        ckks_eva->sub_dynamic(ciph_sigmoid, ciph_y_tmp, ciph_sigmoid, ckks_encoder);

        Ciphertext ciph_gradient;
        for (auto i = 0; i < n; ++i)
        {
            auto ciph = ciph_x_transpose[i];
            ckks_eva->drop_modulus(ciph, ciph, ciph_sigmoid.parms_id());
            ckks_eva->multiply_relin(ciph, ciph_sigmoid, ciph, relin_keys);
            ckks_eva->rescale_dynamic(ciph, ciph, scale);

            ciph = accumulate_slot_matrix(ckks_eva, rot_keys, ciph, block_size, block_num);
            ciph = accumulate_top_n(ciph, block_size, ckks_encoder, enc, ckks_eva, rot_keys);

            std::vector<std::complex<double>> vec_mask{1.0};
            Plaintext plain_mask;
            ckks_encoder.encode(vec_mask, ciph.parms_id(), ciph.scale(), plain_mask);
            ckks_eva->multiply_plain(ciph, plain_mask, ciph);

            ckks_eva->rotate(ciph, ciph, -i, rot_keys);
            if (i == 0)
            {
                ciph_gradient = ciph;
            }
            else
            {
                ckks_eva->add(ciph, ciph_gradient, ciph_gradient);
            }
        }
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

        ckks_eva->multiply_const(ciph_gradient, learning_rate / m , ciph_gradient.scale(), ciph_gradient, ckks_encoder);
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

#ifdef DEBUG_LRTRAIN
        // check gradient
        std::vector<double> expected_gradient(n, 0.0);
        {
            for (auto i = 0; i < m; ++i)
            {
                for (auto j = 0; j < n; ++j)
                {
                    expected_gradient[j] += (expected_sigmoid[i] - y[i].real()) * x_transpose[j][i].real();
                }
            }

            auto res = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_gradient);
            std::cout << "fhe gradient  |  expected gradient" << std::endl;
            for (auto j = 0; j < n; ++j)
            {
                std::cout << res[j].real() << " " << expected_gradient[j] / m * learning_rate << std::endl;
            }
        }
#endif

        // ciph_grad_concat = concatenate(ciph_grad, ciph_grad)
        Ciphertext ciph_grad_concat;
        {
            Ciphertext ciph_grad_rotated;
            ckks_eva->rotate(ciph_gradient, ciph_grad_rotated, -block_size, rot_keys);
            ckks_eva->add(ciph_gradient, ciph_grad_rotated, ciph_grad_concat);
        }

        Ciphertext ciph_gradient_shift;
        for (auto i = 0; i < block_size; ++i)
        {
            std::vector<std::complex<double>> mask(block_size * 2, {0.0, 0.0});
            std::fill_n(mask.begin() + i, block_size, std::complex<double>{1.0, 0.0});
            Plaintext plain_mask;
            ckks_encoder.encode(mask, ciph_grad_concat.parms_id(), ciph_grad_concat.scale(), plain_mask);

            Ciphertext ciph_grad_concat_rotated;
            ckks_eva->multiply_plain(ciph_grad_concat, plain_mask, ciph_grad_concat_rotated);
            ckks_eva->rescale(ciph_grad_concat_rotated, ciph_grad_concat_rotated);
            ckks_eva->rotate(ciph_grad_concat_rotated, ciph_grad_concat_rotated, -(i * block_size - i), rot_keys);

            if (i == 0)
            {
                ciph_gradient_shift = ciph_grad_concat_rotated;
            }
            else
            {
                ckks_eva->add_dynamic(ciph_grad_concat_rotated, ciph_gradient_shift, ciph_gradient_shift, ckks_encoder);
            }
        }

        for (auto i = 0, _block_num = block_num; (_block_num >>= 1) > 1; ++i)
        {
            Ciphertext ciph_tmp;
            ckks_eva->rotate(ciph_gradient_shift, ciph_tmp, -(block_size * block_size * (1 << i)), rot_keys);
            ckks_eva->add(ciph_gradient_shift, ciph_tmp, ciph_gradient_shift);
        }

        // update ciph_weight
        // TODO scale loss
        ciph_gradient_shift.scale() = ciph_weight.scale();
        ckks_eva->sub_dynamic(ciph_weight, ciph_gradient_shift, ciph_weight, ckks_encoder);

#ifdef DEBUG_LRTRAIN
        // check updated weight
        for (auto j = 0; j < n; ++j)
        {
            expected_weight[j] -= learning_rate * expected_gradient[j] / m;
        }
        std::cout << "fhe weight  |  expected weight" << std::endl;
        auto res = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_weight);
        for (auto i = 0; i < n; ++i)
        {
            std::cout << res[i].real() << " " << expected_weight[i].real() << std::endl;
        }
#endif

        timer.end();
        std::cout << "epoch " << epoch << " end..." << std::endl;
        timer.print_time("lr train time: ");

        // bootstrap
        if(ciph_weight.level() < 10){
            auto start = chrono::high_resolution_clock::now();
            std::cout << "bootstraping start..." << std::endl;
            ckks_eva->bootstrap(ciph_weight, ciph_weight, relin_keys,rot_keys, ckks_encoder);
            auto stop = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
            std::cout << "bootstraping TIME: " << duration.count() << " microseconds" << std::endl;
        }
    }

    std::cout << "fhe training accuracy : " << accuracy_of_ciph(ciph_weight, x, y, dec, ckks_encoder) << std::endl;
#ifdef DEBUG_LRTRAIN
    std::cout << "expected training accuracy : " << accuracy_of_plain(expected_weight, x, y) << std::endl;
#endif

    return 0;
}

double sigmoid(double x)
{
    return (0.5 + 0.197 * x - 0.004 * x * x * x);
}

Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys)
{
    Ciphertext ciph_result;
    eva->evaluate_poly_vector(ciph, ciph_result, polys, ciph.scale(), relin_keys, encoder);
    return ciph_result;
}

double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y)
{
    int cnt = 0;
    for (auto i = 0; i < m; ++i)
    {
        double sum = 0.0;
        for (auto j = 0; j < n; ++j)
        {
            sum += x[i][j].real() * weight[j].real();
        }
        if (abs(sigmoid(sum) - y[i].real()) < 0.5)
        {
            ++cnt;
        }
    }
    return (double)cnt / m;
}

double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder)
{
    Plaintext plain_weight;
    dec.decrypt(ciph_weight, plain_weight);
    std::vector<std::complex<double>> message;
    encoder.decode(plain_weight, message);
    return accuracy_of_plain(message, x, y);
}

void print_weight_and_bias(const std::vector<std::complex<double>> &weight)
{
    std::cout << "weight and bias: " << std::endl;
    for (auto i = 0; i < n; ++i)
    {
        std::cout << weight[i].real() << std::endl;
    }
    std::cout << std::endl;
}

void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string& file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file: " + file);
    }
    for (int i = 0; i < m; ++i)
    {
        for (auto j = 0; j < n; ++j)
        {
            if (!(in_file >> matrix[i][j]))
            {
                POSEIDON_THROW(config_error, "read file error: " + file);
            }
        }
    }
}

void read_file(std::vector<std::complex<double>> &matrix, const std::string& file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file: " + file);
    }
    for (int i = 0; i < n; ++i)
    {
        if (!(in_file >> matrix[i]))
        {
            POSEIDON_THROW(config_error, "read file error: " + file);
        }
    }
}

void preprocess(int block_size,
                int block_num,
                std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T)
{
    for (auto &vec : x)
    {
        vec.insert(vec.end(), block_size - vec.size(), {0.0, 0.0});
    }

    int row_added = block_size - (m % block_size);
    x.resize(x.size() + row_added);
    std::fill_n(x.end() - row_added, row_added, std::vector<std::complex<double>>(block_size, {0.0, 0.0}));

    for (auto i = 0; i < n; ++i)
    {
        for (auto j = 0; j < m; ++j)
        {
            x_transpose[i][j] = x[j][i];
        }
    }
    for (auto i = 0; i < block_num; ++i)
    {
        for (auto j = 0; j < block_size; ++j)
        {
            for (auto k = 0; k < block_size; ++k)
            {
                x_diag_T[i * block_size + j][k] = x[k + i * block_size][(j + k) % block_size];
            }
        }
    }
}

Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys &rot_keys)
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
    while (n)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            bottom_nth += 1 << cnt;
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, const_n - bottom_nth, rot_keys);
            ckks_eva->add(ciph_sum, ciph_tmp, ciph_sum);
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, 1 << cnt, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
        ++cnt;
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

int get_size(int min, int max)
{
    int num = 1;
    while (num < min)
    {
        num *= 2;
    }
    if (num > max)
    {
        POSEIDON_THROW(invalid_argument_error, "size not supported");
    }
    return num;
}

Ciphertext accumulate_block_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size)
{
    Ciphertext ciph_sum = ciph;
    for (auto i = 1; i < block_size; i <<= 1)
    {
        Ciphertext ciph_rotate = ciph_sum;
        eva->rotate(ciph_rotate, ciph_rotate, i * block_size, rot_key);
        eva->add(ciph_sum, ciph_rotate, ciph_sum);
    }
    return ciph_sum;
}

Ciphertext accumulate_slot_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size, int block_num)
{
    Ciphertext ciph_sum = ciph;
    for (auto i = 1; i < block_num; i <<= 1)
    {
        Ciphertext ciph_rotate = ciph_sum;
        eva->rotate(ciph_rotate, ciph_rotate, i * block_size * block_size, rot_key);
        eva->add(ciph_sum, ciph_rotate, ciph_sum);
    }
    return ciph_sum;
}

std::vector<std::complex<double>> vector_to_block_message(const std::vector<std::complex<double>> &vec, int cnt, int block_size)
{
    std::vector<std::complex<double>> ans;
    for (auto i = 0, j = 0; i < cnt; ++i)
    {
        ans.push_back(vec[i]);
        if ((i + 1) % block_size == 0)
        {
            ans.insert(ans.end(), (block_size - 1) * block_size, std::complex<double>(0.0, 0.0));
        }
    }
    return ans;
}