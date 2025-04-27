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
#include <limits.h>
#include <unistd.h>
#include <fstream>

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

#define DEBUG_LRTRAIN

const int EPOCHS = 1;
const double learning_rate = 0.95;
int m = 5;
int n = 3;

namespace check
{
template <typename T> void print_vector(const std::vector<T> &vec)
{
    ofstream of("output.txt", ios::app);
    of << "print vector: " << std::endl;
    for (auto value : vec)
    {
        of << value << std::endl;
    }
    of << std::endl;
}

template <typename T> void print_matrix(const std::vector<std::vector<T>> &matrix)
{
    ofstream of("output.txt", ios::app);
    of << "print matrix: " << std::endl;
    for (auto row : matrix)
    {
        for (auto value : row)
        {
            of << value << " ";
        }
        of << std::endl;
    }
}

}  // namespace check

void read_file(std::vector<std::complex<double>> &matrix, std::string file);
void read_file(std::vector<std::vector<std::complex<double>>> &matrix, std::string file);
Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);
std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);
double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y);
double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder);

void preprocess(const std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T,
                std::vector<std::vector<std::complex<double>>> &identity_matrix);
// ciph.slot[0] = slot[0] + slot[1] + ... + slot[n-1]
// ciph.slot[x] = 0 , x != 0
Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys rot_keys);
double sigmoid(double x);
Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys);

void update_weight(const std::vector<std::vector<std::complex<double>>> &x,
                   const std::vector<std::complex<double>> &y,
                   std::vector<std::complex<double>> &weight);
void update_weight_approx();

std::string get_executable_directory()
{
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1)
    {
        return "";  // 读取失败
    }
    path[len] = '\0';

    char *last_slash = strrchr(path, '/');
    if (last_slash == nullptr)
    {
        return "";  // 路径中无 '/'，理论上不可能
    }

    // 截取目录部分（去掉可执行文件名）
    *last_slash = '\0';
    return std::string(path);
}

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(20, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    vector<vector<complex<double>>> x(m, vector<complex<double>>(m, {0.0, 0.0}));
    vector<complex<double>> y(m, {0.0, 0.0});
    vector<complex<double>> weight(m, {0.0, 0.0});
    vector<vector<complex<double>>> x_transpose(m, vector<complex<double>>(m, {0.0, 0.0}));
    vector<vector<complex<double>>> x_diag_T(m, vector<complex<double>>(m, {0.0, 0.0}));
    vector<vector<complex<double>>> identity_matrix(m, vector<complex<double>>(m, {0.0, 0.0}));

    std::string exe_path_directory = get_executable_directory();
    read_file(x, exe_path_directory + "/" + "x_train.txt");
    read_file(y, exe_path_directory + "/" + "y_train.txt");

    auto slot_size = 1 << ckks_param_literal.log_slots();
    double scale = std::pow(2.0, q_def);

    if ((m << 1) > slot_size)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "size of matrix * 2 must be smaller than ciphertext slot!");
    }

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
    auto _weight = weight;

    preprocess(x, x_transpose, x_diag_T, identity_matrix);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys conj_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    vector<Ciphertext> ciph_x_transpose = encode_and_encrypt(ckks_encoder, enc, x_transpose, scale);
    vector<Ciphertext> ciph_x_diag_T = encode_and_encrypt(ckks_encoder, enc, x_diag_T, scale);
    Ciphertext ciph_y = encode_and_encrypt(ckks_encoder, enc, y, scale);
    Ciphertext ciph_weight = encode_and_encrypt(ckks_encoder, enc, weight, scale);

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

    util::Timestacs timer;
    timer.start();
    for (auto epoch = 0; epoch < EPOCHS; ++epoch)
    {
        // used for diagnoal matrix multiplication
        Ciphertext ciph_weight_shift;
        ckks_eva->rotate(ciph_weight, ciph_weight_shift, -m, rot_keys);
        ckks_eva->add(ciph_weight, ciph_weight_shift, ciph_weight_shift);

        Ciphertext ciph_tmp;
        enc.encrypt_zero(ciph_tmp);
        // ensure the scale and paramId of ciph_tmp = ciph_result
        ckks_eva->multiply_relin(ciph_tmp, ciph_weight, ciph_tmp, relin_keys);

        // calculate ciph_tmp = (theta * x1, theta * x2, ... , theta * xm, ...)
        for (auto i = 0; i < m; ++i)
        {
            Ciphertext ciph_result;
            Ciphertext ciph_weight_rotated;
            ckks_eva->rotate(ciph_weight_shift, ciph_weight_rotated, i, rot_keys);
            ckks_eva->multiply_relin(ciph_x_diag_T[i], ciph_weight_rotated, ciph_result,
                                     relin_keys);
            ckks_eva->add(ciph_tmp, ciph_result, ciph_tmp);
        }
        ckks_eva->rescale(ciph_tmp, ciph_tmp);

#ifdef DEBUG_LRTRAIN
        // check theta^T * x
        std::vector<std::complex<double>> dot_product;
        {
            check::print_matrix(x);
            check::print_matrix(x_diag_T);
            check::print_vector(weight);
            std::vector<double> _dot_product;
            for (auto i = 0; i < m; ++i)
            {
                double _sum = 0.0;
                for (auto j = 0; j < m; ++j)
                {
                    _sum += x[i][j].real() * _weight[j].real();
                }
                _dot_product.push_back(_sum);
            }

            dot_product = decrypt_and_decode(ckks_encoder, dec, ciph_tmp);
            std::cout << "fhe value  |  perdict value" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << dot_product[i].real() << " " << _dot_product[i] << std::endl;
            }
        };
#endif

        if (0 == epoch)
        {
            ckks_eva->multiply_const(ciph_y, 1.0, scale, ciph_y, ckks_encoder);
            ckks_eva->rescale_dynamic(ciph_y, ciph_y, scale);
        }

        // calculate sigmoid(theta^T x)
        Ciphertext ciph_sigmoid =
            sigmoid_approx(ciph_tmp, polys, ckks_encoder, ckks_eva, relin_keys);

#ifdef DEBUG_LRTRAIN
        // check sigmoid
        std::vector<double> perdict_sigmoid(m, 0.0);
        {
            auto res = decrypt_and_decode(ckks_encoder, dec, ciph_sigmoid);
            for (auto i = 0; i < m; ++i)
            {
                perdict_sigmoid[i] = sigmoid(dot_product[i].real());
            }
            std::cout << "fhe sigmoid  |  perdict sigmoid" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << res[i] << " " << perdict_sigmoid[i] << std::endl;
            }
        }
#endif

        // calculate gradient
        ckks_eva->sub_dynamic(ciph_sigmoid, ciph_y, ciph_sigmoid, ckks_encoder);
        Ciphertext ciph_sum;
        Ciphertext ciph_accumulate;
        for (auto j = 0; j < m; ++j)
        {
            ckks_eva->drop_modulus(ciph_x_transpose[j], ciph_x_transpose[j],
                                   ciph_sigmoid.parms_id());
            ckks_eva->multiply_relin(ciph_sigmoid, ciph_x_transpose[j], ciph_accumulate,
                                     relin_keys);
            ckks_eva->rescale_dynamic(ciph_accumulate, ciph_accumulate, scale);
            ciph_accumulate =
                accumulate_top_n(ciph_accumulate, m, ckks_encoder, enc, ckks_eva, rot_keys);

            Plaintext plain_mask;
            ckks_encoder.encode(identity_matrix[0], ciph_accumulate.parms_id(),
                                ciph_accumulate.scale(), plain_mask);
            ckks_eva->multiply_plain(ciph_accumulate, plain_mask, ciph_accumulate);
            ckks_eva->rotate(ciph_accumulate, ciph_accumulate, -j, rot_keys);
            if (j == 0)
            {
                Plaintext plain_sum;
                ckks_encoder.encode(std::complex<double>{0.0, 0.0}, ciph_accumulate.parms_id(),
                                    ciph_accumulate.scale(), plain_sum);
                enc.encrypt(plain_sum, ciph_sum);
            }
            ckks_eva->add(ciph_sum, ciph_accumulate, ciph_sum);
        }
        ckks_eva->rescale_dynamic(ciph_sum, ciph_tmp, scale);

        Ciphertext ciph_gradient;
        ckks_eva->multiply_const(ciph_tmp, 1.0 / m, ciph_tmp.scale(), ciph_gradient, ckks_encoder);
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

#ifdef DEBUG_LRTRAIN
        // check gradient
        {
            std::vector<double> perdict_gradient(m, 0.0);
            for (auto j = 0; j < m; ++j)
            {
                auto sum = 0.0;
                for (auto i = 0; i < m; ++i)
                {
                    sum += (perdict_sigmoid[i] - y[i].real()) * x[i][j].real();
                }
                perdict_gradient[j] = sum / m;
            }
            auto res = decrypt_and_decode(ckks_encoder, dec, ciph_gradient);
            std::cout << "fhe gradient  |  perdict gradient" << std::endl;
            for (auto j = 0; j < m; ++j)
            {
                std::cout << res[j].real() << " " << perdict_gradient[j] << std::endl;
            }
        }
#endif

        // update ciph_weight
        ckks_eva->multiply_const(ciph_gradient, learning_rate, ciph_gradient.scale(), ciph_tmp,
                                 ckks_encoder);
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);
        ckks_eva->sub_dynamic(ciph_weight, ciph_tmp, ciph_weight, ckks_encoder);

        // check weight updated begin
        update_weight(x, y, _weight);
        std::cout << "fhe weight  |  perdict weight" << std::endl;
        auto res = decrypt_and_decode(ckks_encoder, dec, ciph_weight);
        for (auto i = 0; i < n; ++i)
        {
            std::cout << res[i].real() << " " << _weight[i].real() << std::endl;
        }
    }

    timer.end();
    timer.print_time("lr train time: ");

    Plaintext plain_weight;
    dec.decrypt(ciph_weight, plain_weight);
    ckks_encoder.decode(plain_weight, weight);

    std::cout << "accuracy of ciph: " << accuracy_of_plain(weight, x, y) << std::endl;

    return 0;
}

double sigmoid(double x)
{
    // return(exp(x) / (1 + exp(x)));
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

void read_file(std::vector<std::vector<std::complex<double>>> &matrix, std::string file)
{
    std::ifstream inFile_X(file, ios::in);
    for (int i = 0; i < m; ++i)
    {
        for (auto j = 0; j < n; ++j)
        {
            if (!(inFile_X >> matrix[i][j]))
            {
                POSEIDON_THROW(config_error, "无法打开文件：" + file);
            }
        }
    }
}

void read_file(std::vector<std::complex<double>> &matrix, std::string file)
{
    std::ifstream inFile_X(file, ios::in);
    for (int i = 0; i < n; ++i)
    {
        if (!(inFile_X >> matrix[i]))
        {
            POSEIDON_THROW(config_error, "无法打开文件：" + file);
        }
    }
}

void preprocess(const std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T,
                std::vector<std::vector<std::complex<double>>> &identity_matrix)
{
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < m; ++j)
        {
            x_transpose[i][j] = x[j][i];
        }
    }
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < m; ++j)
        {
            x_diag_T[i][j] = x[j][(i + j) % m];
        }
    }
    for (int i = 0; i < m; ++i)
    {
        identity_matrix[i][i] = 1.0;
    }
}

Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
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
    for (int i = 0; i < m; ++i)
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

void update_weight(const std::vector<std::vector<std::complex<double>>> &x,
                   const std::vector<std::complex<double>> &y,
                   std::vector<std::complex<double>> &weight)
{
    std::vector<std::complex<double>> sig(m);
    std::vector<std::complex<double>> grad(n);

    for (auto i = 0; i < m; ++i)
    {
        auto sum = 0.0;
        for (auto j = 0; j < n; ++j)
        {
            sum += x[i][j].real() * weight[j].real();
        }
        sig[i] = sigmoid(sum);
    }

    for (auto j = 0; j < n; ++j)
    {
        for (auto i = 0; i < m; ++i)
        {
            grad[j] += (sig[i] - y[i].real()) * x[i][j].real();
        }
        grad[j] /= m;
        weight[j] -= learning_rate * grad[j];
    }
}
