#include "batch_handler.h"
#include "src/util/debug.h"

namespace
{
    // get 2^x where min <= 2^x <= max
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
}

BatchHandler::BatchHandler(int slot_size, int degree, int block_size, int m, int n)
    : slot_size_(slot_size),degree_(degree), block_size_(block_size), m_(m), n_(n)
{

}

Ciphertext BatchHandler::encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                            vector<std::complex<double>> &message, double scale)
{
    Plaintext plain;
    Ciphertext ciph;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
    return ciph;
}

Ciphertext BatchHandler::encode_and_encrypt_block(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::vector<std::complex<double>>> &message, double scale)
{
    std::vector<std::complex<double>> block_message;
    for (const auto &vec : message)
    {
        for (const auto &e : vec)
        {
            block_message.push_back(e);
        }
        block_message.insert(block_message.end(), block_size_ - n_, {0.0, 0.0});
    }

    return encode_and_encrypt(encoder, encryptor, block_message, scale);
}

std::vector<Ciphertext> BatchHandler::encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
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

Ciphertext BatchHandler::encode_and_encrypt_weight(const CKKSEncoder &encoder,
                                                        const Encryptor &encryptor,
                                                        vector<std::complex<double>> &message,
                                                        double scale)
{
    if (message.size() < block_size_)
    {
        message.insert(message.end(), block_size_ - message.size(), {0.0, 0.0});
    }

    std::vector<std::complex<double>> message_sum;
    std::vector<std::complex<double>> message_rotate = message;
    for (auto i = 0; i < block_size_; ++i)
    {
        std::rotate(message_rotate.begin(), message_rotate.begin() + i, message_rotate.end());
        for (auto &e : message_rotate)
        {
            message_sum.push_back(e);
        }
    }

    message_sum.resize(degree_ / 2);
    for (auto i = 0, sz = degree_ / (block_size_ * block_size_); i < sz; ++i)
    {
        for (auto j = 1; j < block_size_; ++j)
        {
            message_sum[j * sz + i] = message_sum[i];
        }
    }

    return encode_and_encrypt(encoder, encryptor, message_sum, scale);
}

std::vector<Ciphertext> BatchHandler::encode_and_encrypt_tranpose(const CKKSEncoder &encoder,
                                                     const Encryptor &encryptor,
                                                     std::vector<std::vector<std::complex<double>>> &message,
                                                     double scale)
{
    std::vector<Ciphertext> ciph_x_transpose;

    for (auto& vec : message)
    {
        std::vector<std::complex<double>> message_expand;
        for (auto i = 0; i < std::ceil(n_ / block_size_); ++i)
        {
            for (auto j = 0; j < block_size_; ++j)
            {
                message_expand.push_back(vec[i * block_size_ + j]);
            }
            message_expand.insert(message_expand.end(), (block_size_ - 1) * block_size_, {0.0, 0.0});
        }
        ciph_x_transpose.push_back(encode_and_encrypt(encoder, encryptor, message_expand, scale));
    }

    return ciph_x_transpose;
}

std::vector<std::complex<double>> BatchHandler::decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph)
{
    Plaintext plain;
    decryptor.decrypt(ciph, plain);
    std::vector<std::complex<double>> message;
    encoder.decode(plain, message);
    return message;
}

