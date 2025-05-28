#ifndef POSEIDON_BATCH_HANDLER_H
#define POSEIDON_BATCH_HANDLER_H

#include "src/ciphertext.h"
#include "src/ckks_encoder.h"
#include "src/encryptor.h"
#include "src/decryptor.h"

using namespace poseidon;

class BatchHandler
{
public:
    BatchHandler(int slot_size, int degree, int block_size, int m, int n);

    Ciphertext encode_and_encrypt_block(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                  std::vector<std::vector<std::complex<double>>> &message, double scale);

    Ciphertext encode_and_encrypt_weight(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                                     std::vector<std::complex<double>> &message,
                                                     double scale);
    std::vector<Ciphertext> encode_and_encrypt_tranpose(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                             std::vector<std::vector<std::complex<double>>> &message,
                                             double scale);

    std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                         Decryptor &decryptor, const Ciphertext &ciph);

    Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                  std::vector<std::complex<double>> &message, double scale);

    std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                               std::vector<std::vector<std::complex<double>>> &message,
                                               double scale);

private:
    int slot_size_;     // slot size
    int degree_;        // polynomial degree
    int block_size_;    // size of block matrix
    int m_;             // row size of training set x
    int n_;             // column size of training set x
};

#endif  // POSEIDON_BATCH_HANDLER_H
