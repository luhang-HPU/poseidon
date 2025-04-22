//
// Created by Lenovo on 2025/3/17.
//

#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    ParametersLiteralDefault bgv_param_literal(BGV, 4096, sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    auto bgv_eva = PoseidonFactory::get_instance()->create_bgv_evaluator(context);
    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey publicKey;

    keygen.create_public_key(publicKey);

    Encryptor encryptor(context, publicKey);
    Decryptor decryptor(context, keygen.secret_key());

    vector<uint64_t> vec_data = {97, 98, 99};
    Plaintext plain, plain_load;
    Ciphertext ciph, ciph_load;

    encoder.encode(vec_data, plain);
    encryptor.encrypt(plain, ciph);

    ciph_load.unsafe_load(context,
                          reinterpret_cast<const poseidon_byte *>(ciph.data()),
                          ciph.size());

    decryptor.decrypt(ciph_load, plain_load);
    vector<uint64_t> vec_res;
    encoder.decode(plain_load, vec_res);

    if (vec_data.size() != vec_res.size())
    {
        return -1;
    }
    for (auto i = 0; i < vec_data.size(); ++i)
    {
        if (vec_data[i] != vec_res[i])
        {
            std::cout << "error" << std::endl;
            return -1;
        }
    }

    return 0;
}
