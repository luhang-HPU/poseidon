#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    cout << BANNER << std::endl;
    cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    cout << "" << std::endl;

    ParametersLiteralDefault bgv_param_literal(BGV, 4096, sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    auto bgv_eva = PoseidonFactory::get_instance()->create_bgv_evaluator(context);
    BatchEncoder encoder(context);
    KeyGenerator keygen(context);
    PublicKey pub_key;

    keygen.create_public_key(pub_key);

    Encryptor encryptor(context, pub_key);
    Decryptor decryptor(context, keygen.secret_key());

    vector<uint64_t> vec_data = {97, 98, 99};
    Plaintext plain, plain_load;
    Ciphertext ciph, ciph_load;

    encoder.encode(vec_data, plain);
    encryptor.encrypt(plain, ciph);

    stringstream ss;
    ciph.save(ss);
    ciph_load.unsafe_load(context, ss);

    decryptor.decrypt(ciph_load, plain_load);
    vector<uint64_t> vec_res;
    encoder.decode(plain_load, vec_res);

    for (auto i = 0; i < vec_data.size(); ++i)
    {
        printf("source_data[%d]   : %ld  \n", i, vec_data[i]);
        printf("result_data[%d]   : %ld  \n", i, vec_res[i]);
    }

    return 0;
}
