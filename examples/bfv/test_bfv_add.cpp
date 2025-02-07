#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    ParametersLiteralDefault bfv_param_literal(BFV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    auto bfv_eva = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    BatchEncoder enc(context);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plain1, plain2, plain_res;
    Ciphertext ciph1, ciph2, ciph_res;
    auto slot_num = bfv_param_literal.slot();
    vector<uint64_t> message1 = {1, 2, 3};
    vector<uint64_t> message2 = {4, 5, 6};
    vector<uint64_t> message_res;

    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);

    // ADD
    bfv_eva->add(ciph1, ciph2, ciph_res);
    bfv_eva->read(ciph_res);
    decryptor.decrypt(ciph_res, plain_res);
    enc.decode(plain_res, message_res);
    auto message_want = message1;
    for (auto i = 0; i < message_want.size(); i++)
        message_want[i] = message1[i] + message2[i];

    for (auto i = 0; i < message_want.size(); i++)
    {
        printf("source_data[%d] : %ld\n", i, message_want[i]);
        printf("result_data[%d] : %ld\n", i, message_res[i]);
    }
}
