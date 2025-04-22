#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    ParametersLiteral bgv_param_literal{BGV, 13, 11, 40, 1, 1, Modulus{0x7FFFB0001}, {}, {}};
    vector<uint32_t> log_q_tmp{40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40};
    vector<uint32_t> log_p_tmp{41};

    bgv_param_literal.set_log_modulus(log_q_tmp, log_p_tmp);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    std::shared_ptr<EvaluatorBgvBase> bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    BatchEncoder enc(context);
    KeyGenerator keygen(context);
    PublicKey public_key;

    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Plaintext plain1, plain2, plain_res;
    Ciphertext ciph1, ciph2, res;
    auto slot_num = bgv_param_literal.slot();
    vector<uint64_t> message1 = {};
    vector<uint64_t> message2 = {};
    for (int i = 0; i < 8192; i++)
    {
        message1.push_back(i);
        message2.push_back(i);
    }
    vector<uint64_t> message_res, message_cur;
    enc.encode(message1, plain1);
    enc.encode(message2, plain2);
    encryptor.encrypt(plain1, ciph1);
    encryptor.encrypt(plain2, ciph2);
    Timestacs timestacs;
    auto message_want = message1;


    // ROTATE_ROW
    {
        print_example_banner("Example: ROTATE_ROW / ROTATE_ROW in bgv");
        timestacs.start();
        // elf = 8193 === step = -2048
        bgv_eva->apply_galois(ciph1, ciph2, 8193, galois_keys);
        bgv_eva->rotate_row(ciph2, ciph2, 2048, galois_keys);

        timestacs.end();
        // bgv_eva->read(ciph2);
        timestacs.print_time("TIME : ");
        decryptor.decrypt(ciph2, plain_res);
        enc.decode(plain_res, message_res);
        for (auto i = 0; i < 10; i++)
        {
            printf("source_data[%d] : %ld\n", i, message_want[i]);
            printf("result_data[%d] : %ld\n", i, message_res[i]);
        }
    }

    return 0;
}
