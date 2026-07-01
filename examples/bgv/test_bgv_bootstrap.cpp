#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/bgv_recryption_data.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"

using namespace poseidon;
using namespace poseidon::util;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    // Use default BGV parameters (degree=16384, plain_modulus=786433)
    ParametersLiteralDefault bgv_param_literal(BGV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    PoseidonContext context =
        PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    std::shared_ptr<EvaluatorBgvBase> bgv_eva =
        PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    BatchEncoder encoder(context);

    // Data key generator
    KeyGenerator data_keygen(context);
    PublicKey public_key;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    data_keygen.create_public_key(public_key);
    data_keygen.create_galois_keys(galois_keys);
    data_keygen.create_relin_keys(relin_keys);

    // Boot secret key: create a second key generator for a different secret key
    KeyGenerator boot_keygen(context);
    BootstrappingKey boot_key = data_keygen.create_bootstrapping_key(boot_keygen.secret_key());

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, data_keygen.secret_key());

    // Initialize recryption data for bootstrapping with plaintext prime p=2
    // r=1: working mod 2; m=2*degree: cyclotomic order
    // noise_bound and coeff_bound are rough estimates for the fresh ciphertext
    BgvRecryptionData recrypt_data;
    long degree = 16384;
    recrypt_data.init(/*plaintext_prime=*/2, /*r=*/1, /*m=*/2 * degree,
                      /*noise_bound=*/10.0, /*coeff_bound=*/10.0);

    std::cout << "Recryption data initialized:" << std::endl;
    std::cout << "  p = " << recrypt_data.p << std::endl;
    std::cout << "  e = " << recrypt_data.e << std::endl;
    std::cout << "  e_prime = " << recrypt_data.e_prime << std::endl;
    std::cout << "  al_mod = " << recrypt_data.al_mod << std::endl;
    std::cout << "  r = " << recrypt_data.r << std::endl;
    std::cout << std::endl;

    // Prepare test messages
    Plaintext plt;
    Ciphertext ct;
    std::vector<uint64_t> msg = {1, 2, 3, 4, 5};
    std::vector<uint64_t> msg_res;

    encoder.encode(msg, plt);
    encryptor.encrypt(plt, ct);

    Timestacs timestacs;

    // Step 1: Perform some operations to consume noise budget
    print_example_banner("Example: BGV Bootstrap");
    std::cout << "Initial level: " << ct.level() << std::endl;

    // Multiply to increase noise
    {
        std::cout << "Performing multiply_relin to increase noise..." << std::endl;
        timestacs.start();
        bgv_eva->multiply_relin(ct, ct, ct, relin_keys);
        bgv_eva->read(ct);
        timestacs.end();
        timestacs.print_time("Multiply time: ");
        std::cout << "Level after multiply: " << ct.level() << std::endl;
    }

    // Step 2: Bootstrap to refresh the ciphertext
    {
        std::cout << "Running thin_bootstrap..." << std::endl;
        Ciphertext bootstrapped;
        timestacs.start();
        bgv_eva->thin_bootstrap(ct, bootstrapped, recrypt_data, boot_key, relin_keys);
        bgv_eva->read(bootstrapped);
        timestacs.end();
        timestacs.print_time("Bootstrap time: ");

        // Decrypt and verify
        decryptor.decrypt(bootstrapped, plt);
        encoder.decode(plt, msg_res);

        std::cout << "Bootstrap completed. Result level: " << bootstrapped.level() << std::endl;
        std::cout << "Decrypted result after bootstrap:" << std::endl;
        for (size_t i = 0; i < std::min(msg.size(), msg_res.size()); i++)
        {
            printf("  slot[%zu] : expected=%ld, got=%ld\n", i, msg[i] * msg[i], msg_res[i]);
        }
    }

    std::cout << "\nBGV bootstrap example completed." << std::endl;
    return 0;
}
