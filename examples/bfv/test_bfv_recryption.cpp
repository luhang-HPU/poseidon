#include "poseidon/batchencoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/recryption.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <chrono>
#include <vector>

using namespace poseidon;

int main()
{
    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;

    ParametersLiteralDefault bfv_param_literal(BFV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bfv_param_literal);
    auto bfv_eva = PoseidonFactory::get_instance()->create_bfv_evaluator(context);

    std::vector<uint64_t> vec_result;
    int mat_size = bfv_param_literal.slot();
    uint64_t plain_modulus = bfv_param_literal.plain_modulus().value();

    // create message
    vector<uint64_t> message1;
    sample_random_vector(message1, mat_size, 10);

    // init Plaintext and Ciphertext
    Plaintext plain, plain_res;
    Ciphertext cipher;
    PublicKey public_key;
    RelinKeys relin_keys;
    BatchEncoder bfv_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);

    KeyGenerator bootstrap_kgen(context);
    PublicKey bootstrap_public_key;
    bootstrap_kgen.create_public_key(bootstrap_public_key);
    auto recryption_key =
        create_recryption_key(context, kgen.secret_key(), public_key, bootstrap_kgen.secret_key(),
                              bootstrap_public_key);

    Encryptor enc(context, public_key);
    Decryptor dec(context, kgen.secret_key());

    // encode && encrypt
    bfv_encoder.encode(message1, plain);
    enc.encrypt(plain, cipher);
    std::cout << "degree = " << bfv_param_literal.degree()
              << ", q primes = " << bfv_param_literal.q().size()
              << ", p primes = " << bfv_param_literal.p().size() << std::endl;
    std::cout << "after encryption, level = " << cipher.level() << std::endl;

    // evaluate
    auto start = std::chrono::high_resolution_clock::now();
    bfv_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    std::cout << "after multiply, level = " << cipher.level() << std::endl;
    while (cipher.level() > 2)
    {
        bfv_eva->drop_modulus_to_next(cipher, cipher);
        std::cout << "after drop modulus, level = " << cipher.level() << std::endl;
    }

    RecryptionData recryption_data(context);
    recryption_data.set_plain_base(plain_modulus, 1);
    recryption_data.set_auxiliary_exponents(2, 1);
    LinearMatrixGroup coeff_to_slot_map;
    LinearMatrixGroup slot_to_coeff_map;
    try
    {
        bgv_build_thin_recryption_maps(context, bfv_encoder, cipher.level(), coeff_to_slot_map,
                                       slot_to_coeff_map);
        recryption_data.set_linear_maps(coeff_to_slot_map, slot_to_coeff_map);
        GaloisKeys linear_map_galois_keys;
        kgen.create_galois_keys(bgv_recryption_required_galois_steps(recryption_data),
                                linear_map_galois_keys);
        recryption_key =
            create_recryption_key(context, kgen.secret_key(), public_key,
                                  bootstrap_kgen.secret_key(), bootstrap_public_key,
                                  linear_map_galois_keys, relin_keys);
    }
    catch (const poseidon_error &err)
    {
        std::cerr << "BFV thin recryption map generation is not complete: " << err.what()
                  << std::endl;
        return 2;
    }
    Recryptor recryptor(context, *bfv_eva, recryption_data);

    std::cout << "before recryption, level = " << cipher.level() << std::endl;
    std::cout << "recryption params: plain_modulus = " << plain_modulus
              << ", bootstrap plain_base p = " << recryption_data.parameters().plain_base
              << ", p^r = " << recryption_data.parameters().p_power_r
              << ", p^e' = " << recryption_data.parameters().p_power_e_prime
              << ", q = p^e + 1 = " << recryption_data.parameters().bootstrap_modulus
              << std::endl;

    auto preprocessed = recryptor.preprocess(cipher, recryption_key.bootstrap_switch_key);
    for (int part = 0; part < static_cast<int>(preprocessed.raw_parts.size()) && part < 2; ++part)
    {
        std::cout << "rawModSwitch part[" << part << "][0..2] = "
                  << preprocessed.raw_parts[part].coeffs[0] << ", "
                  << preprocessed.raw_parts[part].coeffs[1] << ", "
                  << preprocessed.raw_parts[part].coeffs[2] << std::endl;
        std::cout << "makeDivisible part[" << part << "][0..2] = "
                  << preprocessed.divisible_parts[part].coeffs[0] << ", "
                  << preprocessed.divisible_parts[part].coeffs[1] << ", "
                  << preprocessed.divisible_parts[part].coeffs[2] << std::endl;
        std::cout << "divide p^e' part[" << part << "][0..2] = "
                  << preprocessed.divided_parts[part].coeffs[0] << ", "
                  << preprocessed.divided_parts[part].coeffs[1] << ", "
                  << preprocessed.divided_parts[part].coeffs[2] << std::endl;
    }

    try
    {
        recryptor.recrypt(cipher, cipher, recryption_key);
    }
    catch (const poseidon_error &err)
    {
        std::cerr << "BFV public recryption is not complete: " << err.what() << std::endl;
        return 2;
    }

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Recryption TIME: " << duration.count() << " microseconds" << std::endl;

    std::cout << "after recryption, level = " << cipher.level() << std::endl;

    // decode && decrypt
    dec.decrypt(cipher, plain_res);
    bfv_encoder.decode(plain_res, vec_result);
    for (int i = 0; i < 10; i++)
    {
        message1[i] *= message1[i];
        message1[i] %= plain_modulus;
        std::cout << "source vec[" << i << "] : " << message1[i] << std::endl;
        std::cout << "result vec[" << i << "] : " << vec_result[i] << std::endl;
        if (message1[i] != vec_result[i])
        {
            std::cerr << "BFV recryption mismatch at slot " << i << std::endl;
            return 1;
        }
    }

    return 0;
}
