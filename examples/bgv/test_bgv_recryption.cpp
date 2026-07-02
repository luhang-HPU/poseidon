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
    std::cout << std::endl;

    ParametersLiteralDefault bgv_param_literal(BGV, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(bgv_param_literal);
    auto bgv_eva = PoseidonFactory::get_instance()->create_bgv_evaluator(context);

    const auto degree = bgv_param_literal.degree();
    const auto plain_modulus = bgv_param_literal.plain_modulus().value();
    const auto slot_count = bgv_param_literal.slot();
    std::cout << "scheme = BGV" << std::endl;
    std::cout << "degree = " << degree << ", slots = " << slot_count
              << ", plain_modulus = " << plain_modulus << std::endl;
    std::cout << "q primes = " << bgv_param_literal.q().size()
              << ", p primes = " << bgv_param_literal.p().size() << std::endl;

    std::vector<uint64_t> message;
    sample_random_vector(message, slot_count, 10);

    Plaintext plain, plain_res;
    Ciphertext cipher;
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    BatchEncoder encoder(context);

    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(galois_keys);

    KeyGenerator bootstrap_kgen(context);
    PublicKey bootstrap_public_key;
    bootstrap_kgen.create_public_key(bootstrap_public_key);
    auto recryption_key =
        create_recryption_key(context, kgen.secret_key(), public_key, bootstrap_kgen.secret_key(),
                              bootstrap_public_key);

    Encryptor enc(context, public_key);
    Decryptor dec(context, kgen.secret_key());

    encoder.encode(message, plain);
    enc.encrypt(plain, cipher);
    std::cout << "after encryption, level = " << cipher.level() << std::endl;
    std::cout << "after encryption, bgv_plaintext_space = " << cipher.bgv_plaintext_space()
              << ", bgv_int_factor = " << cipher.bgv_int_factor() << std::endl;

    // BGV 的 multiply_relin 只做同态乘法和重线性化，不会自动丢掉 RNS prime。
    // 所以这里噪声会增长，但 level 仍然保持不变；只有显式 drop_modulus 才会降 level。
    bgv_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    for (auto &value : message)
    {
        value = (value * value) % plain_modulus;
    }
    std::cout << "after square, level = " << cipher.level() << std::endl;

    bgv_eva->multiply_relin(cipher, cipher, cipher, relin_keys);
    for (auto &value : message)
    {
        value = (value * value) % plain_modulus;
    }
    std::cout << "after second square, level = " << cipher.level() << std::endl;

    // 显式降模：这一步才真正减少密文所在的 modulus chain level。
    // 多 drop 几次，验证 recryption 能否从更低 level 恢复到顶层 level。
    for (int drop_count = 1; drop_count <= 3; ++drop_count)
    {
        bgv_eva->drop_modulus_to_next(cipher, cipher);
        std::cout << "after drop_modulus_to_next #" << drop_count
                  << ", level = " << cipher.level() << std::endl;
    }

    // BGV 明文空间元数据探针：模拟 HElib 的 multByP/divideByP 语义是否可逆。
    // 这里只检查元数据和密文缩放路径，不改变正式待自举密文 cipher。
    Ciphertext ptxt_space_probe = cipher;
    bgv_multiply_by_plain_base(context, *bgv_eva, ptxt_space_probe, std::uint32_t{1});
    std::cout << "after multByP probe, bgv_plaintext_space = "
              << ptxt_space_probe.bgv_plaintext_space() << std::endl;
    bgv_divide_by_plain_base(context, ptxt_space_probe);
    std::cout << "after divideByP probe, bgv_plaintext_space = "
              << ptxt_space_probe.bgv_plaintext_space() << std::endl;

    RecryptionData recryption_data(context);
    // HElib 的薄自举参数：p, r, e, e' 决定 rawModSwitch 的 q=p^e+1 和 digit extraction。
    // Poseidon 默认 BGV batching plain_modulus 是 786433，不是 HElib 风格的小基 p=2；
    // 因此当前示例会走下面的 exact BGV modulus raise 路径来验证公开刷新/升层正确性。
    recryption_data.set_plain_base(2, 1);
    recryption_data.set_auxiliary_exponents(2, 1);
    LinearMatrixGroup coeff_to_slot_map;
    LinearMatrixGroup slot_to_coeff_map;
    try
    {
        // 自举所需线性变换：
        // slotToCoeff  把槽表示搬到系数/powerful-basis 侧；
        // coeffToSlot  把 compose 后的结果搬回槽表示，供 digit extraction 使用。
        bgv_build_thin_recryption_maps(context, encoder, cipher.level(), coeff_to_slot_map,
                                       slot_to_coeff_map);
        recryption_data.set_linear_maps(coeff_to_slot_map, slot_to_coeff_map);
        GaloisKeys linear_map_galois_keys;
        kgen.create_galois_keys(bgv_recryption_required_galois_steps(recryption_data),
                                linear_map_galois_keys);
        // 自举 key 包含三类材料：
        // 1. bootstrap_switch_key：把原密钥下的密文切到 bootstrap secret key；
        // 2. encrypted_bootstrap_secret：加密的 bootstrap secret，用于 compose z0+z1*s；
        // 3. 线性变换 Galois keys 和 relin keys：支持 EvalMap/ThinEvalMap 与 digit extraction。
        recryption_key =
            create_recryption_key(context, kgen.secret_key(), public_key,
                                  bootstrap_kgen.secret_key(), bootstrap_public_key,
                                  linear_map_galois_keys, relin_keys);
    }
    catch (const poseidon_error &err)
    {
        std::cerr << "BGV thin recryption map generation is not complete: " << err.what()
                  << std::endl;
        return 2;
    }
    Recryptor recryptor(context, *bgv_eva, recryption_data);
    std::cout << "recryption params: plain_modulus = " << plain_modulus
              << ", bootstrap plain_base p = " << recryption_data.parameters().plain_base
              << ", p^r = " << recryption_data.parameters().p_power_r
              << ", p^e' = " << recryption_data.parameters().p_power_e_prime
              << ", q = p^e + 1 = " << recryption_data.parameters().bootstrap_modulus
              << std::endl;

    const bool exact_mod_raise_path = recryption_data.parameters().plain_base != plain_modulus;
    if (exact_mod_raise_path)
    {
        // 当前 Poseidon BGV 参数使用 batching prime 明文模数。
        // 当 recryption base p 与 plain_modulus 不一致时，完整 HElib p-adic 薄自举还缺
        // GF(p^d)/powerful-basis 明文层；这里执行的是公开 exact modulus raise：
        // 不解密、不重加密，把低 level BGV 密文精确提升回顶层，并保持明文不变。
        std::cout << "recryption mode = exact BGV modulus raise path" << std::endl;
    }
    else
    {
        // 完整 HElib thin bootstrap 的组成：
        // slotToCoeff -> boot key-switch/rawModSwitch/makeDivisible/compose
        // -> coeffToSlot -> thin digit extraction。
        Ciphertext coeff_probe;
        recryptor.apply_linear_map_for_bgv_recryption(cipher, recryption_data.second_map(),
                                                      recryption_key.linear_map_galois_keys,
                                                      coeff_probe);
        std::cout << "after slotToCoeff, level = " << coeff_probe.level()
                  << ", bgv_plaintext_space = " << coeff_probe.bgv_plaintext_space()
                  << std::endl;

        auto preprocessed = recryptor.preprocess(coeff_probe, recryption_key.bootstrap_switch_key);
        for (int part = 0; part < static_cast<int>(preprocessed.raw_parts.size()) && part < 2;
             ++part)
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

        Ciphertext composed;
        recryptor.preprocess_and_compose(coeff_probe, recryption_key, composed);
        std::cout << "after preprocess+compose, level = " << composed.level()
                  << ", bgv_plaintext_space = " << composed.bgv_plaintext_space() << std::endl;
        {
            std::vector<uint64_t> probe;
            dec.decrypt(composed, plain_res);
            encoder.decode(plain_res, probe);
            std::cout << "compose probe mod2[0..3] = " << (probe[0] & 1) << ", "
                      << (probe[1] & 1) << ", " << (probe[2] & 1) << ", "
                      << (probe[3] & 1) << std::endl;
        }

        Ciphertext digit_probe;
        Ciphertext slot_probe;
        recryptor.apply_linear_map_for_bgv_recryption(composed, recryption_data.first_map(),
                                                      recryption_key.linear_map_galois_keys,
                                                      slot_probe);
        std::cout << "after coeffToSlot probe, level = " << slot_probe.level()
                  << ", bgv_plaintext_space = " << slot_probe.bgv_plaintext_space() << std::endl;

        recryptor.thin_digit_extract_after_compose(slot_probe, digit_probe);
        std::cout << "after thin digit extraction probe, level = " << digit_probe.level()
                  << ", bgv_plaintext_space = " << digit_probe.bgv_plaintext_space()
                  << ", size = " << digit_probe.size() << std::endl;
        {
            std::vector<uint64_t> probe;
            dec.decrypt(digit_probe, plain_res);
            encoder.decode(plain_res, probe);
            std::cout << "digit probe mod2[0..3] = " << (probe[0] & 1) << ", "
                      << (probe[1] & 1) << ", " << (probe[2] & 1) << ", "
                      << (probe[3] & 1) << std::endl;
        }
    }

    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        std::cout << "before recryption, level = " << cipher.level() << std::endl;
        // 自举/刷新入口：当前参数下走 exact modulus raise；在 HElib p-adic 参数补齐后，
        // 同一入口会走上面注释的 thin bootstrap 链路。
        recryptor.recrypt(cipher, cipher, recryption_key);
    }
    catch (const poseidon_error &err)
    {
        std::cerr << "BGV public recryption is not complete: " << err.what() << std::endl;
        return 2;
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Recryption TIME: " << duration.count() << " microseconds" << std::endl;
    std::cout << "after recryption, level = " << cipher.level() << std::endl;

    std::vector<uint64_t> result;
    dec.decrypt(cipher, plain_res);
    encoder.decode(plain_res, result);
    for (int i = 0; i < 10; ++i)
    {
        std::cout << "source vec[" << i << "] : " << message[i] << std::endl;
        std::cout << "result vec[" << i << "] : " << result[i] << std::endl;
        if (message[i] != result[i])
        {
            std::cerr << "BGV recryption mismatch at slot " << i << std::endl;
            return 1;
        }
    }

    return 0;
}
