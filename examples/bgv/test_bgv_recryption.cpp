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

// 对比 main 新增：这个例子专门验证 BGV recryption 路径。它先制造较低 level 的密文，
// 再通过 evaluator 的 bootstrap 一键入口刷新，最后逐槽比较正确性。
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
    BatchEncoder encoder(context);

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

    std::cout << "bootstrap mode = evaluator one-call BGV bootstrap" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        std::cout << "before bootstrap, level = " << cipher.level() << std::endl;
        // 对齐 CKKS 示例的用户体验：自举细节由 evaluator 内部封装。
        // 当前默认 BGV 参数下，这个入口执行公开 exact modulus raise；
        // 若之后传入带 HElib EvalMap 的 RecryptionData，可走完整 thin bootstrap 链。
        bgv_eva->bootstrap(cipher, cipher, recryption_key);
    }
    catch (const poseidon_error &err)
    {
        std::cerr << "BGV bootstrap failed: " << err.what() << std::endl;
        return 2;
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Bootstrap TIME: " << duration.count() << " microseconds" << std::endl;
    std::cout << "after bootstrap, level = " << cipher.level() << std::endl;

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
