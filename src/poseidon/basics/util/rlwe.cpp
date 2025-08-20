//#include "poseidon/ciphertext.h"
#include "poseidon/basics/util/rlwe.h"
#include "poseidon/basics/randomgen.h"
#include "poseidon/basics/randomtostd.h"
#include "poseidon/basics/util/clipnormal.h"
#include "poseidon/basics/util/common.h"
#include "poseidon/basics/util/globals.h"
#include "poseidon/basics/util/ntt.h"
#include "poseidon/basics/util/polyarithsmallmod.h"
#include "poseidon/basics/util/polycore.h"

using namespace std;

namespace poseidon
{
namespace util
{
void sample_poly_ternary(shared_ptr<UniformRandomGenerator> prng, const PoseidonContext &context,
                         parms_id_type id, uint64_t *destination)
{
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    RandomToStandardAdapter engine(prng);
    uniform_int_distribution<uint64_t> dist(0, 2);

    POSEIDON_ITERATE(iter(destination), coeff_count,
                     [&](auto &I)
                     {
                         uint64_t rand = dist(engine);
                         uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
                         POSEIDON_ITERATE(
                             iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus),
                             coeff_modulus_size,
                             [&](auto J) { *get<0>(J) = rand + (flag & get<1>(J).value()) - 1; });
                     });
}

void sample_poly_ternary_with_hamming(shared_ptr<UniformRandomGenerator> prng,
                                      const PoseidonContext &context, parms_id_type id,
                                      uint64_t *destination)
{
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    auto hamming_weight = context.parameters_literal()->hamming_weight();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    RandomToStandardAdapter engine(prng);
    uniform_int_distribution<uint64_t> dist(0, 2);
    uniform_int_distribution<size_t> dist_deg(0, coeff_count);

    unordered_map<size_t, uint64_t> index_map;
    while (hamming_weight != 0)
    {
        uint64_t rand = dist(engine);
        size_t index = dist_deg(engine);
        uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
        if (rand != 1 && index_map.find(index) == index_map.end())
        {
            index_map[index] = rand;
            hamming_weight--;
        }
        for (auto i = 0; i < coeff_modulus_size; i++)
        {
            destination[i * coeff_count + index] = rand + (flag & coeff_modulus[i].value()) - 1;
        }
    }
}

void sample_poly_normal(shared_ptr<UniformRandomGenerator> prng, const PoseidonContext &context,
                        parms_id_type id, uint64_t *destination)
{
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    if (are_close(global_variables::noise_max_deviation, 0.0))
    {
        set_zero_poly(coeff_count, coeff_modulus_size, destination);
        return;
    }

    RandomToStandardAdapter engine(prng);
    ClippedNormalDistribution dist(0, global_variables::noise_standard_deviation,
                                   global_variables::noise_max_deviation);

    POSEIDON_ITERATE(
        iter(destination), coeff_count,
        [&](auto &I)
        {
            int64_t noise = static_cast<int64_t>(dist(engine));
            uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
            POSEIDON_ITERATE(
                iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                [&](auto J)
                { *get<0>(J) = static_cast<uint64_t>(noise) + (flag & get<1>(J).value()); });
        });
}

void sample_poly_cbd(shared_ptr<UniformRandomGenerator> prng, const PoseidonContext &context,
                     parms_id_type id, uint64_t *destination)
{
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    if (are_close(global_variables::noise_max_deviation, 0.0))
    {
        set_zero_poly(coeff_count, coeff_modulus_size, destination);
        return;
    }

    if (!are_close(global_variables::noise_standard_deviation, 3.2))
    {
        throw logic_error(
            "centered binomial distribution only supports standard deviation 3.2; use rounded "
            "Gaussian instead");
    }

    auto cbd = [&]()
    {
        unsigned char x[6];
        prng->generate(6, reinterpret_cast<poseidon_byte *>(x));
        x[2] &= 0x1F;
        x[5] &= 0x1F;
        return hamming_weight(x[0]) + hamming_weight(x[1]) + hamming_weight(x[2]) -
               hamming_weight(x[3]) - hamming_weight(x[4]) - hamming_weight(x[5]);
    };

    POSEIDON_ITERATE(
        iter(destination), coeff_count,
        [&](auto &I)
        {
            int32_t noise = cbd();
            uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
            POSEIDON_ITERATE(
                iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                [&](auto J)
                { *get<0>(J) = static_cast<uint64_t>(noise) + (flag & get<1>(J).value()); });
        });
}

void sample_poly_uniform(shared_ptr<UniformRandomGenerator> prng, const PoseidonContext &context,
                         parms_id_type id, uint64_t *destination)
{
    // Extract encryption parameters
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();
    size_t dest_byte_count = mul_safe(coeff_modulus_size, coeff_count, sizeof(uint64_t));

    constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);

    // Fill the destination buffer with fresh randomness
    prng->generate(dest_byte_count, reinterpret_cast<poseidon_byte *>(destination));

    for (size_t j = 0; j < coeff_modulus_size; j++)
    {
        auto &modulus = coeff_modulus[j];
        uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
        transform(destination, destination + coeff_count, destination,
                  [&](uint64_t rand)
                  {
                      // This ensures uniform distribution
                      while (rand >= max_multiple)
                      {
                          prng->generate(sizeof(uint64_t),
                                         reinterpret_cast<poseidon_byte *>(&rand));
                      }
                      return barrett_reduce_64(rand, modulus);
                  });
        destination += coeff_count;
    }
}

void sample_poly_uniform_seal_3_4(shared_ptr<UniformRandomGenerator> prng,
                                  const PoseidonContext &context, parms_id_type id,
                                  uint64_t *destination)
{
    // Extract encryption parameters
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    RandomToStandardAdapter engine(prng);

    constexpr uint64_t max_random = static_cast<uint64_t>(0x7FFFFFFFFFFFFFFFULL);
    for (size_t j = 0; j < coeff_modulus_size; j++)
    {
        auto &modulus = coeff_modulus[j];
        uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
        for (size_t i = 0; i < coeff_count; i++)
        {
            // This ensures uniform distribution
            uint64_t rand;
            do
            {
                rand = (static_cast<uint64_t>(engine()) << 31) |
                       (static_cast<uint64_t>(engine()) >> 1);
            } while (rand >= max_multiple);
            destination[i + j * coeff_count] = barrett_reduce_64(rand, modulus);
        }
    }
}

void sample_poly_uniform_seal_3_5(shared_ptr<UniformRandomGenerator> prng,
                                  const PoseidonContext &context, parms_id_type id,
                                  uint64_t *destination)
{
    // Extract encryption parameters
    auto context_data = context.crt_context()->get_context_data(id);
    auto &parms = context_data->parms();
    auto coeff_modulus = context_data->coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.degree();

    RandomToStandardAdapter engine(prng);

    constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
    for (size_t j = 0; j < coeff_modulus_size; j++)
    {
        auto &modulus = coeff_modulus[j];
        uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
        for (size_t i = 0; i < coeff_count; i++)
        {
            // This ensures uniform distribution
            uint64_t rand;
            do
            {
                rand = (static_cast<uint64_t>(engine()) << 32) | static_cast<uint64_t>(engine());
            } while (rand >= max_multiple);
            destination[i + j * coeff_count] = barrett_reduce_64(rand, modulus);
        }
    }
}

void encrypt_zero_asymmetric(const PublicKey &public_key, const PoseidonContext &context,
                             parms_id_type parms_id, bool is_ntt_form, Ciphertext &destination)
{
    // We use a fresh memory pool with `clear_on_destruction' enabled
    MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    auto global_context_data = context.crt_context();
    auto &context_data = *context.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto plain_modulus = Modulus(parms.plain_modulus());

    size_t encrypted_size = public_key.data().size();
    SchemeType type = parms.scheme();
    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = is_ntt_form;
    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    RNSPoly poly_u(context, parms.parms_id(), ternary);
    RNSPoly poly_e0(context, parms.parms_id(), centered_binomial);
    RNSPoly poly_e1(context, parms.parms_id(), centered_binomial);

    poly_u.coeff_to_dot();
    poly_u.multiply(public_key[0], destination[0]);
    poly_u.multiply(public_key[1], destination[1]);
    if (!is_ntt_form)
    {
        destination[0].dot_to_coeff();
        destination[1].dot_to_coeff();
    }

    if (type == BGV)
    {
        if (is_ntt_form)
        {
            poly_e0.coeff_to_dot();
            poly_e1.coeff_to_dot();
        }
        poly_e0.multiply_scalar(plain_modulus.value(), poly_e0);
        poly_e1.multiply_scalar(plain_modulus.value(), poly_e1);
    }
    else
    {
        if (is_ntt_form)
        {
            poly_e0.coeff_to_dot();
            poly_e1.coeff_to_dot();
        }
    }
    destination[0].add(poly_e0, destination[0]);
    destination[1].add(poly_e1, destination[1]);
}

void encrypt_zero_symmetric(const SecretKey &secret_key, const PoseidonContext &context,
                            parms_id_type parms_id, bool is_ntt_form, bool save_seed,
                            Ciphertext &destination)
{
    // We use a fresh memory pool with `clear_on_destruction' enabled.
    MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    auto global_context_data = context.crt_context();
    auto &context_data = *context.crt_context()->get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto plain_modulus = Modulus(parms.plain_modulus());
    size_t encrypted_size = 2;
    SchemeType type = parms.scheme();
    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = is_ntt_form;

    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    // If a polynomial is too small to store UniformRandomGeneratorInfo,
    // it is best to just disable save_seed. Note that the size needed is
    // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
    // of an indicator word that indicates a seeded ciphertext.
    size_t poly_uint64_count =
        mul_safe(parms.degree(), decltype(parms.degree())(parms.p().size() + parms.q().size()));
    size_t prng_info_byte_count =
        static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
    size_t prng_info_uint64_count =
        divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
    if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
    {
        save_seed = false;
    }

    // Create an instance of a random number generator. We use this for sampling
    // a seed for a second PRNG used for sampling u (the seed can be public
    // information. This PRNG is also used for sampling the noise/error below.
    auto bootstrap_prng = context.random_generator()->create();

    // Sample a public seed for generating uniform randomness
    prng_seed_type public_prng_seed;
    bootstrap_prng->generate(prng_seed_byte_count,
                             reinterpret_cast<poseidon_byte *>(public_prng_seed.data()));

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto ciphertext_prng =
        UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);
    // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/ckks
    // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
    // destination[1].set_random(context,gaussian,);
    // Sample a uniformly at random
    if (is_ntt_form)
    {
        // Sample the NTT form directly
        destination[1].set_random(context, gaussian, ciphertext_prng);
    }
    else
    {
        // Sample non-NTT form and store the seed
        destination[1].set_random(context, gaussian, ciphertext_prng);
        destination[1].coeff_to_dot();
    }
    // Sample e <-- chi
    // Calculate -(as+ e) (mod q) and store in c[0] in BFV/ckks
    // Calculate -(as+pe) (mod q) and store in c[0] in BGV
    RNSPoly noise(context, parms.parms_id(), centered_binomial, bootstrap_prng);
    destination[1].multiply(secret_key.poly(), destination[0]);
    if (is_ntt_form)
    {
        // Transform the noise e into NTT representation
        noise.coeff_to_dot();
    }
    else
    {
        destination[0].dot_to_coeff();
    }

    if (type == BGV)
    {
        // noise = pe instead of e in BGV
        noise.multiply_scalar(plain_modulus.value(), noise);
    }

    destination[0].add(noise, destination[0]);
    destination[0].negate();
    if (!is_ntt_form && !save_seed)
    {
        destination[1].dot_to_coeff();
    }
    if (save_seed)
    {
        UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

        uint64_t *c1 = destination.data(1);
        // Write prng_info to destination.data(1) after an indicator word
        c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
        prng_info.save(reinterpret_cast<poseidon_byte *>(c1 + 1), prng_info_byte_count,
                       compr_mode_type::none);
    }
}
}  // namespace util
}  // namespace poseidon
