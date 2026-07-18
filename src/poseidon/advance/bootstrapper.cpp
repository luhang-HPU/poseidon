#include "poseidon/advance/bootstrapper.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace poseidon
{
namespace
{
constexpr double kPi = 3.141592653589793238462643383279502884;

struct CosineHeapNode
{
    int degree = -1;
    std::vector<double> cheb;
};

std::vector<CosineHeapNode> read_cosine_heap(std::istream &input)
{
    int heap_len = 0;
    input >> heap_len;
    std::vector<CosineHeapNode> heap(static_cast<std::size_t>(heap_len));
    int index = 0;
    int degree = 0;
    while (input >> index >> degree)
    {
        if (index < 0 || index >= heap_len)
        {
            throw std::runtime_error("invalid bootstrap cosine heap index");
        }
        heap[static_cast<std::size_t>(index)].degree = degree;
        heap[static_cast<std::size_t>(index)].cheb.resize(static_cast<std::size_t>(degree + 1));
        for (int i = 0; i <= degree; ++i)
        {
            input >> heap[static_cast<std::size_t>(index)].cheb[static_cast<std::size_t>(i)];
        }
    }
    return heap;
}

std::vector<CosineHeapNode> parse_cosine_heap(const std::string &path)
{
    if (!path.empty())
    {
        std::ifstream input(path);
        if (!input)
        {
            throw std::runtime_error("failed to open bootstrap cosine heap: " + path);
        }
        return read_cosine_heap(input);
    }

static const char kCosineHeap[] = R"COSINE_HEAP(
15
0 59
-0.21723396226668855
-0.056455156176228185
-0.43488242420513659
-0.050411698744358917
-0.43793863957409878
-0.039916217661921208
-0.44813287040679449
-0.028684347413970345
-0.46935671547262919
-0.022999376313826108
-0.49856312296040408
-0.030614583970954122
-0.51779872340888525
-0.056128435020732462
-0.49183804419230285
-0.092504982743242497
-0.38533019232262809
-0.11476110597257933
-0.20741951935852452
-0.090623556631916045
-0.053494395146506312
-0.018261607434632317
-0.058419300762727352
0.039405420083093932
-0.21526006141139435
0.003764336030247521
-0.26513551593143315
-0.080186009999403619
-0.030194138094870908
-0.048124156063272273
0.11674848976884277
0.064948700860489057
-0.14957480693954412
-0.006289941699993655
-0.13780980282152958
-0.083378272779132672
0.21131417516404909
0.09241536515119209
-0.21564555901328301
-0.070122967853132365
0.1164131424794055
0.034764632051480837
-0.061398176042494826
-0.01556471410521126
0.019426586090230516
0.0048156963872466988
-0.0080031386678985838
-0.0016841104666696418
0.0013424503264896442
0.00030616355837303658
-0.00067475928156572297
-0.0001199031557578406
0.89739614597887793e-5
0.47803669134572563e-5
-0.45075364388216766e-4
-0.70174672780438559e-5
-0.37640919430990063e-5
-0.47545076021261857e-6
-0.15990186088549553e-5
-0.23658667586961395e-6

1 27
-0.14957480693954412
-0.01257988339998731
-0.27561960564305915
-0.16675654555826534
0.42262835032809819
0.18483073030238418
-0.43129111802656602
-0.14024593570626473
0.23282628495881099
0.069529264102961674
-0.12279635208498965
-0.03112942821042252
0.038853172180461032
0.0096313927744933975
-0.016006277335797168
-0.0033682209333392837
0.0026849006529792883
0.00061232711674607315
-0.0013495185631314459
-0.00023980631151568119
0.17947922919577559e-4
0.95607338269145126e-5
-0.90150728776433532e-4
-0.14034934556087712e-4
-0.75281838861980125e-5
-0.95090152042523713e-6
-0.31980372177099107e-5
-0.47317335173922789e-6

2 31
-0.21723396226668855
-0.056455156176228185
-0.43488242420513659
-0.050411698744358917
-0.43793863957409878
-0.039915981075245338
-0.44813127138818564
-0.028683871963210133
-0.46935295138068609
-0.022992358846548064
-0.49851804759601587
-0.030619364337867579
-0.51780769737034504
-0.056008531864974622
-0.49116328491073713
-0.092811146301615534
-0.38667264264911774
-0.11307699550590968
-0.19941638069062594
-0.095439253019162744
-0.072920981236736828
-0.0026968933294210567
0.0029788752797674746
0.0046407880316130954
-0.33167320389079985
0.073887303883379886
-0.049489956918150145
-0.17260137515059571
-0.24150831325892
0.035254116715860399
0.25455829259037235
0.071238642560482712

3 11
0.0026849006529792883
0.0012246542334921463
-0.0026990371262628919
-0.00047961262303136239
0.35895845839155117e-4
0.19121467653829025e-4
-0.00018030145755286706
-0.28069869112175424e-4
-0.15056367772396025e-4
-0.19018030408504743e-5
-0.63960744354198213e-5
-0.94634670347845578e-6

4 15
-0.14957480693954412
-0.01257988339998731
-0.27561960564305915
-0.16675654555826534
0.42262835032809819
0.18483120347573592
-0.43128791998934831
-0.1402449848047443
0.23283381314269719
0.069543299037517761
-0.12270620135621322
-0.031138988944249434
0.038835224257541454
0.0098711990860090787
-0.014656758772665722
-0.0039805480500853568

5 15
-0.38667264264911774
-0.22615399101181937
-0.39883276138125187
-0.19087850603832549
-0.14584196247347366
-0.0053937866588421134
0.0059577505595349492
0.0092815760632261908
-0.66334640778159969
0.14777460776675977
-0.098979913836300289
-0.34520275030119142
-0.48301662651784
0.070508233431720797
0.5091165851807447
0.14247728512096542

6 15
-0.21723396226668855
-0.1276937987367109
-0.68944071679550894
-0.085665815460219315
-0.19643032631517878
0.13268539407535037
-0.39864131447003549
-0.10257117584659002
-0.13767974748988624
-0.027633146878161159
-0.50149692287578334
-0.027922471008446522
-0.44488671613360821
0.039430721154188122
-0.29174690422011119
0.020265849204294151

7 3
-0.15056367772396025e-4
-0.38036060817009485e-5
-0.12792148870839643e-4
-0.18926934069569116e-5

8 7
0.0026849006529792883
0.0012246542334921463
-0.0026990371262628919
-0.00047961262303136239
0.35895845839155117e-4
0.20067814357307481e-4
-0.00017390538311744724
-0.26168066071324949e-4

9 7
0.23283381314269719
0.13908659807503552
-0.24541240271242644
-0.062277977888498869
0.077670448515082908
0.019742398172018157
-0.029313517545331443
-0.0079610961001707136

10 7
-0.14957480693954412
-0.0085993353499019533
-0.26096284687039343
-0.17662774464427442
0.38379312607055673
0.21597019241998535
-0.30858171863313509
-0.20978828384226207

11 7
-0.66334640778159969
0.29554921553351954
-0.19795982767260058
-0.69040550060238283
-0.96603325303568001
0.14101646686344159
1.0182331703614894
0.28495457024193085

12 7
-0.38667264264911774
-0.36863127613278479
-0.90794934656199657
-0.26138673947004628
0.33717466404436635
0.3398089636423493
0.10493766439583524
-0.13849303170353358

13 7
-0.13767974748988624
-0.055266293756322318
-1.0029938457515667
-0.055844942016893044
-0.88977343226721643
0.078861442308376244
-0.58349380844022238
0.040531698408588302

14 7
-0.21723396226668855
-0.14795964794100505
-0.39769381257539775
-0.12509653661440744
0.24845638981842943
0.16060786508379689
0.10285560840574785
-0.07493802896842886

)COSINE_HEAP";

    std::istringstream input(kCosineHeap);
    return read_cosine_heap(input);
}

const std::vector<CosineHeapNode> &cosine_heap(const std::string &path)
{
    static const auto embedded_heap = parse_cosine_heap({});
    if (path.empty())
    {
        return embedded_heap;
    }

    static std::mutex mutex;
    static std::map<std::string, std::vector<CosineHeapNode>> heaps;
    std::lock_guard<std::mutex> lock(mutex);
    auto [it, inserted] = heaps.try_emplace(path);
    if (inserted)
    {
        it->second = parse_cosine_heap(path);
    }
    return it->second;
}
}

Bootstrapper::Bootstrapper(const PoseidonContext &context,
                           EvaluatorCkksBase &evaluator, const CKKSEncoder &encoder,
                           long log_slots, long boundary_k, double initial_scale,
                           double final_scale, std::string cosine_heap_path)
    : context_(context), evaluator_(evaluator), encoder_(encoder), log_slots_(log_slots),
      slots_(1L << log_slots), boundary_k_(boundary_k), initial_scale_(initial_scale),
      final_scale_(final_scale), cosine_heap_path_(std::move(cosine_heap_path))
{
}

int Bootstrapper::giant_step(int count)
{
    int best_value = count;
    int best_k = 1;
    for (int k = 1; k <= static_cast<int>(3 * std::sqrt(count)); ++k)
    {
        int value = static_cast<int>(std::ceil(static_cast<double>(count) / k)) + k - 1;
        if (value < best_value)
        {
            best_value = value;
            best_k = k;
        }
    }
    return best_k;
}

bool Bootstrapper::has_nonzero(const std::vector<Complex> &values)
{
    return std::any_of(values.begin(), values.end(), [](const auto &value) {
        return value.real() != 0.0 || value.imag() != 0.0;
    });
}

void Bootstrapper::rotate_coeff(long log_slots, long full_slots, int shift,
                                     const std::vector<Complex> &input,
                                     std::vector<Complex> &output)
{
    const int slot_len = 1 << log_slots;
    const int repeat_count = static_cast<int>(full_slots / slot_len);
    output.clear();
    output.reserve(full_slots);
    for (int r = 0; r < repeat_count; ++r)
    {
        for (int i = 0; i < slot_len; ++i)
        {
            output.push_back(input[(slot_len + i + shift) % slot_len]);
        }
    }
}

void Bootstrapper::generate_linear_coefficients()
{
    gen_original_coefficients();
    generate_slot_to_coeff_coefficients();
    generate_coeff_to_slot_coefficients();
}

void Bootstrapper::mod_raise(const Ciphertext &cipher, Ciphertext &destination) const
{
    if (cipher.size() != 2)
    {
        throw std::invalid_argument("Bootstrapper::mod_raise supports size-2 ciphertexts only");
    }

    Ciphertext coeff_cipher;
    if (cipher.is_ntt_form())
    {
        evaluator_.ntt_inv(cipher, coeff_cipher);
    }
    else
    {
        coeff_cipher = cipher;
    }

    if (coeff_cipher.coeff_modulus_size() != 1)
    {
        throw std::invalid_argument(
            "Bootstrapper::mod_raise expects the ciphertext at single-prime q0 level");
    }

    const auto first_parms_id = context_.crt_context()->first_parms_id();
    destination.resize(context_, first_parms_id, coeff_cipher.size());
    destination.scale() = coeff_cipher.scale();
    destination.is_ntt_form() = false;

    const auto first_context_data = context_.crt_context()->first_context_data();
    const auto &modulus = first_context_data->coeff_modulus();
    const auto coeff_modulus_size = destination.coeff_modulus_size();
    const auto degree = destination.poly_modulus_degree();
    const std::uint64_t q0 = modulus[0].value();

    std::vector<std::uint64_t> minus_q0(coeff_modulus_size, 0);
    for (std::size_t j = 1; j < coeff_modulus_size; ++j)
    {
        minus_q0[j] = modulus[j].value() - (q0 % modulus[j].value());
    }

    for (std::size_t poly_idx = 0; poly_idx < coeff_cipher.size(); ++poly_idx)
    {
        const auto src_zero = coeff_cipher.data(poly_idx);
        auto dest_poly = destination.data(poly_idx);
        for (std::size_t j = 0; j < coeff_modulus_size; ++j)
        {
            const auto q = modulus[j].value();
            auto dest = dest_poly + j * degree;
            for (std::size_t i = 0; i < degree; ++i)
            {
                dest[i] = src_zero[i] % q;
                if (src_zero[i] > (q0 >> 1))
                {
                    dest[i] += minus_q0[j];
                    dest[i] -= (dest[i] >= q) ? q : 0;
                }
            }
        }
        destination[poly_idx].coeff_to_dot();
    }
    destination.is_ntt_form() = true;
}

void Bootstrapper::gen_original_coefficients()
{
    const long n = slots_;
    original_coeffs_.resize(log_slots_);
    double theta0 = kPi / (2 * n);
    int block_len = 1;
    int block_count = static_cast<int>(n);
    for (int level = 0; level < log_slots_; ++level)
    {
        original_coeffs_[level].assign(3, std::vector<Complex>(n));
        block_len <<= 1;
        block_count >>= 1;
        const double theta = theta0 * (1 << (log_slots_ - 1 - level));
        int power = 1;
        auto zeta = std::polar(1.0, theta * power);
        for (int j = 0; j < block_len / 2; ++j)
        {
            for (int k = 0; k < block_count; ++k)
            {
                const int base = k * block_len + j;
                original_coeffs_[level][1][base] = 1.0;
                original_coeffs_[level][1][base + block_len / 2] = -zeta;
                original_coeffs_[level][0][base] = 0.0;
                original_coeffs_[level][0][base + block_len / 2] = 1.0;
                original_coeffs_[level][2][base] = zeta;
                original_coeffs_[level][2][base + block_len / 2] = 0.0;
            }
            power = (5 * power) % (1 << (level + 3));
            zeta = std::polar(1.0, theta * power);
        }
    }

    original_inv_coeffs_.resize(log_slots_);
    theta0 = -kPi / (2 * n);
    block_len = static_cast<int>(n);
    block_count = 1;
    for (int level = 0; level < log_slots_; ++level)
    {
        original_inv_coeffs_[level].assign(3, std::vector<Complex>(n));
        const double theta = theta0 * (1 << level);
        int power = 1;
        auto zeta = std::polar(1.0, theta * power);
        for (int j = 0; j < block_len / 2; ++j)
        {
            for (int k = 0; k < block_count; ++k)
            {
                const int base = k * block_len + j;
                original_inv_coeffs_[level][1][base] = 0.5;
                original_inv_coeffs_[level][1][base + block_len / 2] = -0.5 * zeta;
                original_inv_coeffs_[level][0][base] = 0.0;
                original_inv_coeffs_[level][0][base + block_len / 2] = 0.5 * zeta;
                original_inv_coeffs_[level][2][base] = 0.5;
                original_inv_coeffs_[level][2][base + block_len / 2] = 0.0;
            }
            power = (5 * power) % (1 << ((log_slots_ - 1 - level) + 3));
            zeta = std::polar(1.0, theta * power);
        }
        block_len >>= 1;
        block_count <<= 1;
    }
}

void Bootstrapper::generate_slot_to_coeff_coefficients()
{
    const int div3 = static_cast<int>(std::floor(log_slots_ / 3.0));
    const int div2 = static_cast<int>(std::floor((log_slots_ - div3) / 2.0));
    const int div1 = static_cast<int>(log_slots_ - div3 - div2);
    const int total1 = (1 << div1) - 1;
    const int total2 = (1 << div2) - 1;
    const int total3 = (1 << div3) - 1;
    const int step1 = 1;
    const int step2 = 1 << div1;
    const int step3 = 1 << (div1 + div2);

    fft_coeffs1_.assign(2 * total1 + 1, std::vector<Complex>(slots_));
    fft_coeffs2_.assign(2 * total2 + 1, std::vector<Complex>(slots_));
    fft_coeffs3_.assign(total3 + 1, std::vector<Complex>(slots_));

    std::vector<Complex> tmp(slots_);
    std::vector<int> counts;
    auto &coeffs = original_coeffs_;

    counts.resize(div1);
    for (int state = 0; state < static_cast<int>(std::pow(3, div1)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div1; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << p);
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div1; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << p);
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p][counts[p]][(k + step1 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            fft_coeffs1_[pos + total1][k] += tmp[k];
        }
    }

    counts.assign(div2, 0);
    for (int state = 0; state < static_cast<int>(std::pow(3, div2)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div2; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << p);
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div2; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << p);
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p + div1][counts[p]]
                                [(k + step2 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            fft_coeffs2_[pos + total2][k] += tmp[k];
        }
    }

    counts.assign(div3, 0);
    for (int state = 0; state < static_cast<int>(std::pow(3, div3)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div3; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << p);
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div3; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << p);
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p + div1 + div2][counts[p]]
                                [(k + step3 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            fft_coeffs3_[(pos + total3 + 1) % (total3 + 1)][k] += tmp[k];
        }
    }
}

void Bootstrapper::generate_coeff_to_slot_coefficients()
{
    const int div1 = static_cast<int>(std::floor(log_slots_ / 3.0));
    const int div2 = static_cast<int>(std::floor((log_slots_ - div1) / 2.0));
    const int div3 = static_cast<int>(log_slots_ - div1 - div2);
    const int total1 = (1 << div1) - 1;
    const int total2 = (1 << div2) - 1;
    const int total3 = (1 << div3) - 1;
    const int step1 = 1 << (log_slots_ - div1);
    const int step2 = 1 << (log_slots_ - div1 - div2);
    const int step3 = 1;

    inv_fft_coeffs1_.assign(total1 + 1, std::vector<Complex>(slots_));
    inv_fft_coeffs2_.assign(2 * total2 + 1, std::vector<Complex>(slots_));
    inv_fft_coeffs3_.assign(2 * total3 + 1, std::vector<Complex>(slots_));

    std::vector<Complex> tmp(slots_);
    std::vector<int> counts;
    auto &coeffs = original_inv_coeffs_;

    counts.resize(div1);
    for (int state = 0; state < static_cast<int>(std::pow(3, div1)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div1; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << (div1 - 1 - p));
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div1; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << (div1 - 1 - p));
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p][counts[p]][(k + step1 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            inv_fft_coeffs1_[(pos + total1 + 1) % (total1 + 1)][k] += tmp[k];
        }
    }

    counts.assign(div2, 0);
    for (int state = 0; state < static_cast<int>(std::pow(3, div2)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div2; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << (div2 - 1 - p));
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div2; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << (div2 - 1 - p));
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p + div1][counts[p]]
                                [(k + step2 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            inv_fft_coeffs2_[pos + total2][k] += tmp[k];
        }
    }

    counts.assign(div3, 0);
    for (int state = 0; state < static_cast<int>(std::pow(3, div3)); ++state)
    {
        int ind = state;
        int pos = 0;
        for (int p = 0; p < div3; ++p)
        {
            int r = ind % 3;
            pos += (r - 1) * (1 << (div3 - 1 - p));
            counts[p] = r;
            ind = (ind - r) / 3;
        }
        int current_pos = pos;
        std::fill(tmp.begin(), tmp.end(), Complex(1.0, 0.0));
        for (int p = 0; p < div3; ++p)
        {
            current_pos -= (counts[p] - 1) * (1 << (div3 - 1 - p));
            for (int k = 0; k < slots_; ++k)
            {
                tmp[k] *= coeffs[p + div1 + div2][counts[p]]
                                [(k + step3 * (slots_ + current_pos)) % slots_];
            }
        }
        for (int k = 0; k < slots_; ++k)
        {
            inv_fft_coeffs3_[pos + total3][k] += tmp[k];
        }
    }

    for (auto &diag : inv_fft_coeffs1_)
    {
        for (auto &value : diag)
        {
            value *= 1.0 / boundary_k_;
        }
    }
    for (auto &diag : inv_fft_coeffs3_)
    {
        for (auto &value : diag)
        {
            value *= 0.5;
        }
    }
}

void Bootstrapper::multiply_vector_reduced_error(
    const Ciphertext &cipher, const std::vector<Complex> &values, Ciphertext &destination) const
{
    Plaintext plain;
    encoder_.encode(values, cipher.parms_id(), cipher.scale(), plain);
    evaluator_.multiply_plain(cipher, plain, destination);
}

void Bootstrapper::multiply_vector_unit_scale(
    const Ciphertext &cipher, const std::vector<Complex> &values, Ciphertext &destination) const
{
    Plaintext plain;
    encoder_.encode(values, cipher.parms_id(), 1.0, plain);
    evaluator_.multiply_plain(cipher, plain, destination);
}

void Bootstrapper::add_reduced_error(const Ciphertext &lhs, const Ciphertext &rhs,
                                          Ciphertext &destination) const
{
    destination = lhs;
    add_inplace_reduced_error(destination, rhs);
}

void Bootstrapper::add_inplace_reduced_error(Ciphertext &lhs, const Ciphertext &rhs) const
{
    lhs.scale() = rhs.scale();
    evaluator_.add(lhs, rhs, lhs);
}

void Bootstrapper::rotate_allow_transparent(const Ciphertext &cipher,
                                                 Ciphertext &destination, int step,
                                                 const GaloisKeys &galois_keys) const
{
    try
    {
        evaluator_.rotate(cipher, destination, step, galois_keys);
    }
    catch (const std::exception &ex)
    {
        if (destination.is_valid() && std::strstr(ex.what(), "transparent"))
        {
            return;
        }
        throw;
    }
}

void Bootstrapper::eval_mod(const Ciphertext &cipher,
                                          Ciphertext &destination,
                                          const RelinKeys &relin_keys,
                                          uint32_t double_angle,
                                          double inverse_coeff,
                                          double target_scale) const
{
    (void)target_scale;
    const auto &heap = cosine_heap(cosine_heap_path_);
    const int heap_m =
        static_cast<int>(std::llround(std::log2(static_cast<double>(heap.size() + 1)))) - 1;
    const int heap_first = (1 << heap_m) - 1;
    const int heap_last = (1 << (heap_m + 1)) - 1;
    int heap_k = 2;
    for (int i = heap_first; i < heap_last; ++i)
    {
        if (heap[static_cast<std::size_t>(i)].degree >= 0)
        {
            heap_k = std::max(heap_k, heap[static_cast<std::size_t>(i)].degree + 1);
        }
    }
    const double zero = 1.0 / cipher.scale();

    auto multiply_const_rescale = [&](const Ciphertext &input, double coeff,
                                      Ciphertext &output) {
        evaluator_.multiply_const(input, coeff, input.scale(), output, encoder_);
        evaluator_.rescale(output, output);
    };

    auto last_modulus_value = [&](const Ciphertext &input) {
        auto data = context_.crt_context()->get_context_data(input.parms_id());
        return static_cast<double>(data->coeff_modulus().back().value());
    };

    auto reduced_add = [&](const Ciphertext &lhs, const Ciphertext &rhs,
                           Ciphertext &output) {
        if (lhs.coeff_modulus_size() == rhs.coeff_modulus_size())
        {
            output = lhs;
            output.scale() = rhs.scale();
            evaluator_.add(output, rhs, output);
            return;
        }
        if (lhs.coeff_modulus_size() < rhs.coeff_modulus_size())
        {
            Ciphertext rhs_adjusted;
            const double scale_adjust =
                lhs.scale() * last_modulus_value(rhs) / (rhs.scale() * rhs.scale());
            evaluator_.multiply_const(rhs, scale_adjust, rhs.scale(), rhs_adjusted, encoder_);
            rhs_adjusted.scale() = lhs.scale() * last_modulus_value(rhs);
            evaluator_.rescale(rhs_adjusted, rhs_adjusted);
            evaluator_.drop_modulus(rhs_adjusted, rhs_adjusted, lhs.parms_id());
            output = lhs;
            output.scale() = rhs_adjusted.scale();
            evaluator_.add(output, rhs_adjusted, output);
            return;
        }

        Ciphertext lhs_adjusted;
        const double scale_adjust =
            rhs.scale() * last_modulus_value(lhs) / (lhs.scale() * lhs.scale());
        evaluator_.multiply_const(lhs, scale_adjust, lhs.scale(), lhs_adjusted, encoder_);
        lhs_adjusted.scale() = rhs.scale() * last_modulus_value(lhs);
        evaluator_.rescale(lhs_adjusted, lhs_adjusted);
        evaluator_.drop_modulus(lhs_adjusted, lhs_adjusted, rhs.parms_id());
        lhs_adjusted.scale() = rhs.scale();
        evaluator_.add(lhs_adjusted, rhs, output);
    };

    auto reduced_add_inplace = [&](Ciphertext &lhs, const Ciphertext &rhs) {
        Ciphertext tmp;
        reduced_add(lhs, rhs, tmp);
        lhs = tmp;
    };

    auto reduced_sub = [&](const Ciphertext &lhs, const Ciphertext &rhs,
                           Ciphertext &output) {
        if (lhs.coeff_modulus_size() == rhs.coeff_modulus_size())
        {
            output = lhs;
            output.scale() = rhs.scale();
            evaluator_.sub(output, rhs, output);
            return;
        }
        if (lhs.coeff_modulus_size() < rhs.coeff_modulus_size())
        {
            Ciphertext rhs_adjusted;
            const double scale_adjust =
                lhs.scale() * last_modulus_value(rhs) / (rhs.scale() * rhs.scale());
            evaluator_.multiply_const(rhs, scale_adjust, rhs.scale(), rhs_adjusted, encoder_);
            rhs_adjusted.scale() = lhs.scale() * last_modulus_value(rhs);
            evaluator_.rescale(rhs_adjusted, rhs_adjusted);
            evaluator_.drop_modulus(rhs_adjusted, rhs_adjusted, lhs.parms_id());
            output = lhs;
            output.scale() = rhs_adjusted.scale();
            evaluator_.sub(output, rhs_adjusted, output);
            return;
        }

        Ciphertext lhs_adjusted;
        const double scale_adjust =
            rhs.scale() * last_modulus_value(lhs) / (lhs.scale() * lhs.scale());
        evaluator_.multiply_const(lhs, scale_adjust, lhs.scale(), lhs_adjusted, encoder_);
        lhs_adjusted.scale() = rhs.scale() * last_modulus_value(lhs);
        evaluator_.rescale(lhs_adjusted, lhs_adjusted);
        evaluator_.drop_modulus(lhs_adjusted, lhs_adjusted, rhs.parms_id());
        lhs_adjusted.scale() = rhs.scale();
        evaluator_.sub(lhs_adjusted, rhs, output);
    };

    auto reduced_multiply = [&](const Ciphertext &lhs, const Ciphertext &rhs,
                                Ciphertext &output) {
        if (lhs.coeff_modulus_size() == rhs.coeff_modulus_size())
        {
            Ciphertext lhs_copy = lhs;
            lhs_copy.scale() = rhs.scale();
            evaluator_.multiply_relin(lhs_copy, rhs, output, relin_keys);
            return;
        }
        if (lhs.coeff_modulus_size() < rhs.coeff_modulus_size())
        {
            Ciphertext rhs_adjusted;
            const double scale_adjust =
                lhs.scale() * last_modulus_value(rhs) / (rhs.scale() * rhs.scale());
            evaluator_.multiply_const(rhs, scale_adjust, rhs.scale(), rhs_adjusted, encoder_);
            rhs_adjusted.scale() = lhs.scale() * last_modulus_value(rhs);
            evaluator_.rescale(rhs_adjusted, rhs_adjusted);
            evaluator_.drop_modulus(rhs_adjusted, rhs_adjusted, lhs.parms_id());
            Ciphertext lhs_copy = lhs;
            lhs_copy.scale() = rhs_adjusted.scale();
            evaluator_.multiply_relin(lhs_copy, rhs_adjusted, output, relin_keys);
            return;
        }

        Ciphertext lhs_adjusted;
        const double scale_adjust =
            rhs.scale() * last_modulus_value(lhs) / (lhs.scale() * lhs.scale());
        evaluator_.multiply_const(lhs, scale_adjust, lhs.scale(), lhs_adjusted, encoder_);
        lhs_adjusted.scale() = rhs.scale() * last_modulus_value(lhs);
        evaluator_.rescale(lhs_adjusted, lhs_adjusted);
        evaluator_.drop_modulus(lhs_adjusted, lhs_adjusted, rhs.parms_id());
        lhs_adjusted.scale() = rhs.scale();
        evaluator_.multiply_relin(lhs_adjusted, rhs, output, relin_keys);
    };

    auto multiply_chebyshev = [&](const Ciphertext &lhs, const Ciphertext &rhs,
                                  Ciphertext &output) {
        reduced_multiply(lhs, rhs, output);
        evaluator_.rescale(output, output);
        evaluator_.add(output, output, output);
    };

    std::vector<Ciphertext> baby(heap_k);
    std::vector<bool> baby_valid(heap_k, false);
    baby[1] = cipher;
    baby_valid[1] = true;

    for (int i = 2; i < heap_k; i *= 2)
    {
        multiply_chebyshev(baby[i / 2], baby[i / 2], baby[i]);
        evaluator_.add_const(baby[i], -1.0, baby[i], encoder_);
        baby_valid[i] = true;
    }

    for (int i = 1; i < heap_k; ++i)
    {
        if (baby_valid[i])
        {
            continue;
        }
        const int lpow2 = 1 << static_cast<int>(std::floor(std::log2(i)));
        const int res = i - lpow2;
        const int diff = std::abs(lpow2 - res);
        multiply_chebyshev(baby[lpow2], baby[res], baby[i]);
        reduced_sub(baby[i], baby[diff], baby[i]);
        baby_valid[i] = true;
    }

    std::vector<Ciphertext> giant(heap_m);
    const int lpow2 = 1 << (static_cast<int>(std::ceil(std::log2(heap_k))) - 1);
    const int res = heap_k - lpow2;
    const int diff = std::abs(lpow2 - res);
    if (res == 0)
    {
        giant[0] = baby[lpow2];
    }
    else if (diff == 0)
    {
        multiply_chebyshev(baby[lpow2], baby[lpow2], giant[0]);
        evaluator_.add_const(giant[0], -1.0, giant[0], encoder_);
    }
    else
    {
        multiply_chebyshev(baby[lpow2], baby[res], giant[0]);
        reduced_sub(giant[0], baby[diff], giant[0]);
    }

    for (int i = 1; i < heap_m; ++i)
    {
        multiply_chebyshev(giant[i - 1], giant[i - 1], giant[i]);
        evaluator_.add_const(giant[i], -1.0, giant[i], encoder_);
    }

    std::vector<Ciphertext> cipher_heap(heap.size());
    std::vector<bool> cipher_heap_valid(heap.size(), false);
    for (int i = heap_first; i < heap_last; ++i)
    {
        const auto &node = heap[static_cast<std::size_t>(i)];
        if (node.degree < 0)
        {
            continue;
        }

        bool has_acc = false;
        Ciphertext acc;
        for (int j = 1; j <= node.degree; ++j)
        {
            const double coeff = node.cheb[static_cast<std::size_t>(j)];
            if (std::abs(coeff) <= zero)
            {
                continue;
            }
            Ciphertext term;
            if (j < heap_k)
            {
                multiply_const_rescale(baby[j], coeff, term);
            }
            else
            {
                multiply_const_rescale(giant[0], coeff, term);
            }
            if (!has_acc)
            {
                acc = term;
                has_acc = true;
            }
            else
            {
                reduced_add_inplace(acc, term);
            }
        }

        if (!has_acc)
        {
            multiply_const_rescale(baby[1], 0.0, acc);
            has_acc = true;
        }
        if (std::abs(node.cheb[0]) > zero)
        {
            evaluator_.add_const(acc, node.cheb[0], acc, encoder_);
        }

        cipher_heap[static_cast<std::size_t>(i)] = acc;
        cipher_heap_valid[static_cast<std::size_t>(i)] = true;
    }

    int depth = heap_m;
    int giant_index = 0;
    while (depth != 0)
    {
        --depth;
        const int first = (1 << depth) - 1;
        const int last = (1 << (depth + 1)) - 1;
        for (int i = first; i < last; ++i)
        {
            const auto &node = heap[static_cast<std::size_t>(i)];
            if (node.degree < 0)
            {
                continue;
            }

            const int left = 2 * (i + 1) - 1;
            const int right = 2 * (i + 1);
            if (!cipher_heap_valid[static_cast<std::size_t>(left)])
            {
                cipher_heap[static_cast<std::size_t>(i)] =
                    cipher_heap[static_cast<std::size_t>(right)];
            }
            else
            {
                Ciphertext prod;
                reduced_multiply(cipher_heap[static_cast<std::size_t>(left)],
                                 giant[static_cast<std::size_t>(giant_index)], prod);
                evaluator_.rescale(prod, prod);
                reduced_add(prod, cipher_heap[static_cast<std::size_t>(right)],
                            cipher_heap[static_cast<std::size_t>(i)]);
            }
            cipher_heap_valid[static_cast<std::size_t>(i)] = true;
        }
        ++giant_index;
    }

    destination = cipher_heap[0];
    const double inverse_root =
        std::pow(inverse_coeff, 1.0 / static_cast<double>(1ULL << double_angle));
    double curr_scale = inverse_root;
    for (uint32_t i = 0; i < double_angle; ++i)
    {
        curr_scale *= curr_scale;
        reduced_multiply(destination, destination, destination);
        evaluator_.rescale(destination, destination);
        evaluator_.add(destination, destination, destination);
        evaluator_.add_const(destination, -curr_scale, destination, encoder_);
    }
}

double Bootstrapper::inverse_coefficient(uint32_t double_angle) const
{
    const auto &heap = cosine_heap(cosine_heap_path_);
    if (heap.empty() || heap[0].degree < 0)
    {
        throw std::runtime_error("bootstrap cosine heap has no root polynomial");
    }

    const auto &root = heap[0];
    double value_at_zero = 0.0;
    for (int degree = 0; degree <= root.degree; ++degree)
    {
        const double chebyshev_at_zero =
            std::cos(static_cast<double>(degree) * kPi / 2.0);
        value_at_zero += root.cheb[static_cast<std::size_t>(degree)] * chebyshev_at_zero;
    }

    const double unscaled_value_at_zero =
        std::cos(kPi / static_cast<double>(1ULL << (double_angle + 1)));
    const double inverse_root = value_at_zero / unscaled_value_at_zero;
    return std::pow(inverse_root, static_cast<double>(1ULL << double_angle));
}

void Bootstrapper::bsgs_linear_transform(
    Ciphertext &destination, const Ciphertext &cipher, int total_len, int basic_step,
    int coeff_log_slots, const std::vector<std::vector<Complex>> &coeffs,
    const GaloisKeys &galois_keys) const
{
    const int gs = giant_step(2 * total_len + 1);
    const int basic_start = -total_len + gs * std::floor((total_len + 0.0) / gs);
    const int giant_first = -std::floor((total_len + 0.0) / gs);
    const int giant_last = std::floor((2 * total_len + 0.0) / gs) + giant_first;

    std::vector<Ciphertext> baby(gs);
    for (int i = basic_start; i < basic_start + gs; ++i)
    {
        if (i == 0)
        {
            baby[i - basic_start] = cipher;
        }
        else
        {
            rotate_allow_transparent(cipher, baby[i - basic_start],
                                     (slots_ + i * basic_step) % slots_, galois_keys);
        }
    }

    bool has_output = false;
    Ciphertext output;
    std::vector<Complex> rotated_coeff;
    for (int i = giant_first; i <= giant_last; ++i)
    {
        bool has_giant = false;
        Ciphertext giant;
        const int stop = (i != giant_last) ? basic_start + gs - 1 : total_len - i * gs;
        for (int j = basic_start; j <= stop; ++j)
        {
            rotate_coeff(coeff_log_slots, slots_, (-i) * gs * basic_step,
                         coeffs[(i * gs + j) + total_len], rotated_coeff);
            if (!has_nonzero(rotated_coeff))
            {
                continue;
            }
            Ciphertext term;
            multiply_vector_reduced_error(baby[j - basic_start], rotated_coeff, term);
            if (!has_giant)
            {
                giant = term;
                has_giant = true;
            }
            else
            {
                add_inplace_reduced_error(giant, term);
            }
        }

        Ciphertext giant_rot;
        if (!has_giant)
        {
            continue;
        }
        if (i != 0)
        {
            rotate_allow_transparent(giant, giant_rot,
                                     (slots_ + i * gs * basic_step) % slots_, galois_keys);
        }
        else
        {
            giant_rot = giant;
        }

        if (!has_output)
        {
            output = giant_rot;
            has_output = true;
        }
        else
        {
            add_inplace_reduced_error(output, giant_rot);
        }
    }
    destination = output;
}

void Bootstrapper::rotated_bsgs_linear_transform(
    Ciphertext &destination, const Ciphertext &cipher, int total_len, int basic_step,
    int coeff_log_slots, const std::vector<std::vector<Complex>> &coeffs,
    const GaloisKeys &galois_keys) const
{
    const int gs = giant_step(total_len + 1);
    const int giant_last = std::floor((total_len + 0.0) / gs);

    std::vector<Ciphertext> baby(gs);
    for (int i = 0; i < gs; ++i)
    {
        if (i == 0)
        {
            baby[i] = cipher;
        }
        else
        {
            rotate_allow_transparent(cipher, baby[i], (slots_ + i * basic_step) % slots_,
                                     galois_keys);
        }
    }

    bool has_output = false;
    Ciphertext output;
    std::vector<Complex> rotated_coeff;
    for (int i = 0; i <= giant_last; ++i)
    {
        bool has_giant = false;
        Ciphertext giant;
        const int stop = (i != giant_last) ? gs - 1 : total_len - i * gs;
        for (int j = 0; j <= stop; ++j)
        {
            rotate_coeff(coeff_log_slots, slots_, (-i) * gs * basic_step,
                         coeffs[i * gs + j], rotated_coeff);
            if (!has_nonzero(rotated_coeff))
            {
                continue;
            }
            Ciphertext term;
            multiply_vector_reduced_error(baby[j], rotated_coeff, term);
            if (!has_giant)
            {
                giant = term;
                has_giant = true;
            }
            else
            {
                add_inplace_reduced_error(giant, term);
            }
        }

        Ciphertext giant_rot;
        if (!has_giant)
        {
            continue;
        }
        if (i != 0)
        {
            rotate_allow_transparent(giant, giant_rot,
                                     (slots_ + i * gs * basic_step) % slots_, galois_keys);
        }
        else
        {
            giant_rot = giant;
        }

        if (!has_output)
        {
            output = giant_rot;
            has_output = true;
        }
        else
        {
            add_inplace_reduced_error(output, giant_rot);
        }
    }
    destination = output;
}

void Bootstrapper::slot_to_coeff_transform(Ciphertext &destination, const Ciphertext &cipher,
                                           const GaloisKeys &galois_keys) const
{
    const int div3 = static_cast<int>(std::floor(log_slots_ / 3.0));
    const int div2 = static_cast<int>(std::floor((log_slots_ - div3) / 2.0));
    const int div1 = static_cast<int>(log_slots_ - div3 - div2);
    const int total1 = (1 << div1) - 1;
    const int total2 = (1 << div2) - 1;
    const int total3 = (1 << div3) - 1;
    const int step1 = 1;
    const int step2 = 1 << div1;
    const int step3 = 1 << (div1 + div2);

    Ciphertext tmp1;
    bsgs_linear_transform(tmp1, cipher, total1, step1, log_slots_, fft_coeffs1_, galois_keys);
    evaluator_.rescale_dynamic(tmp1, tmp1, cipher.scale());

    Ciphertext tmp2;
    bsgs_linear_transform(tmp2, tmp1, total2, step2, log_slots_, fft_coeffs2_, galois_keys);
    evaluator_.rescale_dynamic(tmp2, tmp2, cipher.scale());

    auto context_data = context_.crt_context()->get_context_data(tmp2.parms_id());
    const auto &modulus = context_data->coeff_modulus();
    const double mod_zero =
        static_cast<double>(context_.crt_context()->first_context_data()->coeff_modulus()[0].value());
    const double curr_mod = static_cast<double>(modulus[tmp2.level()].value());
    auto scaled_coeffs = fft_coeffs3_;
    const double factor = curr_mod * mod_zero * final_scale_ /
                          (tmp2.scale() * tmp2.scale() * initial_scale_);
    for (auto &diag : scaled_coeffs)
    {
        for (auto &value : diag)
        {
            value *= factor;
        }
    }

    rotated_bsgs_linear_transform(destination, tmp2, total3, step3, log_slots_, scaled_coeffs,
                                  galois_keys);
    evaluator_.rescale_dynamic(destination, destination, final_scale_);
    destination.scale() = mod_zero * final_scale_ / initial_scale_;
}

void Bootstrapper::coeff_to_slot_transform(Ciphertext &destination, const Ciphertext &cipher,
                                           const GaloisKeys &galois_keys) const
{
    const int div1 = static_cast<int>(std::floor(log_slots_ / 3.0));
    const int div2 = static_cast<int>(std::floor((log_slots_ - div1) / 2.0));
    const int div3 = static_cast<int>(log_slots_ - div1 - div2);
    const int total1 = (1 << div1) - 1;
    const int total2 = (1 << div2) - 1;
    const int total3 = (1 << div3) - 1;
    const int step1 = 1 << (log_slots_ - div1);
    const int step2 = 1 << (log_slots_ - div1 - div2);
    const int step3 = 1;

    Ciphertext tmp1;
    rotated_bsgs_linear_transform(tmp1, cipher, total1, step1, log_slots_, inv_fft_coeffs1_,
                                  galois_keys);
    evaluator_.rescale_dynamic(tmp1, tmp1, cipher.scale());

    Ciphertext tmp2;
    bsgs_linear_transform(tmp2, tmp1, total2, step2, log_slots_, inv_fft_coeffs2_, galois_keys);
    evaluator_.rescale_dynamic(tmp2, tmp2, cipher.scale());

    bsgs_linear_transform(destination, tmp2, total3, step3, log_slots_, inv_fft_coeffs3_,
                          galois_keys);
    evaluator_.rescale_dynamic(destination, destination, cipher.scale());
}

void Bootstrapper::coeff_to_slot(const Ciphertext &cipher, Ciphertext &real_part,
                                 Ciphertext &imag_part,
                                 const GaloisKeys &galois_keys) const
{
    Ciphertext tmp;
    coeff_to_slot_transform(tmp, cipher, galois_keys);

    std::vector<Complex> minus_i(slots_, Complex(0.0, -1.0));
    Ciphertext tmp_imag;
    multiply_vector_unit_scale(tmp, minus_i, tmp_imag);

    Ciphertext conj_imag;
    Ciphertext conj_real;
    evaluator_.conjugate(tmp_imag, galois_keys, conj_imag);
    evaluator_.conjugate(tmp, galois_keys, conj_real);
    add_reduced_error(tmp, conj_real, real_part);
    add_reduced_error(tmp_imag, conj_imag, imag_part);
}

void Bootstrapper::slot_to_coeff(const Ciphertext &real_part, const Ciphertext &imag_part,
                                 Ciphertext &destination,
                                 const GaloisKeys &galois_keys) const
{
    std::vector<Complex> i_vec(slots_, Complex(0.0, 1.0));
    Ciphertext imag_scaled;
    multiply_vector_unit_scale(imag_part, i_vec, imag_scaled);
    Ciphertext combined;
    add_reduced_error(real_part, imag_scaled, combined);
    slot_to_coeff_transform(destination, combined, galois_keys);
}

}  // namespace poseidon
