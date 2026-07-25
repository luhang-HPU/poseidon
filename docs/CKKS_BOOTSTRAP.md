# Poseidon 新版 CKKS Bootstrap 使用与参数配置指南

本文说明 Poseidon 当前新版 CKKS Bootstrap 的使用方法、参数含义、模数链布局、
输入输出约束和调参方法。这里的“新版”特指下面这个接口：

```cpp
EvaluatorCkksBase::bootstrap(
    const Ciphertext &input,
    Ciphertext &output,
    const RelinKeys &relin_keys,
    const GaloisKeys &galois_keys,
    const CKKSEncoder &encoder,
    const BootstrapConfig &config);
```

对应实现位于：

- [`src/poseidon/evaluator/evaluator_ckks_base.h`](../src/poseidon/evaluator/evaluator_ckks_base.h)
- [`src/poseidon/evaluator/evaluator_ckks_base.cpp`](../src/poseidon/evaluator/evaluator_ckks_base.cpp)
- [`src/poseidon/advance/bootstrapper.h`](../src/poseidon/advance/bootstrapper.h)
- [`src/poseidon/advance/bootstrapper.cpp`](../src/poseidon/advance/bootstrapper.cpp)

旧版 `EvalModPoly` 接口仍然保留，但它的参数体系、模数链配置和输出处理方式与
新版不同。除非正在维护旧代码，否则新程序建议使用 `BootstrapConfig` 接口。

## 1. 新版 Bootstrap 做了什么

新版 Bootstrap 在一次调用中完成：

```text
输入密文准备
    │
    ├─ 对齐到 q0/message_ratio 所要求的 scale
    ├─ 降到单素数 q0 层
    │
    ▼
ModRaise
    │
    ▼
CoeffToSlot
    ├─ real slots
    └─ imag slots
    │
    ▼
EvalMod
    ├─ real EvalMod
    └─ imag EvalMod
    │
    ▼
SlotToCoeff
    │
    ├─ 可选实数投影
    └─ 恢复 message ratio
    │
    ▼
输出密文
```

默认参数对应当前的 14-level Bootstrap 配置。这里的“14-level”是指从
ModRaise 后的完整模数链顶部开始，到 Bootstrap 输出为止，默认配置预计消耗
14 个模数层级。应用如果还要统一输出 scale，通常需要再执行一次
`multiply_const + rescale`，额外消耗一个计算层级。

## 2. 使用前必须满足的条件

### 2.1 CKKS 参数

当前已验证的基线配置是：

```text
logN                = 16
log_slots           = 15
normal log_scale    = 46
q0_level            = 0
q0                  = 51-bit 单素数
bootstrap primes    = 14 × 51-bit
special prime P     = 1 × 51-bit
```

其中：

- `q0_level=0` 非常重要，它表示 q0 只由 `Q[0]` 一个素数组成；
- 新版 `ModRaise` 明确要求输入位于单素数 q0；
- 14 个 51-bit Bootstrap 素数放在 Q 链末尾；
- q0 与 Bootstrap 素数之间可以放置应用需要的 46-bit 计算素数；
- `P={51}` 用于 key switching、rotation 和 relinearization。

### 2.2 密文条件

传入 Bootstrap 的密文必须满足：

- 是当前 `PoseidonContext` 创建的合法 CKKS 密文；
- 密文 `size()==2`；
- 密文 level 不低于 q0 level；
- scale 应接近或低于 `q0 / 2^log_message_ratio`；
- 数据范围必须落在当前 EvalMod 近似所能覆盖的范围内；
- 已生成 relinearization keys 和足够的 Galois keys。

如果密文经过了密文乘密文而没有 relinearize，密文通常会变成 size 3，必须先执行：

```cpp
evaluator->relinearize(input, input, relin_keys);
```

如果使用 `multiply_relin` 或 `multiply_relin_dynamic`，结果通常已经恢复为 size 2。

## 3. 推荐的模数链布局

Q 链按下面的顺序传给 `set_log_modulus()`：

```text
低 level                                                     高 level
Q[0]          Q[1 ... compute_count]         trailing Bootstrap primes
51-bit q0     46-bit application primes      14 × 51-bit
```

可以用下面的函数生成：

```cpp
std::vector<std::uint32_t>
make_bootstrap_modulus_chain(std::size_t compute_prime_count)
{
    constexpr std::uint32_t q0_bits = 51;
    constexpr std::uint32_t compute_bits = 46;
    constexpr std::uint32_t bootstrap_bits = 51;
    constexpr std::size_t bootstrap_prime_count = 14;

    std::vector<std::uint32_t> chain;
    chain.reserve(1 + compute_prime_count + bootstrap_prime_count);
    chain.push_back(q0_bits);
    chain.insert(chain.end(), compute_prime_count, compute_bits);
    chain.insert(chain.end(), bootstrap_prime_count, bootstrap_bits);
    return chain;
}
```

例如：

```cpp
// q0 + 20 个应用计算素数 + 14 个 Bootstrap 素数
auto log_q = make_bootstrap_modulus_chain(20);
```

`compute_prime_count` 不是 Bootstrap 固定参数。它取决于：

- Bootstrap 之前需要保留多少计算深度；
- Bootstrap 之后还要运行多少卷积或多项式；
- 是否需要额外做输出 scale 归一化；
- 下一次 Bootstrap 之前需要消耗多少层。

最小功能示例只需要：

```text
1 × q0 + 1 × compute prime + 14 × Bootstrap prime
```

但这种配置在 Bootstrap 后几乎没有后续计算空间，不适合作为完整应用参数。

## 4. 最小完整示例

下面的示例展示 context、keys、输入密文和新版 Bootstrap 的完整初始化过程。

```cpp
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace poseidon;

std::vector<std::uint32_t> bootstrap_chain()
{
    std::vector<std::uint32_t> chain;
    chain.push_back(51);                 // 单素数 q0
    chain.insert(chain.end(), 1, 46);   // 示例保留一个计算层
    chain.insert(chain.end(), 14, 51);  // 14-level Bootstrap
    return chain;
}

int main()
{
    constexpr std::uint32_t log_n = 16;
    constexpr std::uint32_t log_slots = 15;
    constexpr std::uint32_t log_scale = 46;
    constexpr std::uint32_t hamming_weight = 5;
    constexpr std::uint32_t q0_level = 0;

    ParametersLiteral parameters{
        CKKS,
        log_n,
        log_slots,
        log_scale,
        hamming_weight,
        q0_level,
        0,
        {},
        {}
    };
    parameters.set_log_modulus(bootstrap_chain(), {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context =
        PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, keygen.secret_key());
    Decryptor decryptor(context, keygen.secret_key());

    std::vector<std::complex<double>> source(encoder.slot_count());
    for (std::size_t i = 0; i < source.size(); ++i)
    {
        source[i] = std::sin(static_cast<double>(i) / 32.0);
    }

    Plaintext plain;
    encoder.encode(source, parameters.scale(), plain);

    Ciphertext input;
    encryptor.encrypt(plain, input);

    BootstrapConfig config;
    config.boundary_k = 25;
    config.log_message_ratio = 5;
    config.double_angle = 2;
    config.scaling_log = 51;
    config.output_ratio = 32;
    config.project_real = true;
    config.inverse_coeff = 0.0;

    Ciphertext output;
    evaluator->bootstrap(
        input,
        output,
        relin_keys,
        galois_keys,
        encoder,
        config);

    Plaintext output_plain;
    std::vector<std::complex<double>> decoded;
    decryptor.decrypt(output, output_plain);
    encoder.decode(output_plain, decoded);

    std::cout << "input[0]  = " << source[0] << '\n';
    std::cout << "output[0] = " << decoded[0] << '\n';
    std::cout << "output level = " << output.level() << '\n';
    std::cout << "output scale = " << output.scale() << '\n';
}
```

仓库中可以直接运行的版本位于：

```text
examples/ckks/test_ckks_bootstrap.cpp
```

构建和运行：

```bash
cmake -S . -B build
cmake --build build --target test_ckks_bootstrap -j2
./build/bin/test_ckks_bootstrap --new
```

注意：不带 `--new` 时，示例默认运行的是旧版 Bootstrap。

在项目内部增加新的可执行程序时，可以沿用现有 CMake 链接方式：

```cmake
add_executable(my_ckks_bootstrap my_ckks_bootstrap.cpp)
target_link_libraries(my_ckks_bootstrap poseidon_shared)
```

## 5. `BootstrapConfig` 参数详解

默认定义如下：

```cpp
struct BootstrapConfig
{
    std::uint32_t boundary_k = 25;
    std::uint32_t log_message_ratio = 5;
    std::uint32_t double_angle = 2;
    std::uint32_t scaling_log = 51;
    std::uint32_t output_ratio = 32;
    bool project_real = true;
    double inverse_coeff = 0.0;
    std::string cosine_heap_path;
};
```

### 5.1 `boundary_k`

默认值：

```cpp
config.boundary_k = 25;
```

作用：

- 控制 CoeffToSlot 阶段的边界归一化；
- 参与 FFT/逆 FFT 线性变换系数的缩放；
- 决定送入 EvalMod 多项式的归一化范围。

设置原则：

- 当前嵌入式 cosine heap 与 `boundary_k=25` 是已验证组合；
- 输入值范围较小时优先保持 25；
- 增大它通常可以容纳更大的输入范围，但会压缩有效信号，可能降低有效精度；
- 设置过小可能使部分 slot 超出 EvalMod 有效区间，出现明显误差、离群点或 NaN。

代码要求：

```text
boundary_k > 0
```

在没有重新做全 slot 误差测试之前，不建议仅凭输入最大值随意修改。

### 5.2 `log_message_ratio`

默认值：

```cpp
config.log_message_ratio = 5;
```

实际 message ratio 为：

```text
message_ratio = 2^log_message_ratio = 32
```

它用于：

- 计算 Bootstrap 输入在 q0 层的目标 scale：

  ```text
  target input scale ≈ q0 / message_ratio
  ```

- 计算 ModRaise 后进入 EvalMod 前的 scale 调整；
- 配合 `output_ratio` 恢复输出幅值。

当前基线中：

```text
q0 ≈ 2^51
message_ratio = 2^5
q0/message_ratio ≈ 2^46
```

这正好与应用的常规 CKKS scale `2^46` 对齐。

因此推荐保持下面的关系：

```text
q0_bits - log_message_ratio ≈ normal_log_scale
```

默认配置就是：

```text
51 - 5 = 46
```

代码要求：

```text
log_message_ratio < 31
```

如果修改该值，通常也要同时检查：

- q0 bit 数；
- 应用常规 `log_scale`；
- `output_ratio`；
- EvalMod 输入范围和最终误差。

### 5.3 `double_angle`

默认值：

```cpp
config.double_angle = 2;
```

EvalMod 先计算 cosine/Chebyshev 近似，再通过重复的 double-angle 恢复目标函数。
每轮大致执行：

```text
y <- 2*y*y - c
```

影响：

- double-angle 越多，EvalMod 的乘法深度和 level 消耗越高；
- 同时会改变 inverse coefficient 的计算；
- 与 cosine heap 的近似目标、精度和稳定性相关。

代码要求：

```text
double_angle < 31
```

当前 14-level 配置是围绕 `double_angle=2` 调好的。修改它之后不能再假设仍然只消耗
14 层，必须实际测量：

```cpp
const auto raised_level =
    context.crt_context()->first_context_data()->level();
const auto consumed = raised_level - output.level();
```

### 5.4 `scaling_log`

默认值：

```cpp
config.scaling_log = 51;
```

EvalMod 内部目标 scale 为：

```text
eval_mod_scale = 2^scaling_log
```

它主要影响：

- CoeffToSlot 输出进入 EvalMod 前的 scale；
- Chebyshev 多项式求值时的数值精度；
- rescale 时与 Bootstrap 素数的匹配关系。

推荐：

```text
scaling_log ≈ Bootstrap prime bit size
```

当前 Bootstrap 素数为 51-bit，因此使用 `scaling_log=51`。

设置过大可能触发 scale 越界或快速耗尽噪声预算；设置过小则可能明显损失精度。

代码要求：

```text
scaling_log < 63
```

### 5.5 `output_ratio`

默认值：

```cpp
config.output_ratio = 32;
```

它用于补偿 Bootstrap 输入准备阶段使用的 message ratio。通常设置为：

```text
output_ratio = 2^log_message_ratio
```

默认配置中：

```text
output_ratio = 32 = 2^5
```

当 `project_real=true` 时，内部先计算：

```text
output + conjugate(output) = 2 * Re(output)
```

随后实际乘以：

```text
output_ratio / 2
```

两者合起来仍然恢复完整的 `output_ratio`。

代码要求：

- `output_ratio > 0`；
- 当 `project_real=true` 时，`output_ratio` 必须为偶数。

如果输出整体相差固定的 2、16、32 倍，应优先检查这个参数与
`log_message_ratio` 是否匹配。

### 5.6 `project_real`

默认值：

```cpp
config.project_real = true;
```

当它为 `true` 时，Bootstrap 内部执行实数投影：

```text
Re(x) = (x + conjugate(x)) / 2
```

适用场景：

- 神经网络；
- 实数统计计算；
- 所有 slot 理论上都只承载实数的应用。

设置为 `false`：

- 保留复数结果；
- 不执行共轭投影；
- `output_ratio` 不再要求是偶数。

不要在 Bootstrap 外部再次对已经 `project_real=true` 的结果执行同样的实数投影，
否则会增加无意义的旋转、乘法和 level 消耗。

### 5.7 `inverse_coeff`

默认值：

```cpp
config.inverse_coeff = 0.0;
```

当值不大于 0 时，Bootstrapper 会根据 cosine heap 根多项式和
`double_angle` 自动计算 inverse coefficient。

推荐：

- 使用内嵌 cosine heap 时保持 `0.0`；
- 只有使用自定义多项式、且已经离线计算并验证修正系数时，才手动指定正数；
- 错误的值会造成 EvalMod 输出的系统性比例或偏移误差。

### 5.8 `cosine_heap_path`

默认值为空：

```cpp
config.cosine_heap_path.clear();
```

空路径表示使用编译进 `bootstrapper.cpp` 的默认 cosine heap。

指定路径时：

```cpp
config.cosine_heap_path = "/absolute/path/to/cosine_heap.txt";
```

文件使用纯空白分隔格式：

```text
heap_node_count
node_index degree
c0
c1
...
c_degree
node_index degree
...
```

例如一个仅用于展示格式的简化文件：

```text
3
0 2
0.1
0.2
0.3
1 1
0.4
0.5
2 1
0.6
0.7
```

注意：

- 系数是 Chebyshev basis 系数，不是普通 monomial basis；
- 节点索引按二叉 heap 布局；
- 根节点必须有效；
- 文件目前不支持注释语法；
- 自定义 heap 必须与 `boundary_k`、`double_angle` 和目标函数共同生成；
- 仅仅换一组普通 cosine 多项式系数通常不能正确工作。

外部 heap 按路径在进程内缓存。同一个路径第一次读取后，即使运行期间修改文件，
后续 Bootstrap 也不会自动重新加载；调试新系数时应重启进程或使用新路径。

高级用户在替换 heap 后，至少应重新测量最大误差、RMSE、level 消耗和不同输入范围。

## 6. 推荐配置组合

### 6.1 当前已验证基线

```cpp
BootstrapConfig config;
// 全部使用默认值
```

等价于：

```cpp
config.boundary_k = 25;
config.log_message_ratio = 5;
config.double_angle = 2;
config.scaling_log = 51;
config.output_ratio = 32;
config.project_real = true;
config.inverse_coeff = 0.0;
config.cosine_heap_path.clear();
```

对应参数：

```text
normal scale       = 2^46
q0                 = 51-bit
Bootstrap primes   = 14 × 51-bit
P                  = 51-bit
real-valued slots  = yes
```

### 6.2 保留复数输出

```cpp
BootstrapConfig config;
config.project_real = false;
config.output_ratio = 32;
```

这种配置适用于 slot 的虚部有实际语义的程序。需要用复数输入同时验证实部和虚部误差。

### 6.3 修改常规 CKKS scale

如果要把常规 scale 从 `2^46` 改为 `2^s`，优先保持：

```text
q0_bits - log_message_ratio ≈ s
```

例如理论上：

```text
q0_bits=51, log_message_ratio=6 -> normal scale≈2^45
```

但这不是只改一个参数就能保证工作的配置。还必须检查：

- 46-bit 计算素数是否也需要调整；
- `scaling_log=51` 是否仍与 Bootstrap primes 匹配；
- `output_ratio` 是否改为 64；
- cosine heap 的误差是否仍可接受；
- 总 level 消耗是否变化。

生产代码中建议先保持 `2^46/51-bit/32` 基线，只对应用计算层数量做调整。

## 7. 输入 scale 和 level 的处理

新版接口内部会：

1. 读取输入的 `q0_level`；
2. 如果输入高于 `q0+1`，直接 drop 到 `q0+1`；
3. 计算：

   ```text
   q0_over_message_ratio =
       nearest_power_of_two(q0 / 2^log_message_ratio)
   ```

4. 当输入 scale 较小时，通过整数常数乘法把 scale 提高到目标附近；
5. drop 到 q0；
6. 执行 ModRaise。

因此调用者通常不需要手动 drop 到 q0。

但当前新版路径不会像旧版那样主动反复 rescale 一个过大的输入 scale。推荐在调用前
确保：

```text
input.scale() ≈ 2^46
q0/message_ratio ≈ 2^46
```

调试时可以打印：

```cpp
auto data =
    context.crt_context()->get_context_data(input.parms_id());

std::cout << "input level = " << input.level() << '\n';
std::cout << "input chain index = " << data->chain_index() << '\n';
std::cout << "input scale = " << input.scale() << '\n';
std::cout << "input size = " << input.size() << '\n';
```

Bootstrap 会主动丢弃 q0 以上尚未使用的 level，因此调用时机也很重要。一般应在
应用计算已经接近 q0、确实需要刷新密文时调用；如果密文仍处在很高的计算 level，
提前 Bootstrap 会直接浪费剩余层级。

一次 Bootstrap 完成后，输出回到 Bootstrap 素数之下、计算素数区域的高处。应用可以
继续消耗计算素数，接近 q0 后再次调用 Bootstrap。只要每轮的输入 size、scale 和值域
仍满足要求，同一套 context、relinearization keys 和 Galois keys 可以重复使用。

## 8. Bootstrap 输出 scale 归一化

新版 Bootstrap 的首要目标是刷新密文和恢复明文值，不保证输出 scale 恰好等于应用的
常规 scale。ResNet18 和 ResNet50 在 Bootstrap 后额外执行一次归一化。

可以使用下面的辅助函数：

```cpp
void normalize_bootstrap_output_scale(
    const PoseidonContext &context,
    EvaluatorCkksBase &evaluator,
    const CKKSEncoder &encoder,
    Ciphertext &cipher)
{
    const double target_scale =
        context.parameters_literal()->scale();

    const double relative_error =
        std::abs(cipher.scale() / target_scale - 1.0);
    if (relative_error <= 1.0e-3)
    {
        return;
    }

    auto context_data =
        context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data ||
        context_data->coeff_modulus().size() <= 1)
    {
        throw std::invalid_argument(
            "no level available for Bootstrap scale normalization");
    }

    const double q_last =
        static_cast<double>(
            context_data->coeff_modulus().back().value());
    const double plain_scale =
        target_scale * q_last / cipher.scale();

    if (!std::isfinite(plain_scale) || plain_scale < 1.0)
    {
        throw std::invalid_argument(
            "invalid Bootstrap scale normalization factor");
    }

    Ciphertext normalized;
    evaluator.multiply_const(
        cipher, 1.0, plain_scale, normalized, encoder);
    evaluator.rescale(normalized, normalized);

    const double normalized_error =
        std::abs(normalized.scale() / target_scale - 1.0);
    if (normalized_error > 1.0e-3)
    {
        throw std::runtime_error(
            "failed to normalize Bootstrap output scale");
    }

    normalized.scale() = target_scale;
    cipher = std::move(normalized);
}
```

这个操作会消耗一个额外 level，所以模数链中必须给它留出空间。

如果 Bootstrap 后只立刻解密，不再做同态计算，可以不归一化，只要使用密文自身记录的
scale 正常解码即可。

## 9. 如何验证一组参数

不要只查看前几个 slot。至少检查全部 slots 的：

- 最大绝对误差；
- 最大误差所在 slot；
- mean absolute error；
- RMSE；
- 输出实部范围；
- 输出虚部范围；
- Bootstrap 消耗层数；
- 输出 scale；
- 是否出现 NaN 或 infinity。

示例误差统计：

```cpp
double max_error = 0.0;
double squared_error_sum = 0.0;
std::size_t max_error_slot = 0;

for (std::size_t i = 0; i < expected.size(); ++i)
{
    const double error = std::abs(actual[i] - expected[i]);
    squared_error_sum += error * error;
    if (error > max_error)
    {
        max_error = error;
        max_error_slot = i;
    }
}

const double rmse =
    std::sqrt(squared_error_sum /
              static_cast<double>(expected.size()));
```

建议至少使用这些输入分布：

1. `[-1, 1]` 均匀随机实数；
2. 正弦序列；
3. 接近应用真实上界的数据；
4. 正负边界附近的数据；
5. 稀疏输入和全零输入；
6. 当 `project_real=false` 时，随机复数输入。

应用层最好设置明确的误差阈值并返回非 0，而不是只打印误差。

## 10. 调参顺序

推荐按下面顺序调试，避免一次修改多个互相耦合的参数。

### 第一步：固定已知可工作的 Bootstrap 参数

```text
boundary_k        = 25
log_message_ratio = 5
double_angle      = 2
scaling_log       = 51
output_ratio      = 32
project_real      = true
inverse_coeff     = auto
```

只调整应用需要的 46-bit 计算素数数量。

### 第二步：检查输入状态

确认：

```text
size              = 2
scale             ≈ 2^46
q0_level          = 0
Q[0]              = 51-bit
trailing primes   = 14 × 51-bit
```

### 第三步：检查值域

在 Bootstrap 前解密调试样本，记录所有 slots 的最大绝对值。若只有少量离群点，
应先检查前序算子的 scale、mask 或 batch normalization，而不是立即增大
`boundary_k`。

### 第四步：测量 level 和误差

记录：

```cpp
const auto top_level =
    context.crt_context()->first_context_data()->level();
const auto consumed_levels = top_level - output.level();
```

默认应以 14-level 为目标。如果修改 `double_angle`、cosine heap 或 scale 后层数发生
变化，需要同步修改模数链预算。

### 第五步：一次只修改一个参数

推荐优先级：

1. `boundary_k`；
2. `log_message_ratio` 和 `output_ratio` 成对修改；
3. `scaling_log` 与 Bootstrap prime bits 成对修改；
4. `double_angle`；
5. 自定义 cosine heap 和 `inverse_coeff`。

后两项属于算法级调参，不建议作为普通应用配置。

## 11. 常见错误

### 11.1 `supports size-2 ciphertexts only`

原因：输入密文没有 relinearize。

处理：

```cpp
evaluator->relinearize(input, input, relin_keys);
```

### 11.2 `expects the ciphertext at single-prime q0 level`

常见原因：

- `q0_level` 不是 0；
- 模数链的 q0 由多个素数组成；
- 手动调用 `Bootstrapper::mod_raise()` 时没有先降到 q0。

新版公开 `evaluator->bootstrap()` 会自动降到 q0，但 context 本身仍必须配置
`q0_level=0`。

### 11.3 `bootstrap input is below q0 level`

输入已经消耗到了 context 所定义 q0 以下，无法再执行 Bootstrap。检查模数链、
`q0_level` 和前序 rescale 次数。

### 11.4 `scale out of bounds`

检查：

- 输入 scale 是否远大于 `q0/message_ratio`；
- `scaling_log` 是否大于 Bootstrap prime bits；
- 是否重复手动修改了 `cipher.scale()`；
- Q 链是否缺少 51-bit Bootstrap 素数。

### 11.5 rotation/Galois key 错误

当前最稳妥的方式是生成全部 Galois keys：

```cpp
keygen.create_galois_keys(galois_keys);
```

CoeffToSlot 和 SlotToCoeff 使用多组 BSGS rotation。只生成应用卷积所需的少量 rotation
keys，通常不足以支持 Bootstrap。

### 11.6 输出整体差固定倍数

优先检查：

```text
output_ratio == 2^log_message_ratio
```

还要确认 `project_real` 是否与输入数据类型一致，以及外部是否重复做了实数投影。

### 11.7 少数 slot 误差特别大

检查：

- Bootstrap 前的最大绝对值和离群点；
- `boundary_k` 是否覆盖真实值域；
- 前序密文的 scale 和 level 是否一致；
- 是否把无效 padding slot 也作为有效数据比较；
- 自定义 cosine heap 是否与当前参数匹配。

### 11.8 找不到 cosine heap

当 `cosine_heap_path` 非空时，路径由运行程序的进程直接打开。建议使用绝对路径。
不需要自定义系数时保持空字符串即可。

## 12. 性能和内存注意事项

### 12.1 线性变换系数会重复生成

当前 `EvaluatorCkksBase::bootstrap()` 每次调用都会：

1. 构造新的 `Bootstrapper`；
2. 生成原始 FFT 系数；
3. 生成 CoeffToSlot 系数；
4. 生成 SlotToCoeff 系数。

因此在 ResNet 一类需要执行几十次 Bootstrap 的程序中，会存在重复的 CPU 和内存开销。
当前接口还没有暴露可复用的预计算 Bootstrap context。

### 12.2 当前是 full-slot Bootstrap

`Bootstrapper` 直接使用 context 的：

```text
log_slots
slots = 2^log_slots
```

目前没有独立的 partial-slot 或按 stage 设置 `bootstrap_log_slots` 的公开参数。即使某个
网络 stage 只使用部分 slots，也仍按完整 slot 数生成和执行线性变换。

### 12.3 Evaluation keys 较大

生成全部 Galois keys 会占用较多时间和内存，但这是当前最简单可靠的 Bootstrap
初始化方式。若要裁剪 rotation keys，需要先从三段 BSGS 变换中完整收集所有旋转步长，
再做功能回归测试。

### 12.4 软件后端

当前示例和 Trident 接入都显式使用：

```cpp
PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
```

因此本文参数首先代表软件 evaluator 上的已知配置。切换其他后端前应重新验证其对
ModRaise、rotation、relinearization、透明密文和 scale 对齐的支持。

## 13. 新旧接口不要混用

旧版接口：

```cpp
EvalModPoly eval_mod_poly(...);
evaluator->bootstrap(
    input, output,
    relin_keys, galois_keys, encoder,
    eval_mod_poly);
```

旧版高精度接口：

```cpp
evaluator->bootstrap_high_precision(
    input, output,
    relin_keys, galois_keys, encoder,
    eval_mod_poly);
```

新版接口：

```cpp
BootstrapConfig config;
evaluator->bootstrap(
    input, output,
    relin_keys, galois_keys, encoder,
    config);
```

主要差异：

| 项目 | 旧版 | 新版 |
|---|---|---|
| 配置对象 | `EvalModPoly` | `BootstrapConfig` |
| 线性变换 | `HomomorphicDFTMatrixLiteral` | `Bootstrapper` 内部三段 BSGS |
| EvalMod | `evaluate_poly_vector` | cosine heap baby-step/giant-step |
| 高精度入口 | 单独函数 | 新版默认路径 |
| 实数投影 | 通常由应用额外完成 | `project_real=true` 时内部完成 |
| q0 | 旧例子可使用合并 q0 | 新版要求单素数 q0 |
| 默认目标 | 旧兼容路径 | 14-level 新路径 |

不要把旧版 `EvalModPoly` 参数直接翻译成同名的新版参数，也不要在新版
`project_real=true` 后照搬旧应用的外部实数投影。

## 14. 生产使用检查清单

调用 Bootstrap 前：

- [ ] 使用 CKKS；
- [ ] `q0_level=0`；
- [ ] `Q[0]` 是 51-bit 单素数；
- [ ] Q 链末尾有 14 个 51-bit Bootstrap 素数；
- [ ] P 链包含 51-bit special prime；
- [ ] 正常计算 scale 为 `2^46`；
- [ ] 输入密文 `size()==2`；
- [ ] 输入 scale 接近 `2^46`；
- [ ] 已生成 relinearization keys；
- [ ] 已生成 Bootstrap 所需的 Galois keys；
- [ ] 输入全 slot 值域已经测量；
- [ ] 使用默认 `BootstrapConfig` 建立基线。

调用 Bootstrap 后：

- [ ] 检查输出 level；
- [ ] 检查输出 scale；
- [ ] 检查全部 slots 的最大误差和 RMSE；
- [ ] 检查虚部是否符合 `project_real` 预期；
- [ ] 后续需要计算时执行输出 scale 归一化；
- [ ] 为归一化额外预留一个 level；
- [ ] 把误差阈值加入自动测试。

## 15. 安全参数说明

本文给出的 `logN=16` 和较长 Q 链来自当前功能实现与神经网络接入配置。总模数位数、
secret key hamming weight、special primes 和安全级别之间需要单独进行安全评估。

示例代码主要用于验证 Bootstrap 功能和精度，不应把“示例能够运行”等同于某个具体
安全等级已经得到证明。生产部署时应根据目标安全级别重新核算完整参数集。
