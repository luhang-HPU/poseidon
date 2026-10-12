# test_ckks_bootstrap_cmp.cpp 说明文档

本文档描述 [`examples/ckks/test_ckks_bootstrap_cmp.cpp`](../examples/ckks/test_ckks_bootstrap_cmp.cpp)
的功能、代码结构、各函数职责，以及修改参数时的入口位置。

该测试用于对比 `evaluator_ckks_base.h` 中两个 CKKS Bootstrap 实现的性能与精度：

| 接口 | 版本 | 实现路径 |
|------|------|----------|
| `bootstrap(..., EvalModPoly&)` | 旧版 | `bootstrap_core` 内联流水线（lattigo 风格） |
| `bootstrap(..., BootstrapConfig&)` | 新版 | `Bootstrapper` 类（HEAAN 风格 + cosine-heap 组合求值） |

## 1. 功能概述

在**完全相同**的 `ParametersLiteral`、模数链、密钥、编码方式与输入密文下，测量 4 个变体：

| 变体 | 说明 |
|------|------|
| `new/59 (heap)` | 新版接口，使用编译进 `bootstrapper.cpp` 的内嵌 cosine heap（根多项式 59 阶，`cosine_heap_path` 留空） |
| `old/59` | 旧版接口，`EvalModPoly` 拟合阶数 `sine_degree = 59` |
| `old/30` | 旧版接口，`sine_degree = 30`（`k = 16`） |
| `old/22` | 旧版接口，`sine_degree = 22`（`k = 12`） |

每个变体重复执行 3 次（`kRepeats`），每次测量：

- **性能**：bootstrap 调用的墙钟时间（只计 bootstrap 本身，不含编码/加密/解密）、消耗模数层数（输入 level − 输出 level）、输出 scale；
- **精度**：解密解码后与原始消息逐 slot 比较，统计 max abs error、rmse，并换算精度 bits（`log2(1/err)`）。

汇总表取 3 次中**时间中位数**那次的结果（同进程内误差指标是确定的，跨进程因密钥随机有微小波动）。

共享配置（四个变体唯一允许不同的是 bootstrap 配置）：

```text
ParametersLiteral{CKKS, 15, 14, 40, 1, 0, 0, {}, {}}   // log_scale = 40 → parameters.scale() = 2^40
q 链 = 20 × 51-bit 素数，p 链 = 1 × 60-bit（BV key switching）
N = 2^15，slots = 2^14，encode 使用 parameters.scale()（2^40）
确定性消息 sin(0.7·i + 0.3)，同一份新鲜加密的输入密文供所有变体共用
```

程序头部会把上述配置**从结构体实测读回并打印**（`print_header`），所以打印内容永远与实际运行一致，不会因改参数而失真。

## 2. 构建与运行

```bash
# 构建（仓库根目录，软件版配置）
cmake --build build --target test_ckks_bootstrap_cmp -j

# 运行
./build/bin/test_ckks_bootstrap_cmp
```

- 全程约 5–6 分钟（密钥生成约 1.5 分钟 + 12 次 bootstrap，每次约 20–35 s，参考 128 核服务器实测）；
- 长时间运行建议 nohup 后台 + 轮询日志：`nohup ./test_ckks_bootstrap_cmp > run.log 2>&1 &`；
- 单个变体抛异常（如层数耗尽）只会以 `FAILED` 记入汇总表，不影响其余变体。

## 3. 代码结构与函数介绍

### 3.1 数据结构

| 结构 | 字段 | 用途 |
|------|------|------|
| `ErrorStats` | `max_error`, `rmse` | 一次解码的误差统计 |
| `RunResult` | `seconds`, `input_level`, `output_level`, `consumed_levels`, `output_scale_log2`, `max_error`, `rmse` | 一次 bootstrap 的全部测量指标（只存原始测量，精度 bits 在打印时现算） |
| `Variant` | `version`, `sine_degree`, `tag`, `name` | 一个对比点：`version` 0=旧版 / 1=新版；`tag` 用于逐次打印、`name` 用于汇总表 |
| `Result` | `ok`, `note`, `median` | 一个变体的聚合结果；失败时 `note` 存异常信息 |
| `TestEnvironment` | `context`, `evaluator`, `relin_keys`, `galois_keys`, `encoder`, `decryptor`, `input`, `source` | 四个变体共享的全部环境（context/密钥/编解码器/共享输入密文/明文消息）；`encoder`/`decryptor` 用 `unique_ptr` 持有（不可默认构造） |
| `VariantSpec` | `meta`, `eval_mod_poly`, `bootstrap_config` | 变体元信息 + 预构建好的 bootstrap 配置（旧版用 `eval_mod_poly`，新版用 `bootstrap_config`） |

### 3.2 函数

| 函数 | 职责 |
|------|------|
| `setup_environment()` | 搭建共享环境：`ParametersLiteral`、模数链、context、evaluator、密钥、encoder/decryptor、确定性消息、encode（用 `parameters.scale()`）+ encrypt 生成唯一的共享输入密文。`Encryptor`/`KeyGenerator` 只在此函数局部存在 |
| `fitting_k(sine_degree)` | 拟合阶数 → k 的映射：`≥48 → k=25`，否则 `k=(degree+2)/2`。保证 `2k−1 ≥ degree+1` 且小阶数不被 `gen_degrees` 静默抬高（见 4.5 节约束） |
| `make_eval_mod_poly(context, sine_degree)` | 旧版配置工厂：构造 `EvalModPoly(context, CosDiscrete, sf=2^51, level_start=1, log_message_ratio=7, double_angle=3, k, arcsine=0, sine_degree)` |
| `make_bootstrap_config()` | 新版配置工厂：返回 `BootstrapConfig`（boundary_k=25, ratio 2^5, da=2, scaling_log=51, output_ratio=32, project_real=false，内嵌 heap） |
| `make_variant_specs(context)` | 变体表 + 批量预构建：把 4 个 `Variant` 与各自配置组装成 `VariantSpec` 列表。`EvalModPoly` 内部的 GMP 高精度插值每个变体只执行一次，且在计时区之外 |
| `calculate_error(actual, expected)` | 逐 slot 误差统计 → `ErrorStats` |
| `median_of(runs)` | 按 `seconds` 排序取中位数的 `RunResult` |
| `run_once(bootstrap_call, input, decryptor, encoder, source)` | 测量一次 bootstrap 调用：计时 → 记 level/scale → 解密解码 → 误差统计。无打印、无配置构造，纯测量 |
| `run_variant(spec, env)` | 把 `spec` 中预构建的配置绑定到共享 evaluator/密钥（封装成 lambda），重复 `kRepeats` 次并聚合出 `Result` |
| `run_all_variants(specs, env)` | 顺序运行全部变体，逐个 try/catch，失败的记为 `FAILED` 不中断其他变体 |
| `scheme_name(scheme)` | `SchemeType` → 字符串（打印用） |
| `describe_modulus_chain(chain)` | 模数链摘要：按 `Modulus::bit_count()` 分组连续同位数素数，如 `20 x 51`、`1 x 60 + 21 x 40` |
| `print_header(env, specs)` | 打印头部。所有数据**实时读回**自 `ParametersLiteral`（经 `env.context.parameters_literal()`）、旧路径的 `EvalModPoly` 访问器（`scaling_factor()/message_ratio()/double_angle()/k()/sc_fac()`）与 `BootstrapConfig` 字段 |
| `print_run(tag, rep, r)` | 打印单次运行的进度行（nohup 轮询日志用） |
| `print_summary(specs, results)` | 打印最终对比表，精度 bits 在此现算 |
| `main()` | 只含主逻辑步骤：日志级别 → 搭环境 → 构建变体配置 → 打印头部 → 运行全部变体 → 打印汇总表 |

### 3.3 调用流程

```text
main
 ├─ setup_environment()                // 参数、context、密钥、共享输入密文
 ├─ make_variant_specs(context)        // 变体表 + 预构建 EvalModPoly / BootstrapConfig
 ├─ print_header(env, specs)           // 从结构体读回配置并打印
 ├─ run_all_variants(specs, env)
 │    └─ run_variant(spec, env) × 4    // try/catch 逐变体
 │         ├─ lambda 绑定 evaluator->bootstrap(...)
 │         └─ run_once(...) × kRepeats ──> print_run(...) 进度行
 │              └─ calculate_error(...)
 └─ print_summary(specs, results)      // 汇总对比表
```

## 4. 参数修改指南

### 4.1 共享参数 → `setup_environment()`

| 想改什么 | 位置 | 说明 |
|----------|------|------|
| scheme / log_n / log_slots / log_scale / hamming_weight / q0_level | `ParametersLiteral parameters{CKKS, 15, 14, 40, 1, 0, 0, {}, {}}` | 按构造参数顺序：scheme、log_n、log_slots、**log_scale**（决定 encode scale = `parameters.scale()` = 2^log_scale）、hamming_weight、q0_level |
| q 模数链 | `std::vector<uint32_t> log_q(20, 51)` | 每个元素是一个素数的位数。改长度即改层数预算（当前 59 阶旧版 da=3 实测最多耗 15 层，20 个素数够用） |
| p 模数链 | `parameters.set_log_modulus(log_q, {60})` 的第二个参数 | 特殊素数（key switching 用） |
| 测试消息 | `env.source[i] = std::sin(0.7*i + 0.3)` | 任意复数向量均可，注意幅值需落在 EvalMod 有效区间内（见 4.5） |
| encode scale | `env.encoder->encode(env.source, parameters.scale(), plain)` | 当前用 `parameters.scale()`；也可换固定值如 `1<<40`，但需满足 4.5 的约束 |

### 4.2 旧版路径参数 → `make_eval_mod_poly()`（及 `fitting_k()`）

`EvalModPoly` 构造参数顺序（`homomorphic_mod.h`）：

```cpp
EvalModPoly(context, CosDiscrete, /*scaling_factor*/ 2^51,
            /*level_start*/ 1, /*log_message_ratio*/ 7, /*double_angle*/ 3,
            /*k*/ fitting_k(sine_degree), /*arcsine_degree*/ 0, /*sine_degree*/ deg);
```

| 参数 | 当前值 | 含义 / 约束 |
|------|--------|-------------|
| `scaling_factor` | 2^51 | EvalMod 工作 scale，应 ≈ bootstrap 素数位数（51） |
| `level_start` | 1 | 起始层（`bootstrap_core` 内部会按实际密文重写，一般不用改） |
| `log_message_ratio` | 7 | 消息比例 2^7；必须满足 `q0 / 2^log_message_ratio ≥ encode scale`，当前 2^44 ≥ 2^40 ✓ |
| `double_angle` | 3 | cosine 之后的倍角迭代次数；每多 1 次多耗约 1 层、精度更好（本测试中 2→3 使 rmse 从 ~17.7 bits 提升到 ~21.6 bits） |
| `k` | 由 `fitting_k()` 决定 | cosine 拟合区间边界；必须与 `sine_degree` 匹配（见 4.5），一般不手动改 |
| `arcsine_degree` | 0 | 0 = 走 `sqrt_2pi` 校正的非 arcsine 路径 |
| `sine_degree` | 变体决定 | 拟合多项式阶数 |

### 4.3 新版路径参数 → `make_bootstrap_config()`

对应 `BootstrapConfig`（定义在 `evaluator_ckks_base.h`，字段含义详见 `docs/CKKS_BOOTSTRAP.md`）：

| 字段 | 当前值 | 含义 / 约束 |
|------|--------|-------------|
| `boundary_k` | 25 | **必须**与所用 cosine heap 的区间匹配（内嵌 heap 为 25） |
| `log_message_ratio` | 5 | 消息比例 2^5；新版入口有硬校验：`input scale > q0/2^ratio` 直接抛异常。当前 2^46 ≥ 2^40 ✓ |
| `double_angle` | 2 | 倍角次数 |
| `scaling_log` | 51 | EvalMod 目标 scale 的 log2，应 ≈ bootstrap 素数位数 |
| `output_scaling_log` | 0 | 0 = 保持 q0 派生的输出 scale（新版输出 ~2^51，旧版输出被归一到 `parameters.scale()` = 2^40） |
| `output_ratio` | 32 | 补偿本路径的 message ratio，应满足 `output_ratio = 2^log_message_ratio`；`project_real=true` 时必须为偶数 |
| `project_real` | false | 保持复数消息（纯刷新语义，与旧版对齐）；置 true 则做实数投影 |
| `inverse_coeff` | 0.0 | 0 = 由 heap 根多项式自动推导 |
| `cosine_heap_path` | `""` | 空 = 内嵌 59 阶 heap；也可指向 heap 文件（如 `examples/ckks/heap59.txt`、`heap22.txt`），格式见 `CKKS_BOOTSTRAP.md` |

### 4.4 对比变体集合 → `make_variant_specs()` 中的 `variants` 表

```cpp
const std::vector<Variant> variants = {
    {1, 59, "new/59", "new/59 (heap)"},
    {0, 59, "old/59", "old/59"},
    {0, 30, "old/30", "old/30"},
    {0, 22, "old/22", "old/22"},
};
```

每行是 `{version, sine_degree, 逐次打印 tag, 汇总表 name}`。增删变体直接改这张表（如加一个 `old/40`）；`version=1` 的变体 `sine_degree` 仅用于标签（内嵌 heap 固定 59）。

### 4.5 参数联动约束（改动前必读）

| 约束 | 原因 | 违反的后果 |
|------|------|-----------|
| `encode scale ≤ q0 / 2^log_message_ratio`（两条路径各自检查） | 两条路径在 ModRaise 前都只会**上调**输入 scale 到 `q0/ratio`，不会下调；新版入口（`evaluator_ckks_base.cpp` 的 `bootstrap`）直接拒绝超标的输入 | 新版抛异常；旧版静默跳过对齐、EvalMod 区间错位导致输出错误 |
| `2k − 1 ≥ sine_degree + 1`（旧版） | `cosine_approx.cpp` 的 `gen_degrees` 把实际拟合阶数下限钉在 `2k−1`，请求更低的阶数会被**静默抬高** | 例如固定 k=25 时请求 30/22 阶实际得到 48 阶拟合，对比失真。`fitting_k()` 已保证该约束，自定义阶数时注意 |
| `boundary_k` 与 cosine heap 区间一致（新版） | heap 多项式按固定区间预生成 | 超出区间的 slot 出现大误差/NaN |
| `output_ratio = 2^log_message_ratio`（新版） | 输入准备阶段按 ratio 缩放，输出需等比补偿 | 输出整体差固定倍数（如 2×/32×） |
| `scaling_factor` / `scaling_log` ≈ bootstrap 素数位数 | rescale 与素数的匹配关系 | 精度下降或 scale 越界 |
| 消息幅值落在 EvalMod 有效区间 | cosine/正弦拟合只在 `[-boundary, boundary]`（归一后）内有效 | 边界 slot 误差激增 |

改 `log_scale`（即 encode scale）是最敏感的改动：必须同步检查两条路径的 ratio 约束（4.2 与 4.3 的不等式），必要时同步调整 `log_message_ratio` 与 `output_ratio`。

## 5. 输出解读

头部（数据均实时读回，见 3.2 的 `print_header`）：

```text
=== CKKS bootstrap old/new comparison (4 variants) ===
common: {CKKS, 15, 14, 40, 1, 0}, q = 20 x 51, p = 1 x 60, N = 2^15, slots = 2^14
        encode 2^40 (= parameters.scale()), median of 3 runs
old: EvalModPoly sf = 2^51, ratio = 2^7, double_angle = 3, k = 25, sine_degree = 59/30/22
new: BootstrapConfig boundary_k = 25, ratio = 2^5, double_angle = 2, scaling_log = 51, output_ratio = 32, project_real = false
input ciphertext: level = 19, scale = 2^40.00
```

逐次运行行与汇总表列含义：

| 列 | 含义 |
|----|------|
| `time [s]` | 3 次的中位墙钟时间 |
| `used levels` | 输入 level（19，共 20 个素数）− 输出 level |
| `max abs error` / `rmse` | 全部 2^14 个 slot 的最大绝对误差 / 均方根误差 |
| `prec(rmse)` / `prec(max)` | `log2(1/rmse)` / `log2(1/max_error)`，单位 bits |
| `out scale`（逐次行） | 输出密文 scale：旧版被归一到 `parameters.scale()`，新版为 q0 派生（本配置 ≈ 2^51），两者语义不同，比较时注意 |

## 6. 最近一次实测（2026-09-16，172.16.61.103，Release，128 核）

配置即第 5 节头部所示（旧版 ratio 2^7 / da 3，新版 ratio 2^5 / da 2）：

```text
variant              time [s] used levels    max abs error         rmse  prec(rmse)   prec(max)
new/59 (heap)           32.37          14        5.075e-06    3.167e-06     18.27 b     17.59 b
old/59                  23.27          15        1.997e-06    3.219e-07     21.57 b     18.93 b
old/30                  22.60          14        1.977e-06    1.541e-07     22.63 b     18.95 b
old/22                  21.79          14        3.617e-05    3.788e-07     21.33 b     14.75 b
```

要点：该配置下旧版三个变体精度均反超新版（rmse 约 21–23 bits vs 18.3 bits），且 30/22 阶相对 59 阶几乎没有精度损失、时间更短；新版的优势场景需在两条路径参数对齐（同 ratio/同 da）时重新评估。注意本表两条路径的 ratio 与 double_angle 并不相同，属于"各自较优参数"的对比而非严格同配置对比。
