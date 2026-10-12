# CtS-first 实数单路自举：level=1 入口，22 阶 ×3

**系数精度更新（2026-09-28）：** 下文历史数据使用原来的“仅偶项”求值模式。
新发现离散拟合包含非零奇数项，可用 `poly.enable_full_cosine_coefficients()` 显式启用。
详见 [22 阶系数优化实验](../experiments/bootstrap_coeff22/README.md)。
历史 H=32 失败结果不能直接当作完整 22 阶多项式的能力上限。
当前 H=5 完整系数配置及 45-bit 链的结果统一见该实验文档；本页下半部分保留旧偶项
模式的历史结果，不代表完整系数模式的最新精度。

主仓库软件后端新增实验性接口 `EvaluatorCkksBase::bootstrap_real`。
它保留原 `EvalModPoly` 自举的低层入口和先升模顺序，不使用前置 StC，
也不改变原来的双路 `bootstrap` 路径。旧的前置 StC 实验接口（要求输入 level>=3）
及其独立测试已移除；当前实数单路统一使用本文的 `bootstrap_real`。

## 和 Helios 的关系

本地 `Helios.pdf` 第 3 页图 2 展示 ModRaise →（稀疏 SubSum）→ CtS → EvalMod → StC。
第 9 页说明其配置中满槽复数 CF 需要两次 EvalMod，其他配置只需要一次；
第 10 页表 8 包含 CF、real 的应用。

本文实现参考这个配置方向，但**不是 Helios 源代码移植或逐算法复现**。
论文没有给出实数 CF 的完整重构代码，也没有提供本实现的 22 阶参数。
下面的半系数重构是针对 Poseidon 的矩阵约定推导并验证的实现。
没有实现论文的 SSE 密钥封装、GPU 图改写或融合；稀疏秘密权重 H 不等于 SSE。

## 接口

```cpp
// 示例实验参数：N=65536，满槽，Q=20 个 51-bit 素数，P={60}，
// context.scale()=2^40。H 与安全参数需另外选择并评估。
EvalModPoly poly(context, CosDiscrete,
                 std::ldexp(1.0, 51), // EvalMod 工作 scale
                 1,                  // level_start 会由自举内部设置
                 7,                  // message ratio R=128
                 3,                  // double angle
                 12,                 // K；该离散拟合实际生成 22 阶
                 0,                  // 不加 arcsine 修正
                 22);
poly.enable_full_cosine_coefficients(); // 当前精度实验使用完整系数；库默认仍为旧偶项模式
evaluator->bootstrap_real(input, output, relin_keys, galois_keys, encoder, poly);
```

- 调用者必须保证槽消息为实数，满槽数为 N/2；不支持任意复数消息。
  密文 API 无法在不解密的情况下检查消息类型，不能把此接口当作任意复数的实部投影。
- `q0_level=0`、`input.level() >= 1`。这里 level=1 是两个 Q 素数、还能降一层；
  不把它和仅剩一个 Q 素数的 level=0 混淆。当前接口明确拒绝 level=0。
- 输入必须是本 context 的 size-2 密文，scale 有限且为正。
  本接口要求能通过近整数倍（相对容差 1e-5，上限 2^30）对齐到
  `2^round(log2(q0/R))`，不消耗额外层。推荐使用实验验证过的 2 的幂尺度。
- 输出 scale 与旧 `EvalModPoly` 接口一致，为 `context.scale()`。
- 支持原地调用；需要旋转、共轭和重线性化密钥，不使用秘密密钥。
- 实验固定 22 阶、K=12、倍角 3；API 接收 `EvalModPoly`，其他参数仍需独立验证。
- 没有移植到嵌套 `poseidon/` GPU 仓库。

## 为什么不用前置 StC 也能只算一路

令 N 为多项式环维数，M=N/2。实数槽消息对应的多项式满足
`m(X)=conj(m(X))`，所以其系数满足 `a[N-j]=-a[j]`（1≤j<M），`a[M]=0`。
只要恢复 `a[0]...a[M-1]`，即可恢复全部消息。

ModRaise 引入的整数溢出本身不必满足这种对称性。本实现不假设溢出具有对称性：
先对 CtS 的实系数半组执行 EvalMod，去掉这一半的溢出，再利用**恢复后消息**的
对称性重构。另一半的溢出无需计算，因为那一半的消息由已恢复系数决定。

具体步骤：

1. 按旧版对齐输入 scale，降至 q0 后 ModRaise；没有前置 StC。
2. 三段 CtS，仅提取实系数半组，不生成虚系数支路。
3. 只调用一次 `eval_mod`：22 阶离散余弦拟合 + 三次倍角。
4. 将半组的第 0 槽乘 1/2；该权重折叠到 StC 第一段矩阵的第 0 列，
   不增加密文上的明文乘法或 rescale。
5. 三段 StC 得到 `h(X)=a[0]/2+sum(a[j]X^j, j=1...M-1)`。
6. 共轭相加，得到 `h+conj(h)=m`。

不能只删除虚部 EvalMod 后直接返回。既需要最后的共轭重构，也需要第 0 槽的
半权重；漏掉半权重时，常量 1 会被重构成 2。明文代数测试专门覆盖此情况。

## 层数

在测试的 51-bit 链、R=128、22 阶 ×3 配置下，trace 应为：

```text
input            level=1,  scale=2^40
mod_raise        level=19, scale=2^44
eval_mod_input   level=16, scale=2^44  # CtS 用 3 层
eval_mod_output  level=8,  scale=2^44  # 多项式 5 层 + 倍角 3 层
output           level=5,  scale=2^40  # StC 用 3 层
```

升模后总共消耗 14 层，与旧版双路 22 阶 ×3 相同。优化的是 EvalMod 的调用数
和计算量，不是把两条并行分支的层数相加后减半。权重折叠和共轭相加不多用一层。

## 精度与限制

22 阶 ×3、K=12、R=128 不是任意消息和秘密分布下的精度保证。
没有 arcsine 修正时，常量消息 1 的正弦线性化偏差约为 4.02e-4；
随机/近零均值输入可能小得多，不能只报告随机输入的 RMSE。
这个偏差在旧双路对照中也存在。调大 R 或限制消息幅值可改变误差，但需核对系数的
适用区间、scale 并测试，不能自动推断更大 R 总是更好。

K=12 的覆盖范围、实际整数溢出分布、秘密密钥权重和多轮运算都要单独评估。
小 N / 小 H 的功能实验不构成 128-bit 安全认证，不能用它替代论文的 SSE=32 配置。
后续已测试 20×45-bit 链：scale=2^40 时用 R=32；保留 R=128 则将 scale 降至 2^38。
这两组仍消耗 14 层，但精度不同于 51-bit 基线，详见系数实验文档；不能将工作 scale
和输入 scale 任意替换，也不能同时沿用 45-bit q0、R=128、输入 scale=2^40。

## 构建与复现

```bash
cmake -S . -B build
cmake --build build --target test_ckks_bootstrap_cf_real -j4

# 快速检查半系数重构，以及两半独立整数溢出下的理想模约减重构
./build/bin/test_ckks_bootstrap_cf_real --algebra-only

# 六类实数输入，完整系数，双方相同密钥、密文和参数的单/双路对照
POSEIDON_BOOTSTRAP_TRACE=1 ./build/bin/test_ckks_bootstrap_cf_real --log-n 13 --h 5 \
    --full-coefficients

# 满尺寸，默认输入 level=1
./build/bin/test_ckks_bootstrap_cf_real --log-n 16 --h 5 --single-only --full-coefficients

# 原地调用，连续三轮；两轮之间执行密文平方并 rescale
./build/bin/test_ckks_bootstrap_cf_real --log-n 13 --h 5 --single-only \
    --full-coefficients --distribution random --amplitude 0.2 --rounds 3 --square-between --in-place
```

每次进程生成独立密钥。`--repeats` 在同一组密钥下重复，不等于跨密钥统计。
默认测试门限为最大绝对误差 1e-3，覆盖常量 1 在 R=128 下的固有偏差，
并非声称达到 1e-5 精度；可通过 `--max-error` 设置应用需要的更严格门限。
测试同时检查有限值、实际阶数、层数和输出 scale；任一路超限即返回非零。
支持六类分布：sine、random、constant、edges、impulse、zero。
不带 `--single-only` 时，两路使用完全相同的输入作为对照。

以下历史实验结果见随附 [CKKS_BOOTSTRAP_CF_REAL_RESULTS.json](CKKS_BOOTSTRAP_CF_REAL_RESULTS.json)，
使用旧偶项模式（没有 `--full-coefficients`）；实测结论仅适用于其中参数。
共记录 11 组进程、62 次自举测量，其中 2 组保留为
失败边界；另记录原默认双路和当时的 StC-first 单路两项回归。
JSON 是历史记录，保留原始命令与结果；其中已移除的 StC-first 测试命令不再可运行。

### 历史：旧偶项模式满尺寸 22 阶单路结果

N=65536、32768 实数槽、H=5、R=128、22 阶 ×3、Q=20×51-bit、P=60，
初始消息幅值≤1。六类输入均从 level=1 开始，输出 level=5、scale=2^40，
单/双路都通过默认 1e-3 最大误差门限。该组使用同一密钥，每类使用同一输入密文配对。

| 输入 | 双路最大误差 | 单路最大误差 | 单路 RMSE |
|---|---:|---:|---:|
| sine | 4.752e-5 | 5.011e-5 | 5.980e-7 |
| random | 4.716e-5 | 4.953e-5 | 5.949e-7 |
| constant | 4.061e-4 | 4.522e-4 | 4.016e-4 |
| edges | 2.095e-4 | 2.094e-4 | 2.007e-4 |
| impulse | 4.731e-5 | 4.915e-5 | 5.930e-7 |
| zero | 4.738e-5 | 5.045e-5 | 5.934e-7 |

没有前置 StC，没有牺牲槽数，也没有通过提高输入 level 来掩盖入口限制。
单路不是无损精度优化：相同配置下误差可能略高，必须按应用门限检查。

### 历史：旧偶项模式的边界与负例

- N=8192、H=5、R=128、22 阶 ×3：六类输入单/双路配对测试通过默认 1e-3 门限，
  全部从 level=1 输入，输出 level=5、scale=2^40，升模后消耗 14 层。
- 相同规模、R=256：六类配对测试也通过；单路常量 1 最大误差约 1.097e-4，
  随机输入约 9.07e-6。不能外推成任意规模的精度保证。
- N=8192、H=5、随机幅值 0.2：原地调用，连续三轮自举且轮间平方，
  对照原消息的 1、2、4 次方，三轮最大误差都小于 1.04e-5。
- 较高 level=5 入口的单路随机测试通过；输入仍在升模前降至最低模数。
- **精度门限负例：** R=128、常量 1、要求最大误差≤1e-4，测试返回失败，
  实测约 4.031e-4。没有把默认较宽门限的通过解释为达到 1e-4。
- **秘密权重负例：** N=8192、H=32、22 阶/K=12/倍角 3/R=128，
  随机输入单路最大误差约 0.469、双路约 0.466，均失败。
  **不能把 H=5 的 22 阶配置直接推广到 H=32，更不能宣称复现了论文的 SSE。**
- H=32 的另一次独立密钥实验改用 30 阶/K=16/倍角 3，单路最大误差约 4.66e-7，
  双路约 5.40e-7，均通过且仍消耗 14 层。两种阶数使用不同密钥，
  该结果不等于完成失败概率统计；30 阶是可继续验证的备选参数。
- N=65536、H=32、30 阶/K=16/倍角 3 的满槽随机配对实验也通过，
  单路最大误差 5.117e-6、RMSE 9.675e-7；双路最大误差 6.839e-6、RMSE 9.326e-7。
  两者从 level=1 输入、返回 level=5，均消耗 14 层。
- H=32、请求 59 阶/K=25 的离散拟合实际生成 **58 阶**，单路随机测试通过，
  实测消耗 15 层。测试会报告 requested_degree 与 degree，避免混淆名义阶数。
- 原默认 59 阶 heap 双路回归为 14 层并通过误差检查；当时的 StC-first 单路回归通过
  （该实验路径现已移除，历史结果保留）。

这些实验有部分并行执行，日志中的 seconds 用于诊断，不能当作隔离环境下的性能基准。

独立明文测试覆盖 8～1024 个槽、常量/脉冲/边界/非零均值实数消息。
直接重构最大误差 2.23e-15；向两组系数加入互不相关的整数溢出，再对单路做理想
模约减与重构，最大误差 2.07e-10。后一项是浮点代数检查，不是密文 EvalMod 精度。
