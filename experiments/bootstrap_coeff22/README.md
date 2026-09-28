# 22 阶 EvalMod 系数精度实验

本实验保持实际次数 22、K=12、倍角 3、满槽实数单路、level=1 入口不变。
主仓库软件后端，Q=20×51-bit、P=60、输入/输出 scale=2^40。
不修改原来的偶项模式默认行为，也不改变其他自举路径的默认参数。

当前按用户选择，后续精度优化固定以 **H=5、R=128、22 阶、倍角 3、完整系数**
为实验基线，暂不推进 H=32。`test_ckks_bootstrap_cf_real` 的默认 H 已从 1 改为 5；
完整系数仍需显式传入 `--full-coefficients`，单路仍需 `--single-only`。
这只调整实验程序的 H 默认值，不修改库的私钥参数默认值；H=5 不构成生产安全认证。
下文 `results.json` 保留改动前的历史实验与源文件哈希，原命令已显式指定 H=5/H=32。

## 发现：生成的系数不等于实际使用的系数

`ApproximateCos(12,22,R,3)` 生成 23 个 Chebyshev 系数，包含非零奇数项，例如
未乘 `sqrt_2pi` 前，T1 系数约为 -7.72403112614e-5，T3 约为 -7.02524814287e-5。
但原 `EvalModPoly` 构造器将 `is_odd` 设成 false，保留 `is_even=true`。
当前 PS evaluator 据此跳过奇数项，因此旧模式并没有计算完整的插值多项式。

虽然目标余弦函数是偶函数，离散插值节点在 `(j-1/4)/K` 上，关于原点不对称。
它的有限阶插值多项式并不必然为偶多项式。不能只凭目标余弦为偶函数而删除奇数项。

新增 `enable_full_cosine_coefficients()` **不改变生成的系数值**，只根据实际非零项
启用相应的求值分支。这里的 is_even/is_odd 在当前求值器中是“包含哪些奇偶项”的
选择标记；同时为 true 表示包括常数项在内的混合多项式。
奇数项会增加部分计算量，但实测仍消耗 5 个多项式 level，完整自举仍为 14 层。

```cpp
EvalModPoly poly(context, CosDiscrete, std::ldexp(1.0, 51),
                 1, 7, 3, 12, 0, 22); // R=128；其余参数与旧模式相同
poly.enable_full_cosine_coefficients();
evaluator->bootstrap_real(input, output, relin_keys, galois_keys, encoder, poly);
```

## 可复现的系数重算与加载

`fit_coefficients.py` 用 mpmath 的 100 位十进制精度，独立解 23×23 的 Chebyshev
插值方程：j=-11,...,11，x=(j-1/4)/12，目标 cos(3πx)。得到的多项式为 22 阶，
系数与原离散拟合的完整系数在 double 舍入误差范围内一致。
因此这不是声称找到了一组神奇的新系数；主要收益来自恢复原先丢掉的奇数项。

```bash
# 依赖 mpmath（验证环境 1.3.0）；输出 23 个未缩放的 Chebyshev 系数
python3 experiments/bootstrap_coeff22/fit_coefficients.py

# 对比完整多项式与删除奇数项后的标量误差；这不是密文精度
python3 experiments/bootstrap_coeff22/fit_coefficients.py --format json --ratio 128
```

固定系数文件为 `cos22_full_k12_da3.txt`。它只对应 K=12、倍角 3、22 阶的归一化
基底，不要把文件套在其他 K、倍角次数或基底上。

`EvalModPoly::set_cosine_coefficients(vector<double>)` 接收**未乘 sqrt_2pi**的系数，
内部应用本 context 的缩放并启用对应奇偶项。系数个数必须与当前多项式一致，
最高次系数不能为零，所有值必须有限；该接口不自行证明逼近误差或输入覆盖范围。
测试程序支持 `--coefficient-file` 加载此格式，并检查非法系数不会破坏原多项式。

## 必须区分两种误差

1. 只恢复完整系数：减少离散拟合残差，尤其是整数点附近的偏差。
2. 调整 message ratio R：改变正弦线性化误差与数值噪声的折中；这不是系数优化本身。

无 arcsine 修正时，理想残余仍为 `R/(2π)*sin(2π*m/R)`。
对常量 1，R=128 时偏差约 4.02e-4；只恢复奇数项无法消除这项偏差。
R=1024、2048 的对应偏差约为 6.27e-6、1.57e-6，但更大的 R 会放大某些数值误差。

本次另外尝试了连续余弦截断和采样点上的加权拟合/预失真拟合。
连续截断虽然改善了宽区间的余弦误差，却引入约 1.43e-5 的整数点标量残差；
部分自由拟合在整数点、未覆盖区间或数值稳定性上表现较差，未接入默认方案。
这些探索不能证明 22 阶预失真绝对不可行，只说明本次没有验证出优于完整离散系数的方案。

对于 51-bit q0 和固定输入 scale=2^40，本次测试的 R=1024/2048 分别要求输入能
对齐到约 2^41/2^40。不能无限增大 R；更不能直接推广到 45/40-bit 模数配置。

## 密文测试

```bash
cmake --build build --target test_ckks_bootstrap_cf_real -j4

# 同密钥、同密文、同参数，只有系数求值模式不同；同时报告 baseline/candidate
./build/bin/test_ckks_bootstrap_cf_real --log-n 13 --h 5 --single-only \
    --full-coefficients --compare-coefficients --distribution all

# 系数文件加载，并另外调整 R；与上一条不是严格的仅系数对照
./build/bin/test_ckks_bootstrap_cf_real --log-n 13 --h 5 --single-only \
    --coefficient-file experiments/bootstrap_coeff22/cos22_full_k12_da3.txt \
    --ratio-log 11 --distribution all --max-error 0.00001

# 也支持用逗号选择多个输入分布，减少重复生成密钥的开销
./build/bin/test_ckks_bootstrap_cf_real --log-n 16 --h 5 --single-only \
    --full-coefficients --compare-coefficients --distribution random,constant
```

所有测试均检查有限值、实际 22 阶、实际 14 层、输出 scale，支持原地调用和轮间平方。
比较模式下 baseline 或 candidate 任意一项超过门限，程序都会返回非零，
所以必须分别检查 CSV 行，不能把 baseline 失败误读成 candidate 也失败。

## 实测结果（2026-09-28）

主对照使用 N=65536、32768 满槽实数、H=5、R=128；每组 baseline/candidate
使用同一密钥、同一输入密文，只改变奇偶项求值标记，不改变系数数值。
误差为解密后的复数槽值与原消息之差的绝对值，RMSE 在所有槽上计算。

| 输入 | 旧偶项最大误差 | 完整系数最大误差 | 旧偶项 RMSE | 完整系数 RMSE |
| --- | ---: | ---: | ---: | ---: |
| 均匀随机 [-1,1] | 5.4343e-5 | 4.7654e-6 | 6.1365e-7 | 3.3039e-7 |
| 所有槽为 1 | 4.5729e-4 | 4.0603e-4 | 4.0145e-4 | 4.0144e-4 |

这一组随机输入的最大误差改善约 **11.4 倍**，不是对任意输入或密钥的保证。
常量 1 的 RMSE 几乎不变，与前述正弦线性化偏差一致。
两种模式均为输入 level=1，升模后从 level=19 到 level=5，消耗 14 层，
输出 scale=2^40。完整系数的多项式求值仍为 5 层；没有增加倍角次数。

额外改变 R 的 N=65536、H=5 完整系数测试如下。各 R 进程重新生成密钥，
因此不是同密钥的严格 R 参数对照，不能将数值差异全部归因于 R。

| R | 随机输入最大误差 | 常量 1 最大误差 | 本次测试结果 |
| --- | ---: | ---: | --- |
| 128 | 4.7654e-6 | 4.0603e-4 | 两种输入均通过 1e-3 门限 |
| 1024 | 1.8237e-5 | 2.2313e-5 | 六种输入中，常量未通过 2e-5 门限 |
| 2048 | 1.2192e-4 | 1.3231e-4 | 六种输入均未通过 2e-5 门限 |

小规模 N=8192 的 R=2048 六分布测试曾全部通过 1e-5，但该结果不能推广到
N=65536。增大 R 的收益与噪声需要一起评估，本次不修改默认 R。

### 后续 45-bit 链验证

N=65536、32768 满槽实数、H=5、22 阶完整系数、倍角 3、P=60，
将 Q 改为 20×45-bit；每组独立生成密钥。两组都从 level=1 开始，
升模后 level=19 → 5，消耗 14 层，最大误差门限均为 1e-3。

| 输入/输出 scale | R | 随机输入最大误差 | 常量 1 最大误差 | 门限检查 |
| --- | ---: | ---: | ---: | --- |
| 2^40 | 32 | 6.5735e-5 | 6.4733e-3 | 常量失败，进程返回 2 |
| 2^38 | 128 | 6.1122e-4 | 7.7871e-4 | 两种输入通过，进程返回 0 |

当前 scale 对齐要求约为 `input_scale <= q0/R`，因此 45-bit q0 不能同时保留
R=128 和输入 scale=2^40。该组合被参数检查拒绝，不应删除检查强行运行。
R=32 时常量 1 的理想正弦线性化偏差约为 6.4131e-3，与实测量级一致。
这里的 R/scale 扫描不是同密钥对照，不能据此估计失败概率，也没有修改默认参数。
这两组是后续补充测试，不在下述早期 `results.json` 中。

```bash
./build/bin/test_ckks_bootstrap_cf_real --log-n 16 --h 5 --single-only \
    --full-coefficients --work-bits 45 --input-bits 40 --ratio-log 5 \
    --distribution random,constant
./build/bin/test_ckks_bootstrap_cf_real --log-n 16 --h 5 --single-only \
    --full-coefficients --work-bits 45 --input-bits 38 --ratio-log 7 \
    --distribution random,constant
```

### 边界与其他回归

**H=32 仍不可靠。** N=8192、R=128 的四次独立密钥测试（含初始试验）中，
完整系数有三次通过 1e-3，一次严重失败：最大误差 88.9760，RMSE 40.0215；
同次旧偶项最大误差也达到 81.2194。另一次旧偶项失败、完整系数通过。
这些样本既不能证明 H=32 可用，也不足以估计失败概率；失败密文未保存，
不能仅据输出误差断定根因。输入覆盖范围、升模后的误差分布仍需专门验证。

其他通过的检查：

- N=8192、H=5、R=128 的六种分布同密文系数对照。
- 100 位与 160 位精度重算得到完全相同的 double 文本，与提交的 23 项系数文件一致。
- N=8192 的系数文件加载，六种分布通过 1e-5（R=2048）。
- N=8192 的原地三轮自举、轮间平方，输入幅值 0.2，最大误差不超过 2.13e-6（R=2048）。
- N=8192 的双路/单路、旧偶项/完整系数四路随机输入对照，均通过 1e-3。
- 当时的 StC-first 59 阶路径回归通过，最大误差 9.85e-5；该实验路径及专属测试
  现已移除，这一条仅是历史回归记录，不再是可运行的入口。
- 非法系数个数、NaN、零最高次项的拒绝检查，以及启用完整系数不改变系数值的检查。

H=5/H=32 测试均是功能和精度实验，不构成生产安全参数或失败概率认证，未实现论文 SSE。
实验有并行执行，seconds 不是隔离环境的性能基准。
逐项数据、命令、失败记录与源文件哈希见 [results.json](results.json)。
JSON 保留历史原始记录，其中已移除的 StC-first 测试命令不再可运行；当前使用
`test_ckks_bootstrap_cf_real`，原双路接口仍然保留。
前面三个初始小规模试验经系数 setter 做了缩放往返；主满槽对照及之后的
`--full-coefficients` 测试直接使用只修改标记的接口，没有这个舍入差异。
