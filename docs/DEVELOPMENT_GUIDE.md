# Poseidon 开发规范说明

## 1. 文档目的

本文档用于约定 Poseidon C++ 库的开发规范，适用于以下工作：

- 同态加密核心流程开发
- BFV、BGV、CKKS 三种 scheme 的 evaluator 实现
- 底层算术、上下文与参数管理
- 示例、benchmark 以及后续测试体系建设

目标是让这个库在持续迭代时保持：

- 正确性优先
- 结构清晰
- 易于评审
- 易于维护

尤其是在 `参数`、`level`、`scale`、`NTT form`、`parms_id` 这些容易引入隐式错误的路径上，必须把约束写清楚、守住边界。

## 2. 项目整体认知

Poseidon 当前以共享库 `poseidon_shared` 作为主构建产物，核心源码位于 `src/poseidon`。

从外部使用方式看，这个库的主链路是：

1. `ParametersLiteral` 或 `ParametersLiteralDefault`
2. `PoseidonFactory`
3. `PoseidonContext`
4. `KeyGenerator`
5. 编码器：`BatchEncoder` 或 `CKKSEncoder`
6. `Encryptor`
7. Evaluator：`EvaluatorBfvBase`、`EvaluatorBgvBase`、`EvaluatorCkksBase`
8. `Decryptor`

`examples/bfv`、`examples/bgv`、`examples/ckks` 是当前最直接的用法说明和验证入口，开发时应优先把它们当作“可执行文档”理解。

## 3. 目录与模块规范

### 3.1 主要目录职责

- `src/poseidon`
  对外核心头文件与实现。
- `src/poseidon/basics`
  基础能力层，包括内存管理、序列化、模数、底层工具等。
- `src/poseidon/evaluator`
  evaluator 抽象接口与公共 evaluator 逻辑。
- `src/poseidon/evaluator/software`
  软件后端下的 scheme-specific evaluator 实现。
- `src/poseidon/key`
  密钥相关实现，包括 keyswitch、relin keys、galois keys。
- `src/poseidon/advance`
  高阶同态能力，如线性变换、DFT、bootstrap 相关能力。
- `src/poseidon/factory`
  工厂层与后端选择逻辑。
- `src/poseidon/util`
  公共工具与辅助逻辑。
- `examples`
  按 scheme 分类的示例程序。
- `bench`
  benchmark 与性能测量代码。
- `tests`
  预留的测试目录。当前顶层 CMake 尚未将其完整接入主验证流程，因此现阶段应视为“可扩展测试位”，而不是已完备的测试体系。

### 3.2 文件放置原则

- 对外 API 所属的头文件，放在对应模块下的 `src/poseidon/...`。
- scheme 无关的 evaluator 公共逻辑，放在 `src/poseidon/evaluator`。
- scheme 相关的软件实现，放在 `src/poseidon/evaluator/software`。
- 复合型高阶算子，放在 `src/poseidon/advance`，不要塞进基础加解密流程。
- 使用示例放在 `examples`，不要把示例逻辑写进库代码。
- 性能测试代码放在 `bench`，不要混进 `examples`。

## 4. 构建与依赖规范

### 4.1 构建系统

- 以 CMake 为唯一构建事实来源。
- 新增库代码时，默认继续归入现有 `poseidon_shared` target，除非有明确的架构拆分理由。
- 保持当前按模块 `add_subdirectory(...)` 的组织方式。
- 新增源文件后，要确认它能被当前模块里的 glob 规则纳入构建。

### 4.2 第三方依赖

当前构建选项支持的依赖包括但不限于：

- GMP
- Microsoft GSL
- ZLIB
- Zstandard
- spdlog
- Intel HEXL
- OpenMP

依赖引入规则：

- 优先复用现有依赖，不轻易引入新的第三方库。
- 只有在“正确性需要”或“性能收益明确”时，才考虑增加新依赖。
- 可选依赖必须通过 CMake option 控制。
- 任何加速路径都必须与软件路径保持一致的外部行为和结果语义。

## 5. C++ 代码风格规范

### 5.1 命名规范

- 类型、类名使用 `PascalCase`
  例如：`PoseidonContext`、`KeyGenerator`、`ParametersLiteral`
- 函数、方法使用 `snake_case`
  例如：`create_public_key`、`drop_modulus_to_next`
- 文件名使用小写 `snake_case`
  例如：`poseidon_context.cpp`、`parameters_literal.h`
- 宏使用 `POSEIDON_` 前缀的大写风格
  例如：`POSEIDON_THROW`、`POSEIDON_NODISCARD`
- 枚举值遵循当前仓库既有风格
  例如：`CKKS`、`BFV`、`BGV`、`DEVICE_SOFTWARE`

### 5.2 头文件与命名空间

- 头文件统一使用 `#pragma once`。
- 公共符号放在 `namespace poseidon` 下。
- `poseidon::util` 这类更细的命名空间只在确有必要时使用。
- 头文件中禁止使用 `using namespace ...`。
- `.cpp` 文件中如需 `using namespace`，应控制范围，避免扩大污染。新代码默认优先使用显式限定名，除非会明显损害可读性。

### 5.3 接口风格

- 明显轻量的 accessor 可以保留为头文件中的 `inline`。
- 尽量保持 `const` 正确性。
- 大对象优先按 `const &` 传参，除非明确需要转移所有权。
- 对性能敏感或频繁分配的路径，优先复用 `MemoryPoolHandle` 体系。
- 沿用现有所有权风格：
  - 上下文数据常使用 `shared_ptr`
  - 工厂创建 evaluator 常使用 `unique_ptr`

### 5.4 异常与错误处理

- 库内参数校验与错误报告，优先使用 Poseidon 现有异常宏和风格。
- 对非法参数、非法表示形式、非法密钥状态、不支持的 scheme 或 backend 组合，要尽早失败。
- 错误信息要描述“违反了什么约束”，而不仅仅是“出错了”。

建议重点校验的边界包括：

- scheme 类型是否匹配当前逻辑
- plaintext / ciphertext 是否处于正确的 NTT form
- `parms_id` 是否有效
- 是否缺少 rotation / relin 所需密钥
- `scale` 是否兼容
- modulus 切换是否合理

## 6. 同态加密正确性约束

这一部分不是代码风格建议，而是必须遵守的正确性规则。

### 6.1 Scheme 分层必须清晰

- 不要把 BFV、BGV、CKKS 的专属逻辑混在同一条模糊路径里，除非这段逻辑确实是 scheme 无关的。
- 一旦行为因 scheme 不同而变化，就要在边界处显式分支并校验前提。
- 不要因为 API 形状相似，就机械复制不同 scheme 的实现。

### 6.2 表示形式不变量

- 操作前必须明确 plaintext / ciphertext 是否应处于 NTT form。
- 修改 ciphertext 时，要维护好这些状态的一致性：
  - `parms_id`
  - level
  - size
  - scale
  - correction factor
- 凡是会改变 level 或 scale 的操作，都要让状态迁移清晰、可审查。
- 不要默认任意 ciphertext 都能套用顶层 context data，必要时必须基于该对象自身的 `parms_id` 取上下文。

### 6.3 CKKS 特别规范

- `scale` 是 CKKS 语义的一部分，不只是附带字段。
- 算术前要判断 scale 是否兼容。
- 乘法类操作之后，要明确 rescale / drop modulus 的预期路径。
- 新增 CKKS 功能时，应说明：
  - 消耗哪些 level
  - 依赖哪些 key
  - 结果处于什么 scale 范围
- 任何改变模数链位置的 helper，都必须保证 `parms_id` 迁移合法且可解释。

### 6.4 密钥相关操作

- rotation 依赖有效的 Galois keys。
- relinearization 和 multiply-relinearize 依赖有效的 Relin keys。
- keyswitch 行为必须遵循 context 中配置的 variant。
- backend 特定的密钥要求，必须在接口边界提前校验，不能把未定义行为留给深层实现。

## 7. 模块设计规范

### 7.1 公共 API 层

公共类要向使用者暴露稳定、可理解的能力边界。除非某个底层细节本来就是抽象的一部分，否则不要轻易把底层实现细节泄漏到外部接口。

### 7.2 Evaluator 层

- 抽象 base evaluator 用来定义 scheme 能力边界。
- software evaluator 用来承接具体后端实现。
- 只有真正可复用、且不会损害 scheme 清晰度的逻辑，才放进 base 层共享。

### 7.3 底层算术层

- 底层算术 kernel 要尽量保持小而专注，方便 review。
- 如果逻辑能沉淀为公共底层 helper，就不要在 evaluator 中复制粘贴。
- 性能优化不能掩盖正确性前提。若某个 fast path 依赖不明显的约束，应添加简短注释说明。

### 7.4 Factory 与 backend 选择

- `PoseidonFactory` 是后端与 evaluator 创建的首选入口。
- 新增 backend 逻辑时，不要把 backend 分支扩散到无关模块。
- 如果加入硬件路径，软件路径仍然应作为基准实现与正确性参考。

## 8. 示例、性能测试与测试规范

### 8.1 示例代码

- 示例就是可执行文档。
- 一个示例应尽量聚焦一个场景，或者在同一个示例里按清晰的 banner / block 分段。
- 新增公共能力时，原则上要补充或更新对应示例。
- 示例命名保持与当前风格一致，例如 `test_ckks_basic.cpp`。

### 8.2 Benchmark

- benchmark 应测量稳定、边界明确的操作。
- 不要把 benchmark 与调试打印、临时实验逻辑混杂在一起。
- benchmark 内容应尽量反映真实使用场景，如：
  - keygen
  - encode/decode
  - encrypt/decrypt
  - evaluator 核心操作
  - 高阶变换

### 8.3 测试

当前现状：

- 仓库中存在 `tests/unit`、`tests/integration`、`tests/benchmark` 目录。
- 但顶层 CMake 还没有把它们完整串成主测试流程。

当前开发要求：

- 任何影响正确性的改动，都必须至少通过一种“可执行验证”确认。
- 如果暂时没有正式 test target，应使用 example、局部验证程序或 benchmark 辅助验证，并记录验证方式。
- 后续若完善测试体系，建议沿用以下分层：
  - unit test：验证底层算术、工具函数、不变量
  - integration test：验证完整 encrypt -> evaluate -> decrypt 流程
  - benchmark：只用于性能测量，不承担正确性回归主职责

新增同态功能时，建议覆盖这些验证场景：

- encrypt -> evaluate -> decrypt 的 round-trip
- rescale 或 drop modulus 之后的跨 level 行为
- 依赖 rotation / relin key 的操作
- 参数非法、缺 key、form 不匹配、scale 不兼容时的失败路径
- 与明文域预期结果的对比

## 9. 开发变更流程

实现新功能或修 bug 时，建议按以下顺序推进：

1. 先确认目标属于哪个 scheme，以及它依赖哪些表示形式和 level 假设。
2. 找到公开 API 入口，再沿链路定位内部 evaluator 和底层算术路径。
3. 判断改动应落在共享层、scheme 层，还是底层工具层。
4. 在最早能发现非法输入的边界加校验。
5. 显式维护 `parms_id`、level、scale、NTT form 的状态迁移。
6. 用 example、test、benchmark 或组合方式完成验证。
7. 如果改动影响使用方式或语义，要同步更新文档或示例。

## 10. Code Review 检查清单

提交前或 review 时，至少检查以下内容：

- 改动是否落在正确模块
- scheme 前提是否明确
- NTT form 假设是否有校验
- `parms_id`、level、scale 的迁移是否合法
- key-dependent 操作是否检查了所需密钥
- 错误信息是否表达了具体约束
- 新能力是否有可运行验证
- 是否为了优化而牺牲了软件路径的正确性和可读性

## 11. 默认开发建议

除非有充分理由，否则默认遵循以下开发习惯：

- 把 `examples` 作为理解和验证功能的第一入口
- 把 `poseidon_shared` 视为主要库边界
- 保持现有命名与模块布局
- 优先写显式正确性检查，而不是依赖隐式前提
- 将 scheme-specific 逻辑保持分离
- 对 CKKS 的 level 与 scale 变化保持高度可读
- 对不明显的算术或性能假设，加简短注释说明

## 12. 维护说明

本文档基于当前仓库结构、构建方式和代码风格整理而成，刻意区分了两类内容：

- 仓库当前已经存在的事实
- 团队后续建议遵循的开发规范

如果未来构建方式、测试体系或 backend 架构发生变化，应同步更新本文档，确保它始终是可靠的工程参考，而不是过期说明。
