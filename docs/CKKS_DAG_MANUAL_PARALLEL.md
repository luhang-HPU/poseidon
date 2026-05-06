# CKKS 手工并行样例说明

本文档说明文件 `examples/ckks/test_ckks_dag_manual_parallel_24.cpp` 的设计目的、计算流程、并行策略，以及如何用它观察性能优化效果。

## 1. 这个文件是做什么的

这个样例的目标不是做一个最短的 CKKS demo，而是构造一个：

- 同时包含 `add`、`sub`、`multiply`、`relinearize`、`rescale_dynamic`、`rotate` 的 workload
- 前半段存在明显可并行分支
- 后半段存在明确 merge 和串行 tail
- 既能跑单线程基线，也能跑手工并行版本
- 能输出耗时和精度对比
- 适合被 HE DAG 工具抽成计算图

所以它本质上是一个“用于并行化实验和 DAG 抽图验证的 CKKS 样例”。

## 2. 文件里的整体结构

这个文件可以分成 6 个部分：

1. 明文参考计算工具函数
2. 三个 HE 分支函数
3. 一个最终归约函数 `final_reduce`
4. 单线程 workload
5. 手工并行 workload
6. `main()` 中的初始化、计时、解密和精度验证

从结构上看，这个文件不是把所有 HE 操作平铺在 `main()` 里，而是先把计算拆成多个 branch，再在 workload 中控制执行方式。

## 3. 计算逻辑长什么样

整个计算可以抽象成下面这张结构图：

```text
branch_add   = smooth_square_branch(a, b)
branch_quad  = diff_energy_branch(c, d)
branch_cross = cross_mix_branch(a, b, c, d)

merged_left = branch_add + branch_quad
merged_all  = merged_left + branch_cross
tail_prod   = merged_all * branch_add
result      = tail_prod + rotate(tail_prod, 32)
```

也就是说：

- 前面有 3 条独立分支
- 这 3 条分支彼此没有数据依赖
- 后面通过 `final_reduce` 做汇合
- 汇合之后再做一条串行 tail chain

这正是它适合做并行化和 DAG 抽图的原因。

## 4. 三个分支分别做了什么

### 4.1 `smooth_square_branch`

对应函数：

- `smooth_square_branch(...)`

计算过程：

```text
sum_ab         = a + b
rot_ab_1       = rotate(sum_ab, 1)
smooth_ab      = sum_ab + rot_ab_1
smooth_sq      = smooth_ab * smooth_ab
smooth_sq_relin= relinearize(smooth_sq)
smooth_sq_res  = rescale(smooth_sq_relin)
smooth_sq_rot4 = rotate(smooth_sq_res, 4)
branch_add     = smooth_sq_res + smooth_sq_rot4
```

这个分支的特点是：

- 前半段以 `add + rotate` 为主
- 中间有一个平方
- 乘法后做 `relinearize + rescale_dynamic`
- 最后再做一次旋转聚合

### 4.2 `diff_energy_branch`

对应函数：

- `diff_energy_branch(...)`

计算过程：

```text
diff_cd       = c - d
diff_rot2     = rotate(diff_cd, 2)
diff_mix      = diff_cd + diff_rot2
diff_sq       = diff_mix * diff_mix
diff_sq_relin = relinearize(diff_sq)
diff_sq_res   = rescale(diff_sq_relin)
diff_sq_rot8  = rotate(diff_sq_res, 8)
branch_quad   = diff_sq_res + diff_sq_rot8
```

这个分支的特点是：

- 先做差分
- 再做一次固定步长的平滑
- 再做平方
- 末尾只保留一次旋转聚合，结构和第一个分支更对称

### 4.3 `cross_mix_branch`

对应函数：

- `cross_mix_branch(...)`

计算过程：

```text
prod_ac       = a * c
prod_ac_relin = relinearize(prod_ac)
prod_ac_res   = rescale(prod_ac_relin)

prod_bd       = b * d
prod_bd_relin = relinearize(prod_bd)
prod_bd_res   = rescale(prod_bd_relin)

cross_sum     = prod_ac_res + prod_bd_res
cross_rot8    = rotate(cross_sum, 8)
cross_mix     = cross_sum + cross_rot8
cross_rot16   = rotate(cross_mix, 16)
branch_cross  = cross_mix + cross_rot16
```

这个分支的特点是：

- 内部本身有两条乘法链
- 是三个分支里最“重”的一个
- 通常也是并行阶段里更容易成为瓶颈的分支

## 5. `final_reduce` 做了什么

对应函数：

- `final_reduce(...)`

它负责把前三个 branch 的结果汇合，并做最后一段串行计算：

```text
merged_left   = branch_add + branch_quad
merged_all    = merged_left + branch_cross
tail_prod     = merged_all * branch_add
tail_relin    = relinearize(tail_prod)
tail_res      = rescale(tail_relin)
tail_rot32    = rotate(tail_res, 32)
result        = tail_res + tail_rot32
```

这个函数在并行化分析里很重要，因为它是：

- 三个并行 branch 的汇合点
- 后续串行关键路径的主体

## 6. 单线程版本做了什么

对应函数：

- `ckks_single_thread_workload(...)`

它的逻辑非常直接：

1. 先顺序执行 `smooth_square_branch`
2. 再顺序执行 `diff_energy_branch`
3. 再顺序执行 `cross_mix_branch`
4. 最后执行 `final_reduce`

也就是说，虽然算法本身有 3 条独立分支，但单线程版本没有利用这种并行性。

它的意义是：

- 提供性能基线
- 作为并行版本的 correctness baseline

## 7. 多线程版本做了什么

对应函数：

- `ckks_manual_parallel_workload(...)`

这个版本和单线程版的数学计算完全相同，区别只在于执行方式：

```text
ParallelGroup parallel(thread_pool);
parallel.go(branch_add task);
parallel.go(branch_quad task);
parallel.go(branch_cross task);
parallel.wait();

final_reduce(...);
```

也就是说：

- 3 个 branch 被投递到线程池并发执行
- `parallel.wait()` 等待这 3 条任务全部完成
- 完成后再进入串行的 `final_reduce`

这里使用的是 `ParallelGroup` 包装，而不是直接暴露三组 `enqueue + future.get()`，这样调用点更像一个“并行区块”，读代码会更清楚。

## 8. 为什么这个并行版本是安全的

这版并行化能保证结果和单线程一致，原因很直接：

- 三个 branch 只读共享输入 `ct_a / ct_b / ct_c / ct_d`
- 每个 branch 只写自己的局部结果 `branch_add / branch_quad / branch_cross`
- 分支之间没有写写冲突
- 最后的 `final_reduce` 仍然按固定顺序串行执行

换句话说，这里改变的是“前面三条独立分支同时做”，而不是改变算子顺序或者 merge 顺序。

因此：

- 单线程结果和并行结果应当一致
- 并行版不应引入额外误差

## 9. 为什么能加速，但不会到 3x

这个例子通常能拿到大约 2x 左右的 speedup，但很难到 3x，主要原因有 3 个：

1. 只有前面三条 branch 能并行
2. `final_reduce` 是串行的
3. 三个 branch 的负载并不均衡，`cross_mix_branch` 更重

所以即使线程数是 3，也不可能线性加速到 3 倍。

如果你看到大约 `2.0x ~ 2.3x` 的加速，这通常是一个合理结果。

## 10. 文件里为什么还保留明文参考计算

文件前面有一组 `*_ref` 函数，例如：

- `smooth_square_branch_ref`
- `diff_energy_branch_ref`
- `cross_mix_branch_ref`
- `build_reference`

这些不是冗余代码，它们的作用是：

- 用普通复数向量在 CPU 上跑一遍同样的数学流程
- 在程序最后拿解密结果和明文参考结果比
- 验证单线程版和并行版是不是都算对了

所以这个文件不是只测速度，也会一起测 correctness。

## 11. `main()` 里做了什么

`main()` 大致按下面顺序工作：

1. 构造 CKKS 参数
2. 创建 context、evaluator、encoder、encryptor、decryptor
3. 生成 `public_key / relin_keys / galois_keys`
4. 采样 4 组随机输入消息 `msg_a / msg_b / msg_c / msg_d`
5. 编码并加密成 `ct_a / ct_b / ct_c / ct_d`
6. 计算明文参考结果 `expected`
7. 跑单线程 workload，并记录时间
8. 跑手工并行 workload，并记录时间
9. 解密两边结果
10. 打印时间、speedup 和精度统计

因此这个文件本身就是一个完整的 benchmark + correctness check。

## 12. 这个样例和 DAG 抽图的关系

这个文件是专门为 DAG 场景友好设计过的，原因是：

- 前面有明显的 3 路 branch
- 后面有明显的 merge 点
- 分支内部包含丰富的 CKKS 操作类型
- 每个 branch 被拆成独立 helper function
- 多线程版本的并行区块也比较清晰

对 DAG 工具来说，这样的代码很容易抽出：

- 哪些操作在同一个 branch
- 哪些 branch 彼此独立
- 哪些地方必须汇合
- 哪一段是关键路径

## 13. 如何编译和运行

编译：

```bash
cmake --build build --target test_ckks_dag_manual_parallel_24 -j2
```

运行：

```bash
./build/bin/test_ckks_dag_manual_parallel_24
```

如果想单独生成这个多线程函数的 DAG：

```bash
./hedag_pipeline examples/ckks/test_ckks_dag_manual_parallel_24.cpp \
  --function ckks_manual_parallel_workload \
  --case-name ckks_manual_parallel_graph
```

如果想生成单线程版本的 DAG：

```bash
./hedag_pipeline examples/ckks/test_ckks_dag_single_thread_24_parallel.cpp \
  --function ckks_single_thread_workload \
  --case-name ckks_single_thread_graph
```

## 14. 你读这个文件时最值得关注的地方

如果只想快速看懂，建议按下面顺序读：

1. `ckks_single_thread_workload`
2. `ckks_manual_parallel_workload`
3. `final_reduce`
4. 三个 branch 函数
5. `main()`

这样最容易先抓住“结构”，再理解“每个分支里面具体做了什么”。

## 15. 一句话总结

`test_ckks_dag_manual_parallel_24.cpp` 做的事情是：

“在同一个程序里，对同一条 CKKS 计算链同时提供单线程和手工并行两种执行方式，并用时间和精度结果去验证并行化是否值得、是否正确。”
