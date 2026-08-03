# OpenShield Fuzzing

针对攻击面最大的**输入解析器**做覆盖引导模糊测试，目标是：任意输入（合法结构变异 / 截断 / 纯随机字节）下解析器**绝不崩溃、绝不越界**。

## 目标

| Target | 模块 | 攻击面 |
|--------|------|--------|
| PSBT (BIP174) | `core/psbt.c` | 主机传入的待签交易（不可信） |
| EVM tx (RLP) | `core/clearsign.c` | 主机传入的待签交易（不可信） |
| Keccak-256 | `core/keccak.c` | 所有哈希输入 |
| EIP-712 domain | `core/eip712.c` | typed data（不可信） |

这些都是设备从**不可信主机**接收数据的入口，是 fuzzing 的最高价值目标。

## 方法

GCC `-fsanitize=address,undefined`（无需 libFuzzer/clang）：
- **ASan**: 缓冲区溢出、UAF、越界
- **UBSan**: 整数溢出、UB（如 memcpy NULL）

语料策略（确定性 PRNG，可复现）：
1. 合法结构 + 系统性位/字节变异（bit flip / byte set / invert / swap）
2. 合法结构 + 随机截断
3. 纯随机字节（含 `"psbt\xff"` 魔数注入提高命中）

## 运行

```bash
cd fuzz
make run            # 100k 迭代
./fuzz_parsers 500000   # 自定义迭代数
```

退出码 0 + "no crash" = 通过。任何 ASan/UBsan 报告 = 真实 bug，且 PRNG 种子固定可复现。

## 结果

- **100,000 迭代，ASan/UBSan 完全干净**（0 崩溃 / 0 越界 / 0 UB）
- 过程中发现 1 处 UB 在 **fuzz 驱动自身**（`memcpy(NULL,0)`），被测解析器代码无此问题——已修驱动。

## 后续

- 接 libFuzzer/AFL 做真正的覆盖率引导（当前为结构化变异+随机）
- 增加 BIP39 助记词解析、base58 解码（若引入）为 target
