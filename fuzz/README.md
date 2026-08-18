# HardID Fuzzing

针对攻击面最大的**输入解析器**做模糊测试，目标是：任意输入（合法结构变异 / 截断 / 纯随机字节）下解析器**绝不崩溃、绝不越界、绝无 UB**。

## 目标

| Target | 模块 | 攻击面 | Harness |
|--------|------|--------|---------|
| PSBT (BIP174) | `core/psbt.c` | 主机传入的待签交易（不可信） | fuzz_parsers / fuzz_full |
| EVM tx (RLP/ERC20) | `core/clearsign.c` | 主机传入的待签交易（不可信） | fuzz_parsers / fuzz_full |
| CBOR | `core/cbor.c` | CTAP2 请求（USB 不可信） | fuzz_parsers / fuzz_full |
| Keccak-256 | `core/keccak.c` | 所有哈希输入 | fuzz_full |
| EIP-712 domain | `core/eip712.c` | typed data（不可信） | fuzz_parsers / fuzz_full |
| BIP39 助记词 | `core/bip39.c` | 恢复短语输入（字符串） | fuzz_full |
| BIP32 派生路径 | `core/bip32.c` | 派生路径字符串（主机） | fuzz_full |
| linkproto 帧 | `core/linkproto.c` | 主机链路帧解析 | fuzz_full |
| CTAP2 请求 | `core/ctap2.c` | FIDO 命令分发 | fuzz_full |
| CTAPHID 帧层 | `core/fido_ctaphid.c` | USB HID 64 字节包 | fuzz_full |
| tx 组装 | `core/tx_asm.c` | 签名→DER/witness 组装 | fuzz_full |
| secp256r1/256k1 | `core/secp256r1.c`/`secp256k1.c` | 公钥解析 | fuzz_full |
| base58check | `core/base58.c` | 地址编码 | fuzz_full |

这些都是设备从**不可信主机/USB**接收数据的入口，是 fuzzing 的最高价值目标。

## 方法

GCC `-fsanitize=address,undefined`（无需 libFuzzer/clang）：
- **ASan**: 缓冲区溢出、UAF、越界
- **UBSan**: 整数溢出、UB（如 memcpy NULL、NULL 解引用）

语料策略（确定性 PRNG，可复现）：
1. 合法结构 + 系统性位/字节变异（bit flip / byte set / invert / swap）
2. 合法结构 + 随机截断
3. 纯随机字节（含魔数注入提高命中）
4. 字符串类 target（bip39/bip32）偏置字母表提高命中

## 运行

```bash
cd fuzz
make                # 构建 fuzz_parsers + fuzz_full
make run            # fuzz_parsers 100k + fuzz_full 200k
./fuzz_full 500000              # 自定义迭代数
./fuzz_full 500000 0x1234dead   # 自定义种子（多进程并行用不同种子）
```

退出码 0 + "no crash" = 通过。任何 ASan/UBSan 报告 = 真实 bug，且 PRNG 种子固定可复现。

## 结果（2026-08-16 全量模糊测试）

- **`fuzz_parsers`**：100,000 迭代，ASan/UBSan 干净。
- **`fuzz_full`**（13 target，全不可信输入入口）：**400,000 迭代（2 个种子）**，ASan/UBSan 干净。
- 过程中发现 2 处问题，**均在 fuzz 驱动自身**，被测核心代码无此问题：
  1. `fuzz_bip39` 误把 32 字节 `ent` 当 64 字节 seed 传给 `os_bip39_mnemonic_to_seed`（该 API 契约 seed 为 64 字节）——修驱动。
  2. `fuzz_secp` 传 NULL 给 `os_secp256k1_parse_pubkey`/`os_secp256r1_parse_pubkey`（point_out 输出参数须非 NULL）——修驱动，改用 96 字节 jacobian point 缓冲。
- **诚实记录**：`os_secp256k1_parse_pubkey`/`os_secp256r1_parse_pubkey` 对 point_out 无 NULL 检查，属内部 API（调用方信任），非当前攻击面，未加防御性检查——如未来暴露到不可信输入路径需补。

## 后续

- 接 libFuzzer/AFL 做真正的覆盖率引导（当前为结构化变异+随机；环境无 clang/afl，仅 gcc）
- 全量 fuzz 的 PBKDF2（bip39 seed，2048 轮）是性能瓶颈，已降频到 1/64 输入
- 硬件侧信道实测（功耗/EM）需示波器 + 真机，见 SECURITY_AUDIT「后续」表
