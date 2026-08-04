# HardID 硬件钱包 — 软件开发工程文档

> **版本**: v1.0
> **日期**: 2026-08-02
> **上游**: 自 BitExchange-MCU (2014 TREZOR fork) 演进

---

## 1. 系统架构

```
┌────────────────────────────────────────────────────┐
│                    主机端 (Host)                     │
│  Sparrow / Electrum / MetaMask / HardID-bridge │
│  - 构造交易(PSBT/rawTx)、广播、地址簿、watch-only    │
└──────────────────┬─────────────────────────────────┘
                   │ QR 气隙(优先) / USB 最小数据面
┌──────────────────▼─────────────────────────────────┐
│                   主控 MCU (应用处理器)              │
│  ┌──────────┬──────────┬──────────┬───────────┐    │
│  │ UI/显示  │ 交易解析  │ 协议层    │ 通信栈     │    │
│  │ Clear    │ Clear    │ PSBT/    │ QR/USB    │    │
│  │ Sign渲染 │ Sign引擎 │ EIP-712  │           │    │
│  └──────────┴──────────┴──────────┴───────────┘    │
│  ┌──────────────────────────────────────────────┐  │
│  │ 加密服务层(调用SE，不持密钥)                    │  │
│  │ HKDF / RFC6979协调 / 地址派生(xpub only)      │  │
│  └──────────────────────────────────────────────┘  │
│  无密钥材料存储 — flash 只放固件+配置                │
└──────────────────┬─────────────────────────────────┘
                   │ SPI / I2C / ISO7816
┌──────────────────▼─────────────────────────────────┐
│              安全芯片 SE (EAL6+)                     │
│  - 种子/私钥存储(不可读出)  - PIN 验证与退避状态      │
│  - 硬件 TRNG              - ECDSA 签名(SE内完成)     │
│  - SignPolicy 持久化      - 单调计数器(防降级)        │
│  - 一机一密出厂证书        - 抗 DPA/错误注入          │
└────────────────────────────────────────────────────┘
```

**设计铁律**: MCU 是"可 compromised 的"，SE 是信任根。任何密钥运算、PIN 比对、策略计数都在 SE 内；MCU 只处理解析与显示。

---

## 2. 硬件选型（已定案：ESP32-P4 + 双 ACL16，见 05_硬件选型决策报告）

### 2.1 主控：ESP32-P4
- **RISC-V 双核**（HP + LP），**无射频**（天生气隙），MIPI-CSI 相机 + MIPI-DSI 大屏
- 大 SRAM/PSRAM：支撑 Clear Sign 重解析（EVM ABI、RLP、大 PSBT、EIP-712）与大屏渲染
- 注意：沿用 STM32F2 的旧 BitExchange 设计**不可接受**（wallet.fail 已演示 flash 提取），故私钥绝不留主控
- flash 加密 + Secure Boot v2；固件可复现构建

### 2.2 安全芯片：双 航芯 ACL16（EAL6+）
- **SE1「金库」**：种子存储、BIP32 派生、ECDSA 签名、TRNG#1
- **SE2「守卫」**：PIN 验证+退避、SignPolicy 限额计数、单调计数器（防降级）、出厂证明、TRNG#2
- **职责分离**：单点被攻破不全局失守；签名授权可由两颗独立芯片交叉强制
- **三源熵升级**：`SE1_TRNG || SE2_TRNG || host_entropy` —— 主控 TRNG 退出信任链
- **关键待验证**：ACL16 是否硬件原生支持 secp256k1（若否需重评）

### 2.3 备选 SE（若 ACL16 secp256k1 不支持）

| 芯片 | 认证 | 说明 |
|------|------|------|
| 紫光同芯 | EAL6+ | 车规积累，备选 |
| 汇顶 eSE | SOGIS CC EAL6+ + 商密二级 | 算法最全，成本较高 |

### 2.4 版本规划对应
- V1：无相机 → 主机扫码传入，屏幕 QR 输出签名
- V2：P4 原生 MIPI-CSI 相机 + 指纹 + 大屏 → 全气隙（QR 输入 + QR 输出）

---

## 3. 软件模块

### 3.1 仓库结构（建议）

```
hardid-mcu/
├── bootloader/          # 安全启动，验签，防降级
├── firmware/
│   ├── main.c           # 启动: rng_self_test → 主循环
│   ├── rng.c            # TRNG驱动(加固版,见 RNG_HARDENING_MEMO)
│   ├── se_driver.c      # SE 抽象层(ACL16/紫光/汇顶可切换)
│   ├── clearsign/
│   │   ├── btc_psbt.c   # PSBT 解析 + 找零校验
│   │   ├── evm_tx.c     # legacy/EIP-1559
│   │   └── eip712.c     # 结构化数据 schema 渲染
│   ├── policy.c         # SignPolicy 限额/窗口/冷静期
│   ├── pin.c            # PIN 退避(逻辑在SE，MCU仅传参)
│   ├── multisig.c       # M-of-N 配置与部分签名
│   └── ui/              # 屏幕渲染、乱序键盘、QR 显示
├── crypto/              # HKDF、BIP32/39/44(xpub侧)、RFC6979协调
├── host-tools/          # bridge、QR 编解码、复现构建校验
└── tests/
    ├── host-sim/        # 主机模拟测试(rng/HKDF已验证模式)
    └── fuzz/            # PSBT/交易解析 fuzzing
```

### 3.2 SE 驱动抽象层（关键解耦）

双 SE 架构下，组合驱动 `se_composite` 将调用路由到 SE1（金库）或 SE2（守卫）。`se_driver.h` 接口已按此拆分（见 `code/core/se_driver.h`）：

| 接口 | 路由 | 说明 |
|------|------|------|
| `store_seed` / `is_initialized` / `sign_digest` / `get_xpub` | **SE1** | 密钥相关 |
| `verify_pin` / `policy_authorize` / `monotonic_*` / `attest` | **SE2** | 访问控制与状态 |
| `get_random` | SE1 + SE2 | 双 TRNG，HKDF 各自喂入 |

```c
// se_composite.c — 路由示例（真实后端 se_acl16.c 实现单颗驱动,组合层复用×2）
static const se_driver_t composite = {
    .get_random       = se_dual_get_random,     /* SE1||SE2 各取并混合 */
    .store_seed       = se1_store_seed,
    .is_initialized   = se1_is_initialized,
    .sign_digest      = se1_sign_digest,        /* SE内完成,可要求SE2解锁令牌 */
    .get_xpub         = se1_get_xpub,
    .verify_pin       = se2_verify_pin,
    .policy_authorize = se2_policy_authorize,
    .monotonic_read   = se2_monotonic_read,
    .monotonic_increment = se2_monotonic_increment,
    .attest           = se2_attest,
};
```

**安全不变量（第 16 轮审计）**：`sign_digest` 必须要求会话已被 `verify_pin` 解锁（双 SE 时可由 SE2 签发短时令牌，SE1 验签后签名——两颗独立芯片交叉强制）。

```c
// se_driver.h — 所有 SE 操作经此接口，可切换供应商
typedef struct {
    int (*init)(void);
    int (*get_random)(uint8_t *buf, size_t len);
    int (*store_seed)(const uint8_t *seed32);          // 一次性,不可读
    int (*sign)(const uint8_t *path, uint32_t path_len,
                const uint8_t *digest32, uint8_t *sig64); // SE内完成
    int (*verify_pin)(const uint8_t *pin, uint32_t len,
                      uint32_t *wait_seconds_out);      // 返回退避等待
    int (*policy_check_and_consume)(uint32_t policy_id,
                uint64_t amount, bool *need_manual_out);
    int (*monotonic_read)(uint32_t *counter);
    int (*monotonic_increment)(void);
} se_driver_t;
```

### 3.3 RNG 子系统（已加固）

复用 2026-08-02 对 BitExchange rng.c 的加固成果（`代码/RNG_HARDENING_MEMO.md`）：
- 错误标志恢复（SEIS/CEIS 清除 + RNG 块复位，RM0090 序列）
- 有界轮询 + 失败安全停机（`rng_fatal_error`，可覆写显示错误）
- 启动自检 `rng_self_test()`（stuck-at / 重复输出检测）
- **升级点**: 旧版单源（STM32 TRNG）→ 新版三源混合

```c
// 种子生成的三源混合（HKDF-SHA256, RFC 5869）
// PRK = HMAC(salt="HardID seed v1", se_trng || mcu_trng || host_entropy)
// OKM = HMAC(PRK, "mnemonic" || 0x01)
```
HKDF 已用 RFC 5869 Test Case 1 验证（rng-test/test_hkdf.c）。

### 3.4 Clear Sign 引擎

**解析优先级**:
1. 已知合约 ABI（内置常用：ERC20 approve/transfer、主流 DEX router）
2. EIP-712 typed data（按 schema 逐字段渲染）
3. 简单转账（原生币/标准代币）
4. **未知一律降级**：红色警告 + calldata 哈希 + 长按确认，绝不猜测

**地址显示**: EIP-55 校验和大小写 + 首尾缩略，屏幕与签名数据同源（同一结构体渲染，杜绝"显示 A 签 B"）。

### 3.5 PIN 子系统（无自毁）

- PIN 哈希 + fail_count + lock_until 全部在 SE
- MCU 只显示"请等待 HH:MM:SS"，无法绕过、无法重置计时
- 掉电持久化：每次失败立即写 SE
- 胁迫 PIN：SE 返回"切换视图"标志，MCU 挂载诱饵 SeedVault

---

## 4. 通信协议

### 4.1 QR 气隙（优先）
- 入：主机显示 PSBT/交易 → 设备相机扫描（V2）或手动确认哈希（V1 无相机时用 USB 传数据但视为不可信输入）
- 出：设备屏幕显示签名 QR（UR 编码，BC-UR 标准分片）
- 数据格式：crypto-psbt / eth-sign-request / eth-signature（遵循 Blockchain Commons UR）

### 4.2 USB 最小数据面
- 仅 3 类消息：TxIn（待签）、SigOut（签名）、Version（版本查询）
- 无调试、无内存读写、无固件读写接口
- 所有输入视为不可信，经 Clear Sign 解析与边界检查

---

## 5. 构建与发布（可复现构建）

```bash
# 工具链锁定
arm-none-eabi-gcc 13.2.1 (固定版本)
# 可复现构建
make reproducible   # SOURCE_DATE_EPOCH 固定, 去路径/时间戳
sha256sum hardid-v1.0.0.bin
# 与 release 公布的哈希比对 — 任何第三方可验证
```

**发布流程**: 源码 tag → CI 复现构建 → 多签名者独立构建比对哈希一致 → 固件 ECDSA 签名 → 发布（bin + 哈希 + 签名 + 构建日志）

---

## 6. 测试策略

| 层 | 方法 | 已验证资产 |
|----|------|-----------|
| 单元 | 主机模拟（stub 寄存器/SE） | rng.c 8/8 通过；HKDF RFC5869 向量通过 |
| 解析 | fuzzing（PSBT/EIP-712 畸形输入） | 待建 |
| 集成 | 主机模拟全流程（初始化→签名→退避→升级） | 待建 |
| 故障注入 | 调试器强制 SEIS、断电恢复退避计时 | 待真机 |
| 审计 | 第三方固件安全审计 + 渗透测试 | 发布前 |

---

## 7. 与 BitExchange 遗产的关系

| 组件 | 处置 |
|------|------|
| rng.c | **已加固**（RNG_HARDENING_MEMO.md），可直接移植 |
| HKDF 熵混合 | **已实现**于 reset.c，改为 "HardID seed v1" salt |
| 裸 SHA256 混合 | 废弃 |
| STM32F2 主控存钥 | 废弃 → SE 存钥 |
| USB 全功能接口 | 废弃 → QR 优先 + USB 最小数据面 |
| PIN 自毁设计（旧 TREZOR 传统） | **禁止** → 指数退避无上限 |

---

*关联文档：`01_PRD`、`02_ERD`、`03_时序图`、`安全核心审核报告.md`、`代码/RNG_HARDENING_MEMO.md`*
*文档结束*
