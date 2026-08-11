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
  （S3 测试板当前无双 SE，软件侧由 §3.3 物理熵池补强，2026-08-11 落地）
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
- **升级点**: 旧版单源（STM32 TRNG）→ 新版多源混合（核心熵 + 物理熵池）

```c
// 种子生成的多源混合（HKDF-SHA256, RFC 5869）
// PRK = HMAC(salt="HardID seed v1", se1_trng || se2_trng || host_entropy || phys[32])
//   注: se2 槽位由 os_seed_se2_trng 提供, weak 缺省回退主控 TRNG (单 SE 构建)
// OKM = HMAC(PRK, "mnemonic" || 0x01)
```
HKDF 已用 RFC 5869 Test Case 1 验证（rng-test/test_hkdf.c）。

**物理熵池（2026-08-11 落地，设计见 08_HardID_多熵源设计.md）**
- `core/phys_entropy.c`：无条件 SHA-256 熵池，全部物理源先过池再混入 Extract
  输入（禁止任何单源原始字节直接作密钥材料）；前缀安全长度域 + 单次提取擦除。
- `core/seed.h` 新增可选钩子 `os_seed_phys_extra(buf, len)`（弱符号缺省返回 1
  = 跳过，绝不 fail-closed）。板层 entropy_s3.c / entropy_p4.c 实现 strong 版。
- 物理源：S4 触摸坐标 LSB 抖动 + S5 温度传感器热噪声（esp_driver_tsens）+
  S6 I2C 应答延迟 LSB + S7 RTC 慢时钟漂移（S3 读 RTC_CNTL_TIME0_REG，
  P4 无此寄存器用 esp_timer）。
- **链接陷阱（已修复）**：entropy 模块唯一导出符号与 seed.c 的 weak 缺省同名，
  GNU ld 归档扫描用 weak 满足引用、不提取 strong obj → 板层
  `os_entropy_force_link()` 强制拉入（`os_board_hw_init` 调用），ELF W→T 验证。
- REQUIRES 增加 `esp_driver_tsens`、`esp_timer`。

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
| 单元 | 主机模拟（stub 寄存器/SE） | rng.c 8/8 通过；HKDF RFC5869 向量通过；phys_entropy 池通过 |
| 解析 | fuzzing（PSBT/EIP-712 畸形输入） | fuzz 50k 无崩溃 |
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

## 8. 实现进展（2026-08-10，S3 测试板走查轮）

本日在 ESP32-S3 测试板（mock SE + 无 PIN dev 构建）首次烧录走查，24 个提交。模块级变更：

> **架构定位（PRD v1.1，2026-08-10 定案）**：HardID 收敛为**标准签名模块**——开放签名接口给第三方调用，只做签名，不能进行任何其他操作；管理操作（init/recover/wipe/brain phrase）仅设备本机 UI，永不进入接口面。工程含义：linkproto/HOST LINK 是开放签名接口的 v0 形态，按"单动词 SIGN 契约"收敛（拒绝一切非签名动词）；**SIGN 请求为结构化载荷**（app id + BIP32 路径 + 原始交易字节，PRD §3.4），经 `os_signsvc_delegate` 与设备本机 SIGN 走同一解析→固件独立复核→WYSIWYS 确认→真链 sighash→SE 签名管线（2026-08-11 `f40a653` 关闭盲签红线，废除裸 digest/主密钥签名入口）；FIDO2/CTAP2 列入 V2.0 路线，认证断言复用同一签名内核。

**signsvc（签名委派）**
- 真 sighash 管线落地：EVM 走 `os_evm_sighash`（EIP-155：6 字段 legacy 注入 app 预期 chainId；9 字段空 r/s 载荷校验 v；typed 信封校验 chainId 字段；已签名输入拒绝）；BTC 系走 `os_btc_sighash_from_psbt`（BIP143 全 preimage：hashPrevouts/hashSequence/outpoint/scriptCode/amount/nSequence/hashOutputs/locktime/type；仅原生 P2WPKH + SIGHASH_ALL，其余拒绝）。官方测试向量双过（EIP-155 `daf5a779…`、BIP143 `c37af311…`）
- BTC 逐输入签名：`os_sign_outcome` 增 `sigs[16][64] + recids + sig_count`（EVM 单签保持 sig64）
- fw_reparse 按**解析器能力**分派（BTC 族 0/2/3/145、EVM 族 60/61/966），目录链从"可安装不可签"修复为可签；`apply_native_symbol` 统一规范化显示代币符号
- NULL confirm 恒 ABORT（删除从未定义的 `HARDID_HOST_TEST` 死旁路）；verify_intent 不再 const-cast 改调用方 intent

**App parse vtable**：加 `coin_type` 参数（4-arg）——共享解析器据此渲染 per-coin 地址。psbt.c 地址表：BTC(bc/0x00/0x05)、LTC(ltc/0x30/0x32)、DOGE(无 segwit, 0x1e/0x16)、BCH(legacy base58; cashaddr 待后续)；bech32 HRP 参数化。与 Python BIP173 参考逐字节一致

**se_mock（mock SE，dev 构建）**
- `derive_session()`：brain phrase → volatile session seed（HardID 两步 KDF，规范写在 se_driver.h）；wipe/掉电即失
- NVS 持久化种子+PIN（`ESP_PLATFORM` guard，host 测试保持纯 RAM）——mock 天然 RAM-only 导致 brain phrase gate 在真机永远触发不了；brain phrase 本身**绝不持久化**
- wipe 同步清零 PIN 缓冲

**UI（S3 组件）**
- 键盘三页字符集（A-Z / a-z / 0-9+16符号），passphrase 录入路径专用；预览对非 A-Z 字符回退 font7
- Recover 录入实时候选列表（`os_bip39_words_with_prefix`，首字母即出 3×8 候选 + 溢出计数）；WORD N 恒显修复
- 主菜单按 `is_initialized` 动态隐藏 INITIALIZE/RECOVER
- 主菜单交互定稿（走查驱动，`67c176a`/`9b17fa4`）：当前项包在通栏选框内高亮，仅 OK 键或选框内点击激活，点其他区域忽略（原"点任意区域即选中"易误触）；选框通栏 240px 以容纳最长标签 FACTORY RESET（13 字符 2x = 232px）；顶部提示小字 5x7→2x
- HOST LINK 会话改显式 BACK 按钮退出（原"点任意处退出"，stray 触摸会误退会话）
- **RGB565 字节序修复**：ST7789 默认大端色数据，全部 16 位色值此前被对调（按钮蓝碰巧仍像蓝未被发现，LOGO 暴露）——panel 配置 `.data_endian = LCD_RGB_DATA_ENDIAN_LITTLE`；按钮改品牌蓝 0x039E
- **esp_lcd 零拷贝队列竞态修复**（`60c1e3d`）：SPI 颜色传输是零拷贝+异步队列，`draw_bitmap` 返回时 DMA 仍在读调用方栈上行缓冲；函数返回后栈被触摸/I2C 轮询复用 → 末批纯色区域（选框、导航键）出现彩色窄条。修复：每个绘制函数返回前发 MIPI DCS NOP（0x00）——io 驱动在发 polling 命令前会收割全部在途事务，借此排空队列
- LOGO 可复现生成器 `logo/gen_logo.py`（PIL：黑底合成→LANCZOS→RGB565→core/logo.h）

**测试**：host 22 套件 + 3 adversarial 套件全绿（composite t3 pin 预存失败除外，与本轮无关）。新增：test_se t8（brain phrase KDF 固定向量）、test_clearsign t13（EIP-155 官方向量+拒绝项）、test_psbt t6/t7（per-coin 地址、BIP143 官方向量+拒绝项）、test_app t17/t18（目录链签名+族摘要锁定）。测试构造器 RLP 改规范编码（单字节 <0x80 直编）、witness_utxo fixture 改规范 CTxOut

**dev-only Kconfig**（均依赖 SE_MOCK，生产默认关）：`HARDID_DEV_NO_PIN`、`HARDID_DEV_TEST_SEED`（4 词测试种子）

---

## 9. 实现进展（2026-08-11，多熵源 Layer A）

本日提交 `c4ca262`..`46c3252`，落地设计文档 08 的 Layer A 物理熵源。模块级变更：

**phys_entropy（新模块，core/）**
- 无条件 SHA-256 熵池：`os_phys_pool_init/absorb/extract`；absorb 带前缀安全
  长度域（长度字段入池），extract 输出 32B 且擦除池（单次使用）。host 测试
  `tests/test_phys_entropy.c` 覆盖长度域混淆 / 顺序敏感性 / 提取后擦除。
- 设计原则：禁止任何单源原始字节直接作密钥材料——全部物理源先过池。

**seed.c 钩子**
- `os_seed_phys_extra()` 弱符号缺省返回 1（跳过）；strong 实现（板层）返回 0
  时混入 HKDF Extract 输入。任一子源失败仅跳过该子源，整体不 fail-closed。

**entropy_s3.c / entropy_p4.c（板层采集）**
- S4 触摸：CST816D 坐标低 4 位抖动，150ms 窗口 ≤64 样本（请求 2ms 间隔，
  实际受 CONFIG_FREERTOS_HZ=100 限制为 ~10ms/tick，有界防 stall）；S5 tsens：install→enable→8×get_celsius 取 float LSB→disable+uninstall；
  S6 总线：touch_get 读延迟（esp_timer 差）LSB；S7 RTC：S3 读 RTC_CNTL_TIME0_REG
  低位，P4 用 esp_timer。
- `os_entropy_force_link()`：见 §3.3 链接陷阱修复。
- CMakeLists 增 REQUIRES `esp_driver_tsens`、`esp_timer`；两平台构建通过。

**DEV 触摸注入器（touch.c + Kconfig，dev-only）**
- `CONFIG_HARDID_DEV_TOUCH_INJECT`（依赖 SE_MOCK，默认 n）：USB-JTAG RX 收
  `P x y` / `R` 行合成触摸，atomic_int 跨核同步，与真实 CST816D 事件同入口。
  用途：无触屏/自动化真机走查（初始化全链路、熵采集回归）。

**真机验证（S3）**
- DEV 注入器驱动 UI：menu OK → 4 词 TEST → `seedgen begin` → `temperature_sensor:
  Range [-10°C~80°C]` → `physical entropy mixed into seed` → `seedgen done rc=0`。
- 链接修复后 ELF 符号 `os_seed_phys_extra` 由 W 变 T；恢复生产配置引导干净。

**测试**：host 新增 phys_entropy 套件，26 套件全绿（composite t3 预存失败
除外）；fuzz 50k 无崩溃；CI host-tests.yml 加入 phys_entropy 分支。

---

*关联文档：`01_PRD`、`02_ERD`、`03_时序图`、`安全核心审核报告.md`、`代码/RNG_HARDENING_MEMO.md`、*`../MEMORY.md`*
*文档结束*
