# HardID 硬件钱包 — ERD 实体关系图

> **版本**: v1.0
> **日期**: 2026-08-02
> **说明**: 硬件钱包无传统数据库，本 ERD 描述**设备内持久化状态**（安全芯片 SE 安全存储区 + 主控 flash 配置区）与**会话内实体**的逻辑关系。标注 [SE] 的实体仅存于安全芯片；标注 [FLASH] 的存于主控；标注 [HOST] 的仅存于主机端。

---

## 1. 实体关系总览

```
                        ┌──────────────┐
                        │   Device     │ 设备（出厂身份）
                        │  [SE+FLASH]  │
                        └──────┬───────┘
                               │ 1:1
              ┌────────────────┼────────────────┐
              │                │                │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
       │  SeedVault  │  │  PinState   │  │ Firmware    │
       │ 种子库 [SE]  │  │ PIN 态 [SE] │  │ 固件 [FLASH]│
       └──────┬──────┘  └─────────────┘  └─────────────┘
              │ 1:N
       ┌──────▼──────┐         ┌──────────────┐
       │   Account   │────────>│  Multisig    │
       │  账户 [SE]  │  N:0..1 │  配置 [SE]   │
       └──────┬──────┘         └──────────────┘
              │ 1:N
       ┌──────▼──────┐         ┌──────────────┐
       │   Address   │<────────│  AddressBook │
       │ 地址(派生)  │  [HOST] │  地址簿      │
       └─────────────┘         └──────────────┘
              │ 1:N
       ┌──────▼──────────────┐
       │   Transaction       │ 交易（无持久化，会话实体）
       │  ├─ UnsignedTx      │
       │  └─ SignedTx        │
       └──────┬──────────────┘
              │ 受策略约束
       ┌──────▼──────┐  ┌──────────────┐
       │ SignPolicy  │  │  AuditLog    │
       │ 签名策略[SE] │  │ 审计日志[SE] │
       └─────────────┘  └──────────────┘
```

---

## 2. 实体定义

### 2.1 Device（设备）[SE+FLASH]
| 字段 | 类型 | 存储 | 说明 |
|------|------|------|------|
| device_id | string(32) | SE | 128 位唯一序列号（SE 出厂预置） |
| vendor_cert | bytes | SE | 一机一密出厂证书（正品验证用） |
| model | string | FLASH | 硬件型号（V1 / V2 指纹版） |
| created_at | timestamp | FLASH | 首次初始化时间 |

### 2.2 SeedVault（种子库）[SE]
> 设备仅一个活动种子 + 可选胁迫种子。私钥材料永不读出 SE。

| 字段 | 类型 | 说明 |
|------|------|------|
| seed_handle | opaque ref | SE 内部句柄（非密钥本身） |
| strength | enum(128/192/256) | 助记词强度 |
| has_passphrase | bool | 是否启用第 25 词 |
| fingerprint | bytes(4) | BIP32 主密钥指纹（可公开） |
| created_at | timestamp | 生成时间 |

**关系**: 1 Device — N SeedVault（1 主 + 1 胁迫诱饵）
**红线**: 无任何删除/擦除路径（自毁禁令）

### 2.3 Account（账户）[SE 派生]
| 字段 | 类型 | 说明 |
|------|------|------|
| account_index | uint32 | BIP44 account' |
| coin_type | uint32 | BIP44 coin'（0=BTC, 60=ETH, id 专用类型码） |
| xpub | string | 扩展公钥（可导出给主机做 watch-only） |
| label | string(32) | 用户命名 |

**关系**: 1 SeedVault — N Account；N Account — 0..1 MultisigConfig

### 2.4 Address（地址）[派生，不持久化]
| 字段 | 类型 | 说明 |
|------|------|------|
| derivation_path | string | m/44'/coin'/acct'/change/index |
| address | string | 编码后地址（base58/bech32/checksum） |
| used | bool | 是否已收付（由主机地址簿同步） |

### 2.5 Transaction（交易）[会话实体]
| 字段 | 类型 | 说明 |
|------|------|------|
| tx_id | hash | 交易哈希 |
| chain | enum | BTC / ETH / ... |
| unsigned | struct | UnsignedTx（PSBT / EVM raw） |
| parsed_intent | struct | Clear Sign 解析结果：to, amount, fee, method, risk_level |
| signature | bytes | SignedTx（签名结果，唯一允许离开设备的输出） |
| status | enum | parsed → confirmed → signed / rejected |

**约束**: parsed_intent.risk_level=unknown 时必须二次确认才可签名

### 2.6 SignPolicy（自动签名策略）[SE]
| 字段 | 类型 | 说明 |
|------|------|------|
| policy_id | uint32 | 策略 ID |
| account_ref | ref→Account | 绑定账户 |
| per_tx_limit | uint256 | 单笔限额（最小单位） |
| window_limit | uint256 | 时间窗限额 |
| window_seconds | uint32 | 窗口长度（如 86400） |
| window_spent | uint256 | 当前窗口已用额度（持久化） |
| window_start | timestamp | 当前窗口起点（持久化） |
| pending_change | bool | 策略修改冷静期标记（24h 后生效） |

**约束**: window_spent/window_start 掉电持久化；超限回落手动确认

### 2.7 PinState（PIN 状态）[SE]
| 字段 | 类型 | 说明 |
|------|------|------|
| pin_hash | bytes | PIN 加盐哈希（SE 内） |
| fail_count | uint32 | 连续错误次数（持久化） |
| lock_until | timestamp | 退避截止时间（持久化） |
| duress_pin_hash | bytes|null | 胁迫 PIN（→诱饵视图，不擦除） |

**红线**: 无 max_attempts 字段——永不触发擦除

### 2.8 MultisigConfig（多签配置）[SE]
| 字段 | 类型 | 说明 |
|------|------|------|
| threshold_m | uint8 | M |
| total_n | uint8 | N |
| cosigner_xpubs | list | 共同签署人 xpub 集合 |
| script_type | enum | P2SH / P2WSH / Taproot |

### 2.9 Firmware（固件）[FLASH]
| 字段 | 类型 | 说明 |
|------|------|------|
| version | semver | 当前版本 |
| monotonic_counter | uint32 | 防降级计数器（只增） |
| signature | bytes | 固件签名（bootloader 验签） |
| build_hash | hash | 可复现构建比对哈希 |

### 2.10 AuditLog（审计日志）[SE，环形缓冲]
| 字段 | 类型 | 说明 |
|------|------|------|
| seq | uint64 | 单调序号 |
| event | enum | boot/rng_fail/pin_fail/sign/sign_auto/policy_change/fw_update/tamper |
| detail | bytes(32) | 摘要（不含敏感数据） |
| timestamp | timestamp | 时间 |

### 2.11 AddressBook（地址簿）[HOST]
仅存主机端：常用收款地址标签、账户 watch-only xpub、余额缓存。设备不信任其内容，收款地址必须在设备屏幕二次确认。

---

## 3. 关键不变量（Invariants）

1. SeedVault 的私钥材料不存在任何读出接口（含调试模式）
2. PinState 无擦除触发器；SignPolicy 修改必经冷静期
3. Transaction 只有 status=signed 时 signature 才存在且可输出
4. Firmware.monotonic_counter 不可逆
5. AuditLog 仅追加，单条不可改（环形覆盖最旧记录）

---

*文档结束*
