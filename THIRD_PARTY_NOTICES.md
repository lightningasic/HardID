# OpenShield — Third-Party Notices & License Provenance

> **日期**: 2026-08-02
> **目的**: 记录 OpenShield 代码的许可证来源与合规处置

---

## 1. 结论

OpenShield 的全新代码（`code/` 目录）为 **clean-room 重写**，采用 **Apache License 2.0**。

经全量审查（2026-08-02），上游 BitExchange-Hardware-Wallet 仓库 **不含任何 Ms-RSL 污染**，其代码基础为 2014 年 **LGPLv3** 时代的 TREZOR One 固件。即便如此，为彻底消除协议传染风险与技术债，核心加密与安全模块已完全重写，不复制任何 TREZOR 代码。

---

## 2. 上游组件清单

| 组件 | 来源 | 许可证 | 处置 |
|------|------|--------|------|
| trezor-mcu (固件, 2014 fork) | SatoshiLabs | **LGPLv3** | 仅参考架构思路；**不复制代码**；新代码 Apache 2.0 |
| trezor-crypto (密码学子库) | SatoshiLabs (Tomas Dzetkulic, Pavol Rusnak) | **MIT** | 可自由使用（若引用，保留 MIT 头） |
| ed25519-donna | Andrew Moon (floodyberry) | **Public domain / MIT-like** | 可自由使用 |
| libopencm3 | libopencm3 project | **LGPLv3** | 硬件抽象库，若使用按 LGPL 动态/静态链接规则处理 |
| Ms-RSL 代码 | — | — | **经审查：零引用**（见 §3） |

---

## 3. Ms-RSL 污染审查记录（2026-08-02）

针对"TREZOR 2014-08-01 曾尝试 relicense 为 Ms-RSL"的担忧，做了以下核查：

| 检查项 | 方法 | 结果 |
|--------|------|------|
| 全仓库 Ms-RSL 头 | `grep -rl "Reference Source License"` 170 源文件 | **0 个** |
| 核心文件许可证头 | 逐文件读头部 | 53/53 为 LGPLv3 |
| trezor-mcu master 最终状态 | 克隆官方仓库查 COPYING | **一直是 LGPLv3**（至 2019 归档） |
| Ms-RSL relicense 提交 2147c5f | `git branch --contains` | **不在任何分支**，从未进 master |
| 2014-08 后新特征 | 查 trezor.io 头、EMULATOR 宏、SECS/CECS | **0 处引用** |
| 2018 年 BitExchange 多币种提交 | 读 commit diff | 仅改数据常量（币种名、forkid 0x4f），非代码抄袭 |

**结论**: BitExchange 是 2014 年 LGPLv3 时代的合法 fork，无 Ms-RSL 风险。

---

## 4. 为何仍选择完全重写

1. **技术债**: 2014 代码携带 wallet.fail 演示的全部漏洞（STM32 flash 提取、无 RNG 自检等）
2. **架构演进**: OpenShield 采用 SE 存钥 + 三源熵 + Clear Sign，与旧架构本质不同
3. **协议自由**: Apache 2.0 比 LGPL 更利于商业合作与硬件分发（无静态链接开源义务）
4. **知识产权干净**: clean-room 重写 = 无衍生作品争议

---

## 5. 新代码许可证

`code/` 目录下所有 OpenShield 原生代码采用：

```
Apache License 2.0
Copyright (C) 2026 LightningASIC / OpenShield contributors
```

选择 Apache 2.0 而非 GPLv3 的理由：
- 含明确的**专利授权条款**（对硬件+软件混合产品重要）
- 允许闭源商业分发（利于未来 ODM/合作）
- 与"完全开源"原则兼容（代码仍全部公开，只是授权更自由）

---

*审查人: opencode (AI) — 建议由法务对最终产品分发做正式合规确认*
