# HardID FIDO2 设计 — CTAP2 认证器 (V2.0)

- 日期: 2026-08-12
- 状态: **设计评审中**（先文档、后代码；与仓库文档先行惯例一致）
- 范围: 将 HardID 从只做链上签名，扩展为**同时是标准 FIDO2/WebAuthn 认证器**（CTAP2 over USB HID）。不改变现有链签名管线/SE 信任根；FIDO 断言复用同一签名内核与 SE 密钥信任链。

## 0. 背景与目标

PRD §1 架构定位（v1.1）：HardID 是**标准签名模块**——对外只开放签名操作。
V2.0 路线（PRD §5）把 FIDO2/WebAuthn（CTAP2 认证器）列为远期目标，
"认证断言复用同一签名内核"。工程文档 §8（2026-08-10）确认这一方向。

本设计把该目标落成一份可评审、可里程碑拆分的具体方案。核心目标：

1. **FIDO 凭证私钥永不出 SE**——与链起来的密钥同等级信任，密钥材料
   仍全部由 SE 持有、由 SE 签名，MCU 只做协议/CBOR/传输。
2. **复用现有信任链**——本机 PIN（指数退避）、seed 派生、`os_signsvc`
   WYSIWYS 精神（用户手按确认）继续成立，不新造信任根。
3. **原生 USB HID 传输**——升级到 ESP32-S3 原生 USB 的 HID（TinyUSB），
   浏览器可直接识别为 FIDO 认证器（CTAP HID 设备）。
4. **第一版里程碑收敛**——non-resident（non-discoverable）凭证 + ES256
   (P-256) + 基础 attestation，跑通 `makeCredential`/`getAssertion`；
   resident keys / PIN/UV 协议 / 高级扩展列入后续。

### 术语
- **CTAP2 / FIDO2**：authenticator 侧协议（CBOR 命令集），本设计实现。
- **WebAuthn**：Relying Party(浏览器) 侧协议。设备不实现 WebAuthn，只满足其
  要求的算法与数据格式。
- **CTAP HID / CTAPHID**：CTAP2 在 USB HID 上的帧传输层（REDIRECT: 每包 64B，
  INIT 帧 CID+CMD+BCNT 头 7B，CONT 帧 5B 头）。
- **ES256**：WebAuthn 默认算法 = ECDSA secp256r1 (P-256)，COSE alg -7。
- **attestation**：注册时向 RP 证明"这把凭证出自本认证器"。
- **RP**：Relying Party（网站/服务的明文 + SHA-256 的 rpIdHash）。
- **credential ID / user handle**：凭证标识与用户标识。

## 1. 架构决策（三选一，已定案）

| 决策点 | 选项 | 选定 | 理由 |
|--------|------|------|------|
| 曲线 | (a) 全新增 P-256 (b) 复用 k1 (c) SE 原生 | **(a) MCU 软实现 P-256 + SE 扩接口** | WebAuthn **强制** ES256 (P-256)，k1 无法通过认证；ACL16 是否原生支持 P-256 未确认，故先 MCU 软实现走通，SE 接口预留 |
| 传输 | (a) 隧道复用 linkproto (b) 原生 CTAPHID (TinyUSB) (c) 双轨 | **(b) 原生 USB HID (TinyUSB)** | 浏览器只能用 CTAP HID 发现认证器；隧道方案无法通过浏览器互操作测试 |
| 里程碑 | (a) 完整 CTAP2 v2.0 (b) 最小认证器 (c) 先文档 | **(c) 先文档 → (b) 最小认证器** | 仓库惯例文档先行；第一版收敛到 non-resident + ES256 |

### 1.1 重要硬件约束：USB 双口互斥
ESP32-S3 有 **两个 USB 控制器**（USB-OTG 与 USB-Serial-JTAG），但**共享同一
PHY（GPIO19/20）**，同一时刻只能启用一个（ESP-IDF 文档明确）：

- 现在：链路签名用 USB-Serial-JTAG（CDC 控制台 + linkproto/HOST LINK）。
- FIDO 后：原生 USB-OTG 跑 TinyUSB HID。**若还要保留 CDC 调试/链路控制台，
  必须切到 TinyUSB 暴露 composite（HID + CDC）**，或外部 PHY 同时启用两者。
- 影响：`os_board_hw_init` 的 `usb_serial_jtag_*` 初始化与 linkproto 传输
  层需要抽象/改造；本次不保留外部 PHY 硬件，设计默认 **TinyUSB composite
  (CTAPHID + CDC)**，让链路签名与 FIDO 共存于原生 USB。

## 2. 分层架构

```
浏览器 / WebAuthn                HOST LINK 客户端 (第三方钱包)
   │ CTAP2 over HID                  │ linkproto over CDC
   ▼                                 ▼
┌────────────────────────  ESP32-S3 原生 USB (TinyUSB)  ────────────────────────┐
│  transport: CTAPHID 帧层 (core/fido_ctaphid.c)      CDC 帧层 (link_esp 移植)  │
│  protocol : CTAP2 CBOR 命令 (core/ctap2.c)          linkproto 服务 (linksvc)  │
│  identity : fido_core (凭证管理/attestation)         signsvc (链签名)          │
│  crypto   : P-256 软实现 (core/secp256r1)  ←─ SE 驱动 (se_driver.h 扩展)       │
│  UI       : FIDO 确认屏 (esp-idf-s3 screen.c fido 屏)                          │
└─────────────────────────────────────────────────────────────────────────────────┘
  信任根：SE (种子/派生密钥/PIN 全在 SE、签名在 SE 内) —— FIDO 复用同一 SE
```

- 全部核心逻辑放 `core/`（host 可测），传输/UI 只有极薄胶合层在
  `esp-idf-s3`/`esp-idf` 组件——与现有 linkproto/signsvc 的测试架构一致。
- 新增文件（预期）：
  - `core/secp256r1.c/.h` — P-256 域运算 + ECDSA 签名/验签（clean-room）。
  - `core/fido.h` — FIDO 数据结构：credential、rpIdHash、user handle、
    flags、COSE 头。
  - `core/fido_core.c` — 凭证生命周期：makeCredential / getAssertion /
    GetInfo 应答、凭证派生、attestation 组装。
  - `core/ctap2.c` — CTAP2 CBOR 命令解析/编码 + 错误码映射。
  - `core/fido_ctaphid.c` — HID 帧拆分/重组，INIT/CONT 状态机，CRC。
  - `core/se_driver.h` 扩展：`se_p256*` 接口（见 §5）。
  - `esp-idf-s3/components/hardid/usb_desc.c` — TinyUSB 描述符
    （FIDO usage page 0xF1D0，HID + CDC composite）。
  - `esp-idf-s3/components/hardid/fido_esp.c` — FIDO 屏幕入口
    （从主菜单进入 FIDO 会话）。

## 3. CTAP2 协议范围（第一版）

### 3.1 支持的 CTAP2 命令
| 命令 | CTAP2 值 | 第一版 | 备注 |
|------|---------|--------|------|
| authenticicatorMakeCredential | 0x01 | ✅ | non-resident 凭证注册 |
| authenticicatorGetAssertion | 0x02 | ✅ | 用 allowList 匹配；返回签名断言 |
| authenticatorGetInfo | 0x04 | ✅ | 声明算法支持、选项 |
| authenticatorClientPIN | 0x06 | ❌ 后续 | PIN/UV 协议第二版 |
| authenticatorReset | 0x07 | ⚠️ 受限 | 仅真机长按组合 + 本机 UI 双重确认 |
| authenticatorGetNextAssertion | 0x08 | ❌ 后续 | 依赖 discoverable keys |
| authenticatorConfig | 0x0D | ❌ 后续 | |

### 3.2 GetInfo 应答要点（第一版）
```json
{
  "versions": ["FIDO_2_0"],
  "extensions": [],
  "options": {
    "rk": false,          // first version: non-resident
    "up": true,           // user presence = 触摸确认
    "uv": false,          // first version: 无 PIN/UV 认证
    "clientPin": false,
    "credentialManagement": false,
    "attestationConveyancePreferenceSupported": false
  },
  "algorithms": [{"type": "public-key", "alg": -7}],   // ES256 唯一
  "maxMsgSize": 7609,     // CTAPHID 64B 包：64-7 + 128*(64-5)
  "maxCredentialIdLength": 128,
  "maxCredentialCountInList": 8
}
```

### 3.3 第一版明确不做（防范围蔓延）
- discoverable/resident keys（rk=false）→ 不做 `GetNextAssertion`。
- PIN/UV 协议、bio 指纹、largeBlob、credentialManagement、config。
- 外部 NFC / Hybrid QR（CTAP 2.3 新通道）——无硬件。

## 4. 凭证模型与存储

### 4.1 non-resident 凭证
- **宿主持有 credential ID**，每次断言由 RP 在 allowList 里回传。
- 设备为每个凭证派生独立 P-256 密钥对（见 §5 派生），**私钥只存在于
  SE 内部**，不落 MCU 存储。非 resident 模式下设备侧无需持久凭证存储；
  断言时按 allowList 的 credential ID 反查/重派生，命中即签名。
- 凭证 ID = `HMAC-SHA256(master_seed, credIdSource)`（16-byte 截断作为
  对外呈现的 credentialId；派生信息存入 SE 内部，或由 SE 用内部 KDF
  可重算）。**关键：没有任何私钥/派生种子流出 SE。**

### 4.2 派生路径（建议，待 SE 后端确认）
在 SE 内维护一个 **FIDO 凭证根**（由主种子经 BIP32 派生第 44' 或 +
高位到专用分支，或 SE 独立生成）。每个注册的凭证按
`credential_index || rpIdHash` 派生 P-256 子密钥。这样：
- 私钥永不输到 MCU；签名在 SE 内完成（复用现有 SE 签名能力逻辑）。
- 凭证**无需持久化**（幂等重派生），reset/恢复种子后与链账户一致地恢复。

### 4.3 凭证计数
- 每个 RP 维护 signCount（uint32），断言返回；用于 detect cloned
  authenticator。存 SE 内单调计数器或派生确定性计数（决定：SE 内计数，
  复用现有 `monotonic` 语义，见 se_driver.h）。

## 5. 密码学：ES256 (P-256) 软实现 + SE 扩展

### 5.1 现状
`se_driver.h` 只有 secp256k1 的 `sign_digest(path,digest32,sig64,recid)`、
`get_xpub`、`attest`。**没有 P-256**。WebAuthn 默认/强制算法是 ES256
=P-256 (secp256r1, COSE alg -7)。

### 5.2 两条并行实现
| 实现 | 位置 | 用途 |
|------|------|------|
| P-256 域运算 + ECDSA | `core/secp256r1.c`（新增，host 可测） | 保证 ES256 可用性；支持验签（断言自检）；万一 SE 不支持 P-256 时的兜底路径（DEV 明确标注） |
| SE 接口扩展 | `se_driver.h` + `se_mock.c` | 生产形态：P-256 私钥在 SE、签名在 SE；接口签名沿用签名语义 |

SE 接口建议新增（沿用现有四参数风格，向后兼容）：
```c
/* FIDO: derive-or-create a P-256 credential key for (cred_idx, rp_hash32)
 * inside the SE and sign digest32, outputting 64-byte compact
 * r||s (big-endian). recid is N/A for P-256 (assertion uses raw R,S point). */
int (*fido_p256_sign)(uint32_t cred_idx, const uint8_t rp_hash32[32],
                      const uint8_t digest32[32],
                      uint8_t sig64[64]);
```
- mock SE：先在 `se_mock.c` 用 §4.2 派生物理实现（喂入 P-256 软实现）。
- ACL16：**需向硬件确认原生 P-256 + SHA-256 支持与否**（决策已选 b 方案，
  预留 `fido_p256_sign` 接口形态不变，仅后端实现不同）。

### 5.3 数据流
```
host (浏览器) ──CTAP2 CBOR──> fido_core
   makeCredential -> 派生 cred key (SE 内)，拼 authData (含 rpIdHash|flags|signCount|凭证)
                   -> SE fido_p256_sign(digest = authData || clientDataHash)
                   -> 组装 attestation (COSE x/cert，用 SE attest 密钥)
   getAssertion   -> 按 allowList credId 重派生，拼 authData (含 rpIdHash|flags|signCount)
                   -> SE fido_p256_sign(digest = authData || clientDataHash)
                   -> 返回 {credential, authData, signature}
```
注：CTAP2 §6.1/§6.2 签名对象恒为 `authData ‖ clientDataHash`（rpIdHash 已作为
authData 首字段包含在内），非旁列 rpIdHash。

## 6. 用户交互（复用 WYSIWYS 精神）

- 现有 `screen.c` 已有触摸确认体系（Yes/No、倒计时、`ui_wait_release`）。
  FIDO 新增 **FIDO 会话屏**（从主菜单进入，与 HOST LINK 同级）：
  1. 进入前先 PIN 解锁（复用 `ui_enter_pin`，启用设备 PIN 时）——与
     linkproto 握手一致。
  2. makeCredential：显示屏显示 **RP 域名**（明文）+"注册新登录密钥?" ，
     Yes/No。允许多 RP 明文长于屏幕则滚动/截断提示。
  3. getAssertion：显示 RP 域名 + "确认登录?"，Yes/No；signCount 变化
     提示（检测克隆风险）。
  4. 触摸即 User Presence（up=true）：Yes 按键即确认，无需额外按钮。
- **不做**：RP 提供的完整 user 展示（个人隐私），第一版只显示 RP 名。

## 7. 测试与验证计划

| 层 | 方法 |
|----|------|
| P-256 域运算 | host 单测：RFC6979 向量、自扩展密钥双过、`os_secp256r1_*` 与 Python cryptography 逐字节对齐 |
| CTAPHID 帧 | host 单测：拆包/重组（1..N 包、首包 + CONT 顺序、坏 CRC、超长 BCNT、channel busy）、INIT nonce 匹配 |
| CTAP2 命令 | host 单测：每个命令合法/非法 CBOR、错误码映射、GetInfo 常量 |
| FIDO 协议组合 | host Python 驱动脚本：完整 makeCredential→getAssertion 生命周期 |
| 互操作 | 真机 + 浏览器（Chrome `WebAuthn` demos）、Yubico `ctap-hid-fido2` 工具、FIDO2 conformance 工具集（预排，非认证） |
| SE 后端 | 真机 ACL16 后跑同一 host 用例，交换后端零改动 |

CI：host-tests workflow 增加 P-256/CTAP/CTAPHID 套件；保留既有"每轮蓝/绿"

## 8. 里程碑拆分

| 里程碑 | 内容 | 出口标准 |
|--------|------|---------|
| F1 | 设计评审通过、文档合入 | 本设计经 eng review 无 blocked 项 |
| F2 | `core/secp256r1` 软实现 + host 单测 | RFC6979 双过 + Python 对齐 + CI 入套件 |
| F3 | TinyUSB composite 上板（HID FIDO usage + CDC），CTAPHID 帧层 | 真机 `lsusb` 见 FIDO 设备；host 测试 CTAPHID；linkproto 经 CDC 仍通 |
| F4 | `fido_core` + `ctap2`：makeCredential/getAssertion/GetInfo，SE mock 后端 | host Python 生命周期双过；无 PIN dev 构建真机浏览器 demo |
| F5 | FIDO 确认屏 + PIN 门 + attestation | 真机两条完整流程 + 截图证据；`ctap-hid-fido2` 通过 |
| F6 | (视硬件) ACL16 P-256 后端；FIDO2 conformance 预排 | SE 真机流程双过 |

## 9. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| ACL16 无原生 P-256 | 生产后端要变 | 设计已隔离 SE 接口变化；MCU 软实现先可用（标注 DEV），等硬件确认 |
| USB 双控制器互斥 | 影响现有 CDC 控制台/链路签名 | 设计默认 TinyUSB composite（HID+CDC 同设备）；改造 link_esp 到 composite CDC |
| Sign count 存储一致性 | 克隆检测失效 | 确定性派生计数 or SE 内单调计数（选一，实现文档固化） |
| CBOR 攻击面 | 解析器漏洞 | 只在 core 用有界解析（同 psbt/clearsign 的 review 惯例），host fuzz 补 |
| 浏览器互操作细节 | 过不了 WebAuthn demo | F4/F5 真机 demo + conformance 预排为硬性出口 |

## 10. 与现有系统的关系（不回归保证）

- **链路签名不受影响**：linkproto 传输迁移到 composite CDC 后，既有
  `hd_link_serve`/`os_signsvc_delegate` 与 host 测试原样运行。
- **SE 信任根不变**：FIDO 私钥派生/签名仍全在 SE；`se_driver.h` 向后兼容
  追加接口，老后端编译不受破坏（新增字段可弱符号/函数指针数组扩展）。
- **主菜单**：新增 FIDO 入口（初始化后可见）；无 PIN dev 构建下仍可直接进
  FIDO（对齐 HOST LINK dev 行为）。