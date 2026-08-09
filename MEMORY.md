# MEMORY.md

## V2.0 架构升级与多轮循环审计 (当前主线, 2026-08)

### 工作流约定 (用户确认 2026-08-09)
- **只在 ESP32-S3 (esp-idf-s3) 开发 + 烧录验证; 确认真机行为正确后再移植到 P4 (esp-idf)。**
- 不要每次改动都 cp 到 esp-idf/ 并构建 P4; 等用户确认 S3 真机 OK 再同步。

### 架构决策 (用户确认)
- 主私钥 = BIP32 根种子; App 部署 = 运行期动态安装; 市场 = 官方审查制;
  签名 = 委派给系统固件 (App 永不接触私钥); App = 官方核心+三方提交;
  Clear Sign 解析 = App 自带解析器。
- 签名唯一入口 `os_signsvc_delegate`; WYSIWYS 用固件 clean-room 独立解析器
  fw_reparse (按 coin_type 分派) 与 App intent 精确比对, 不是重跑 App.parse。
- 无固件解析器的链拒绝签名 (与官方审查制一致)。

### 提交链 (本地 main, 领先 origin)
- `0af3021` V2.0 app 架构 (core/app.h, app_registry, signsvc) + S3/P4 + 测试
- `af0dcc7` 自审计轮1 (verify data_hash, 防重注册, OS_SIGN_LOCKED, UI接入)
- `9524843` 自审计轮2 (EVM demo tx RLP 修复 + 统一 demo builder + t12 parity)
- `260cc42` kimi轮1: H1(>8B整数拒绝) H2(长度回绕) H3(固件独立解析) M3/M4/M5/M6/M9/M12
- `b236233` kimi轮2: M7(suspended coin保留) M13(path白名单+硬化) M1(chainId) M2(2930) L2/L3/L4/L5/L6/L10

### 测试
- host 全回归 20 套件绿, 除 **test_composite t3 (pin) 预存失败** — 与审计修复无关,
  只依赖 hal/se_* (se_transport/se_acl16/se_composite), 自 bb5db78 未改, 脚本化交互问题。
- test_app 已入 CI (.github/workflows/host-tests.yml)。
- 双固件 S3 (ilp32f) + P4 构建过。

### 阻塞项 (真机联调/真实资金/发布前必须解决)

**红线 (放行真实资金前必修)** — kimi 审计四轮收尾确认:
- **M11 真实 sighash**: EVM 签 keccak256(raw) 而非 EIP-155 sighash; BTC 签
  double-SHA256(PSBT) 而非 BIP143。签名无链上语义=无重放保护。连带: v/r/s 组装、
  chainId 注入、拒绝已签名 legacy 输入 (r/s 非空)、chain_id 上屏、body 耗尽校验、
  to/data is_list 校验。真网资金第一红线。
- **link_esp.c:50 盲签入口**: HD_CMD_SIGN 收裸 32B digest, sign_digest(NULL,0,...),
  完全绕过 signsvc parse/path/WYSIWYS。真机联调前删除或改为走 os_signsvc_delegate。
- **M8 防降级根治** (OTA 前): 版本墓碑持久化 (NVS) + SE 单调计数器消费方
  (vtable 已接线但无固件消费者) + secure boot v2/flash encryption 确认。
- **test_composite t3 预存失败**: PIN 相关 composite 行为, 真机联调前必须查清。

**可接受为 V2.0 bring-up 现状** (SE mock + 无真网资金前提, 已达开发基线):
- M10a BTC 找零检测 (恒 NULL, 降级为多输出 HIGH+MULTI-OUTPUT 总额, 误报非漏报)
- M14 App 沙箱 (signsvc 双解析+官方审查市场兜底, 无三方 App 阶段可接受)
- M13 残留 per-coin purpose (白名单不按 coin 限定, 但 coin 分支隔离仍在, 无密钥破口)

### 阻塞项 (旧记录, 已被上文红线取代/细化)
- **M10b BTC 多输出隐藏**: 已在固件解析器用保守方案 (多输出显示总额+HIGH risk)。
  彻底方案 (逐笔翻页确认) 待 UI 支持。
- **M11 签名 digest 占位**: BTC 对 PSBT 字节 double-SHA256 (非 BIP143 sighash),
  EVM legacy 缺 EIP-155 chainId 注入 + v/r/s 组装。当前签名无链上语义, 真机联调阻塞。
  witness_utxo amount 已在 psbt.c 读出未保存 (BIP143 需要)。
- **M8 防降级根治**: 版本墓碑持久化 (NVS) + SE 单调计数器接线 (hal/se_acl16 已实现
  但无固件调用者) + OTA 升级通道。当前 s_installed 是 RAM 数组, 重启即清空。
- **M14 App 沙箱**: parse() 与固件同特权级, 无 MPU/沙箱 trampoline。V2.0 隔离声明
  需文档标注为未完成项。

### 可延后项
- M10a BTC 找零检测 (change_check=NULL 恒 false, "self change" 分支死代码,
  失效方向安全: 找零被当外部支付多显示, 不藏钱)。
- L8/L9 并发项 (registry 无锁, uninstall 指针悬垂 — 取决并发模型, 当前单任务安全)。
- L12/L13/L14 (死代码/枚举语义/demo builder 长列表头)。

## 状态: 自审+kimi评审双轮完成, 目录链可签名, 待用户拍板 passphrase 密钥空间设计

## 已完成 (Passphrase TREZOR 模型, commit `c34badb`)
- **SE 接口**: 新增 `derive_session()` — SE 存 passphrase-less base seed
  (PBKDF2(mnemonic,"mnemonic")); 开机输入 passphrase 后折叠成 volatile session seed
  (PBKDF2(base_seed,"mnemonic"+passphrase)), 用于本次会话 signing/xpub。
  passphrase 永不落盘, wipe/掉电即失, 每次开机需重输 (TREZOR 式)。
- mock 实现 derive_session + session seed; sign_digest 用 session 或 base;
  wipe 清 session; 空 passphrase = 回 base seed。
- screen: init/recover **不再** 捕获/bake passphrase; 新增 `screen_boot_passphrase_gate()`
  (每次开机、已初始化才问; 未初始化跳过), 在 `ui_run` boot_pin_gate 后调用。
- host 测试 test_se 新增 t7 (base vs session sig、确定性、不同 pass 不同 key、
  空值复位、provision 前拒绝)。20 套件全绿 (composite t3 pin 预存失败不变)。
- S3 固件构建通过。未烧录真机 (板已脱机)。

## 已完成 (目录链审计修复, `974852d` / `2094b43` / `2e6b851` / `ab08649`)
- **fw_reparse 按解析器能力分派** (`974852d`): 原只分派 coin 0/60 → 目录链
  (ltc/doge/bch=2/3/145, etc/polygon=61/966) 可安装但永远无法签。现 BTC 族
  (0,2,3,145) → os_clearsign_parse_btc, EVM 族 (60,61,966) → os_clearsign_parse_evm。
- **native symbol 规范化** (`974852d`): BTC 解析器硬编码 "BTC"、EVM 不设 symbol
  → 目录链显示错代币。coin_native_symbol()/apply_native_symbol() 双解析前归一化。
- **digest 哈希按族分派** (`2094b43`): 原只判 coin==60 → ETC/POLYGON 走 BTC 的
  double-SHA256。现 EVM 族 (60,61,966) 一律 keccak256。
- **回归测试**: t17 (LTC 签名+symbol+路径隔离), t18 (ETC keccak256 族摘要 —
  从确定性 mock 签名反推 digest 验证)。
- **防御** (`2094b43`/`2e6b851`): os_rng_uniform(0) 除零、os_rng_shuffle(len<2)
  size_t 下溢、mock_wipe 清零 PIN 缓冲。
- **kimi 评审 L 级修复** (`ab08649`): L-1 删除 NULL-confirm 死旁路分支
  (HARDID_HOST_TEST 从未定义, 生产逻辑成唯一逻辑); L-2 passphrase gate
  fail-open → SE 状态错/后端缺 derive_session 时显式报错; L-3 verify_intent
  不再 const-cast 改调用方 intent, 用局部副本比较。
- host 22 套件全绿 (composite t3 pin 预存失败除外) + S3 固件构建通过。

## kimi 评审归档 (2026-08-10, 记录: eng passed, kimi-k3)

**已定案 (commit `1fc0da7`)**:
- **H-1 passphrase 密钥空间 → HardID 专属两步派生, 已文档化为正式规范**
  (se_driver.h derive_session 注释): base = PBKDF2(mnemonic,"mnemonic",2048)
  [BIP39 标准], session = PBKDF2(base,"mnemonic"||pass,2048) [HardID]。
  空 passphrase 账户与 BIP39 完全兼容; passphrase 账户为 HardID 专属密钥空间,
  但可用任意 PBKDF2 工具离机恢复 (先算标准 base, 再做第二步 KDF)。
  否决"SE 存助记词文本"方案 (静态秘密面更大)。参考向量: test_se t8
  (官方 BIP39 base 向量 + Python 计算的 session, passphrase 'HardCase9!')。
- **H-2 passphrase 字符集 → 已扩展三页键盘**: kp_capture_alpha 轮转
  A-Z → a-z → 0-9+16符号 (!@#$%^&*()-_=+,.), 切换键标签显示下一页
  (ABC/abc/1#$); 浮动预览对非 A-Z 字符回退 font7 (全 ASCII)。
  PIN/助记词路径不变。

**真机联调/真实资金前必修 (红线升级)**:
- **M-1 目录链地址显示仍是 BTC 编码**: psbt.c script_to_addr 硬编码 bech32
  "bc1" + base58 0x00/0x05。LTC/DOGE/BCH 输出渲染成 BTC 格式地址
  (bc1q… 而非 ltc1q…)。签名锚定原始字节资金不打错, 但用户所见地址与收款方
  给的永远对不上 → WYSIWYS 确认流程失效。需 per-coin 地址编码表。
- **M-2 digest 占位管线升级为阻断级**: 目录链能签后, keccak256(raw) /
  double-SHA256(raw) 占位摘要 = 真网资金第一红线 (原 M11, 已列入上方红线)。

**已修复 (见上 ab08649)**: L-1/L-2/L-3。

## 待办
- M-1 per-coin 地址编码表; M-2 (M11) 真 sighash 落地。
- 真机走查开机 passphrase 流 + 三页键盘 (esp-idf-s3 build 可烧)。
