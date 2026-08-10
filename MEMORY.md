# MEMORY.md

## 已完成 (Recover 候选词 pending-OK 确认, commit `e66c334`, 2026-08-11)
- 输入 4 字母唯一解析后, 不再立即提交并跳 WORD 计数; 改为"待确认 pending"态:
  大字显示唯一词, WORD N 保持当前词序号, 不产生"显示的是下一个词"错觉。
- OK = 确认 pending 词 (此刻才 WORD N+1); 无 pending 时 OK = 完成短语 (计数合法时)。
- SPACE = 把完整短词 (add vs addict) 标为 pending; BACK = 退 pending → 删字母 → 删整词。
- 已构建 + 烧录 + 串口 boot 干净。交互为触摸驱动, 需真机走查确认手感。
  (仅改 esp-idf-s3; P4 待 S3 确认后再同步。)

## 已完成 (单动词 SIGN 契约, commit `8f725c7`, 2026-08-11)
- **linkproto/linksvc 按 PRD v1.1 §3.4 收敛**: 删除开放接口的 HD_CMD_PING /
  HD_CMD_STATUS, 唯一可调用动词 = SIGN。其余一切动词 (旧 PING/STATUS 码、
  未知字节) 一律 HD_ERR_PARAM 拒绝 —— 落定"非 SIGN 动词 100% 拒绝"验收标准。
- linkproto.h / linksvc.h 头注释同步 (不再有 xpub/status 出接口, 只有签名出设备)。
- test_linksvc 重写: status/ping 测试 → fuzz 拒绝环 (0x00..0xFF 采样) + 初始化后
  仍拒绝。host 测试全绿, S3 固件构建通过。
- **烧录验证完成**: 板回线后 idf.py flash 成功 (hash verified), 串口 boot 干净
  (app_main → ST7789 OK → touch ready → starting UI task, 无崩溃)。
  (注: 本机 python 直 ioctl(TIOCMBIS) 报 EFAULT, 改用 idf env 的 pyserial 控制
  dtr/rts 复位成功。)

## V2.0 架构升级与多轮循环审计 (当前主线, 2026-08)

### 工作流约定 (用户确认 2026-08-09)
- **只在 ESP32-S3 (esp-idf-s3) 开发 + 烧录验证; 确认真机行为正确后再移植到 P4 (esp-idf)。**
- 不要每次改动都 cp 到 esp-idf/ 并构建 P4; 等用户确认 S3 真机 OK 再同步。
- **Brain phrase 设计规则 (用户确认 2026-08-10)**: 永不存储 (不落盘/不进 SE NVM,
  只在 RAM 派生 volatile session seed); 只在钱包端触屏键盘录入, 不经 host/串口;
  **粒度 = 每次开机输入一次**, 本次通电周期内多笔签名共用 session (Trezor 同款);
  wipe/断电即失。UI 文案统一叫 brain phrase; 代码标识符保留 passphrase (BIP39 对齐)。
  文档中须强调它是助记词之上的第二层, 不是独立脑钱包。

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
- ~~M11 真实 sighash~~ → **核心已落地 (commit `a47626e`)**: EIP-155 + BIP143
  官方测试向量双过。剩余子项见下方"kimi 评审归档"区 M-2 条目。
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
- ~~M-1 目录链地址 BTC 编码~~ → **已修 (commit `f6e7ee1`)**: parse vtable 加
  coin_type (4-arg), psbt.c per-coin 地址表 (BTC bc/0x00/0x05, LTC ltc/0x30/0x32,
  DOGE 无 segwit 0x1e/0x16, BCH legacy base58; cashaddr 待后续)。test_psbt t6 +
  Python BIP173 参考交叉验证。
- ~~M-2 digest 占位管线~~ → **已修 (commit `a47626e`)**: EVM 真 EIP-155 sighash
  (os_evm_sighash: 6 字段注入 chainId / 9 字段校验 v / typed 校验 chainId /
  拒绝已签名 r/s 非空; 链表 ETH=1 ETC=61 POLYGON=137); BTC 真 BIP143 sighash
  (os_btc_sighash_from_psbt: 原生 P2WPKH + SIGHASH_ALL 限定, 逐输入签名,
  outcome 加 sigs[16][64]+recids+sig_count)。官方测试向量双过: EIP-155
  daf5a779… (test_clearsign t13), BIP143 c37af311… (test_psbt t7)。
  剩余子项 (真机联调前): v/r/s 组装与 witness 注入在 host 侧 (设备出 r||s+recid),
  chain_id 上屏, BTC 多路径输入 (当前单 path 签所有输入), P2SH-P2WPKH/P2WSH
  扩展, link_esp 盲签改走 signsvc。

**已修复 (见上 ab08649)**: L-1/L-2/L-3。

## 已完成 (真机首次烧录 + 显示修复, 2026-08-10, `a218ecb`/`9f0015d`/`afaa8ba`)
- 测试板已回线, 固件刷入成功 (hash 校验过), 启动日志干净:
  app_main → board hw init → ST7789 OK → touch ready → UI task, 无崩溃无门禁挂起。
- **LOGO 修复**: 旧 core/logo.h 是 DeepSeek 盲写 (无图像能力), 缺亮蓝闪电/白钥匙。
  新增可复现生成器 logo/gen_logo.py (PIL: 黑底合成→LANCZOS 1024→160→RGB565),
  删除 logo/logo.h 副本, 直写 core/logo.h。真机确认颜色正确。
- **RGB565 字节序修复 (9f0015d)**: ST7789 默认大端色数据, 我们的小端 uint16_t
  全部被对调 —— 整个 UI 一直跑在交换后的颜色上 (按钮 0x1D8F 碰巧还像蓝色没被发现,
  LOGO 暴露了)。panel 配置加 .data_endian = LCD_RGB_DATA_ENDIAN_LITTLE。
- **按钮改品牌蓝 (afaa8ba)**: C_BTN 0x1D8F(实为青绿) → 0x039E (LOGO 闪电蓝,
  R0,G113,B242), display.h + keypad.c 两处。真机确认正常。
- 注意: 键盘 OK 键仍是 0x03EF 青绿, 如需统一待用户提。
- 串口日志捕获方法 (无 TTY 环境): python fcntl/ioctl TIOCMBIS/TIOCMBIC 脉冲 RTS
  (先 DTR=0, RTS=1 拉低 EN 200ms, 再 RTS=0 释放), select 读 15s。cat 直读只能
  捡到 esptool 复位瞬间的一行, esptool flash_id/read_mac --after hard_reset 的
  复位会丢后续输出。

## 已完成 (循环审计 2026-08-10 第二轮, 4 轮至无新增问题)
- **轮1 金额单位显示 (WYSIWYS 级, `dc1803b`)**: ERC20 代币金额被拼上原生符号
  ("1000 ETH" 实为 USDC, 由 symbol 规范化引入); BTC 系 satoshi 直接贴币符号
  ("90000 BTC"); EVM 原生 wei 贴符号。新增 os_fmt_coin_amount (wei 18 位/sats 8 位
  十进制 trimming), 解析层填十进制币值字符串, 确认屏 fee 同样格式化 + chain_id 上屏。
  test_clearsign t14 锁定格式化器。
- **轮2 sighash 边界 (`ba026bb`)**: BIP143 输出脚本上限 64B → OP_RETURN(80B) 等合法
  输出会被误拒签 → 放宽到 128B (输出只是被哈希, 上限是内存界不是策略); os_evm_sighash
  4KB 栈缓冲改 static (ui_task 8KB 栈上还有 ~1.3KB outcome); SIGN demo 对全部 EVM 族
  App 可用 (ETC/POLYGON 原落入 BTC 提示分支)。
- **轮3 UI/键盘/菜单/NVS**: 无新问题。os_rng_uniform 均匀性验证过; 键盘页状态复位
  路径闭合; mock NVS save/erase 时机正确。性能观察项: 候选词列表逐列 SPI 绘制
  ~20ms/次重绘, 可接受, 真机手感差再改行缓冲。
- **轮4 kimi 对抗复审 (`8a7b7c2`)**: EVM 族判定三处硬编码收敛到
  os_evm_chain_id_for_coin 表 (新 EVM 目录链一处注册即可); se_driver.h 补写
  passphrase KDF 256B 长度界 (真 SE 后端必须同界保证跨后端一致)。
- 全量: host 22 套件 + 3 adversarial 全绿 (composite t3 pin 预存失败除外), S3 固件构建过。
- 文档已同步: 01 PRD (brain phrase 规范 + 进展快照), 04 工程文档 (§8 实现进展),
  06 联调清单 (阶段1/2 S3 已验证 + 4 个真机修复), 07 使用手册 (菜单/brain phrase/
  三页键盘/候选词/真 sighash/功能矩阵)。

## 待办
- M-2 剩余子项: host 侧 v/r/s 组装与 witness 注入 (设备出 r||s+recid),
  BTC 多路径输入, P2SH-P2WPKH/P2WSH 扩展, link_esp 盲签改走 signsvc。
- 真机走查剩余项: 4 词初始化 → 重启 brain phrase gate → SIGN→ETH demo
  (现签真 EIP-155 sighash) → Recover 候选词手感。
