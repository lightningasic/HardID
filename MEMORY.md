# MEMORY.md

## 已完成 (无板会话: WebAuthn RP 服务搭建 + COSE key 二修, commit `b6f47de`/`5ee4b57`, 2026-08-15)
- **重要纠错: 此前 `dd7615d` 的 "COSE key 修复" 本身是错的!** 当时以为 RFC 8152
  EC2 key 是 `{1:kty, 3:crv, -1:x, -2:y}`。实际标准是 **`{1:kty=2, 3:alg=-7,
  -1:crv=1, -2:x, -3:y}`**(canonical 键序 1,3,-1,-2,-3): **y 在 -3 不是 -2**;
  **3 是 alg(-7) 不是 crv**。铁证: python-fido2 `CoseKey.parse` 用 `get(3)` 当 alg,
  `ES256.verify` 用 `self[-1]`=crv / `self[-2]`=x / `self[-3]`=y。旧格式被 fido2
  解析成 **UnsupportedKey**(浏览器/fido2 联调必挂)。真机验签当时能过是因为自洽
  (我手工按自己写的 x/y 构造), 与标准解析器没交叉验证。**已修 (`b6f47de`)**:
  `write_cose_pubkey` 改 5 键标准映射, canonical 键序 1,3,-1,-2,-3。
  **交叉验证**: C 代码生成的 key bytes → fido2 `cbor.decode` + `CoseKey.parse`
  → **ES256** ✓; test_fido 36/36 仍绿; 固件编译通过。
- **WebAuthn RP 测试服务 (新目录 `webauthn-rp/`, `5ee4b57`)**: 本机 HTTPS
  (mkcert localhost 证书, certs/ gitignored) + python-fido2 `fido2.server`
  后端 + 前端 WebAuthn 测试页。端点: `GET /`(页面)、`GET/POST /api/register`、
  `GET/POST /api/login`(challenge 生成 + attestation/assertion 验证)。
  服务在跑: `python3 webauthn-rp/server.py` (https://localhost:8443)。
  新 fido2 版本 API 注意: `register_complete(state, response)` **只收 2 参**
  (options 不需要), 返回 `AuthenticatorData`; `authenticate_complete(state,
  creds, response)`; 前端 base64url 直接喂, 库自动 websafe_decode。
- **无板后端全链路验证通过**: 模拟认证器(标准 COSE key + 真实 ES256 签名)
  走完整 register → login → **后端验签 OK**。证明 RP 后端逻辑正确且设备新
  COSE 格式与 fido2/浏览器兼容。剩浏览器真实联调(需用户在场按设备按钮)。
- **待办**: ① 烧录 `b6f47de` 固件(按住 BOOT 重插 + esptool --after no_reset);
  ② 有头 Chrome 打开 https://localhost:8443(证书用 `--ignore-certificate-errors`
  或信任 rootCA; mkcert -install 需要 sudo, 本机无交互密码故未装), 点 Register
  + 按设备 Yes; ③ confirm 阻塞期间无 keepalive, 浏览器可能 10s 超时(已知待办,
  若出现则加 CTAPHID keepalive 或缩短确认)。

## 已完成 (FIDO 真机 CTAPHID 全链路打通, commit `dd7615d`, 2026-08-15)
- **确认按钮修复已真机验证**: 之前提的 `s_confirm_active`(confirm 期间主任务
  暂停触摸 I2C 轮询)烧录后 makeCredential/getAssertion 的 Yes/No 确认**每次
  都正常响应**(1-3s 内)。根因确认为两任务并发轮询同步 I2C 的竞态。
- **COSE key 编码 bug 修复 (commit `dd7615d`, 真机验证)**: fido_core.c
  `write_cose_pubkey` 曾写 `{1:kty,3:alg,-1:crv,-2:x,-3:y}`,而 RFC 8152
  §13.1.1 的 COSE EC2 公钥是 `{1:kty=EC2, 3:crv=P-256, -1:x, -2:y}` →
  WebAuthn 客户端无法从 attestation 恢复公钥(fido2 库报 "Unsupported
  elliptic curve point type", 且 -1 键是 int 导致解包报错)。已改 4 键标准
  映射。**真机验证**: attestation COSE keys=[-2,-1,1,3], 完整
  makeCredential→getAssertion→ES256 验签(SHA-256(authData||clientDataHash))
  **SIGNATURE VALID**。32/32 host 套件绿。
- **完整端到端现状 (全部真机验证通过)**: CTAPHID INIT/多帧(PING 16/60/100B)、
  GetInfo(10 键 CBOR, 99B)、makeCredential(attestation fmt="none" +
  AAGUID "hardid" + 21B credID + 标准 COSE 公钥)、getAssertion(64B ES256 签名,
  凭据 tag 校验)、确认按钮、多帧续帧(1cff2a0 重试修复)。**设备端 FIDO 栈
  全链路已通**。
- **待办/已知**: ① python-fido2 的 `make_credential` 用 text 键 pkcp(非标准),
  设备 parse_pkcp 返回 0x11 — 真实浏览器/libfido2 发 int 键不受影响; 决定
  是否宽容 text 键; ② browser 端真实 WebAuthn 页面联调(后端 + RP 域)未做;
  ③ 确认屏富渲染(fido_confirm_ui 目前朴素 Yes/No)是 F5; ④ CONFIG_LOG 里
  ui_confirm_yesno 的 ESP_LOGW 坐标诊断日志可留可删。

## 已完成 (FIDO 真机 CTAPHID 联调: 多帧 TX 修复 + 格式确认, commit `1cff2a0`, 2026-08-14)
- **续帧丢失根因 + 修复 (已真机验证)**: `fido_usb_tx_drain` 每帧发送前等
  `tud_hid_ready()` 100ms, 超时就 drop —— 但 `emit_tx` 已一次性推进 tx_sent,
  drop 的续帧永久丢失 → host 卡死等续帧。表现为 **get_info#1 偶发头帧到但
  续帧丢(TIMEOUT)、get_info#2 成功**(间歇性, 与 CBOR#1/#2 卡住的旧观察一致)。
  修复: 发送失败重试 10 次(每次再等 100ms + 5ms backoff)。**验证**: 连续 5 次
  get_info(len=99, status 0x00) 全 OK + 多帧 PING 16/60/100B 全 match +
  get_info 后 PING 交替正常。**单帧响应(ping/INIT/ERROR)一直正常, 只有多帧
  响应间歇失败 → 完全吻合此根因。**
- **usbhid 0x00 剥离机制确认 (client 侧须知)**: Linux usbhid 对无 report-id 的
  OUT report, 若首字节为 0x00 会剥掉(当 report id)。因此客户端写 HID 必须
  **prepend 0x00 report-id**(fido2 `linux.py` 就是这么做的, 写 65B)。手动测试
  脚本若直写 64B 会被剥首字节 → 设备收到错位包 → CTAPHID_ERROR INVALID_SEQ。
  CTAPHID CID 首字节为 0x00 时(如 `0000000e`)此问题必现; INIT(CID ffffffff)
  不受影响 → 解释了"INIT 好、后续错位"的旧现象。
- **makeCredential 请求格式确认 (设备端兼容待办)**: CTAP2 命令字节是 0x01
  (MAKE_CREDENTIAL)/0x02 (GET_ASSERTION), **不是** 0x10 (那是 CTAPHID_CBOR)。
  手动测试正确结构: `CTAPHID_CBOR(0x10) || CTAP2_cmd(0x01) || CBOR`。
  **python-fido2 的 `make_credential(key_params=[{'type':'public-key','alg':-7}])`
  把 pkcp 项的键编码成 TEXT 键("alg"/"type")**, 而 CTAP2 §6.1.3 要求整数键
  (1=type, 3=alg) → 设备端 `parse_pkcp` 的 `cbor_read_uint` 读 text 键失败 →
  **CTAP error 0x11 CBOR_UNEXPECTED_TYPE**。已用标准整数键手动构造验证: 请求
  被正确解析, 设备进入用户确认(挂起等按钮)。**待办**: 决定设备端是否宽容
  text 键 pkcp(真实浏览器/libfido2 都发 int 键; python-fido2 是唯一特例)——
  建议宽容跳过无法解析的 pkcp 项。
- **真机确认按钮不响应 (未解决, 已提修复未验证)**: makeCredential 到确认屏
  (fido_confirm_ui → ui_confirm_yesno) 后**按 Yes 无反应**。根因怀疑 fido_task
  (ui_wait_press, 每 8ms) 与主任务 (BACK 轮询, 每 30ms) **并发轮询同一同步
  I2C 触摸总线** → 触摸读取竞态丢失。**已提交修复 `1cff2a0`**: 加
  `s_confirm_active` 标志, confirm 期间主任务暂停触摸轮询; 同时
  ui_confirm_yesno 加了 `ESP_LOGW("keypad","confirm touch: ...")` 坐标诊断。
  **编译通过但未烧录/未真机验证**(用户离开, 需板交互)。下次验证: 烧录 →
  makeCredential → 按 Yes → 看 LCD/日志坐标是否匹配 Yes 区域 (125,200,225,250)。
  若坐标正常仍不响应, 排查触摸注入残留 s_inj_active 或 CST816D 多任务时序。
- **HID 描述符去 report-id (随 `1cff2a0` 落地, 已真机工作)**: usb_desc.c 把
  CTAP-HID report descriptor 从 config 内嵌 31B (带 report id 1) 改为独立
  29B **无 report id** (经 `tud_hid_descriptor_report_cb` 单独下发);
  fido_esp.c `HID_REPORT_CTAPHID=0`、`fido_usb_rx` 保留长度守卫兼容旧 host。
  配合 fido2 库 prepend 0x00 的 65B 写 → usbhid 剥 0x00 → 设备收正确 64B。
- **board_s3.c 保留 USB/USJ PHY 修复, 删调试残留**: 保留「重开 USJ 时钟 +
  conf0 pad 上拉覆盖/DP 下拉」使共享 FSLS PHY 释放给 OTG 的寄存器写(设备现
  正常枚举 1209:f1d0); 删除 TEMP DEBUG 的 g_usb_dbg_*/g_otg_dbg 快照与
  display.c 的 LCD 寄存器显示块。
- **验证环境**: 板 Waveshare S3-Touch-LCD-2, /dev/hidraw2, fido2 Python 库
  (CtapHidDevice / Ctap2)。烧录: 按住 BOOT 重插 → esptool --after no_reset。

## 已完成 (FIDO 上板循环审计 + 修复, commit `ffc04f7`, 2026-08-13)
首次真机跑 F3 TinyUSB composite 固件，暴露启动回归 + 若干潜伏 bug。31 host
套件 + fuzz 50k (ASan/UBSan) 全绿，boot LOGO 真机验证正常。

- **启动回归（用户报告：卡 home 文本、进不了开机 LOGO）根因 = touch injector**。
  `touch_inject_task` 在 `touch_init()` 里以**优先级 2** 创建（高于 boot/main 任务
  的优先级 1），FIDO 改动把它从 `usb_serial_jtag_read_bytes` 改成读 TinyUSB CDC
  (`hardid_usb_read_byte`)。CDC 半初始化时读循环不能干净阻塞 → 抢占/饿死启动任务
  → task-WDT 重启，`ui_task`（画 LOGO 的）根本没机会跑。**修复**：优先级降到 1 +
  读循环加无条件 `vTaskDelay` 强制让出 CPU。已用屏上分步标记定位（past boot →
  touch done → ... 卡在 injector 创建处）。
- **crypto 严重 bug (secp256r1_mbedtls.c)**: `mbedtls_ecdsa_sign_det_ext` 传了
  `MBEDTLS_MD_NONE`，mbedtls 对 NONE 返回 `BAD_INPUT_DATA`（`mbedtls_md_info_from_type`
  返回 NULL）→ **设备端每次 FIDO 签名必然失败**。md_alg 只选 RFC6979 的 HMAC 哈希
  （不重哈希消息），必须 `MBEDTLS_MD_SHA256` 才与 host 纯实现（core/rfc6979.c 用
  os_hmac_sha256）一致。已改 SHA256。
- **fido_esp.c 三处**: ① `fido_usb_rx` 不跳过 report-ID 字节（描述符用 ID 1，
  host 会在 64B 包前加 1B ID 成 65B）→ 按长度跳过 ID 前缀；② `fido_usb_tx_drain`
  误以为 `tud_hid_report` 是 fifo，IN 端点忙时连续发会丢帧 → 发送前等
  `tud_hid_ready()`；③ `fido_task` ring buffer 先移动 head 再读数据（撕裂读）
  → 改先读后移。
- **健壮性**: main.c `xTaskCreate(ui_task)` 加返回值检查（失败显示红屏而非无声
  卡死）; usb_esp.c `hardid_usb_read_byte` 加 NULL 信号量保护; 删 LINK_RX_BUF 死代码。
- **开机画面**: `os_board_display_home()` 改画品牌 LOGO+字标（不再闪
  "Wallet v0.1 mock SE ready" 状态行）; `screen_run_splash()` 复用该 hook，
  logo.h 仍单处引用不重复占 flash。

## 待办 (FIDO USB composite 不枚举 — F3 上板未完成, 2026-08-13)
- **现象**: host 端只看到 JTAG (303a:1001)，看不到 composite (1209:F1D0)。
  FIDO HID 因此无法用。
- **已诊断**: `tinyusb_driver_install` 返回 OK (LCD 上 usb_rc=0)；PHY mux
  寄存器 `RTCCNTL.usb_conf.sw_usb_phy_sel` 读到 **1 (OTG)**，但 `tud_connected()
  =0`、`tud_mounted()=0`（设备控制器没连上，D+ 上拉未被 host 看到）。host 仍见
  JTAG，说明内部 PHY 实际还在 USJ 侧 / JTAG 外设仍在驱动 GPIO19/20。
- **排查过的方向**（均未解决）: ① 控制台 USB_SERIAL_JTAG→NONE 排除 PHY 占用；
  ② 提前 `usb_serial_jtag_ll_phy_enable_pad(false)` 释放 JTAG pad（无效，可能
  寄存器写没生效或还需关整个 USJ 外设）; ③ dwc2 `dcd_connect` 会自动连（清
  DCTL_SDIS + 配 USB_WRAP.otg_conf 上拉位）。
- **根因（2026-08-14 定位，`c6c885e` 已改，待真机验证）**: ESP32-S3 的 GPIO19/20
  在 USB-Serial-JTAG (USJ) 与 USB-OTG 之间共享。启动时钟初始化
  `esp_system/port/soc/esp32s3/clk.c` 只有在 **`!USJ_ENABLE_USB_SERIAL_JTAG` 且
  控制台不在 USJ** 时才关 USJ pad + 时钟。之前控制台配在 USJ
  (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`)，导致条件不满足 → USJ 一直在驱动
  GPIO19/20 → host 一直枚举 ROM 的 JTAG (303a:1001)，composite 永远出不来。
  这解释了 physel=1（mux 确实切到 OTG）但 conn=0/host 仍见 JTAG 的矛盾。
  之前"控制台→NONE 无效"是因为漏了同时关 `USJ_ENABLE_USB_SERIAL_JTAG`（默认 y，
  被 ESP_CONSOLE_USB_SERIAL_JTAG select，但去掉控制台后仍默认 y）。
- **修复（已提交 `c6c885e`，未真机验证）**: `sdkconfig.defaults` 改
  `CONFIG_ESP_CONSOLE_NONE=y` + `CONFIG_USJ_ENABLE_USB_SERIAL_JTAG=n`。这样启动时
  clk.c 会关 USJ pad + 时钟，OTG 干净接管 PHY。运行期 stdout 仍由
  `tinyusb_console_init()` 重定向到 composite CDC（composite 枚举后才有日志）。
- **下一_session 验证**: 烧 `c6c885e` 后 `lsusb` 应见 composite (1209:F1D0) 而非
  JTAG (303a:1001)；`dmesg` 应看到 JTAG disconnect + 新设备枚举。若仍不枚举，再查
  dwc2 VBUS（self_powered=false, vbus_monitor_io=-1 是否等待 VBUS）。注意：板无
  UART、控制台 NONE 后 boot 早期无日志，调试只能靠 LCD 标记或 composite 起来后 CDC。
- **相关文件**: usb_esp.c (hardid_usb_init), usb_desc.c (composite 描述符),
  board_s3.c (os_board_hw_init 调 USB init), sdkconfig.defaults (控制台/USJ)。

## 已完成 (FIDO F3 host 层: CTAPHID→CTAP2 端到端, commit `32ec4fb`, 2026-08-12)
- **F3 = TinyUSB composite 上板**（设计文档 §8 表）——真机上板部分本机受阻
  （无网络拉 esp_tinyusb 托管组件 + 无 S3 硬件），本里程碑交付 host 可验证的
  **端到端帧层测试**（USB HID 回调将运行的真实路径），30/30 CI 套件 + fuzz
  50k ASan/UBSan 全绿。
- **合规修复 (ctap2.c)**: CTAP2 §6.1.9 —— `options.up` 缺省必须是 true。
  原实现跳过 options map，UP 位永不置位。新增 `parse_options()`（key 0x01=up、
  0x02=uv 容忍忽略 A2、缺省 true），接入 makeCredential K_OPTIONS 与
  getAssertion K_GA_OPTIONS；两处 handler 显式 `up_required=true`。
- **帧层 bug (fido_ctaphid.c)**: `emit_tx` 对 tx_len==0 的 staged 消息
  （WINK/LOCK ack）永不发帧 —— `while(0<0)` 直接返回 0。修复后零长消息
  也先发一个 bcnt=0 的 INIT 头帧（spec 要求响应至少一帧）。
- **tests/test_ctaphid_net.c** (新增, 26 pass): 真实 INIT/CONT 多包帧 →
  ctap2 dispatch → fido_core → mock SE → 应答重组。覆盖 INIT 协商
  （非ce回显/cid 分配/caps 位于 out[0][23]=0x04）、GetInfo、多包
  makeCredential + authData 字段解析（AAGUID "hardid"、UP/AT 旗标、
  credIdLen 0x0015=21）、getAssertion 64B 签名存在、线级拒绝、乱序/超长
  帧错误、未知 CID、WINK ack。
- **踩坑**: ① `ACCUM` 宏参数若是函数调用 `ctaphid_feed(...)` 会被循环
  `i<(k)` 反复求值 → 每轮重复 feed 丢帧/错帧（必须先用局部变量捕获返回
  值）; ② INIT 应答 caps 是 out[0][23] 非 [20]（载荷 17B:
  nonce8+cid4+proto1+maj1+min1+bld1+caps1）; ③ cbor_writer 字段名是
  `len` 非 `pos`; ④ makecred/getassert 请求必须先写 CBOR map head。
- **已提交**: `32ec4fb` (feat) 推送前待推; 下一步 F3 on-board 部分
  （usb_desc.c TinyUSB composite HID 0xF1D0+CDC + fido_esp.c）需网络/真机。

## 已完成 (FIDO F3 on-board 胶合代码, commit WIP, 2026-08-12)
- **`esp-idf-s3/components/hardid/usb_desc.c`** (新增): TinyUSB composite
  描述符——配置头(9B) + IAD | CDC-ACM | CDC data | FIDO HID，共 138B，
  全部**手排原始字节**（对齐 TinyUSB sample 风格），已用 Python 模型逐段
  校验（wTotalLength=138、report 长度字段=31、端点号一致）。
  - FIDO HID: usage page 0xF1D0 / usage 0x01, report id 1, 64B
    IN/OUT interrupt EP, VID 0x1209 / PID 0xF1D0。
  - CDC: ACM + union, notify EP 0x81, bulk 0x03/0x82 —— linkproto/HOST
    LINK 经 composite CDC 共存（设计 §1.1/§2/§10）。
- **`esp-idf-s3/components/hardid/fido_esp.c`** (新增): 薄胶合层。
  - TinyUSB HID OUT 回调 → 8 槽 ring FIFO → fido_task 泵入 `ctaphid_feed`
    → `ctap2_handle` (dispatch，与 host 验证配置逐字节一致) → staged 帧
    → `tud_hid_report` 逐包发 IN。全在 core/ 的 host 单测覆盖同一路径。
  - `screen_run_fido()`: 设备 PIN 门(决策 A6，与 link_esp 同款) → 起
    fido_task → "FIDO serving / plug into a browser / BACK"屏。
  - `fido_confirm_ui`: 连线 core 确认钩子 (core/ctap2 缺省 NULL=DENY 兜底
    A3)，F3 先用朴素 Yes/No，F5 再做丰富渲染。
- **ui.c/screen.h 接线**: 主菜单 MENU_COUNT 7→8，新增 "FIDO" 项
  (index 4) → 调 `screen_run_fido()`; screen.h 声明对应入口。
- **CMakeLists.txt (S3)**: SRCS 增 usb_desc.c/fido_esp.c; REQUIRES 增
  `esp_tinyusb`。
- **验证**: usb_desc.c/fido_esp.c 均通过 -fsyntax-only（stub tusb/esp 头）。
  **编译/真机验证受阻**: 本机无网络拉 esp_tinyusb 托管组件 + 无 S3 硬件。
  F3 出口标准（真机 lsusb 见 FIDO 设备 + linkproto 经 CDC 仍通）必须
  在有网络的硬件环境跑。
- **已知 F5 待办**: confirm 屏富渲染（RP 域名滚动/截断、Yes/No、signCount
  变更提示）；confirm 阻塞期间 RX ring 可能溢出丢帧（浏览器保持信道开放，
  慢确认场景）——终极解是 CTAPHID KEEPALIVE，F5 处理。

## 已完成 (FIDO F4: CTAP2 + CTAPHID + cbor core, commit `597b5ec`, 2026-08-12)
- **F4 出口标准全绿**: 30/30 host 套件 PASS (CI 循环), fuzz 200k ASan/UBSan 干净,
  S3+P4 两个 CMakeLists 均已含 FIDO 源。
- **`core/cbor.c/.h`** (新增): canonical CBOR writer/reader, 深度上限 8 +
  item budget; 修 reader 未推进 pos 的 bug (info<24); 26 项 host 测试。
- **`core/ctap2.c/.h`** (新增): makeCredential/getAssertion 请求解析 +
  指令分发; GetInfo 由 fido_core 直出; pkcp 必须含 alg -7 (否则 0x26)。
- **`core/fido_core.c/.h`** (新增): attestationObject (fmt "none") +
  authenticatorData 拼装; **ES256 签名对象是 SHA-256(authData||clientDataHash)
  而非裸拼接 (审计发现并修复)**; 确认门: 无 confirm handler 即 OPERATION_DENIED;
  GetInfo 10 键 map。
- **`core/fido_ctaphid.c/.h`** (新增): INIT/CONT 帧状态机、广播 CID 分配、
  maxMsg 7609、CBOR status 前置、CTAP1 MSG 拒绝、逐包 drain; 27 项测试
  (含 120B 三包重组、乱序 CONT、超长 BCNT、未知 CID、drain)。
- **`core/se_mock.c` 修复两 bug**: ① mock_fido_tag 栈溢出 (44B 写 51B);
  ② credID 布局对齐设计 §4.1 — epoch(1B)||cred_idx(4B)||tag(16B)=21B
  (原 mock 24B 溢出 21B 数组)。`fido_cred_sign` 签名对象即 digest32 (fido_core
  负责预哈希), epoch/tag 校验失败 → SE_ERR_AUTH 不签名。
- **`tests/test_fido.c`** (新增, 36 pass): 注册/断言全流程 + **真实验签**
  (t3c: SE 公钥 + SHA-256 预哈希 + tamper/wrong-msg 拒收) + 伪造 epoch 拒收 +
  signCount 单调 + 空 allowList + EdDSA 拒绝 + reset 失效凭证。
- **踩坑**: ① fido_core 曾把 69B 拼接 (authData||cdh) 直接传 SE 当 digest32 —
  SE 不会内部哈希, 必须 fido_core 先 SHA-256; ② os_secp256r1_verify 返回
  1=valid/0=invalid (不是 errno 风格), 测试断言方向别写反。
- **遗留 (非本轮)**: tests/test_hkdf.c 与 test_rfc6979 是陈旧文件, 不在 CI
  循环内 (hkdf 由 CI 显式加 hkdf.c; rfc6979 无 .c 源), 未清理。

## 已完成 (FIDO F2: secp256r1 P-256 软实现 + host 单测, commit `67f5753`, 2026-08-12)
- **F2 里程碑出口标准全绿**: RFC6979 双过 + Python 对齐 + CI 入套件。
- **`core/secp256r1.c/.h`** (新增): clean-room P-256 域/点/ECDSA, 4x64 limbs +
  __int128, Jacobian 坐标。公钥未压缩 65B (WebAuthn COSE ES256 要求, 与 k1 的
  33B 压缩 API 不同, header 已注明)。NOT constant-time。
- **`core/rfc6979.c/.h`** (重构): 群阶参数化 — 新增 `os_rfc6979_nonce_n(nbe32,..)`;
  原 `os_rfc6979_nonce` 保留为 secp256k1 包装 (SECP256K1_ORDER 常量), ecdsa.c 零改动。
- **`tests/test_secp256r1.c`** (新增): 10 项 — RFC6979 A.2.5 k 向量 KAT、
  pubkey KAT (RFC priv→Ux/Uy)、sign KAT (low-s 归一)、raw high-s RFC sig 验签、
  压缩公钥 + fe_sqrt 路径、point_add(G,G)==2G、scalar add/mul/inv、roundtrip
  (keys 1-5 × 2 msg)、malformed 拒收、wrong msg/损坏 sig 拒收。
- **Python 逐字节对齐** (cryptography 41): 50 pubkey 逐字节相等 + 50 sig 独立验签
  (Prehashed + DER) + 20 组 scalar add/mul/inv — 全 PASS。
- **踩坑记录 (重要)**: ① 初版曲线常量整体字节序颠倒 (P/N/GX/GY/B 全错) →
  RFC vector 全挂; 修复并独立重算; ② `fe_sqrt` 的 (p+1)/4 指数原是逐 limb 加
  1 丢弃进位 → 压缩公钥解析必挂; 改硬编码 E_SQRT 常量; ③ Python cryptography
  的 ECDSA verify 必须 `encode_dss_signature(r,s)` 转 DER + `Prehashed`, 传裸
  r||s 必拒; ④ RFC6979 向量用纯 Python hmac 复算 k 与 RFC 一致, 但纯 Python
  点乘有 bug (r 对不上) → 改以 cryptography 算 r。
- **循环审计顺带修复**: `hal/se_composite.c` comp_verify_pin 把 errno 风格 rc (0/-2/-3)
  与状态字 SE_SW_OK(0x9000)/SE_SW_LOCKED(0x6983) 直接比较 → 恒等 SE_ERR_AUTH,
  **t3 verify_pin 预存失败根因** (此前 MEMORY 多次记"composite t3 预存失败除外")。
  现已修复, composite 全绿 — 26/26 套件全绿, fuzz 50k 干净。
- 已推送 (4a3b9ed..67f5753)。

## 已完成 (循环代码审计 3 轮 + 自动修复, commits `3f1968d`/`fcd6b40`/`afde203`, 2026-08-11)
- **第1轮 (熵代码)**: phys_entropy extract out_len>32 尾部未初始化 → 清零;
  mix_one 死分支删除; entropy_s3 无条件 got=1 死分支修复; entropy_p4 补 got
  跟踪 (原全源失败也打"mixed"日志); collect_touch 容忍 3 次瞬断;
  collect_bus 不依赖手指 (I2C 事务本身抖动, 无触摸也采 S6); header 注释更正。
- **第2轮 (注入器/提示屏)**: 注入器竞态修复 (先写坐标再置 active, 防跨核读旧
  坐标); 注入坐标钳位到屏边界; 'R' 改整行匹配; 日志仅状态变化时打 (防 wiggle
  洪泛)。
- **第3轮 (core 安全面)**: eip712 encode_word 补 pad_left+len≤32 检查;
  扫描确认 memcmp 全用于公开数据、bip39/base58/clearsign memcpy 均有界、
  rng_uniform 拒绝采样无模偏、se_mock strcpy 有前置边界。
- 每轮验证: host 25/26 (composite t3 预存失败除外) + S3/P4 构建干净 + 原子提交。

## 已完成 (多熵源 Layer A 落地 + 真机验证, commit `46c3252`, 2026-08-11)
- **docs/08 多熵源设计审核通过 → 实现 Layer A (纯固件零 BOM)**:
  `core/phys_entropy.c` 无条件熵池 (SHA-256 链式混合 + 前缀安全长度域 +
  单次提取); `core/seed.c` 新增可选 `os_seed_phys_extra` 钩子混入 HKDF
  Extract (weak 默认返回 1, 绝不 fail-closed)。
- **entropy_s3.c / entropy_p4.c 采集**: 触摸坐标 LSB 抖动 + 温度传感器
  热噪声 + I2C 总线时序抖动 + RTC/esp_timer 漂移 → 熵池 → 输出 32B。
- **关键链接坑 (已修)**: entropy TU 唯一导出 `os_seed_phys_extra`, 而
  seed.c 的同名 weak 默认在 archive 扫描时满足引用 → strong 版从未被拉入,
  seedgen 只花 10ms (根本没跑触摸 150ms 采样+温度传感器)。board_* 调用
  `os_entropy_force_link()` 保证 strong 钩子入图。ELF 符号 W→T 验证。
- **真机验证通过**: DEV touch injector (`CONFIG_HARDID_DEV_TOUCH_INJECT`,
  'P x y'/'R' 经 USB-JTAG RX 合成触摸, 原子变量跨核) 驱动 UI:
  menu OK → 4-words TEST → seedgen begin → `temperature_sensor: Range` →
  `physical entropy mixed into seed` → seedgen done rc=0。之后恢复生产配置
  (dev 三项全关), 引导干净无 panic。
- **两个调试坑记录**: ① `idf.py set-target` 会重置 sdkconfig 的 dev 选项
  为默认 n (之前手动开的 DEV_NO_PIN/TEST_SEED 被冲掉, 设备卡 PIN 屏);
  ② USB-JTAG 端口 open 会触发复位, 驱动脚本必须等 boot 完成再发命令。
- host 全回归 (26 套件含 phys_entropy) 绿 (composite t3 预存失败除外) + fuzz 50k
  干净 + S3/P4 构建过。已推送 (c4ca262..46c3252)。

## 已完成 (HOST LINK 真机走查通过, 2026-08-11)
- **S3 板回线, HOST LINK 结构化 SIGN 端到端真机验证通过**:
  进 HOST LINK 不再重启 → 收 SIGN 帧 → 屏显交易意图 + Yes/No → Yes 确认 →
  签名 + OK 回复 (recid=0, sig_count=1, 确定性签名复现一致), 确认屏关闭回到
  "Host link serving / waiting for frames"。
- **真机暴露两个新缺陷已修 (commit `e58a37e`)**:
  1. 确认屏只有 BACK、按 BACK 即确认 → 改 `ui_confirm_yesno()` 显式 Yes/No,
     Yes 才签名 (true), No 拒绝 (HD_ERR_AUTH); UNKNOWN 双重确认同样走显式按钮。
  2. 服务帧后只画 "frame served" 行, 确认屏残留 → 服务完重绘完整等待屏。
- **真机暴露崩溃已修 (commit `14a37ca`)**: `usb_serial_jtag_read_bytes` 空指针
  panic (LoadProhibited EXCVADDR=0x4) — 低层 API 需要驱动已 install, 而 console
  VFS 默认走 LL 直读不需要驱动, 所以 boot 日志正常但 HOST LINK 首次真机即崩。
  S3+P4 均在 os_board_hw_init install driver + vfs_use_driver。抓崩溃用
  **自动重开端口** 的 python 脚本 (设备重启 USB 重枚举导致 fd 失效, 普通 cat 抓不到)。
- **走查脚本教训**: 用户确认要 ~130s, link_send.py 60s 超时误报"无回复" —
  用 180s 窗口 (link_verify2.py)。确认屏"点击无效"是脚本超时假象, 非设备问题。
- **显示层经验 (用户反馈)**: 彩色长条 + LOGO 颜色两个 bug, DeepSeek 未能解决,
  KIMI 解决。这类显示问题不要依赖 DeepSeek 反复试错。
- host 22 套件全绿 (composite t3 pin 预存失败除外) + fuzz 50k 干净 +
  16 对抗套件全过 + S3/P4 构建过。已推送 (23cff6b..e58a37e)。

## 已完成 (HOST LINK 盲签红线关闭: 结构化 SIGN 改道 signsvc, commit `f40a653`, 2026-08-11)
- **废除 link_esp 裸 digest 主密钥签名入口** (`sign_digest(NULL,0,...)`)。
  HD_CMD_SIGN 载荷改为结构化: `app_id_len | app_id | path_len | path*(u32 BE) | tx`。
- linksvc 不再用 vtable, 直接 `os_signsvc_delegate(app_id, tx, tx_len, path, path_len, confirm)`
  — 与设备本机 SIGN 完全同管线 (app 查找 + coin/path 隔离 + fw 独立重解析 +
  WYSIWYS 确认 + 真链 sighash + SE 签名)。NULL confirm 恒 ABORT。
- 确认屏复用 `screen_confirm_intent` (S3+P4 screen.c 导出), 显示解析后的交易意图
  (收款/金额/手续费/chain id), 不再是 hex digest。
- linkproto: HD_LINK_APP_ID_MAX=16/HD_LINK_PATH_MAX=10/HD_LINK_MAX_TX=2048,
  HD_LINK_MAX_FRAME=2116; OK 回复 = sig64(64)|recid(1)|sig_count(4 BE)。
- link_esp S3+P4: static 重组缓冲 (2KB 级, 移出 8KB ui_task 栈); P4 同步 BACK 按钮 +
  DEV-ONLY 门。CI 补 linkproto/linksvc。
- test_linksvc 端到端重写 (真 mock SE+registry): 非 SIGN 动词拒绝环, 结构化签名
  OK(recid/count), declined, NULL-confirm 无旁路, 未知 app, 错误 coin path,
  畸形 tx, wire roundtrip, 未初始化拒绝。
- host 22 套件全绿 (composite t3 pin 预存失败除外) + S3/P4 构建过。

## 待办 (下一步)
- **营销操作视频 (代码冻结后做)**: host UI 模拟器 — display_host.c 实现
  display.h API 渲染到 240x320 RGB565 帧缓冲 (font7/font8x16 纯 C 数组,
  与真机逐像素一致), screen.c/ui.c/inter.c 编译进 host harness, touch 用
  脚本事件, FreeRTOS 打桩; 逐帧 PNG → ffmpeg 合成 mp4。用户明确: 等第一版
  代码冻结后再做。
- 剩余红线: M8 防降级根治 (NVS 墓碑 + SE 单调计数器 + secure boot v2);
  test_composite t3 pin 预存失败 (真机联调前查清)。
- 循环代码审计继续。
- **未真机验证**: 板未连接, 待回线烧录 HOST LINK 走查 (见 06 联调清单)。
- fuzz 修复 `4ee8531`: fuzz_parsers.c 补 coin_type 参数, Makefile 补 hkdf.c/base58.c
  (psbt API 变更后 CI fuzz 步骤必红, 已恢复绿)。

## 已完成 (P4 同步 recover pending-OK + nvs_flash 修复, commit `9362274`, 2026-08-11)
- P4 (esp-idf) kp_capture_phrase 移植 S3 的 pending-OK 模型 + 空闲引导
  (enter word / enter next word), 行为与 S3 对齐。
- P4 构建曾因缺 nvs_flash 依赖失败 (se_mock.c 自 1ab26f4 引入 nvs_flash.h,
  P4 CMakeLists 没同步) — REQUIRES 补 nvs_flash 后 P4 构建通过。
- 下一步: 循环代码审计。

## 已完成 (Recover 词框引导提示, commit `92c58cc`, 2026-08-11)
- 串口插桩确认计数器每次 OK 都推进 (nwords 0→1→2→3→4), 逻辑正确。
- 词框空闲时 (无 pending/无输入前缀) 显示引导 "enter word"/"enter next word",
  让 OK 后的下一个词输入一目了然。已烧录 boot 干净。
- 注意: 本机 python 直 ioctl(TIOCMBIS) 报 EFAULT, 复位验证用 idf env pyserial。
- P4 待 S3 确认后再同步。

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
- ~~**link_esp 盲签入口**~~ → **已关闭 (commit `f40a653`)**: 结构化 SIGN 改道
  os_signsvc_delegate, 与设备本机同管线 (WYSIWYS); 裸 digest/主密钥签名入口废除。
  待真机 HOST LINK 走查确认 (板未连接)。
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

## 已完成 (host 侧签名组装 + 多输入签名交付, commit `c90ec5b`+`b5725fa`, 2026-08-14)
- **`core/tx_asm.c`** (新增, 主机侧组装, 6 用例 `tests/test_txasm.c`):
  ① `os_evm_sig_assemble` —— r||s||v, EIP-155 `v = 35 + 2*chain_id + recid`
  最小大端 (POLYGON chain_id=137 → 2 字节 v=309); ② `os_btc_sig_to_der` ——
  紧凑 r||s → DER + SIGHASH_ALL, BIP62 low-s 归一 (SE 契约不保证 low-s,
  BTC 端 recid 不用故可安全重归一); ③ `os_btc_witness_p2wpkh` —— 完整
  P2WPKH witness 栈 [sig, pubkey]。主机已有 xpub (setup 时导出), 自行派生
  pubkey, 设备只回紧凑签名。
- **link SIGN 回复修复 (`b5725fa`)**: 原回复只回 `sig64|recid|sig_count`,
  丢掉 BTC 多输入的第 2..n 个签名。现格式 `sig_count(4 BE) | [sig64(64)|
  recid(1)] × sig_count`。新增 2 输入 BTC 签名测试 (plen=134 count=2)。
  32/32 host 套件。
- 遗留 (M-2 剩余): BTC **多路径**输入 (当前单 path 签所有输入, 请求仍单
  path)、P2SH-P2WPKH/P2WSH 扩展。

## 待办
- M-2 剩余子项: ~~host 侧 v/r/s 组装与 witness 注入~~ (完成 `c90ec5b`)；
  ~~多输入签名交付~~ (完成 `b5725fa`)；BTC 多路径输入 (每输入独立 path,
  请求格式仍单 path)、P2SH-P2WPKH/P2WSH 扩展。
  (~~link_esp 盲签改走 signsvc~~ 已完成 `f40a653`。)
- 真机走查剩余项: 4 词初始化 → 重启 brain phrase gate → SIGN→ETH demo
  (现签真 EIP-155 sighash) → Recover 候选词手感 → **HOST LINK 结构化 SIGN**
  (板回线后: 发 EVM tx 帧, 屏显意图确认, 收签名帧)。
