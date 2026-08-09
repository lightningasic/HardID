# MEMORY.md

## V2.0 架构升级与多轮循环审计 (当前主线, 2026-08)

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

## 状态:恢复键盘流畅度调试中,彩条问题暂搁置

## 已完成 (本次会话)
- **幽灵 TTTT 修复**: 同键 60ms 重复锁定 (keypad.c `last_kind` + `last_commit`, 按下了 60ms 内相同 kind 的 press 会被 drop)。不同键快速连击不受影响。真机验证: 连续输入 6 个单词无幽灵、无误伤。
- **闪烁修复**: `kp_draw_phrase_header` 原用 `lcd_fill(C_BG)` 全屏重绘导致每次按键整屏闪烁。改为 `lcd_rect(0,0,240,KP_TOP,C_BG)` 只清 header+预览带 (y<120)。闪烁已消除。
- **OK 键行为**: 词数非法 (非 12/15/18/21/24) 时按 OK 弹 "need 12/15/18/21/24 words" 并停留——预期行为,OK 本身工作正常。

## 待解决 (搁置)
- **恢复键盘蓝色背景右上角固定彩色横条**: 全屏 RAM 镜像帧缓冲扫描确认 framebuffer 无此颜色 (PALETTE OK, 右条带 x170-239 只有蓝底+白字)。软件从未画过它。其他界面无、重启后仍在同位置。非面板坏点 (用户判断)。
  - 已加调试基建: display.c `s_fb` 镜像 + `fb_blit` + `lcd_dump` + `lcd_dump_palette_scan`。
  - 下一步验证方向: 把键格底色 `C_BTN` 临时改纯黑看彩条是否消失 → 判断是"面板对特定色的显示问题"还是"固定物理行"。
  - 亦可检查 ST7789 是否需 `esp_lcd_panel_set_gap()` / 列偏移。

## 调试残留 (需清理)
- keypad.c `kp_capture_phrase`: `printf("RC press ...")`, `printf("RC drop-press ...")`, `printf("RC commit ...")` 日志。
- keypad.c: `static int dumped` + `lcd_dump_palette_scan()` 调用。
- display.c: `s_fb` 镜像缓冲, `fb_blit`, `lcd_dump`, `lcd_dump_palette_scan`。
- display.h: `lcd_dump`, `lcd_dump_palette_scan` 声明。

## 提交链 (未提交, 工作区含未整理改动)
- 同键重复锁定 (last_kind) / 闪烁修复 (lcd_rect header) / RAM 镜像调试基建 均未 commit。
- 上一正式提交: `1e96e06` (P3 recover: OK 词数校验 + 可选 passphrase + 64B BIP39 seed)。

## 待办
- 清理调试日志与镜像缓冲 (或保留镜像做彩条定位)。
- 决定彩条处理方案。
- host 测试跑一遍 (test_se/test_seed/test_bip39) 确认无回归。
- 可选: 12 词全流程真机走查。
