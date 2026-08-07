# MEMORY.md

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
