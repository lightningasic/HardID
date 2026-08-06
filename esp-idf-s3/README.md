# HardID ESP32-S3 联调（bring-up）

目标板：Waveshare ESP32-S3-Touch-LCD-2（ESP32-S3R8：16MB flash + 8MB OPI PSRAM）

本工程是第一版 S3 移植：SE 后端用 `core/se_mock.c`（软件模拟），不需要 ACL16
硬件即可在真机上跑通 boot → RNG 自检 → 三源种子 → BIP39 助记词 → BIP32 xpub →
PIN 门控签名。核心代码仍通过 `HARDID_ROOT` 引用 `../../core`，单一源码事实。

## 前提

- 装有 ESP-IDF v5.x 的机器（linux）
- USB 连接开发板

## 首次构建

```bash
cd code/esp-idf-s3
source $IDF_PATH/export.sh   # 或 . ~/esp/v5.x/esp-idf/export.sh
idf.py set-target esp32s3
idf.py build
```

## 烧录 + 查看串口日志

```bash
idf.py -p /dev/ttyUSB0 flash monitor
# Ctrl+] 退出 monitor
```

预期日志（smoke test）：

```
I () hardid.main: HardID bring-up (ESP32-S3, mock SE backend)
I () hardid.main: seed generated from 3 entropy sources
I () hardid.main: BIP39 mnemonic (24 words):
I () hardid.main: <24 words>
I () hardid.main: xpub m/44'/0'/0'/0/0: xpub6...
I () hardid.main: seed stored in MOCK (mock, RAM only)
I () hardid.main: sign before PIN (expect AUTH fail): -2
I () hardid.main: bring-up OK. Board ready.
```

`sign before PIN = -2 (SE_ERR_AUTH)` 是预期行为：mock 后端强制“签名必须 PIN
解锁”，证明 PIN 门控路径生效。

## 与 P4 工程的差异

| 项 | P4 (esp-idf) | S3 (esp-idf-s3) |
|---|---|---|
| 芯片 | ESP32-P4 | ESP32-S3 |
| SE 后端 | 双 ACL16 (se_composite + SPI) | se_mock（软件） |
| RNG 钩子 | 需自备（缺失） | board_s3.c（esp_random） |
| 种子熵源 | SE1/SE2 TRNG | MCU RNG 双源（ACL16 位留白） |
| 显示 | 待接 | 先用 UART，触摸/显示后续接 |

## 后续接入（TBD）

- ST7789 240×320 屏幕 + CST816 触摸（Waveshare 板载，SPI/I2C）
- ACL16 SPI 传输（复用 hal/se_transport_esp32.c，引脚参考 P4：SCLK=12/MOSI=11/MISO=13）
