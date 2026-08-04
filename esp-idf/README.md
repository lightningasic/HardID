# HardID ESP32-P4 Firmware (ESP-IDF project)

ESP32-P4 + 双 ACL16 硬件钱包的 ESP-IDF 工程骨架。

## 结构

```
esp-idf/
├── CMakeLists.txt                  # 工程入口 (target esp32p4)
├── sdkconfig.defaults              # 目标配置 (flash 16MB, Octal PSRAM)
├── main/
│   ├── CMakeLists.txt
│   └── main.c                      # app_main: SE init → RNG 自检 → 主循环占位
└── components/
    └── hardid/
        └── CMakeLists.txt          # 引用 ../../core + ../../hal 全部 24 个源文件
```

**单一源码事实源**：组件**不复制**代码，直接从仓库根的 `core/` 和 `hal/` 拉取源文件（`HARDID_ROOT = ../..`）。改 core/hal 任何文件，ESP-IDF 工程自动用最新。

## 构建

```bash
# 一次性: 安装 ESP-IDF v5.2+ (ESP32-P4 支持)
#   git clone -b v5.2 --recursive https://github.com/espressif/esp-idf ~/esp/esp-idf
#   ~/esp/esp-idf/install.sh esp32p4
. ~/esp/esp-idf/export.sh          # 激活环境

cd code/esp-idf
idf.py set-target esp32p4          # 应用 sdkconfig.defaults
idf.py build                       # 编译
idf.py -p /dev/ttyUSB0 flash       # 烧录
idf.py -p /dev/ttyUSB0 monitor     # 串口监视
```

## 编译要点

- `target_compile_definitions(... ESP_PLATFORM=1)`：启用 `hal/se_transport_esp32.c` 里的真实 ESP-IDF SPI 实现（host 测试用 stub）。
- `se_mock.c` **被排除**：生产固件用 `se_composite.c`（真实双 ACL16），mock 仅供 host 测试。
- `main/CMakeLists.txt` 的 `REQUIRES hardid driver`：链接 SPI/GPIO 驱动。

## 当前状态

- 工程骨架完整，源文件引用与磁盘**完美匹配**（24 个，已验证）。
- main.c 走通：SE 初始化 → RNG 自检 → 占位主循环。
- **本机无 ESP-IDF，未做真机编译**——首次在有 ESP-IDF 的机器上 `idf.py build` 时需处理可能的头文件/驱动细节（预计很小）。

## 待办（接真机）

1. `idf.py build` 首编译，修任何 ESP-IDF 版本相关的小问题
2. 填 `hal/se_acl16_opcodes.h` 操作码（拿到 ACL16 手册后）
3. 接 UI/Clear Sign 主循环（显示任务 + QR 扫描 + QR/USB 通信）
4. 生产开启 flash 加密 + Secure Boot v2（sdkconfig.defaults 里已注释）
