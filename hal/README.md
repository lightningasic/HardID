# OpenShield SE Hardware Abstraction Layer (HAL)

双 ACL16 安全芯片的硬件抽象层。三层结构：

```
se_driver_t (core/se_driver.h)      ← 上层统一接口
   ↓ 实现
se_composite.c                      ← 双 SE 路由 (SE1 金库 / SE2 守卫)
   ↓ 调用
se_acl16.c + se_acl16_opcodes.h     ← APDU 命令层 (ISO 7816-4 风格)
   ↓ 调用
se_transport.h/.c                   ← 字节级传输 (SPI/I2C/UART hooks)
```

## 文件

| 文件 | 角色 |
|------|------|
| `se_transport.h/.c` | 字节级传输契约：init/cs/reset/write/read。平台（ESP32-P4 SPI/I2C）实现 hooks |
| `se_acl16_opcodes.h` | **APDU 操作码占位符** — 拿到 ACL16 手册后只需改这一个文件 |
| `se_acl16.h/.c` | APDU 帧构建/解析 + 高层操作（random/seed/sign/xpub/pin/policy/monotonic/attest） |
| `se_composite.c` | `se_driver_t` 生产实现：路由到 SE1/SE2 + 双源 TRNG hooks |
| `se_mock.c` (core/) | 软件后端，host 测试/模拟器用 |

## 待办（需 ACL16 数据手册）

1. **填操作码**：`se_acl16_opcodes.h` 里所有 `ACL16_INS_*` 和 `ACL16_CLA` 是占位符
2. **确认 secp256k1 原生支持**：`ACL16_P1_CURVE_SECP256K1` —— 若 ACL16 不原生支持，ECC 退回软件会扩大侧信道暴露面，需重评
3. **响应帧格式**：当前假设 `[data] SW1 SW2`（ISO 7816-4），若 ACL16 用 T=1 或厂商自定义帧，需调整 `se_acl16_apdu` 的解析
4. **ESP32-P4 传输实现**：`se_transport_t` 的 SPI/I2C master hooks

## 测试

`tests/test_acl16.c`（APDU 帧 + 状态映射 + 分块 + CS 路由）、`tests/test_composite.c`（双 SE 路由 + 双源 TRNG）。用 loopback transport 验证，无需硬件。
