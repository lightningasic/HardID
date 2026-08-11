# HardID 多熵源设计 — 扩展物理熵源进入种子生成信任链

- 日期: 2026-08-11
- 状态: **已实现并真机验证** (commit `46c3252`, S3/P4 双构建 + S3 真机走查)
- 范围: 硬件钱包种子生成的多源熵采集与混合, 不改变派生规范/签名管线

## 0. 背景与目标

当前 `os_seed_generate` (core/seed.c) 已经是多源 HKDF 混合:

```
PRK = HKDF-Extract(salt, SE1_TRNG || SE2_TRNG || host_entropy)
seed = HKDF-Expand(PRK, "mnemonic", 32)
```

- `os_seed_se_trng()` — SE1 (ACL16) TRNG, 缺省弱符号 fail-closed
- `os_seed_se2_trng()` — SE2 (ACL16) TRNG, 缺省回退主控 TRNG
- `host_entropy` — 可选主机熵 (创建钱包时主机注入)

目标: 在**不降低可用性**的前提下, 增加更多独立物理熵源, 提升抗侧信道/
抗单一组件损坏的熵保证。关键约束: **任一单源失效不致命** (PRD §3.1),
且不引入可用性妥协 (用户在创建钱包时不希望必须"摇一摇"/录视频)。

## 1. 熵源清单

按「独立性 × 采集成本 × 可用性影响」给建议。**独立**指与主控 TRNG
(esp_random) 没有共享时钟/电源/半导体工艺的随机性来源。

| # | 熵源 | 现网已有 | 采集方式 | 独立性 | 采集成本 | 可用性影响 |
|---|------|---------|---------|--------|---------|-----------|
| S1 | SE1 ACL16 TRNG | ✅ | 现成 SPI 读 | 高 (独立芯片) | 低 | 无 |
| S2 | SE2 ACL16 TRNG | ✅ (生产) | 现成 SPI 读 | 高 | 低 | 无 |
| S3 | 主控 ESP32-S3 TRNG | ✅ | esp_random() | 中 (同一 SoC) | 低 | 无 |
| S4 | 触摸屏触点噪声 (CST816D) | ✅ 已实现 | 采集触摸坐标抖动的低位 | 中 | 低 | 中 (需一次触摸) |
| S5 | 内部温度传感器热噪声 | ✅ 已实现 | esp_driver_tsens 采样摄氏值 LSB | 中 | 低 | 无 |
| S6 | I2C 总线时序抖动 | ✅ 已实现 | 对 touch_get 测应答延迟 LSB | 中 | 低 | 无 |
| S7 | RTC 慢时钟漂移 | ✅ 已实现 | 读 RTC_CNTL_TIME 低位 (P4 用 esp_timer) | 低-中 | 低 | 无 |
| S8 | 射频/近场天线噪声 (若加 WiFi/BLE) | — | 射频 RSSI 采样 | 高 | 高 (加硬件) | 无 |
| S9 | 摄像头传感器噪声 | 硬件可加 | 传感器暗电流采样 | 高 | 高 (加硬件) | 中 (需遮光/校准) |
| S10 | 麦克风环境噪声 | 硬件可加 | ADC 采样本底噪声 | 高 | 高 (加硬件) | 中 (需安静/校准) |
| S11 | 元器件随机性 (分立噪声源) | 硬件可加 | 反相器环/齐纳击穿 ADC | 高 | 高 (加硬件) | 无 |

> **实现说明 (2026-08-11)**: S5 原设计为背光 ADC 纹波, 实机确认背光 GPIO1 是
> 数字电平输出无纹波可采, 改为内部温度传感器 (esp_driver_tsens) 的摄氏值 LSB
> 抖动; S7 在 P4 上无 RTC 计数器寄存器 (RTC_CNTL_TIME0_REG 为 S3 专属), 用
> esp_timer 微秒值 LSB 替代。

**分层建议**:
- **Layer A (零成本, 纯固件, 强烈建议)**: S4 触摸噪声 + S5 背光 ADC +
  S6 总线时序 + S7 RTC 漂移。利用**已有硬件**, 只在初始化时采集。
- **Layer B (需要新外设, 可选)**: S8/S9/S10/S11。摄像头/麦克风本质上是
  "现成传感器", 但采集需要遮光/静音校准, 且增加 BOM。**不建议作为必选**。
- **Layer C (SE 内部)**: S1/S2 已是生产路径, 保持。

## 2. 采集设计 (Layer A 纯固件)

统一入口: 新增 `os_seed_phys_trng()` 概念或扩展现有源函数。**设计原则**:
所有物理源采集放在 `os_seed_generate` 内的一次性"熵收集阶段", 逐源读取、
逐源校验最小熵, 全部混合进 HKDF Extract 输入。

```
extract_input = S1 || S2 || S3 || S4 || S5 || S6 || S7
```

### 2.1 S4 触摸噪声 (CST816D)

- 提示"触摸屏幕任意位置 2 秒" (仅创建钱包时一次)。
- 采集: 以 1ms 间隔采样 `touch_get()`, 取坐标低 2-4 位的抖动,
  累积 ~256 bit 原始噪声。
- 可用性: 加一次触摸引导, 用户可接受 (创建钱包本就需交互)。
- 风险: 坐标抖动可能高度结构化 — 必须过无条件熵池 (见 §4), 不单独依赖。

### 2.2 S5 温度传感器热噪声 (内部 tsens, 实现替代背光 ADC)

- **定案变更 (2026-08-11)**：原设计用背光 ADC 采样纹波。实机确认本板背光
  (GPIO1) 是数字电平输出，无模拟纹波可采 → 改为 ESP32-S3 内建温度传感器
  (esp_driver_tsens，`TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10,80)`)。
- 采集：install → enable → 连续 `get_celsius` 多次，取 float 原始位的 LSB
  抖动（热噪声，与 MCU TRNG 独立）。采样后 disable + uninstall 恢复。
- 无用户交互，瞬时（<100ms）。采集失败（驱动不可用）→ 跳过该子源不失败整体。

### 2.3 S6 总线时序抖动

- 对 SE 发起已知长度 I2C/SPI 读, 用 `esp_timer_get_time()` 测应答延迟,
  取延迟 LSB 抖动。需 SE 应答延迟本身含物理抖动 (由时钟/电源噪声引起)。

### 2.4 S7 RTC 漂移

- 多次读 RTC 计数值, 差值低位。若 RTC 晶振太稳, 熵低 — 仅作辅助源。
- **实现**：S3 读 `RTC_CNTL_TIME0_REG` (150kHz 慢时钟计数) 低位；
  P4 无此寄存器，改用 esp_timer 微秒值 LSB（同样含亚微秒读出抖动）。

### 2.5 Layer B/C 摄像头/麦克风/分立噪声 (硬件阶段)

- 若未来加摄像头: 遮光帧传感器暗噪声 (ISO/增益开高), ADC 采样。
- 若加麦克风: 环境本底噪声 ADC (需低噪声模拟前端, 否则量化后熵极低)。
- 若加分立噪声: 环形振荡器 / 齐纳管雪崩, 需专用模拟滤波 + ADC。
- **结论: 摄像头/麦克风是"现成传感器但难采好熵", 价值取决于模拟前端质量。
  作为 Layer B 可选, 不作为硬件必选。** 若硬件已带, 可接入; 不为此加硬件。

## 3. 接口设计

保持 `os_seed_generate` 签名不变 (S3/P4/host 三端测试已依赖)。扩展方式:
新增一个"额外物理熵"钩子, 由板层实现:

```c
/* seed.h 新增 */
int os_seed_phys_extra(uint8_t *buf, size_t len);
/* 返回 0 = 已填充 len 字节 (可能含低熵, 由池统一处置);
 * 返回 1 = 该源不可用/用户跳过 (不失败);
 * 缺省弱符号 = 返回 1。绝不 fail-closed: Layer A 全是可选增强。 */
```

`os_seed_generate` 内:

```c
uint8_t phys[32] = {0};
if (os_seed_phys_extra(phys, sizeof phys) == 0) {
    os_hmac_sha256_update(&h, phys, sizeof phys);   /* 混入 Extract 输入 */
}
```

板层实现 (esp-idf-s3/components/hardid/board_s3.c 或新 entropy.c):
- 采集 S4-S7 各源原始字节 → 拼接 → 过**无条件哈希池** (§4) → 输出 32B。
- 任一子源采集失败 → 跳过该子源, 不失败整体。
- 采集全部失败/用户跳过 → 返回 1, 种子仍可生成 (S1+S2+S3+host 兜底)。

## 4. 熵池: 无条件混合 (关键安全组件)

**禁止**把任何单源原始字节直接用作密钥材料。全部物理源先过无条件池:

```c
/* 无条件混合: pool = SHA256(pool || src) 逐源吸收; 输出 = SHA256(pool) */
```

- 每源采样量、顺序、连接均可被攻击者控制/猜测, 但**无条件熵池保证**:
  只要至少一个源贡献 ≥1 bit 真随机, 输出与攻击者可预测的其余输入统计独立。
- 再与 S1/S2 (SE TRNG) 一起进 `os_seed_generate` 的 HKDF。SE TRNG 是
  信任根, Layer A 是纵深。

## 5. 威胁模型 (为什么值得加)

| 威胁 | 现状 | 加 Layer A 后 |
|------|------|--------------|
| SE 芯片损坏/无响应 | 种子生成失败 (fail-closed) | 仍失败 (SE 是信任根, 正确) |
| SE TRNG 被旁路/后门 (供应链) | 仅主控 TRNG 兜底 | 多物理源兜底, 单源后门不致命 |
| 主控 TRNG 被软件破坏 (攻击者已 RCE) | SE 兜底 | SE 兜底不变, 物理源再添一层 |
| 创建时熵不足 (行业事件: milk sad) | 三源 | 七源, 且 S4 由用户物理参与 |
| 可复现构建/审计 | HKDF 明确 | 各源采集代码独立可审 |

## 6. 可用性权衡 (诚实评估)

- **Layer A 的 S4 触摸**是唯一需要用户交互的源。选项:
  a) 必做: 创建钱包时引导触摸 2s (熵最好, 推荐)
  b) 可选: 用户可跳过 (跳过则物理源 = S5+S6+S7)
- 摄像头/麦克风若必做会显著伤害创建流程 (要遮光/静音校准), **不建议**。
- 方案定位: Layer A 纯固件零 BOM, 推荐实现; Layer B 视硬件计划决定。

## 7. 验收标准

1. `os_seed_phys_extra` 缺省返回 1, host/S3/P4 现有测试全绿不变。
2. 板层实现后, 创建钱包生成种子, 与"无物理源"版本不同 (确实混入)。
3. 触摸源: 手指导航时采集 ≥64 抖动样本, 采样坐标低位分布非单点。
4. 各子源失败降级: 关掉任意单个子源, 种子生成仍成功。
5. 文档: 04 工程文档三源熵 → 更新为"核心熵 (SE1/SE2/主控) + 物理熵池
   (触摸/ADC/总线/RTC)"。

## 7.5 实现记录 (2026-08-11, commit `46c3252`)

**落地文件**
- `core/phys_entropy.h/.c` — 无条件熵池 (SHA-256 链式吸收, 前缀安全长度域,
  单次提取擦除)。新增 host 测试 `tests/test_phys_entropy.c`, CI 加入。
- `core/seed.h/.c` — `os_seed_phys_extra` 弱符号钩子 (缺省返回 1) 混入
  HKDF Extract 输入; `tests/test_seed.c` 加 stub。
- `esp-idf-s3/components/hardid/entropy_s3.c` — S4 触摸坐标 LSB 抖动
  (150ms 窗口 / ≤64 样本; 请求 2ms 间隔, 实际受 CONFIG_FREERTOS_HZ=100
  限为 ~10ms/tick) + S5 tsens + S6 I2C 读延迟 + S7 RTC 寄存器。
  实现 `os_seed_phys_extra` (strong)。
- `esp-idf/components/hardid/entropy_p4.c` — 同上, S7 改 esp_timer。
- 两个 CMakeLists 加 phys_entropy.c + entropy_*.c + REQUIRES
  esp_driver_tsens esp_timer。

**真机验证 (S3, 经 DEV touch injector 驱动 UI)**
- 走查日志链: `seedgen begin elen=0` → `temperature_sensor: Range [-10°C ~
  80°C]` → `hardid.entropy: physical entropy mixed into seed` → `seedgen
  done rc=0`。物理熵确实进入种子生成。
- **验证盲区 (诚实记录)**: 该走查实证的源为 S5 (tsens 驱动日志可见) +
  S6/S7 (无条件执行)。S4 触摸抖动**未实证**——驱动脚本在触发 seedgen 前
  已抬起手指, collect_touch 采到 0 样本且该计数日志为 DEBUG 级默认不可见。
  S4 代码路径经 host 池测试与构建覆盖, 真机逐源验证 (手指按住屏幕触发
  seedgen) 留待后续。

**已知坑 (链接, 已修复)**
- `os_seed_phys_extra` 是 entropy_s3.c 唯一导出符号, 而 seed.c 提供同名
  weak 缺省。GNU ld archive 扫描时 seed.c.obj 先被 os_seed_generate 拉入,
  其内部引用被同文件 weak 定义满足 → ld 不再提取 entropy_s3.c.obj
  (strong), 最终 ELF 保留 weak no-op (seedgen 仅 10ms, 无熵混入日志)。
  修复: 板层 `os_board_hw_init` 调用 `os_entropy_force_link()` 哑符号
  强制提取; ELF 符号 W→T 验证。**给后续单导出符号模块的通用教训**:
  同名单符号 weak/strong 覆盖只在整 obj 已因其他符号被拉入时才生效。

**DEV 触摸注入器 (`CONFIG_HARDID_DEV_TOUCH_INJECT`, dev-only)**
- 无触屏环境的真机驱动手段: 串口 (USB-JTAG RX) 收 `P x y` / `R` 行合成
  按下/抬起, atomic 变量跨核同步, 与真实 CST816D 事件同一入口。用于驱动
  UI 走查 (初始化流程全链路) 与熵采集回归。

## 8. 落地方案建议

- **立即做 (纯固件)**: Layer A 四项 + 熵池 + 钩子。增量 ~1 个板层文件
  (entropy_s3.c / entropy_p4.c) + seed.c 一处修改。
- **硬件路线图**: 若后续加 WiFi/摄像头/麦克风, 用 §3 钩子直接接入, 无需
  改核心逻辑。**不必为熵单独加硬件**。
- 与 M8 (防降级) 正交; 不依赖 secure boot。
