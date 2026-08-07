# MEMORY — HardID architecture optimization (P0–P3) + handoff

状态：**所有阶段代码已实现、host 测试通过、编译零警告**。真机验证待用户回到机器后执行。

## Commits (this run, from P0 onward)
- `ab551a4` ESP-IDF P0: split ui.c -> inter / keypad / screen layers (warning-free,
  verified on-device menu/sign before user left). Moved mis-created `esp-adf-s3/
  screen.c` to the correct path; added color consts+stdint to display.h.
- `db3f7bf` P3: on-device mnemonic recovery (screen_run_recover).
- `c670458` P1: framed host protocol + Clear-Sign service; USB-Serial-JTAG screen.
- `5ac8c23` P2: SE backend selectable via Kconfig (mock default).
- `ffff1b2` docs: feature matrix reflects Recover / Host link / backend switch.

## What each piece does

### P0 UI layers (components/hardid/)
- `inter.c/h` — touch debounce / release / hit-test / wait_ack / ui_touch_now
- `keypad.c/h` — numeric + alpha keypad, PIN set/enter, confirm dialogs
- `screen.c/h` — initialize / sign / factory_reset / **recover**
- `link_esp.c` — Host link screen (USB-Serial-JTAG driver)
- `ui.c` — 5-item main menu (Initialize / Sign / Recover / Host link / Factory reset)

### P1 host link (core/)
- `linkproto.c/h` — framed, CRC-16/CCITT protocol, both directions
- `linksvc.c/h` — status / ping / PIN-consented sign via an injected SE vtable
- host tests: `tests/test_linkproto.c`, `tests/test_linksvc.c` (both PASS)

### P2 backend switch (core + hal + Kconfig)
- `esp-idf-s3/components/hardid/Kconfig` — HARDID_SE_MOCK (default) / HARDID_SE_ACL16
- CMake pulls `core/se_mock.c` or `hal/se_composite.c + se_acl16.c +
  se_transport_esp32*` accordingly. `CONFIG_HARDID_SE_MOCK=1` confirmed.

### P3 recovery (screen.c)
- menu entry 3 → screen_run_recover(): masked phrase entry → lowercase →
  checksum-validate (`os_bip39_mnemonic_to_entropy`) → new PIN → store seed.
- crypto path proven on host with the official 24-word vector round-trip.

### P3 word-by-word recovery via unique 4-char prefix (new)
- `os_bip39_word_resolve_prefix(p,n)` — resolve a typed prefix to a word index.
- `os_bip39_word_try_commit(p,n)` — auto-commit an *unambiguous* prefix:
  - n==4: the (only) word starting with the prefix commits (BIP39 guarantees
    every word has a unique 4-char prefix — verified over all 2048 words).
  - n<4: only words whose full length == n (short terminal words like "zoo");
    leaves "add" open so "addict"/"address" can be reached, and lets
    KEY_SPACE force-commit the exact short word when the user means "add".
- `os_bip39_word_at(i)` — word by index (for the UI / tests).
- On-screen: `kp_capture_phrase()` in keypad.c — swipe letters of each word's
  prefix; the keypad auto-resolves to the full lowercase word and advances.
  DEL drops a letter or backs out the last word; ENTER finishes; the 8x16
  high-res floats the hovered letter / current prefix.
- `screen_run_recover` now uses `kp_capture_phrase` (returns lowercase phrase
  directly; no manual tolower needed).
- Host tests t7–t15 cover prefix uniqueness, short-word ambiguity, and
  try_commit. All PASS (test_bip39.c). `granted` paths proven on host.

## Verified so far (host / build)
- `idf.py build` zero warnings/errors.
- test_linkproto, test_linksvc, test_bip39 PASS on host.
- blog: mock sign (digest^seed^idx) is a placeholder; PIN-unlock invariant is the
  real safety property (SE_AUTH gate). Real ECDSA only via ACL16 backend.

## LEFT — must verify on REAL hardware (user back at machine)
- The board was **physically unplugged** at the end of this run (`/dev/ttyACM0`
  absent), so the word-by-word recover could not be flashed/verified on-device.
1. **Flash + boot** the new 5-item menu; confirm original 3 flows still work
   (Initialize / Sign / Factory reset) and the layout fits (5 rows, 240x320).
2. **Recover (word-by-word)**: after Factory reset, run Recover → swipe each
   word's unique 4-char prefix → the device expands it to the full lowercase
   word; short words like "add" need SPC to force-commit. Confirm "Recovered.
   Seed + PIN stored." Also test bad-checksum → "Invalid mnemonic."
3. **Host link (P1) transport — risky**: the console already owns USB-Serial-
   JTAG. Connecting a real host & sending a framed SIG/STATUS needs on-device
   bring-up. If `usb_serial_jtag_read_bytes` conflicts with the console, run
   PIN first (the session requires it). Confirm a digest is shown + only signed
   after a `Confirm` tap.
4. **SE backend switch (P2)**: only if ACL16 parts + SPI wiring are fitted.
   NOTE: `screen.c` still calls the mock-only helpers `se_mock_reset()`,
   `se_mock_set_pin()`. For an ACL16 build these must be re-routed to the
   composite API (store_seed / a wipe). This is the known follow-up.

## Environment
- IDF v5.3.2, toolchain esp32s3. Board: Waveshare ESP32-S3-Touch-LCD-2
  (ST7789 240×320, CST816D touch I2C SDA=48/SCL=47 @0x15, 8MB PSRAM / 16MB flash).
- Build dir: `code/esp-idf-s3`. Shell env needed: `source ~/esp/esp-idf/export.sh`.
- Flash: `idf.py -p /dev/ttyACM0 flash` (USB-Serial-JTAG auto-reset; no BOOT).
- Logs: keyboard `idf.py monitor` or `python /tmp/opencode/reset].py` (pyserial).

## Commands for user
```
cd "code/esp-idf-s3"
source ~/esp/esp-idf/export.sh
idf.py build            # already clean
idf.py flash            # device attached -> auto reset
idf.py monitor          # tap menu, walk each flow
```
Host unit tests (no hardware):
```
cd code/tests && cc test_linkproto.c -I.. -o /tmp/t_lp && /tmp/t_lp
cc test_linksvc.c -I.. -o /tmp/t_ls && /tmp/t_ls
cc test_bip39.c -I.. -o /tmp/t_b39 && /tmp/t_b39
```