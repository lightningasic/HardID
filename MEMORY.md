# MEMORY — touch UI ship (latest)

## What changed (commit c55d22a)
- Added `components/hardid/touch.c/h` — CST816D capacitive touch (I2C port 0,
  SDA=48, SCL=47, addr=0x15, 400kHz, internal pullups). Polled; single point.
  Coordinates read raw from regs 0x02-0x06 (num, x_h, x_l, y_h, y_l);
  high nibbles masked `&0x0F`, combined `x_h<<8|x_l`, clamped to 240x320.
  Mapping verified against esp-bsp `esp_lcd_touch_cst816s.c` (DATA_START=0x02,
  identical bitfield). No hw reset/read-ID needed; chip may ACK only on touch —
  `touch_get` returns false on error, caller polls.
- Added `ui.h/c` — touch-only Trezor-style framework:
  - `ui_run()`: main menu (Initialize / Sign / Factory reset), re-draws after
    each action returns.
  - On-screen keypad: numeric page (3x4 + [ABC][DEL][OK]) and alpha page
    (6 cols x 5 rows: A-YZ + [SPC][DEL][OK][123]). Toggle via KEY_TOGGLE.
  - `ui_set_pin` / `ui_enter_pin`: double-entry set + confirm; buffers
    secure_bzero'd on every exit path.
  - `confirm()` clears screen with msg; `confirm_overlay()` draws buttons
    over existing content (keeps recovery phrase visible during confirm).
  - `screen_initialize`: gen seed -> BIP39 mnemonic -> show phrase +
    overlay confirm -> set PIN -> store_seed. Already-init guarded.
  - `screen_fixed_digest_sign`: guard is_initialized -> enter+verify PIN ->
    sign fixed 0x11 digest -> show 64-byte r||s hex. Non-fatal wrong PIN.
  - `screen_factory_reset`: confirm -> se_mock_reset -> home.
- `main.c`: boot -> touch_init -> ui_run (never returns).
- `CMakeLists.txt`: add touch.c/ui.c, REQUIRES esp_driver_i2c.

## Mock-SE helpers used (forward-declared in ui.c)
- `se_mock_set_pin(const uint8_t *pin, size_t len)` / `void se_mock_reset(void)`
  in `core/se_mock.c`; real backend must expose wipe via se_driver_t later.

## Audit status
- 4 rounds, `idf.py build` produces ZERO warnings/errors. Clean proof:
  alpha layout maps 26 letters correctly, keypad fits 320px, PIN zeroized,
  store_seed guarded by is_initialized, touch nibble mapping matches ref.

## Left / DONE note
- DONE: flash + smoke-test on hardware. Touch fixed (commit 049f6c1): menu
  stable, no flicker/crash/watchdog; Buttons 1 (Initialize full flow) and 2
  (Sign) work on-device.
- DONE: touch no longer needs BOOT — `idf.py flash` auto-resets via USB-Serial-JTAG.
- Still LEFT: touch axis calibration if taps land mirrored; Button 3 (Factory
  reset) not yet exercised on-device.
- Note: mock_sign_digest is a deterministic stand-in (digest^seed^idx), NOT
  real ECDSA; the on-device proof is the PIN-unlock invariant (SE_ERR_AUTH
  guard), not crypto validity. Real backend will do ECDSA.

## Commands
- Build/flash/monitor: `source ~/esp/esp-idf/export.sh` then
  `idf.py build`, `idf.py flash monitor` (in esp-idf-s3/).
- Boot smoke: hold BOOT on-board, insert USB.