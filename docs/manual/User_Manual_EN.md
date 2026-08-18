# HardID Hardware Wallet — User Manual (English)

> Version v1.2 · 2026-08-15 · Hardware: ESP32-S3 dev board (240×320 touch screen, no physical buttons)

---

## 1. Safety Notice (read this first)

**Most important warning:**

> ⚠️ **Your seed words are only generated on — and should only be entered into — this wallet.**
> **Anyone else asking you for your seed words is scamming you, including (but not limited to): websites, emails, and apps.**
> **Never give your seed words to anyone, including people claiming to be "support", "official", or "recovery staff".**

Three iron rules:

1. **Private keys never leave the device.** Seed words are shown once, on screen, for you to write down; they are never exported and never touch the network.
2. **Seed words are your only backup.** Whoever has them can take your funds. Write them down by hand, offline, and keep them secret.
3. **A PIN only stops others from using your device — it is not your seed words.** A forgotten PIN can be recovered with your seed words; leaked seed words are unrecoverable.

**Anti-tamper note:** a brand-new device should show the menu and prompt you to initialize. If a device arrives with a PIN or seed words already set, someone may have used it — do not use it; factory-reset and re-initialize.

---

## 2. Overview & Main Menu

- 240×320 capacitive touch screen, all-touch, no physical buttons; USB Type-C power.
- After power-on the logo shows, then the main menu. **Left/right arrows move the selection box; press OK or tap the box to enter.**

Main menu (10 items; INITIALIZE / RECOVER are hidden once the device is initialized):

| Item | Meaning |
|---|---|
| INITIALIZE | Generate a new wallet (first use) |
| RECOVER | Enter seed words to restore a wallet |
| SIGN | Unlock and sign |
| HOST LINK | Serve signing requests from a computer |
| FIDO | Enter FIDO passkey service (when installed) |
| APP MARKET | Install/manage coin apps and FIDO |
| PIN | Set/change PIN and auto-lock timeout |
| ABOUT | Version info |
| LANGUAGE | Switch UI language (EN/中文/日本語/한국어) |
| FACTORY RESET | Erase all device data |

---

## 3. Initialize a Wallet

1. Choose **INITIALIZE** from the menu.
2. Choose the **phrase length**: tap **12** (128-bit entropy) or **24** (256-bit entropy). (Dev builds add a 4-word test option; production firmware does not.)
3. **Entropy screen** (optional, recommended): **hold a finger on the screen**, and the device samples touch jitter as extra entropy — a 3–2–1–0 countdown runs, then generation starts automatically; or tap SKIP. The longer you hold, the more randomness is collected.
4. A **seed-word security warning** appears first — read it, then tap **I UNDERSTAND**.
5. The recovery phrase is shown one word at a time. **Write every word down by hand.** Tap Next for the next word.
6. A **second confirmation** asks you to re-enter the phrase word by word; it must match or the flow will not proceed.
7. You are asked **whether to set a PIN** (optional): Yes → set a 4–16 digit PIN twice; No → run PIN-less.
8. Done; return to the menu.

---

## 4. Recover a Wallet (RECOVER)

1. Choose **RECOVER** on a blank device.
2. The **seed-word security warning** appears; tap I UNDERSTAND.
3. Enter seed words on the on-screen keyboard: **a word auto-fills as soon as its 1–4 letter prefix is unique**. Press OK to commit each word; Back to delete.
4. The checksum is validated; a wrong phrase is rejected and never overwrites existing state.
5. Optionally set a PIN, then the seed is stored.

---

## 5. Signing (SIGN)

- Signing requires a PIN unlock (FIDO is the exception). The session unlocks after the correct PIN.
- The device shows the transaction intent field by field (recipient/amount/risk). **What you confirm on screen is what gets signed.** Confirm to sign, Cancel to abort.
- After the idle auto-lock timeout, the wallet locks again and asks for the PIN.

---

## 6. FIDO (Removable Preinstalled App)

- FIDO is a **removable preinstalled app**: factory state is **not installed**. Activate it from APP MARKET's **Available** page, and the next boot goes straight into FIDO passkey service (like a security key).
- **FIDO has no PIN**: authorizing a website login/registration = tapping **Yes** on the device; the wallet PIN is not required.
- Deleting FIDO (Installed page → FIDO → DELETE) **wipes all registered website credentials** and returns to wallet boot.
- Passkey registration/login on sites such as GitHub works (FIDO2/WebAuthn).

---

## 7. PIN (Optional + Auto-lock)

- PIN is optional: asked at first boot / initialize / recover / after factory reset; you may skip it.
- **Entering the wallet requires the PIN**; after unlocking, the wallet **auto-locks when idle**.
- Auto-lock timeout is set in **PIN → AUTO**: 30s / 1min / 5min / 10min / Never (default 5min).
- Changing the PIN requires the old PIN first; setting or changing a PIN locks the device immediately.

---

## 8. APP MARKET

- Split into **Installed App** and **Available App** pages.
- Installed lists coin apps (BTC/ETH + catalog chains LTC/DOGE/BCH/ETC/POLYGON …) and FIDO (when installed).
- Available lists installable coin apps and FIDO (when not installed).

---

## 9. Language (LANGUAGE)

- Choose **LANGUAGE**, use `<` / `>` to pick **English / 中文 / 日本語 / 한국어**, press OK.
- The menu re-renders immediately in the chosen language; the choice is persisted.

---

## 10. Factory Reset (FACTORY RESET)

**Dangerous: erases the seed, PIN, and FIDO credentials. Irreversible.**

1. Choose **FACTORY RESET**.
2. Type **RESET twice** on the on-screen keypad.
3. If a PIN is set, verify it to prove ownership.
4. After wiping, you are asked whether to set a new PIN, then the device returns to the factory state (FIDO not installed).

---

## 11. FAQ

- **Forgot the PIN?** Recover the device with your seed words and set a new PIN (factory-reset first).
- **Does the device connect to the internet?** No. Private keys never leave the device.
- **Does FIDO need a PIN?** No. FIDO authorization is the on-device Yes.
- **Should I send my seed words to support?** Never. Anyone asking is scamming you.

---

*Always protect your assets by keeping everything offline, private, and written by hand.*
