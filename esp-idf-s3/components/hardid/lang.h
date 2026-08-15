/*
 * HardID — UI language / localization
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The device UI is multi-language (English / 中文 / 日本語 / 한국어). The
 * chosen language is persisted in its own NVS namespace ("lang"), default
 * English. Menu labels are looked up via os_lang_str(); only the main menu
 * and the language names are localized for now — the rest of the UI stays
 * English until it is progressively translated.
 */

#ifndef HARDID_LANG_H
#define HARDID_LANG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LANG_EN = 0,
	LANG_ZH = 1,
	LANG_JA = 2,
	LANG_KO = 3,
	LANG_COUNT = 4,
} lang_id_t;

typedef enum {
	LKEY_INITIALIZE = 0,
	LKEY_RECOVER,
	LKEY_SIGN,
	LKEY_HOST_LINK,
	LKEY_FIDO,
	LKEY_APP_MARKET,
	LKEY_PIN,
	LKEY_ABOUT,
	LKEY_FACTORY_RESET,
	LKEY_LANGUAGE,
	LKEY_INSTALLED_APP,
	LKEY_AVAILABLE_APP,
	LKEY_INSTALL_APP,
	LKEY_BACK,
	LKEY_PIN_SET,
	LKEY_NO_PIN,
	LKEY_SET_PIN,
	LKEY_CHANGE_PIN,
	LKEY_AUTO_LOCK,
	LKEY_COUNT,
} lang_key_t;

/* Current UI language, persisted in NVS (default English). */
lang_id_t os_lang_get(void);
void os_lang_set(lang_id_t lang);

/* Localized UTF-8 label for a menu key in the current language. */
const char *os_lang_str(lang_key_t key);

/* The language's own name (for the language selection screen). */
const char *os_lang_name(lang_id_t lang);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_LANG_H */
