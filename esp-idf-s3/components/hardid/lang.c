/*
 * HardID — UI language / localization
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include "lang.h"

#include "nvs.h"
#include "nvs_flash.h"

#define LANG_NVS_NS "lang"

/* Menu labels, one row per key, one column per language (EN/ZH/JA/KO).
 * UTF-8 encoded; the CJK subset font covers every glyph used here. */
static const char *const s_labels[LKEY_COUNT][LANG_COUNT] = {
	/* LKEY_INITIALIZE */  { "INITIALIZE",   "初始化",     "初期化",     "초기화" },
	/* LKEY_RECOVER */     { "RECOVER",      "恢复",       "復元",       "복구" },
	/* LKEY_SIGN */        { "SIGN",         "签名",       "署名",       "서명" },
	/* LKEY_HOST_LINK */   { "HOST LINK",    "主机连接",   "ホスト接続", "호스트 연결" },
	/* LKEY_FIDO */        { "FIDO",         "FIDO",       "FIDO",       "FIDO" },
	/* LKEY_APP_MARKET */  { "APP MARKET",   "应用市场",   "アプリ市場", "앱 마켓" },
	/* LKEY_PIN */         { "PIN",          "PIN",        "PIN",        "PIN" },
	/* LKEY_ABOUT */       { "ABOUT",        "关于",       "情報",       "정보" },
	/* LKEY_FACTORY_RESET*/ { "FACTORY RESET", "恢复出厂设置", "工場出荷時リセット", "공장 초기화" },
	/* LKEY_LANGUAGE */    { "LANGUAGE",     "语言",       "言語",       "언어" },
	/* LKEY_INSTALLED_APP*/{ "INSTALLED APP", "已安装",    "インストール済み", "설치됨" },
	/* LKEY_AVAILABLE_APP*/{ "AVAILABLE APP", "可安装",    "インストール可能", "설치 가능" },
	/* LKEY_INSTALL_APP */ { "INSTALL APP",  "安装应用",   "アプリをインストール", "앱 설치" },
	/* LKEY_BACK */        { "BACK",         "返回",       "戻る",       "뒤로" },
	/* LKEY_PIN_SET */     { "PIN SET",      "已设置",     "PIN設定済み", "PIN 설정됨" },
	/* LKEY_NO_PIN */      { "NO PIN SET",   "未设置",     "PIN未設定",  "PIN 설정 안 됨" },
	/* LKEY_SET_PIN */     { "SET PIN",      "设置PIN",    "PINを設定",  "PIN 설정" },
	/* LKEY_CHANGE_PIN */  { "CHANGE PIN",   "修改PIN",    "PINを変更",  "PIN 변경" },
	/* LKEY_AUTO_LOCK */   { "AUTO-LOCK",    "自动锁定",   "自動ロック", "자동 잠금" },
};

static const char *const s_lang_names[LANG_COUNT] = {
	"ENGLISH", "中文", "日本語", "한국어",
};

lang_id_t os_lang_get(void)
{
	nvs_flash_init();
	nvs_handle_t h;
	if (nvs_open(LANG_NVS_NS, NVS_READONLY, &h) != ESP_OK)
		return LANG_EN;
	uint8_t v = LANG_EN;
	if (nvs_get_u8(h, "lang", &v) != ESP_OK)
		v = LANG_EN;
	nvs_close(h);
	if (v >= LANG_COUNT)
		v = LANG_EN;
	return (lang_id_t)v;
}

void os_lang_set(lang_id_t lang)
{
	if (lang < 0 || lang >= LANG_COUNT)
		return;
	nvs_flash_init();
	nvs_handle_t h;
	if (nvs_open(LANG_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
		return;
	nvs_set_u8(h, "lang", (uint8_t)lang);
	nvs_commit(h);
	nvs_close(h);
}

const char *os_lang_str(lang_key_t key)
{
	if (key < 0 || key >= LKEY_COUNT)
		return "";
	return s_labels[key][os_lang_get()];
}

const char *os_lang_name(lang_id_t lang)
{
	if (lang < 0 || lang >= LANG_COUNT)
		return "?";
	return s_lang_names[lang];
}
