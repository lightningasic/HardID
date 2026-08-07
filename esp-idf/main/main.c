/*
 * HardID Hardware Wallet — ESP32-P4 main
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * ESP32-P4 + dual ACL16 (or mock, see Kconfig), touch UI.
 *
 * Boot runs the security gate (board init, RNG self-test, SE probe), then
 * the on-screen UI takes over with the six Trezor-style functions driven
 * purely by touch: Initialize (seed + PIN), Sign, Recover, Host link,
 * Factory reset, About. Ported from the ESP32-S3 bring-up build — only the
 * board adapter (board_p4.c + board_p4.h) and target chip differ.
 */

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "boot.h"
#include "display.h"
#include "touch.h"
#include "ui.h"
#ifdef CONFIG_HARDID_SE_ACL16
#include "se_board.h"
#endif

static const char *TAG = "hardid.main";

#define UI_TASK_STACK 8192
#define UI_TASK_PRIO  5

static void ui_task(void *arg)
{
	ui_run();   /* never returns */
}

void app_main(void)
{
	ESP_LOGI(TAG, "HardID (ESP32-P4, touch UI)");

#ifdef CONFIG_HARDID_SE_ACL16
	/* Wire the SPI transport + both ACL16 secure elements before the boot
	 * gate probes them (se_board.c: os_board_se_init sets the transport the
	 * composite driver reads; with the mock backend there is no transport). */
	if (os_board_se_init() != 0) {
		ESP_LOGE(TAG, "SE init FAILED — halting");
		for (;;) { }
	}
#endif

	/* boot: board init (LCD), RNG self-test, SE probe — halts on failure */
	if (os_boot_run() != OS_BOOT_STAGE_MAIN_LOOP) {
		ESP_LOGE(TAG, "boot stage failed");
		for (;;) { }
	}

	/* touch */
	if (touch_init() != 0)
		os_board_display_error("Touch", "init failed");
	else
		ESP_LOGI(TAG, "touch ready");

	/* six-function UI on its own task with a large stack */
	ESP_LOGI(TAG, "starting UI task");
	xTaskCreate(ui_task, "ui", UI_TASK_STACK, NULL, UI_TASK_PRIO, NULL);
	vTaskDelete(NULL);   /* end main task: never spin, keep IDLE healthy */
}