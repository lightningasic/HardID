/*
 * HardID Hardware Wallet — ESP32-S3 main
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Waveshare ESP32-S3-Touch-LCD-2 (ESP32-S3R8), mock SE backend.
 *
 * Boot runs the security gate (RNG self-test, SE probe, display), then the
 * on-screen UI takes over with three Trezor-style functions driven purely by
 * touch: Initialize (seed + PIN), Sign, Factory reset.
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

static const char *TAG = "hardid.main";

#define UI_TASK_STACK 8192
#define UI_TASK_PRIO  5

static void ui_task(void *arg)
{
	ui_run();   /* never returns */
}

void app_main(void)
{
	ESP_LOGI(TAG, "HardID (ESP32-S3, mock SE, touch UI)");

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

	/* Trezor-style three-function UI, on its own task with a large stack
	 * (menu drawing + I2C touch polling overflow the 3.5K main stack). */
	ESP_LOGI(TAG, "starting UI task");
	xTaskCreate(ui_task, "ui", UI_TASK_STACK, NULL, UI_TASK_PRIO, NULL);
	vTaskDelete(NULL);   /* end main task: never spin, keep IDLE healthy */
}