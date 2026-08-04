/*
 * HardID Hardware Wallet — ESP32-P4 firmware entry point
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "se_board.h"
#include "rng.h"

static const char *TAG = "hardid";

void app_main(void)
{
	ESP_LOGI(TAG, "HardID booting (ESP32-P4 + dual ACL16)");

	/* Board + dual-ACL16 bring-up (SPI transport + composite driver) */
	if (os_board_se_init() != 0) {
		ESP_LOGE(TAG, "SE init FAILED — halting");
		for (;;) { vTaskDelay(pdMS_TO_TICKS(1000)); }
	}
	ESP_LOGI(TAG, "SE init OK");

	/* RNG health gate — refuse to run with a broken entropy source */
	if (os_rng_self_test() != 0) {
		ESP_LOGE(TAG, "RNG self-test FAILED — do not use this device");
		for (;;) { vTaskDelay(pdMS_TO_TICKS(1000)); }
	}
	ESP_LOGI(TAG, "RNG self-test OK");

	/* TODO: UI / Clear Sign main loop (display task, QR scan, USB/QR comm) */
	ESP_LOGI(TAG, "boot complete");
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(10000));
	}
}
