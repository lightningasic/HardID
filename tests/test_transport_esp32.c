/* ESP32-P4 SPI transport tests (host stub build). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../hal/se_transport.h"
#include "../hal/se_transport_esp32.h"

#include "../hal/se_transport.c"
#include "../hal/se_transport_esp32.c"

static se_esp32_spi_config cfg = {
	.spi_host = 2,
	.gpio_sclk = 12, .gpio_mosi = 11, .gpio_miso = 13,
	.gpio_cs1 = 10, .gpio_cs2 = 9, .gpio_reset = 8,
	.clock_hz = 10000000, .spi_mode = 0,
};

int main(void)
{
	se_transport_t t;
	if (se_esp32_spi_make_transport(&cfg, &t) != 0) { printf("FAIL make\n"); return 1; }
	se_transport_set(&t);
	se_esp32_stub_reset();

	/* 1 init brings up peripheral + GPIO */
	if (t.init() != SE_T_OK) { printf("FAIL init\n"); return 1; }
	if (se_esp32_stub_init_calls() != 1) { printf("FAIL init calls\n"); return 1; }
	printf("PASS t1 init\n");

	/* 2 CS sequencing: assert SE1, write, deassert */
	uint8_t cmd[] = {0x80, 0x84, 0x04, 0x00, 0x00};
	t.cs(SE_CS_1, true);
	t.write(cmd, sizeof cmd);
	t.cs(SE_CS_1, false);
	int n; const int *log = se_esp32_stub_cs_log(&n);
	if (n < 2 || log[0] != 1 || log[1] != -1) { printf("FAIL t2 cs seq n=%d\n", n); return 1; }
	size_t wn; const uint8_t *w = se_esp32_stub_written(&wn);
	if (wn != sizeof cmd || memcmp(w, cmd, sizeof cmd) != 0) { printf("FAIL t2 write\n"); return 1; }
	printf("PASS t2 CS sequencing + write\n");

	/* 3 CS1 vs CS2 distinct in log */
	se_esp32_stub_reset();
	t.cs(SE_CS_2, true);
	t.cs(SE_CS_2, false);
	t.cs(SE_CS_1, true);
	t.cs(SE_CS_1, false);
	log = se_esp32_stub_cs_log(&n);
	if (n != 4 || log[0] != 2 || log[1] != -2 || log[2] != 1 || log[3] != -1) {
		printf("FAIL t3 cs chips n=%d [%d %d %d %d]\n", n, log[0],log[1],log[2],log[3]); return 1; }
	printf("PASS t3 SE1/SE2 CS distinct\n");

	/* 4 reset pulse */
	se_esp32_stub_reset();
	t.reset(SE_CS_1);
	if (se_esp32_stub_reset_pulses() != 1) { printf("FAIL t4 reset\n"); return 1; }
	printf("PASS t4 reset pulse\n");

	/* 5 read returns scripted bytes */
	se_esp32_stub_reset();
	uint8_t resp[] = {0xDE, 0xAD, 0x90, 0x00};
	se_esp32_stub_set_rx(resp, sizeof resp);
	uint8_t buf[8];
	int r = t.read(buf, sizeof buf, 100);
	if (r != sizeof resp || buf[0] != 0xDE || buf[2] != 0x90) { printf("FAIL t5 read r=%d\n", r); return 1; }
	printf("PASS t5 read\n");

	/* 6 config stored: CS uses cfg pins (implicitly via stub), no crash */
	printf("\nALL ESP32 TRANSPORT TESTS PASSED\n");
	return 0;
}
