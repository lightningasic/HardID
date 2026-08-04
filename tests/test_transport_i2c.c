#include <stdio.h>
#include <string.h>
#include "../hal/se_transport.h"
#include "../hal/se_transport_esp32_i2c.h"
#include "../hal/se_transport.c"
#include "../hal/se_transport_esp32_i2c.c"
int main(void){
    se_esp32_i2c_config cfg = {0, 21, 22, 0x50, 0x51, 400000};
    se_transport_t t;
    if (se_esp32_i2c_make_transport(&cfg, &t) != 0) { printf("FAIL make\n"); return 1; }
    if (t.init() != SE_T_OK) { printf("FAIL init\n"); return 1; }
    t.cs(SE_CS_2, true);
    if (g_cur != SE_CS_2) { printf("FAIL cs routing\n"); return 1; }
    printf("PASS I2C transport make/init/cs\n");
    return 0;
}
