#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../hal/se_board.h"
#include "../core/se_driver.h"
#include "../hal/se_transport.h"
#include "../hal/se_transport_esp32.h"
#include "../hal/se_acl16.h"
#include "../hal/se_transport.c"
#include "../hal/se_transport_esp32.c"
#include "../hal/se_acl16.c"
#include "../hal/se_composite.c"
#include "../hal/se_board.c"
int main(void){
    if (os_board_se_init() != SE_OK) { printf("FAIL board init\n"); return 1; }
    if (se_active() == NULL) { printf("FAIL no active driver\n"); return 1; }
    printf("PASS board init wires SPI transport + dual-ACL16 composite (%s)\n", se_active()->name);
    return 0;
}
