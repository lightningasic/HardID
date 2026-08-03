#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/psbt.h"
#include "../core/psbt.c"
int main(void){
    uint8_t prog[20] = {0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
                        0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6};
    char out[80];
    bech32_v0(prog, 20, out, sizeof out);
    printf("got  %s\nwant %s\n", out, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    return strcmp(out, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")==0 ? 0 : 1;
}
