#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/multisig.h"
#include "../core/multisig.c"
static void mkfp(uint8_t fp[4],uint8_t s){fp[0]=s;fp[1]=s+1;fp[2]=s+2;fp[3]=s+3;}
int main(void){
    /* 1-of-1 multisig (degenerate but valid) */
    os_multisig m; memset(&m,0,sizeof m);
    m.threshold_m=1; m.total_n=1; m.script=OS_MS_P2WSH; m.self_index=0;
    mkfp(m.cosigner_fp[0],10);
    if(os_ms_validate(&m)!=0){printf("FAIL 1-of-1 rejected\n");return 1;}
    printf("PASS 1-of-1 valid\n");
    /* 15-of-15 max */
    m.threshold_m=15; m.total_n=15;
    for(uint8_t i=0;i<15;i++) mkfp(m.cosigner_fp[i],i*10);
    if(os_ms_validate(&m)!=0){printf("FAIL 15-of-15 rejected\n");return 1;}
    printf("PASS 15-of-15 (max) valid\n");
    /* 16 cosigners -> rejected */
    m.total_n=16;
    if(os_ms_validate(&m)==0){printf("FAIL 16 cosigners accepted\n");return 1;}
    printf("PASS >max cosigners rejected\n");
    /* threshold 0 -> rejected */
    m.total_n=3; m.threshold_m=0;
    if(os_ms_validate(&m)==0){printf("FAIL threshold 0 accepted\n");return 1;}
    printf("PASS threshold 0 rejected\n");
    /* quorum with all 15 required: 14 sigs not enough */
    m.threshold_m=15; m.total_n=15;
    for(uint8_t i=0;i<15;i++) mkfp(m.cosigner_fp[i],i*10);
    bool seen[OS_MS_MAX_COSIGNERS]={false};
    uint8_t fp[4];
    for(uint8_t i=0;i<14;i++){ mkfp(fp,i*10); os_ms_record_sig(&m,fp,seen); }
    if(os_ms_quorum(&m,seen)){printf("FAIL 14/15 quorum\n");return 1;}
    mkfp(fp,140); os_ms_record_sig(&m,fp,seen);
    if(!os_ms_quorum(&m,seen)){printf("FAIL 15/15 no quorum\n");return 1;}
    printf("PASS 15-of-15 requires all sigs\n");
    printf("\nALL ROUND-23 TESTS PASSED\n");
    return 0;
}
