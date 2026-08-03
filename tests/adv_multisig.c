/* Round 15: unknown cosigner must be distinguishable (return 0xFF), not
 * silently swallowed. A coordinator feeding strangers must be detectable. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/multisig.h"
#include "../core/multisig.c"
static void mkfp(uint8_t fp[4], uint8_t s){fp[0]=s;fp[1]=s+1;fp[2]=s+2;fp[3]=s+3;}
int main(void){
    os_multisig m; memset(&m,0,sizeof m);
    m.threshold_m=2; m.total_n=3; m.script=OS_MS_P2WSH; m.self_index=0;
    mkfp(m.cosigner_fp[0],10); mkfp(m.cosigner_fp[1],20); mkfp(m.cosigner_fp[2],30);
    bool seen[OS_MS_MAX_COSIGNERS]={false};
    uint8_t a[4],b[4],stranger[4]={99,99,99,99};
    mkfp(a,10); mkfp(b,20);

    /* known signer returns its index */
    if (os_ms_record_sig(&m,a,seen) != 0) { printf("FAIL known a\n"); return 1; }
    if (os_ms_record_sig(&m,b,seen) != 1) { printf("FAIL known b\n"); return 1; }
    printf("PASS known signers return index 0,1\n");

    /* unknown signer returns 0xFF (distinguishable) */
    if (os_ms_record_sig(&m,stranger,seen) != 0xFF) { printf("FAIL stranger not flagged\n"); return 1; }
    printf("PASS unknown signer returns 0xFF (detectable)\n");

    /* quorum still correct with 2 known sigs */
    if (!os_ms_quorum(&m,seen)) { printf("FAIL quorum\n"); return 1; }
    printf("PASS quorum intact\n");
    printf("\nALL ROUND-15 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
