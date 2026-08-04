/* Dual-SE composite driver tests: routing + dual-source TRNG hooks. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../hal/se_transport.h"
#include "../hal/se_acl16.h"
#include "../core/se_driver.h"

/* loopback transport with per-APDU response segments (shared pattern) */
typedef struct { const uint8_t *p; size_t len; } seg_t;
static seg_t g_segs[8];
static int g_nsegs, g_seg_idx;
static size_t g_seg_pos, g_written_len;
static se_chip g_last_cs;
static int lb_init(void){return SE_T_OK;}
static void lb_cs(se_chip c, bool a){ if(a) g_last_cs=c; }
static void lb_reset(se_chip c){(void)c;}
static int lb_write(const uint8_t *b, size_t n){ (void)b; g_written_len+=n; return SE_T_OK; }
static int lb_read(uint8_t *b, size_t n, uint32_t t){
	(void)t;
	if (g_seg_idx >= g_nsegs) return 0;
	seg_t *s=&g_segs[g_seg_idx];
	if (g_seg_pos >= s->len) return 0;
	size_t avail=s->len-g_seg_pos, take=avail<n?avail:n;
	memcpy(b, s->p+g_seg_pos, take); g_seg_pos+=take; return (int)take;
}
static const se_transport_t lb = { lb_init, lb_cs, lb_reset, lb_write, lb_read };
static void script(seg_t *segs, int n){
	g_written_len=0;
	for(int i=0;i<n;i++) g_segs[i]=segs[i];
	g_nsegs=n; g_seg_idx=0; g_seg_pos=0;
}

#include "../hal/se_transport.c"
#include "../hal/se_acl16.c"

/* pull in the composite (it defines se_active + dual TRNG hooks) */
#include "../hal/se_composite.c"

int main(void)
{
	se_transport_set(&lb);
	const se_driver_t *se = se_active();

	/* 1 init */
	if (se->init() != SE_OK) { printf("FAIL t1 init\n"); return 1; }
	printf("PASS t1 composite init (%s)\n", se->name);

	/* 2 store_seed routes to SE1 */
	{
		static uint8_t pb[]={0x90,0x00};
		seg_t s[1]={ {pb,sizeof pb} };
		script(s,1);
		uint8_t seed[32]; memset(seed,0x11,32);
		if (se->store_seed(seed) != SE_OK) { printf("FAIL t2 store\n"); return 1; }
		if (g_last_cs != SE_CS_1) { printf("FAIL t2 store_seed not SE1\n"); return 1; }
		printf("PASS t2 store_seed -> SE1\n");
	}

	/* 3 verify_pin routes to SE2 */
	{
		static uint8_t pb[]={0x00, 0x90,0x00};
		seg_t s[1]={ {pb,sizeof pb} };
		script(s,1);
		uint8_t pin[4]={'1','2','3','4'};
		bool d=false;
		if (se->verify_pin(pin,4,NULL,&d) != SE_OK) { printf("FAIL t3 pin\n"); return 1; }
		if (g_last_cs != SE_CS_2) { printf("FAIL t3 verify_pin not SE2\n"); return 1; }
		printf("PASS t3 verify_pin -> SE2\n");
	}

	/* 4 dual-source TRNG hooks hit SE1 and SE2 respectively */
	{
		static uint8_t r1[]={1,2,3,4,0x90,0x00};
		static uint8_t r2[]={9,8,7,6,0x90,0x00};
		uint8_t b1[4], b2[4];
		seg_t s1[1]={ {r1,sizeof r1} }; script(s1,1);
		if (os_seed_se_trng(b1,4) != 0 || g_last_cs != SE_CS_1) { printf("FAIL t4 se1 trng\n"); return 1; }
		seg_t s2[1]={ {r2,sizeof r2} }; script(s2,1);
		if (os_seed_se2_trng(b2,4) != 0 || g_last_cs != SE_CS_2) { printf("FAIL t4 se2 trng\n"); return 1; }
		if (b1[0]!=1 || b2[0]!=9) { printf("FAIL t4 trng data\n"); return 1; }
		printf("PASS t4 dual-source TRNG SE1+SE2\n");
	}

	/* 5 monotonic routes to SE2 */
	{
		static uint8_t pb[]={0x2A,0x00,0x00,0x00, 0x90,0x00};
		seg_t s[1]={ {pb,sizeof pb} };
		script(s,1);
		uint32_t c=0;
		if (se->monotonic_read(&c) != SE_OK || c != 42) { printf("FAIL t5 mono=%u\n", c); return 1; }
		if (g_last_cs != SE_CS_2) { printf("FAIL t5 mono not SE2\n"); return 1; }
		printf("PASS t5 monotonic -> SE2 (counter=%u)\n", c);
	}

	printf("\nALL COMPOSITE TESTS PASSED\n");
	return 0;
}
