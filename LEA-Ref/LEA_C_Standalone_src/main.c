#include "src/lea.h"
#include "src/lea_locl.h"

#include "benchmark.h"
#include "lea_benchmark.h"
#include "lea_vs.h"

#include <stdio.h>



int main(void)
{
	int ret;
	printf("SIMD: %s\n", get_simd_type());
	if(ret = lea_mmt_ecb_test())	printf("LEA ECB FAIL(%d)\n", ret);
	if(ret = lea_mmt_cbc_test())	printf("LEA CBC FAIL(%d)\n", ret);
	if(ret = lea_mmt_ctr_test())	printf("LEA CTR FAIL(%d)\n", ret);
	if(ret = lea_mmt_ofb_test())	printf("LEA OFB FAIL(%d)\n", ret);
	if(ret = lea_mmt_cfb_test())	printf("LEA CFB FAIL(%d)\n", ret);
	if(ret = lea_cmac_g_test())		printf("LEA CMAC FAIL(%d)\n", ret);
	if(ret = lea_ccm_ge_test())		printf("LEA CCM FAIL(%d)\n", ret);
	if(ret = lea_gcm_ae_test())		printf("LEA GCM FAIL(%d)\n", ret);
	
	lea_key_benchmark();
	lea_ecb_benchmark();
	lea_cbc_benchmark();
	lea_ctr_benchmark();
	lea_ofb_benchmark();
	lea_cfb_benchmark();
	lea_cmac_benchmark();
	lea_ccm_benchmark();
	lea_gcm_benchmark();
	
	return 0;
}
