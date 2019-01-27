/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include "../include/lsh.h"
#include "../include/hmac.h"
#include "lsh_benchmark.h"
#include "benchmark.h"

#pragma warning(disable: 4996)

int lsh_testvector_simd();
int lsh_crosscheck_simd();

static lsh_u8 g_hmac_key_data[384];
static lsh_u8 g_lsh_test_data[1024];

void fout_hex(FILE* fp, const lsh_u8* data, const size_t datalen){
	size_t i;

	if (fp == NULL || data == NULL){
		return;
	}

	for (i = 0; i < datalen; i++){
		fprintf(fp, "%02x", (lsh_u8)data[i]);

		/*
		if (i % 32 == 31){
			fprintf(fp, "\n");
		}
		else if (i % 4 == 3){
			fprintf(fp, " ");
		}
		*/
	}

	if (i % 32 != 31){
		fprintf(fp, "\n");
	}
}

int hmac_lsh_test_type2(const char* path_prefix){
	FILE* fp;
	lsh_uint i;
	lsh_uint hashbit, keylen_idx, msglen;
	lsh_uint tmp;
	lsh_type t_type;

	int hmac256_keylen[] = { 0, 1, 8, 32, 64, 128, 256 };
	int hmac512_keylen[] = { 0, 1, 8, 32, 64, 128, 256, 384 };
	lsh_u8 hmac_result[LSH512_HASH_VAL_MAX_BYTE_LEN];
	char outpath[256];

	if (path_prefix == NULL || strlen(path_prefix) > 200){
		return 1;
	}

	/* hmac key = {2k} + {2*(k-128)+1} + {2(k-256)} */
	g_hmac_key_data[0] = 0;
	for (i = 1; i < 384; i++){
		tmp = g_hmac_key_data[i - 1] + 2;
		if (tmp >= 0x100){
			tmp ^= 0x101;
		}
		g_hmac_key_data[i] = tmp;
	}

	for (i = 0; i < 1024; i++){
		g_lsh_test_data[i] = (lsh_u8)i;
	}

	/* LSH256 */
	for (hashbit = 1; hashbit <= 256; hashbit++){
		t_type = LSH_MAKE_TYPE(0, hashbit);
		for (keylen_idx = 0; keylen_idx < sizeof(hmac256_keylen) / sizeof(int); keylen_idx++){
			sprintf(outpath, "%s%d_%d_%d.txt", path_prefix, 256, hashbit, hmac256_keylen[keylen_idx]);
			fp = fopen(outpath, "wt");
			if (fp == NULL){
				continue;
			}

			for (msglen = 0; msglen < sizeof(g_lsh_test_data); msglen++){
				hmac_lsh_digest(t_type, g_hmac_key_data, hmac256_keylen[keylen_idx], g_lsh_test_data, msglen, hmac_result);
				fprintf(fp, "%d\n", msglen);
				fout_hex(fp, hmac_result, LSH_GET_HASHBYTE(t_type));
				fprintf(fp, "\n");
			}
			fclose(fp);
		}
	}

	/* LSH512 */
	for (hashbit = 1; hashbit <= 512; hashbit++){
		t_type = LSH_MAKE_TYPE(1, hashbit);
		for (keylen_idx = 0; keylen_idx < sizeof(hmac512_keylen) / sizeof(int); keylen_idx++){
			sprintf(outpath, "%s%d_%d_%d.txt", path_prefix, 512, hashbit, hmac512_keylen[keylen_idx]);
			fp = fopen(outpath, "wt");
			if (fp == NULL){
				continue;
			}

			for (msglen = 0; msglen < sizeof(g_lsh_test_data); msglen++){
				hmac_lsh_digest(t_type, g_hmac_key_data, hmac512_keylen[keylen_idx], g_lsh_test_data, msglen, hmac_result);
				fprintf(fp, "%d\n", msglen);
				fout_hex(fp, hmac_result, LSH_GET_HASHBYTE(t_type));
				fprintf(fp, "\n");
			}
			fclose(fp);
		}
	}

	return 0;
}

void lsh_test_type2(lsh_type algtype){

	lsh_uint i;
	lsh_uint k;

	size_t datalen;
	lsh_u8 data[256 * 4];
	lsh_u8 hash[LSH512_HASH_VAL_MAX_BYTE_LEN];

	int databitlen256[16] = { 0, 1, 2, 7, 8, 15, 16, 1023, 1024, 1025, 1024 * 2 - 1, 1024 * 2, 1024 * 2 + 1, 1024 * 3 - 1, 1024 * 3, 1024 * 3 + 1 };
	int databitlen512[16] = { 0, 1, 2, 7, 8, 15, 16, 2047, 2048, 2049, 2048 * 2 - 1, 2048 * 2, 2048 * 2 + 1, 2048 * 3 - 1, 2048 * 3, 2048 * 3 + 1 };

	int* p_databitlen = NULL;
	lsh_err result;
	int bits = 0;
	for (i = 0; i < 256 * 4; ++i){
		data[i] = (lsh_u8)i;
	}

	if (LSH_IS_LSH256(algtype)){
		p_databitlen = databitlen256;
		bits = 256;
	}
	else if (LSH_IS_LSH512(algtype)){
		p_databitlen = databitlen512;
		bits = 512;
	}
	else{
		printf("Unknown LSH Type\n");
		return;
	}

	printf("\n== Test Vector for LSH-%d-%d ==\n\n", bits, LSH_GET_HASHBIT(algtype));
	for (i = 0; i < 16; i++) {
		printf("\n> Input Message Length in Bits: %d\n\n", p_databitlen[i]);
		printf("- Input Message:\n");
		datalen = (p_databitlen[i] + 7) / 8;
		for (k = 0; k < datalen; k++) {
			if (k != 0 && k % 32 == 0){
				printf("\n");
			}

			printf("%02x", data[k]);
			if (k % 4 == 3){
				printf(" ");
			}
		}
		printf("\n\n");


		result = lsh_digest(algtype, data, p_databitlen[i], hash);
		if (result != LSH_SUCCESS){
			printf("ERROR - 0x%04x\n", result);
			return;
		}
		printf("- Hash Value:\n");
		for (k = 0; k < LSH_GET_HASHBYTE(algtype); k++){
			if (k != 0 && k % 32 == 0){
				printf("\n");
			}

			printf("%02x", hash[k]);

			if (k % 4 == 3){
				printf(" ");
			}

		}
		printf("\n");
	}

	return;
}

void lsh_benchmark(){

	unsigned int tMin;

	printf("\nLSH Benchmark Results \n\n");


	// for 64-byte messages
	tMin = lsh256_benchmark(0x200);
	printf("LSH-256-256,   64-byte messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 64));

	// for 4096-byte messages
	tMin = lsh256_benchmark(0x8000);
	printf("LSH-256-256, 4096-byte messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 4096));

	//for long messages
	tMin = (lsh256_benchmark(0x8000) - lsh256_benchmark(0x4000));
	printf("LSH-256-256,      long messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 2048));

	// for 64-byte messages
	tMin = lsh512_benchmark(0x200);
	printf("LSH-512-512,   64-byte messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 64));

	// for 4096-byte messages
	tMin = lsh512_benchmark(0x8000);
	printf("LSH-512-512, 4096-byte messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 4096));

	//for long messages
	tMin = (lsh512_benchmark(0x8000) - lsh512_benchmark(0x4000));
	printf("LSH-512-512,      long messages: ");
	printf("%7.2f cycles/byte\n", get_cpb(tMin, 2048));

	return;
}

int main(){
	lsh_testvector_simd();
	lsh_crosscheck_simd();

	//hmac_lsh_test_type2("hmac_lsh_test_");

	//lsh_test_type2(LSH_TYPE_256_224);
	//lsh_test_type2(LSH_TYPE_256_256);
	//lsh_test_type2(LSH_TYPE_512_224);
	//lsh_test_type2(LSH_TYPE_512_256);
	//lsh_test_type2(LSH_TYPE_512_384);
	//lsh_test_type2(LSH_TYPE_512_512);

	lsh_benchmark();
	
	return 0;
}
