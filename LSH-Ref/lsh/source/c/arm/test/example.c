#include <stdio.h>
#include <string.h>
#include "../src/lsh.h"

int lsh_testvector_simd();

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

void printVal(const char* data, size_t len){
	size_t i;
	for (i = 0; i < len; i++){
		printf("%02x", (lsh_u8)data[i]);
		if (i % 32 == 31){
			printf("\n");
		}
		else if (i % 4 == 3){
			printf(" ");
		}
	}
}

void test0(){
	int bit = 8;
	lsh_type my_type = LSH_MAKE_TYPE(0, bit);
	lsh_u8 source[1024] = { 0, };
	lsh_u8 result[512 / 8] = { 0, };
	lsh256_digest(my_type, source, 32, result);

	printVal(result, (bit+7)/8);
	printf("\n");
}

int main(){
	//lsh_testvector_simd();
	test0();
	//lsh_test_type2(LSH_TYPE_256_224);
	//lsh_test_type2(LSH_TYPE_256_256);
	//lsh_test_type2(LSH_TYPE_512_224);
	//lsh_test_type2(LSH_TYPE_512_256);
	//lsh_test_type2(LSH_TYPE_512_384);
	//lsh_test_type2(LSH_TYPE_512_512);
}
