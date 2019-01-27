#include "ecrypt-sync.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void GenRandom(u8* buf, size_t size)
{
	for (unsigned int i=0; i<size; ++i)
		buf[i+0] = (u8)rand();
}

int GenIncrement()
{
	u8 val;
again:
	GenRandom(&val, 1);
	if((val & 7) == 0)
		goto again;
	return val & 7;
}

void PrintBlock(u8* buf, size_t size)
{
	if (size == 0) { return; }

	unsigned int i=0;
	switch (size%8)
	{
		case 7:
		{
			printf("%02x%02x%02x%02x%02x%02x%02x ",
				buf[0], buf[1], buf[2], buf[3],
				buf[4], buf[5], buf[6]);
			i=7; size -= 7; break;
		}
		case 6:
		{
			printf("%02x%02x%02x%02x%02x%02x ",
				buf[0], buf[1], buf[2], buf[3],
				buf[4], buf[5]);
			i=6; size -= 6; break;
		}
		case 5:
		{
			printf("%02x%02x%02x%02x%02x ",
				buf[0], buf[1], buf[2], buf[3],
				buf[4]);
			i=5; size -= 5; break;
		}
		case 4:
		{
			printf("%02x%02x%02x%02x ", buf[0], buf[1], buf[2], buf[3]);
			i=4; size -= 4; break;
		}
		case 3:
		{
			printf("%02x%02x%02x ", buf[0], buf[1], buf[2]);
			i=3; size -= 3; break;
		}
		case 2:
		{
			printf("%02x%02x ", buf[0], buf[1]);
			i=2; size -= 2; break;
		}
		case 1:
		{
			printf("%02x ", buf[0]);
			i=1; size -= 1; break;
		}
	}
	
	if (size == 0) { return; }

	for (; i<size; i+=8)
	{
		printf("%02x%02x%02x%02x%02x%02x%02x%02x ",
			buf[i+0], buf[i+1], buf[i+2], buf[i+3],
			buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
	}
}

int main(int argc, char* argv[])
{
	static const unsigned int ITER_MAX = 1024;
	unsigned int i=32;

	u8 key[32], iv[32];
	
	u8*  plain = (u8*)malloc(ITER_MAX+16);
	u8* cipher = (u8*)malloc(ITER_MAX+16);

	for (unsigned int i=1; i<ITER_MAX; )
	{
		ECRYPT_ctx ctx;
		memset(&ctx, 0x00, sizeof(ctx));		

		GenRandom(key, sizeof(key));
		//memset(key, 0, sizeof(key));
		ECRYPT_keysetup(&ctx, key, sizeof(key)*8, sizeof(iv)*8);

		GenRandom(iv, sizeof(iv));
		//memset(iv, 0, sizeof(iv));
		ECRYPT_ivsetup(&ctx, iv);
		
		GenRandom(plain, i);
		//memset(plain, 0, ITER_MAX);
		ECRYPT_process_bytes(0, &ctx, plain, cipher, i);
		
		printf("#\n");
				
		printf("Source: hc-256.c reference implementation\n");
		printf("Comment: HC-256, 256-bit key, 256-bit iv, %d-byte msg\n", i);
		
		printf("Key: ");
		PrintBlock(key, sizeof(key));
		printf("\n");

		printf("IV: ");
		PrintBlock(iv, sizeof(iv));
		printf("\n");

		printf("Plaintext: ");
		PrintBlock(plain, i);
		printf("\n");

		printf("Ciphertext: ");
		PrintBlock(cipher, i);
		printf("\n");
		
		printf("Test: Encrypt\n");
		
		if (i < 128)
			i+=2;
		else
			i += GenIncrement();
	}
	
	free(plain);
	free(cipher);
	
	return 0;
}