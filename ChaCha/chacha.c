/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <stdlib.h>
#include <stdio.h>

#include "ecrypt-sync.h"

#define ROUNDS 20

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void salsa20_wordtobyte(u8 output[64],const u32 input[16])
{
  u32 x[16];
  for (int i = 0;i < 16;++i) x[i] = input[i];
  for (int i = ROUNDS;i > 0;i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }
  for (int i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
  for (int i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

void ECRYPT_init(void)
{
  return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 kbits,u32 ivbits)
{
  const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u8 output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[12] = PLUSONE(x->input[12]);
    if (!x->input[12]) {
      x->input[13] = PLUSONE(x->input[13]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const u8 *c,u8 *m,u32 bytes)
{
  ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x,u8 *stream,u32 bytes)
{
  u32 i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  ECRYPT_encrypt_bytes(x,stream,stream,bytes);
}

void XXX_rand_bytes(u8* buffer, size_t size)
{
	static u32 add = ~(u16)0;

    srand(time(NULL) ^ (time_t)add);
	while (size--)
		*buffer++ = (u8)rand();

	add = (u32)rand();
}

void XXX_ctr_setup(ECRYPT_ctx *x, u32 hi, u32 lo)
{
  x->input[12] = lo;
  x->input[13] = hi;
}

int main(int argc, char* argv[])
{
	u8 key[32]; u8 iv[8];
	memset(key, 0x00, sizeof (key));
	memset(iv, 0x00, sizeof (iv));
	
	ECRYPT_ctx ctx;
	ECRYPT_keysetup(&ctx, key, sizeof(key)*8, 0);
	ECRYPT_ivsetup(&ctx, iv);

	u32 hi=0, lo=0xfffffff0;
	XXX_ctr_setup(&ctx, hi, lo);

	u8 kstream[16*64];
	ECRYPT_keystream_bytes(&ctx, kstream, sizeof(kstream));

	printf("Rounds %d, hi %08x, lo %08x\n", ROUNDS, hi, lo);

	for(size_t i=0; i<sizeof(kstream); ++i)
	{
		if (i && i%32 == 0)
			printf(" \\\n");

		printf("%02X", kstream[i]);
	}

	return 0;
}
