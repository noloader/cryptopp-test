#include <msa.h>
#include <stdint.h>

#define ALIGN16 __attribute__((aligned(16)))

int main(int argc, char* argv[])
{
	ALIGN16 uint32_t a[] = {64, 128, 256, 512};
	ALIGN16 uint32_t b[] = {1024, 2048, 4096, 8192};
	ALIGN16 uint32_t c[4];

	v4u32 va = __builtin_msa_ld_w (a, 0);
	v4u32 vb = __builtin_msa_ld_w (b, 0);

	v4u32 vc = __builtin_msa_adds_u_w (va, vb);
	__builtin_msa_st_w (vc, c, 0);

	return 0;
}
