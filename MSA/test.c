#include <msa.h>
#include <stdint.h>
#include <string.h>

inline v4i32 reinterpretq_i32_u32(const v4u32 val) {
	v4i32 res;
	memcpy(&res, &val, sizeof(res));
	return res;
}

inline v4u32 reinterpretq_u32_i32(const v4i32 val) {
	v4u32 res;
	memcpy(&res, &val, sizeof(res));
	return res;
}

#define ALIGN16 __attribute__((aligned(16)))

int main(int argc, char* argv[])
{
	ALIGN16 uint32_t a[] = {64, 128, 256, 512};
	ALIGN16 uint32_t b[] = {1024, 2048, 4096, 8192};
	ALIGN16 uint32_t c[8];

	v4i32 va = __builtin_msa_ld_w (a, 0);
	v4i32 vb = __builtin_msa_ld_w (b, 0);

	v4i32 vc = __builtin_msa_addv_w (va, vb);
	v4i32 vr = va + vb;
	__builtin_msa_st_w (vc, c, 0);
	__builtin_msa_st_w (vr, c, 0+16);

	return (c[0] & 0xff) | (c[4] & 0xff);
}
