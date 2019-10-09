#include <stdio.h>
#include <stdint.h>

// Visual Studio 2008 and below
#if defined(_MSC_VER) && (_MSC_VER < 1600)
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#endif

#include "simeck32.h"
#include "simeck48.h"
#include "simeck64.h"

int main() {
    uint16_t text32[] = {
        0x6877,
        0x6565,
    };
    uint16_t cipher32[2];
    const uint16_t key64[] = {
        0x0100,
        0x0908,
        0x1110,
        0x1918,
    };
    simeck_32_64(key64, text32, cipher32);

    printf("Simeck32/64:\n");
    printf("         Key: %04x %04x %04x %04x\n", key64[3], key64[2], key64[1], key64[0]);
    printf("   Plaintext: %04x %04x\n", text32[1], text32[0]);
    printf("  Ciphertext: %04x %04x\n", cipher32[1], cipher32[0]);
	printf("\n");

    uint32_t text48[] = {
        0x20646e,
        0x726963,
    };
    uint32_t cipher48[2];
    const uint32_t key96[] = {
        0x020100,
        0x0a0908,
        0x121110,
        0x1a1918,
    };
    simeck_48_96(key96, text48, cipher48);

    printf("Simeck48/96:\n");
    printf("         Key: %06x %06x %06x %06x\n", key96[3], key96[2], key96[1], key96[0]);
    printf("   Plaintext: %06x %06x\n", text48[1], text48[0]);
    printf("  Ciphertext: %06x %06x\n", cipher48[1], cipher48[0]);
	printf("\n");

    uint32_t text64[] = {
        0x20646e75,
        0x656b696c,
    };
    uint32_t cipher64[2];
    const uint32_t key128[] = {
        0x03020100,
        0x0b0a0908,
        0x13121110,
        0x1b1a1918,
    };
    simeck_64_128(key128, text64, cipher64);

    printf("Simeck64/128:\n");
    printf("         Key: %08x %08x %08x %08x\n", key128[3], key128[2], key128[1], key128[0]);
    printf("   Plaintext: %08x %08x\n", text64[1], text64[0]);
    printf("  Ciphertext: %08x %08x\n", cipher64[1], cipher64[0]);
	printf("\n");

    return 0;
}
