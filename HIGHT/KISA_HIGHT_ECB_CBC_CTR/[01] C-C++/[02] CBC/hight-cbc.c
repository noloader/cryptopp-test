// Modified by Jeffrey Walton to produce test vectors for Crypto++

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "KISA_HIGHT_CBC.h"

static BYTE Delta[128] = 
{
    0x5A,0x6D,0x36,0x1B,0x0D,0x06,0x03,0x41,
    0x60,0x30,0x18,0x4C,0x66,0x33,0x59,0x2C,
    0x56,0x2B,0x15,0x4A,0x65,0x72,0x39,0x1C,
    0x4E,0x67,0x73,0x79,0x3C,0x5E,0x6F,0x37,
    0x5B,0x2D,0x16,0x0B,0x05,0x42,0x21,0x50,
    0x28,0x54,0x2A,0x55,0x6A,0x75,0x7A,0x7D,
    0x3E,0x5F,0x2F,0x17,0x4B,0x25,0x52,0x29,
    0x14,0x0A,0x45,0x62,0x31,0x58,0x6C,0x76,
    0x3B,0x1D,0x0E,0x47,0x63,0x71,0x78,0x7C,
    0x7E,0x7F,0x3F,0x1F,0x0F,0x07,0x43,0x61,
    0x70,0x38,0x5C,0x6E,0x77,0x7B,0x3D,0x1E,
    0x4F,0x27,0x53,0x69,0x34,0x1A,0x4D,0x26,
    0x13,0x49,0x24,0x12,0x09,0x04,0x02,0x01,
    0x40,0x20,0x10,0x08,0x44,0x22,0x11,0x48,
    0x64,0x32,0x19,0x0C,0x46,0x23,0x51,0x68,
    0x74,0x3A,0x5D,0x2E,0x57,0x6B,0x35,0x5A
};

static BYTE F0[256] = 
{
    0x00,0x86,0x0D,0x8B,0x1A,0x9C,0x17,0x91,
    0x34,0xB2,0x39,0xBF,0x2E,0xA8,0x23,0xA5,
    0x68,0xEE,0x65,0xE3,0x72,0xF4,0x7F,0xF9,
    0x5C,0xDA,0x51,0xD7,0x46,0xC0,0x4B,0xCD,
    0xD0,0x56,0xDD,0x5B,0xCA,0x4C,0xC7,0x41,
    0xE4,0x62,0xE9,0x6F,0xFE,0x78,0xF3,0x75,
    0xB8,0x3E,0xB5,0x33,0xA2,0x24,0xAF,0x29,
    0x8C,0x0A,0x81,0x07,0x96,0x10,0x9B,0x1D,
    0xA1,0x27,0xAC,0x2A,0xBB,0x3D,0xB6,0x30,
    0x95,0x13,0x98,0x1E,0x8F,0x09,0x82,0x04,
    0xC9,0x4F,0xC4,0x42,0xD3,0x55,0xDE,0x58,
    0xFD,0x7B,0xF0,0x76,0xE7,0x61,0xEA,0x6C,
    0x71,0xF7,0x7C,0xFA,0x6B,0xED,0x66,0xE0,
    0x45,0xC3,0x48,0xCE,0x5F,0xD9,0x52,0xD4,
    0x19,0x9F,0x14,0x92,0x03,0x85,0x0E,0x88,
    0x2D,0xAB,0x20,0xA6,0x37,0xB1,0x3A,0xBC,
    0x43,0xC5,0x4E,0xC8,0x59,0xDF,0x54,0xD2,
    0x77,0xF1,0x7A,0xFC,0x6D,0xEB,0x60,0xE6,
    0x2B,0xAD,0x26,0xA0,0x31,0xB7,0x3C,0xBA,
    0x1F,0x99,0x12,0x94,0x05,0x83,0x08,0x8E,
    0x93,0x15,0x9E,0x18,0x89,0x0F,0x84,0x02,
    0xA7,0x21,0xAA,0x2C,0xBD,0x3B,0xB0,0x36,
    0xFB,0x7D,0xF6,0x70,0xE1,0x67,0xEC,0x6A,
    0xCF,0x49,0xC2,0x44,0xD5,0x53,0xD8,0x5E,
    0xE2,0x64,0xEF,0x69,0xF8,0x7E,0xF5,0x73,
    0xD6,0x50,0xDB,0x5D,0xCC,0x4A,0xC1,0x47,
    0x8A,0x0C,0x87,0x01,0x90,0x16,0x9D,0x1B,
    0xBE,0x38,0xB3,0x35,0xA4,0x22,0xA9,0x2F,
    0x32,0xB4,0x3F,0xB9,0x28,0xAE,0x25,0xA3,
    0x06,0x80,0x0B,0x8D,0x1C,0x9A,0x11,0x97,
    0x5A,0xDC,0x57,0xD1,0x40,0xC6,0x4D,0xCB,
    0x6E,0xE8,0x63,0xE5,0x74,0xF2,0x79,0xFF
};

static BYTE F1[256] = 
{
    0x00,0x58,0xB0,0xE8,0x61,0x39,0xD1,0x89,
    0xC2,0x9A,0x72,0x2A,0xA3,0xFB,0x13,0x4B,
    0x85,0xDD,0x35,0x6D,0xE4,0xBC,0x54,0x0C,
    0x47,0x1F,0xF7,0xAF,0x26,0x7E,0x96,0xCE,
    0x0B,0x53,0xBB,0xE3,0x6A,0x32,0xDA,0x82,
    0xC9,0x91,0x79,0x21,0xA8,0xF0,0x18,0x40,
    0x8E,0xD6,0x3E,0x66,0xEF,0xB7,0x5F,0x07,
    0x4C,0x14,0xFC,0xA4,0x2D,0x75,0x9D,0xC5,
    0x16,0x4E,0xA6,0xFE,0x77,0x2F,0xC7,0x9F,
    0xD4,0x8C,0x64,0x3C,0xB5,0xED,0x05,0x5D,
    0x93,0xCB,0x23,0x7B,0xF2,0xAA,0x42,0x1A,
    0x51,0x09,0xE1,0xB9,0x30,0x68,0x80,0xD8,
    0x1D,0x45,0xAD,0xF5,0x7C,0x24,0xCC,0x94,
    0xDF,0x87,0x6F,0x37,0xBE,0xE6,0x0E,0x56,
    0x98,0xC0,0x28,0x70,0xF9,0xA1,0x49,0x11,
    0x5A,0x02,0xEA,0xB2,0x3B,0x63,0x8B,0xD3,
    0x2C,0x74,0x9C,0xC4,0x4D,0x15,0xFD,0xA5,
    0xEE,0xB6,0x5E,0x06,0x8F,0xD7,0x3F,0x67,
    0xA9,0xF1,0x19,0x41,0xC8,0x90,0x78,0x20,
    0x6B,0x33,0xDB,0x83,0x0A,0x52,0xBA,0xE2,
    0x27,0x7F,0x97,0xCF,0x46,0x1E,0xF6,0xAE,
    0xE5,0xBD,0x55,0x0D,0x84,0xDC,0x34,0x6C,
    0xA2,0xFA,0x12,0x4A,0xC3,0x9B,0x73,0x2B,
    0x60,0x38,0xD0,0x88,0x01,0x59,0xB1,0xE9,
    0x3A,0x62,0x8A,0xD2,0x5B,0x03,0xEB,0xB3,
    0xF8,0xA0,0x48,0x10,0x99,0xC1,0x29,0x71,
    0xBF,0xE7,0x0F,0x57,0xDE,0x86,0x6E,0x36,
    0x7D,0x25,0xCD,0x95,0x1C,0x44,0xAC,0xF4,
    0x31,0x69,0x81,0xD9,0x50,0x08,0xE0,0xB8,
    0xF3,0xAB,0x43,0x1B,0x92,0xCA,0x22,0x7A,
    0xB4,0xEC,0x04,0x5C,0xD5,0x8D,0x65,0x3D,
    0x76,0x2E,0xC6,0x9E,0x17,0x4F,0xA7,0xFF
};

#define BLOCK_SIZE_HIGHT        8
#define BLOCK_SIZE_HIGHT_INT    2

#define BLOCK_XOR_HIGHT( OUT_VALUE, IN_VALUE1, IN_VALUE2 ) {    \
    OUT_VALUE[0] = IN_VALUE1[0] ^ IN_VALUE2[0];            \
    OUT_VALUE[1] = IN_VALUE1[1] ^ IN_VALUE2[1];            \
}                                                        \

#define PADDING_ENC_PROCESS_HIGHT( INOUT_VALUE, IN_START, IN_MAX, PADDING_VALUE ){    \
    int i;                                                    \
    for( i =0 ; i<IN_MAX; i++ )                                \
        INOUT_VALUE[IN_START+i] = PADDING_VALUE;            \
}

#define PADDING_DEC_PROCESS_HIGHT( INOUT_VALUE, PADDING_VALUE ){    \
    int i;                                                    \
    for( i =BLOCK_SIZE_HIGHT ; i>-1; --i )                                \
    {                                                        \
        if( PADDING_VALUE == INOUT_VALUE[i])                \
            INOUT_VALUE[i] = 0x00;                            \
        else                                                \
            break;                                            \
    }                                                        \
}

// Encryption Round 
#define HIGHT_ENC(k, i0,i1,i2,i3,i4,i5,i6,i7) {                         \
    XX[i0] = (XX[i0] ^ (HIGHT_F0[XX[i1]] + RoundKey[4*k+3])) & 0xFF;    \
    XX[i2] = (XX[i2] + (HIGHT_F1[XX[i3]] ^ RoundKey[4*k+2])) & 0xFF;    \
    XX[i4] = (XX[i4] ^ (HIGHT_F0[XX[i5]] + RoundKey[4*k+1])) & 0xFF;    \
    XX[i6] = (XX[i6] + (HIGHT_F1[XX[i7]] ^ RoundKey[4*k+0])) & 0xFF;    \
    }

#define EncIni_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    t0 = x0 + mk0;                                        \
    t2 = x2 ^ mk1;                                        \
    t4 = x4 + mk2;                                        \
    t6 = x6 ^ mk3; 

#define EncFin_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    out[0] = x0 + mk0;                                        \
    out[2] = x2 ^ mk1;                                        \
    out[4] = x4 + mk2;                                        \
    out[6] = x6 ^ mk3; 

#define Round(x7,x6,x5,x4,x3,x2,x1,x0)                \
    x1 += (F1[x0] ^ key[0]);                \
    x3 ^= (F0[x2] + key[1]);                \
    x5 += (F1[x4] ^ key[2]);                \
    x7 ^= (F0[x6] + key[3]);


void KISA_HIGHT_ECB_encrypt_forCBC( BYTE *pbszIN_Key128, BYTE *pbszUserKey, const unsigned char *in, unsigned char *out )
{
    register unsigned char t0, t1, t2, t3, t4, t5, t6, t7;
    BYTE *key, *key2;

    key = pbszIN_Key128;
    key2 = pbszUserKey;

    t1 = in[1]; t3 = in[3]; t5 = in[5]; t7 = in[7];
    EncIni_Transformation( in[0], in[2], in[4], in[6], key2[12], key2[13], key2[14], key2[15] );

    Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;        // 1
    Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;        // 2
    Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;        // 3
    Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;        // 4
    Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;        // 5
    Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;        // 6
    Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;        // 7
    Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;        // 8
    Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;        // 9
    Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;        // 10
    Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;        // 11
    Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;        // 12
    Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;        // 13
    Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;        // 14
    Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;        // 15
    Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;        // 16
    Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;        // 17
    Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;        // 18
    Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;        // 19
    Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;        // 20
    Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;        // 21
    Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;        // 22
    Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;        // 23
    Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;        // 24
    Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;        // 25
    Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;        // 26
    Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;        // 27
    Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;        // 28
    Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;        // 29
    Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;        // 30
    Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;        // 31
    Round(t0,t7,t6,t5,t4,t3,t2,t1);                    // 32

    EncFin_Transformation( t1, t3, t5, t7, key2[0], key2[1], key2[2], key2[3] );

    out[1] = t2; out[3] = t4; out[5] = t6; out[7] = t0;
}

#define HIGHT_DEC(k, i0,i1,i2,i3,i4,i5,i6,i7) {                         \
    XX[i1] = (XX[i1] - (HIGHT_F1[XX[i2]] ^ RoundKey[4*k+2])) & 0xFF;    \
    XX[i3] = (XX[i3] ^ (HIGHT_F0[XX[i4]] + RoundKey[4*k+1])) & 0xFF;    \
    XX[i5] = (XX[i5] - (HIGHT_F1[XX[i6]] ^ RoundKey[4*k+0])) & 0xFF;    \
    XX[i7] = (XX[i7] ^ (HIGHT_F0[XX[i0]] + RoundKey[4*k+3])) & 0xFF;    \
}

#define DecIni_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    t0 = x0 - mk0;                                        \
    t2 = x2 ^ mk1;                                        \
    t4 = x4 - mk2;                                        \
    t6 = x6 ^ mk3; 

#define DecFin_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    out[0] = x0 - mk0;                                        \
    out[2] = x2 ^ mk1;                                        \
    out[4] = x4 - mk2;                                        \
    out[6] = x6 ^ mk3; 


#define DRound(x7,x6,x5,x4,x3,x2,x1,x0)                \
    x1 = x1 - (F1[x0] ^ key[0]);                \
    x3 = x3 ^ (F0[x2] + key[1]);                \
    x5 = x5 - (F1[x4] ^ key[2]);                \
    x7 = x7 ^ (F0[x6] + key[3]); 

void KISA_HIGHT_ECB_decrypt_forCBC( BYTE *pbszIN_Key128, BYTE *pbszUserKey, const unsigned char *in, unsigned char *out )
{
    register unsigned char t0, t1, t2, t3, t4, t5, t6, t7;
    unsigned char *key, *key2;

    key = &(pbszIN_Key128[124]);
    key2 = pbszUserKey;

    t1 = in[1]; t3 = in[3]; t5 = in[5]; t7 = in[7];
    DecIni_Transformation( in[0], in[2], in[4], in[6], key2[0], key2[1], key2[2], key2[3] );

    DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
    DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
    DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
    DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
    DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
    DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
    DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
    DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
    DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
    DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
    DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
    DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
    DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
    DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
    DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
    DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
    DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
    DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
    DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
    DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
    DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
    DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
    DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
    DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
    DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
    DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
    DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
    DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
    DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
    DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
    DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
    DRound(t6,t5,t4,t3,t2,t1,t0,t7);

    DecFin_Transformation(t7, t1, t3, t5,key2[12],key2[13],key2[14],key2[15]);

    out[1] = t0; out[3] = t2; out[5] = t4; out[7] = t6;
}

DWORD* chartoint32_for_HIGHT_CBC( IN BYTE *in, IN int inLen )
{
    DWORD *data;
    int len,i;

    if(inLen % 4)
        len = (inLen/4)+1;
    else
        len = (inLen/4);

    data = malloc(sizeof(unsigned int) * len);

    for(i=0;i<len;i++)
    {
        data[i] = ((unsigned int*)in)[i];
    }

    return data;
}

BYTE* int32tochar_for_HIGHT_CBC( IN DWORD *in, IN int inLen )
{
    unsigned char *data;
    int i;

    data = malloc(sizeof(unsigned char) * inLen);

#ifndef BIG_ENDIAN
    for(i=0;i<inLen;i++)
    {
        data[i] = (unsigned char)(in[i/4] >> ((i%4)*8));
    }
#else
    for(i=0;i<inLen;i++)
    {
        data[i] = (unsigned char)(in[i/4] >> ((3-(i%4))*8));
    }
#endif

    return data;
}

int HIGHT_CBC_init( OUT KISA_HIGHT_INFO *pInfo, IN KISA_ENC_DEC enc, IN BYTE *pUserKey, IN BYTE *pbIV )
{
    unsigned char i, j;

    if( NULL == pInfo || 
        NULL == pUserKey ||
        NULL == pbIV )
        return 0;

    memset( pInfo, 0, sizeof(KISA_HIGHT_INFO) );
    pInfo->encrypt = enc;
    memcpy( (BYTE *)pInfo->ivec, (BYTE *)pbIV, BLOCK_SIZE_HIGHT );
    memcpy( pInfo->userKey, pUserKey, 16 );

    for(i=0 ; i < BLOCK_SIZE_HIGHT ; i++)
    {
        for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
            pInfo->hight_key.key_data[ 16*i + j ] = pUserKey[(j-i)&7    ] + Delta[ 16*i + j ];

        for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
            pInfo->hight_key.key_data[ 16*i + j + 8 ] = pUserKey[((j-i)&7)+8] + Delta[ 16*i + j + 8 ];
    }
    
    return 1;
}

int HIGHT_CBC_Process( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *in, IN int inLen, OUT DWORD *out, OUT int *outLen )
{
    int nCurrentCount = BLOCK_SIZE_HIGHT;
    DWORD *pdwXOR;

    if( NULL == pInfo ||
        NULL == in ||
        NULL == out ||
        0 > inLen )
        return 0;

    pInfo->buffer_length = inLen - nCurrentCount;

    if( KISA_ENCRYPT == pInfo->encrypt )
    {
        pdwXOR = pInfo->ivec;

        while( nCurrentCount <= inLen )
        {
            BLOCK_XOR_HIGHT( out, in, pdwXOR );
            KISA_HIGHT_ECB_encrypt_forCBC( pInfo->hight_key.key_data, pInfo->userKey, (BYTE *)out, (BYTE *)out );
            pdwXOR = out;
            nCurrentCount += BLOCK_SIZE_HIGHT;
            in += BLOCK_SIZE_HIGHT_INT;
            out += BLOCK_SIZE_HIGHT_INT;
        }
        
        *outLen = nCurrentCount - BLOCK_SIZE_HIGHT;
        pInfo->buffer_length = inLen - *outLen;

        memcpy( pInfo->ivec, pdwXOR, BLOCK_SIZE_HIGHT );
        memcpy( pInfo->cbc_buffer, in, pInfo->buffer_length );

    }
    else
    {
        pdwXOR = pInfo->ivec;

        while( nCurrentCount <= inLen )
        {
            KISA_HIGHT_ECB_decrypt_forCBC( pInfo->hight_key.key_data, pInfo->userKey, (BYTE *)in, (BYTE *)out );
            
            BLOCK_XOR_HIGHT( out, out, pdwXOR );

            pdwXOR = in;

            nCurrentCount += BLOCK_SIZE_HIGHT;
            in += BLOCK_SIZE_HIGHT_INT;
            out += BLOCK_SIZE_HIGHT_INT;
        }
            
        *outLen = nCurrentCount - BLOCK_SIZE_HIGHT;
        memcpy( pInfo->ivec, pdwXOR, BLOCK_SIZE_HIGHT );
        memcpy( pInfo->cbc_last_block, out - BLOCK_SIZE_HIGHT_INT, BLOCK_SIZE_HIGHT );
    }

    return 1;
}

int HIGHT_CBC_Close( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *out, IN int out_offset, IN int *outLen )
{
    unsigned int nPaddngLeng;
    int i;
    BYTE *pOut;
    out += (out_offset/4);
    pOut = (BYTE *)(out);

    *outLen = 0;

    if( NULL == out )
    {
        return 0;    
    }

    if( KISA_ENCRYPT == pInfo->encrypt )
    {
        nPaddngLeng = BLOCK_SIZE_HIGHT - pInfo->buffer_length;
        for( i = pInfo->buffer_length; i<BLOCK_SIZE_HIGHT; i++ )
            ((BYTE *)pInfo->cbc_buffer)[i] = (BYTE)nPaddngLeng;
        BLOCK_XOR_HIGHT( pInfo->cbc_buffer, pInfo->cbc_buffer, pInfo->ivec );
        
        KISA_HIGHT_ECB_encrypt_forCBC( pInfo->hight_key.key_data, pInfo->userKey, (BYTE *)pInfo->cbc_buffer, pOut );
        out += BLOCK_SIZE_HIGHT_INT;
        *outLen = BLOCK_SIZE_HIGHT;
    }
    else
    {
        nPaddngLeng = ((BYTE*)pInfo->cbc_last_block)[BLOCK_SIZE_HIGHT-1];
        if( nPaddngLeng > 0 && nPaddngLeng <= BLOCK_SIZE_HIGHT )
        {
            for (i = nPaddngLeng; i>0; i--)
            {
                *(pOut - i) = (BYTE)0x00;
            }
            *outLen = nPaddngLeng;
        }
        else 
            return 0;
    }

    return 1;
}

int HIGHT_CBC_Encrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszPlainText, IN int in_offset, IN int nPlainTextLen, OUT BYTE *pbszCipherText )
{
    KISA_HIGHT_INFO info;
    unsigned int *outbuf;
    unsigned int *data;
    unsigned char *newpbszPlainText;
    unsigned char *cdata;
    int outlen = 0;
    int nRetOutLeng = 0;
    int nPaddingLeng = 0;
    int i;
    int nPlainTextPadding = (BLOCK_SIZE_HIGHT - (nPlainTextLen % BLOCK_SIZE_HIGHT));
    newpbszPlainText = malloc(sizeof(unsigned char) * (nPlainTextLen + nPlainTextPadding));
    memcpy(newpbszPlainText, pbszPlainText + in_offset, nPlainTextLen);

    HIGHT_CBC_init( &info, KISA_ENCRYPT, pbszUserKey, pbszIV );

    outlen = ( (nPlainTextLen + nPlainTextPadding)/8) *4;
    outbuf = malloc( sizeof(unsigned int) * outlen );

    data = chartoint32_for_HIGHT_CBC(newpbszPlainText, nPlainTextLen);
    HIGHT_CBC_Process( &info, data, nPlainTextLen, outbuf, &nRetOutLeng );
    HIGHT_CBC_Close( &info, outbuf, nRetOutLeng, &nPaddingLeng );
    cdata = int32tochar_for_HIGHT_CBC(outbuf, nRetOutLeng + nPaddingLeng);
    memcpy(pbszCipherText, cdata, nRetOutLeng + nPaddingLeng);
    free(data);
    free(cdata);
    free(outbuf);

    return nRetOutLeng+nPaddingLeng;
}

int HIGHT_CBC_Decrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszCipherText, IN int in_offset, IN int nCipherTextLen, OUT BYTE *result )
{
    KISA_HIGHT_INFO info;
    unsigned int *outbuf;
    unsigned int *data;
    BYTE *newpbszCipherText;
    BYTE *pbszPlainText;
    unsigned char *cdata;
    int outlen = 0;
    int nRetOutLeng = 0;
    int nPaddingLeng = 0;
    int message_length = 0;
    if ((nCipherTextLen % BLOCK_SIZE_HIGHT) > 0)
    {
        return 0;
    }
    
    newpbszCipherText = malloc(sizeof(unsigned char) * (nCipherTextLen));
    memcpy(newpbszCipherText, pbszCipherText + in_offset, nCipherTextLen);
    pbszPlainText = malloc(sizeof(unsigned char) * (nCipherTextLen));
    
    HIGHT_CBC_init( &info, KISA_DECRYPT, pbszUserKey, pbszIV );

    outlen = ( (nCipherTextLen/8)) *4 ;
    outbuf = malloc(sizeof(unsigned int) * outlen);
    
    data = chartoint32_for_HIGHT_CBC(newpbszCipherText, nCipherTextLen);
    HIGHT_CBC_Process( &info, data, nCipherTextLen, outbuf, &nRetOutLeng );
    if (HIGHT_CBC_Close( &info, outbuf, nRetOutLeng, &nPaddingLeng ) > 0)
    {
        cdata = int32tochar_for_HIGHT_CBC( outbuf, nRetOutLeng - nPaddingLeng );
        memcpy( pbszPlainText, cdata, nRetOutLeng - nPaddingLeng );
        message_length = nRetOutLeng - nPaddingLeng;
        if (message_length < 0)
        {
            message_length = 0;
        }
        memcpy( result, pbszPlainText, message_length);

        free(data);
        free(cdata);
        free(outbuf);

        return message_length;
    }    
    else
        return 0;

}

#if (defined(__BYTE_ORDER__ ) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    defined(__LITTLE_ENDIAN__)
# define HIGHT_LITTLE_ENDIAN 1
#endif

#if (defined(__BYTE_ORDER__ ) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
    defined(__BIG_ENDIAN__)
# define HIGHT_BIG_ENDIAN 1
#endif

// method 1 start
int main()
{
#ifndef HIGHT_BIG_ENDIAN
    printf("This program must be run on a big-endian machine to produce accurate test vectors.\n");
    // return 1;
#endif

    BYTE pbszUserKey[16] = {0x88, 0xe3, 0x4f, 0x8f, 0x08, 0x17, 0x79, 0xf1, 0xe9, 0xf3, 0x94, 0x37, 0x0a, 0xd4, 0x05, 0x89}; 
    BYTE pbszIV[8] = {0x26, 0x8d, 0x66, 0xa7, 0x35, 0xa8, 0x1a, 0x81};
    BYTE plainText[71] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BYTE pbszCipherText[80] = {0x00};
    BYTE pbszPlainText[80] = {0x00};
    int i;
    int nPlainTextLen;
    int nCipherTextLen;

    for (size_t len=8; len < sizeof(plainText); len+=8)
    {
        nPlainTextLen = len;
        nCipherTextLen = HIGHT_CBC_Encrypt( pbszUserKey, pbszIV, plainText, 0, nPlainTextLen, pbszCipherText );
        // Strip the padding. Crypto++ uses NO_PADDING for these tests.
        nCipherTextLen -= 8;

        printf("#\n");
        printf("Source: HIGHT reference implementation\n");
        printf("Comment: HIGHT/CBC, 128-bit key\n");

        printf ("Key: ");
        for (i=0;i<16;i++)    {printf("%02X ",pbszUserKey[i]);}
        printf ("\n");

        printf ("IV: ");
        for (i=0;i<8;i++)    {printf("%02X ",pbszIV[i]);}
        printf ("\n");

        printf ("Plaintext: ");
        for (i=0;i<nPlainTextLen;i++)    {printf("%02X ",plainText[i]);}
        printf ("\n");

        printf ("Ciphertext: ");
        for (i=0;i<nCipherTextLen;i++)    {printf("%02X ",pbszCipherText[i]);}
        printf ("\n");

        printf("Test: Encrypt\n");
    }
    return 0;
}
// method 1 end

/*
// method 2 start
void main()
{

    BYTE pbszUserKey[16] = {0x88, 0xe3, 0x4f, 0x8f, 0x08, 0x17, 0x79, 0xf1, 0xe9, 0xf3, 0x94, 0x37, 0x0a, 0xd4, 0x05, 0x89}; 
    BYTE pbszIV[8] = {0x26, 0x8d, 0x66, 0xa7, 0x35, 0xa8, 0x1a, 0x81};
    BYTE plainText[71] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BYTE pbszCipherText[80] = {0x00};
    BYTE pbszPlainText[80] = {0x00};
    KISA_HIGHT_INFO info;
    int i;
    int nPlainTextLen = 0;
    int nCipherTextLen = 0;
    int message_length = 0;
    int EncryptedMessage_length = 0;
    #define process_blockLeng    16
    unsigned int *outbuf;
    unsigned char *PlainBytes = (BYTE *)(plainText);
    unsigned char *CipherBytes = (BYTE *)(pbszCipherText);
    unsigned int *data;
    unsigned char *cdata;
    int nRetOutLeng = 0;
    int remainleng = 0;
    int nPaddingLeng = 0;


    printf ("Key        : ");
    for (i=0;i<16;i++)    {printf("%02X ",pbszUserKey[i]);}

    printf ("\nIV       : ");
    for (i=0;i<8;i++)    {printf("%02X ",pbszIV[i]);}

    printf ("\n\nLength of Plaintext : ");
    scanf("%d", &nPlainTextLen);

    printf ("\nPlaintext(%d)  : ", nPlainTextLen);
    for (i=0;i<nPlainTextLen;i++)    {printf("%02X ",plainText[i]);}
    
    printf ("\nEncryption....\n");
    // Encryption Algorithm //
    message_length = nPlainTextLen;

    HIGHT_CBC_init( &info, KISA_ENCRYPT, pbszUserKey, pbszIV );
    outbuf = malloc(sizeof(unsigned int) * process_blockLeng);        
    for (i = 0; i < message_length - process_blockLeng; )
    {
        memcpy( pbszPlainText, PlainBytes + i, process_blockLeng );
        data = chartoint32_for_HIGHT_CBC(pbszPlainText, process_blockLeng);
        HIGHT_CBC_Process( &info, data, process_blockLeng, outbuf, &nRetOutLeng );
        cdata = int32tochar_for_HIGHT_CBC( outbuf, nRetOutLeng);
        memcpy( CipherBytes + i, cdata, nRetOutLeng );
        i += nRetOutLeng;
    }
    remainleng = message_length % process_blockLeng;
    if (remainleng == 0)
    {
        remainleng = process_blockLeng;
    }
    memcpy( pbszPlainText, PlainBytes + i, remainleng );
    data = chartoint32_for_HIGHT_CBC(pbszPlainText, remainleng);
    HIGHT_CBC_Process( &info, data, remainleng, outbuf, &nRetOutLeng );
    cdata = int32tochar_for_HIGHT_CBC( outbuf, nRetOutLeng);
    memcpy( CipherBytes + i, cdata, nRetOutLeng );
    i += nRetOutLeng;
    free(cdata);
    HIGHT_CBC_Close( &info, outbuf, 0, &nPaddingLeng );
    cdata = int32tochar_for_HIGHT_CBC(outbuf, nPaddingLeng);
    memcpy(CipherBytes + i, cdata, nPaddingLeng);
    
    free(data);
    free(cdata);

    nCipherTextLen = i + nPaddingLeng;

    printf ("\nCiphertext(%d) : ", nCipherTextLen);
    for (i=0;i<nCipherTextLen;i++)    {printf("%02X ",pbszCipherText[i]);}

    printf ("\n\n\n\nLength of Ciphertext : ");
    scanf("%d", &nCipherTextLen);

    printf ("\nCiphertext(%d) : ", nCipherTextLen);
    for (i=0;i<nCipherTextLen;i++)    {printf("%02X ",pbszCipherText[i]);}

    printf ("\nDecryption....\n");
    // Decryption Algorithm //
    EncryptedMessage_length = nCipherTextLen;
    if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
    {
        nPlainTextLen = 0;
    }
    else
    {
        HIGHT_CBC_init( &info, KISA_DECRYPT, pbszUserKey, pbszIV );

        for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
        {
            memcpy( pbszCipherText, CipherBytes + i, process_blockLeng );
            data = chartoint32_for_HIGHT_CBC(pbszCipherText, process_blockLeng);
            HIGHT_CBC_Process( &info, data, process_blockLeng, outbuf, &nRetOutLeng );
            cdata = int32tochar_for_HIGHT_CBC( outbuf, nRetOutLeng);
            memcpy( PlainBytes + i, cdata, nRetOutLeng );
            i += nRetOutLeng;        
            free(data);
            free(cdata);
        }
        remainleng = EncryptedMessage_length % process_blockLeng;
        if (remainleng == 0)
        {
            remainleng = process_blockLeng;
        }
        memcpy( pbszCipherText, CipherBytes + i, remainleng );
        data = chartoint32_for_HIGHT_CBC(pbszCipherText, remainleng);
        HIGHT_CBC_Process( &info, data, remainleng, outbuf, &nRetOutLeng );
        if (HIGHT_CBC_Close( &info, outbuf, nRetOutLeng, &nPaddingLeng ) > 0)
        {
            cdata = int32tochar_for_HIGHT_CBC(outbuf, remainleng - nPaddingLeng);
            memcpy(PlainBytes + i, cdata, remainleng - nPaddingLeng);
            message_length = i + remainleng - nPaddingLeng;
            
            free(data);
            free(cdata);
            free(outbuf);

            nPlainTextLen = message_length;
        }
        else
        {
            nPlainTextLen = 0;
        }
    }

    printf ("\nPlaintext(%d)  : ", nPlainTextLen);
    for (i=0;i<nPlainTextLen;i++)    {printf("%02X ",PlainBytes[i]);}

    printf ("\n");

}
// method 2 end
*/