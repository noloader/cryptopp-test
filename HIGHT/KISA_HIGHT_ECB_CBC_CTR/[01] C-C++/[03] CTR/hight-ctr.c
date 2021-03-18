// Modified by Jeffrey Walton to produce test vectors for Crypto++

#include "KISA_HIGHT_CTR.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define process_blockLeng    16

unsigned char F0[256] = 
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

unsigned char F1[256] = 
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

unsigned char Delta[128] =
{
    0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41, 0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
    0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c, 0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
    0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50, 0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
    0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29, 0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
    0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
    0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e, 0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
    0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01, 0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
    0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68, 0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a
};

#define BLOCK_XOR_HIGHT( OUT_VALUE, IN_VALUE1, IN_VALUE2 ) {    \
    OUT_VALUE[0] = IN_VALUE1[0] ^ IN_VALUE2[0];            \
    OUT_VALUE[1] = IN_VALUE1[1] ^ IN_VALUE2[1];            \
}

void UpdateCounter_for_HIGHT( BYTE *pbOUT, int nIncreaseValue, int nMin ) 
{
    BYTE bszBackup = 0;                                                
    int i;                                                            
                                                                    
    if( 0 > nMin )                                                
        return ;                                                    
                                                                    
    if( 0 < nMin )                                                
    {                                                                
        bszBackup = pbOUT[nMin];                            
        pbOUT[nMin] += nIncreaseValue;                        
    }                                                                
                                                                    
    for( i=nMin; i>1; --i )                                    
    {                                                                
        if( bszBackup <= pbOUT[i] )                            
            return;                                                    
        else                                                        
        {                                                            
            bszBackup = pbOUT[i-1];                            
            pbOUT[i-1] += 1;                                    
        }                                                            
    }                                                                
                                                                    
    bszBackup = pbOUT[0];                                        
    pbOUT[0] += nIncreaseValue;                                    
}

#define EncIni_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    t0 = x0 + mk0;                                            \
    t2 = x2 ^ mk1;                                            \
    t4 = x4 + mk2;                                            \
    t6 = x6 ^ mk3;                                            

#define EncFin_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)    \
    out[0] = x0 + mk0;                                        \
    out[2] = x2 ^ mk1;                                        \
    out[4] = x4 + mk2;                                        \
    out[6] = x6 ^ mk3; 

#define Round(x7,x6,x5,x4,x3,x2,x1,x0)                        \
    x1 += (F1[x0] ^ key[0]);                                \
    x3 ^= (F0[x2] + key[1]);                                \
    x5 += (F1[x4] ^ key[2]);                                \
    x7 ^= (F0[x6] + key[3]);

void KISA_HIGHT_Block_forCTR( BYTE *pbszIN_Key128, BYTE *pbszUserKey, const unsigned char *in, unsigned char *out )
{
    register unsigned char t0, t1, t2, t3, t4, t5, t6, t7;
    unsigned char *key, *key2;

    key = pbszIN_Key128;
    key2 = pbszUserKey;

    t1 = in[1]; t3 = in[3]; t5 = in[5]; t7 = in[7];
    EncIni_Transformation(in[0],in[2],in[4],in[6],key2[12],key2[13],key2[14],key2[15]);

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

    EncFin_Transformation(t1,t3,t5,t7,key2[0],key2[1],key2[2],key2[3]);

    out[1] = t2; out[3] = t4; out[5] = t6; out[7] = t0;
} 

void InitNonce_HIGHT( IN NONCE_TYPE type, IN BYTE *pbszIV, IN BYTE *pbszCounter, OUT BYTE *pbszNonce )
{
    switch( type )
    {
    case NONCE_OR:
        {
            pbszNonce[0] = pbszIV[0] | pbszCounter[0];
            pbszNonce[1] = pbszIV[1] | pbszCounter[1];
            pbszNonce[2] = pbszIV[2] | pbszCounter[2];
            pbszNonce[3] = pbszIV[3] | pbszCounter[3];
            pbszNonce[4] = pbszIV[4] | pbszCounter[4];
            pbszNonce[5] = pbszIV[5] | pbszCounter[5];
            pbszNonce[6] = pbszIV[6] | pbszCounter[6];
            pbszNonce[7] = pbszIV[7] | pbszCounter[7];
        }
        break;
    case NONCE_AND:
        {
            pbszNonce[0] = pbszIV[0] & pbszCounter[0];
            pbszNonce[1] = pbszIV[1] & pbszCounter[1];
            pbszNonce[2] = pbszIV[2] & pbszCounter[2];
            pbszNonce[3] = pbszIV[3] & pbszCounter[3];
            pbszNonce[4] = pbszIV[4] & pbszCounter[4];
            pbszNonce[5] = pbszIV[5] & pbszCounter[5];
            pbszNonce[6] = pbszIV[6] & pbszCounter[6];
            pbszNonce[7] = pbszIV[7] & pbszCounter[7];
        }
        break;
    case NONCE_XOR:
        {
            pbszNonce[0] = pbszIV[0] ^ pbszCounter[0];
            pbszNonce[1] = pbszIV[1] ^ pbszCounter[1];
            pbszNonce[2] = pbszIV[2] ^ pbszCounter[2];
            pbszNonce[3] = pbszIV[3] ^ pbszCounter[3];
            pbszNonce[4] = pbszIV[4] ^ pbszCounter[4];
            pbszNonce[5] = pbszIV[5] ^ pbszCounter[5];
            pbszNonce[6] = pbszIV[6] ^ pbszCounter[6];
            pbszNonce[7] = pbszIV[7] ^ pbszCounter[7];
        }
        break;
    }
}

DWORD* chartoint32_for_HIGHT_CTR( IN BYTE *in, IN int inLen )
{
    unsigned int *data;
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

BYTE* int32tochar_for_HIGHT_CTR( IN DWORD *in, IN int inLen )
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

void HIGHT_CTR_init( OUT KISA_HIGHT_INFO *pInfo, IN KISA_ENC_DEC enc, IN BYTE *pUserKey, IN BYTE *pszbIV )
{
    unsigned char i, j;

    memset( pInfo, 0, sizeof(KISA_HIGHT_INFO) );
    pInfo->encrypt = enc;
    memcpy( (BYTE *)pInfo->ctr, (BYTE *)pszbIV, BLOCK_SIZE_HIGHT );
    memcpy( pInfo->userKey, pUserKey, 16 );

    for(i=0 ; i < BLOCK_SIZE_HIGHT ; i++)
    {
        for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
            pInfo->hight_key.key_data[ 16*i + j ] = pUserKey[(j-i)&7    ] + Delta[ 16*i + j ];

        for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
            pInfo->hight_key.key_data[ 16*i + j + 8 ] = pUserKey[((j-i)&7)+8] + Delta[ 16*i + j + 8 ];
    }
}

int HIGHT_CTR_Process( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *in, IN int inLen, OUT DWORD *out, OUT int *outLen )
{
    BYTE *pbszCounter;
    DWORD *pdwCounter;
    DWORD *pdwFirst;
    int nCurrentCount = 0;
    
    if( NULL == pInfo ||
        NULL == in ||
        NULL == out ||
        0 > inLen )
        return 0;

    pdwCounter = pInfo->ctr;

    while( nCurrentCount < inLen )
    {
        KISA_HIGHT_Block_forCTR( pInfo->hight_key.key_data, pInfo->userKey, (BYTE *)pdwCounter, (BYTE *)out );
        BLOCK_XOR_HIGHT( out, in, out );

        if( 0 == nCurrentCount )
            pdwFirst = out;

        pbszCounter = (BYTE *)pdwCounter;
        UpdateCounter_for_HIGHT( pbszCounter, 1, (BLOCK_SIZE_HIGHT-1) );

        nCurrentCount += BLOCK_SIZE_HIGHT;
        in += BLOCK_SIZE_HIGHT_INT;
        out += BLOCK_SIZE_HIGHT_INT;
    }

    *outLen = nCurrentCount;
    pInfo->buffer_length = inLen - *outLen;

    return 1;
}

int HIGHT_CTR_Close( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *out, IN int out_offset, IN int *outLen )
{
    unsigned int nEncRmainLeng;
    int i;
    BYTE *pOut;
    out += (out_offset/4);
    pOut = (BYTE *)(out);
    
    nEncRmainLeng = -(pInfo->buffer_length);
    
    for (i = nEncRmainLeng; i>0; i--)
    {
        *(pOut - i) = (BYTE)0x00;
    }
    
    *outLen = nEncRmainLeng;

    return 1;
}

int HIGHT_CTR_Encrypt( IN BYTE *pbszUserKey, IN BYTE *pszbCounter, IN BYTE *pbInputText, IN int in_offset, IN int nInputTextLen, OUT BYTE *pbszOutputText )
{
    int nOutLeng = 0;
    int nEncRmainLeng = 0;
    KISA_HIGHT_INFO info;
    unsigned char *newpbszInputText;
    unsigned int *outbuf;
    unsigned int *data;
    unsigned char *cdata;
    int outlen = 0;
    
    int nInputTextPadding = (BLOCK_SIZE_HIGHT - (nInputTextLen % BLOCK_SIZE_HIGHT)) % BLOCK_SIZE_HIGHT;
    newpbszInputText = (unsigned char *) malloc(sizeof(unsigned char) * (nInputTextLen + nInputTextPadding));
    memcpy(newpbszInputText, pbInputText + in_offset, nInputTextLen);

    HIGHT_CTR_init( &info, KISA_ENCRYPT, pbszUserKey, pszbCounter );

    outlen = ((nInputTextLen + nInputTextPadding)/8) *2;

    outbuf = malloc(sizeof(unsigned int) * outlen);
    data = chartoint32_for_HIGHT_CTR(newpbszInputText, nInputTextLen);

    HIGHT_CTR_Process( &info, data, nInputTextLen, outbuf, &nOutLeng );
    HIGHT_CTR_Close( &info, outbuf, nOutLeng, &nEncRmainLeng);
    cdata = int32tochar_for_HIGHT_CTR(outbuf, nOutLeng - nEncRmainLeng);
    memcpy(pbszOutputText, cdata, nOutLeng - nEncRmainLeng);

    free(data);
    free(cdata);
    free(outbuf);

    return (nOutLeng - nEncRmainLeng);
}

int HIGHT_CTR_Decrypt( IN BYTE *pbszUserKey, IN BYTE *pszbCounter, IN BYTE *pbInputText, IN int in_offset, IN int nInputTextLen, OUT BYTE *pbszOutputText )
{
    int nOutLeng = 0;
    int nEncRmainLeng = 0;
    KISA_HIGHT_INFO info;
    unsigned char *newpbszInputText;
    unsigned int *outbuf;
    unsigned int *data;
    unsigned char *cdata;
    int outlen = 0;
    
    int nInputTextPadding = (BLOCK_SIZE_HIGHT - (nInputTextLen % BLOCK_SIZE_HIGHT)) % BLOCK_SIZE_HIGHT;
    newpbszInputText = (unsigned char *) malloc(sizeof(unsigned char) * (nInputTextLen + nInputTextPadding));
    memcpy(newpbszInputText, pbInputText + in_offset, nInputTextLen);

    HIGHT_CTR_init( &info, KISA_ENCRYPT, pbszUserKey, pszbCounter );

    outlen = ((nInputTextLen + nInputTextPadding)/8) *2;

    outbuf = malloc(sizeof(unsigned int) * outlen);
    data = chartoint32_for_HIGHT_CTR(newpbszInputText, nInputTextLen);

    HIGHT_CTR_Process( &info, data, nInputTextLen, outbuf, &nOutLeng );
    HIGHT_CTR_Close( &info, outbuf, nOutLeng, &nEncRmainLeng);
    cdata = int32tochar_for_HIGHT_CTR(outbuf, nOutLeng - nEncRmainLeng);
    memcpy(pbszOutputText, cdata, nOutLeng - nEncRmainLeng);

    free(data);
    free(cdata);
    free(outbuf);

    return (nOutLeng - nEncRmainLeng);
}
/*
// method 1 start
void main()
{

    BYTE pbszUserKey[16] = {0x088, 0x0e3, 0x04f, 0x08f, 0x008, 0x017, 0x079, 0x0f1, 0x0e9, 0x0f3, 0x094, 0x037, 0x00a, 0x0d4, 0x005, 0x089}; 
    BYTE pbszCounter[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe};
    BYTE InputText[71] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BYTE pbszOutputText[80] = {0x00};
    BYTE pbszInputText[80] = {0x00};
    int i;
    int nInputTextLen;
    int nOutputTextLen;

    printf ("Key    : ");
    for (i=0;i<16;i++)    {printf("%02X ",pbszUserKey[i]);}

    printf ("\nCounter    : ");
    for (i=0;i<8;i++)    {printf("%02X ",pbszCounter[i]);}

    printf ("\n\nEncryption....");

    printf ("\n\nLength of Plaintext : ");
    scanf("%d", &nInputTextLen);

    printf ("\nPlaintext(%d)  : ", nInputTextLen);
    for (i=0;i<nInputTextLen;i++)    {printf("%02X ",InputText[i]);}
    
    // Encryption Algorithm //
    nOutputTextLen = HIGHT_CTR_Encrypt( pbszUserKey, pbszCounter, InputText, 0, nInputTextLen, pbszOutputText );

    printf ("\n\nCiphertext(%d) : ", nOutputTextLen);
    for (i=0;i<nOutputTextLen;i++)    {printf("%02X ",pbszOutputText[i]);}

    printf ("\n\n\n\nDecryption....\n");

    printf ("\nLength of Ciphertext : ");
    scanf("%d", &nOutputTextLen);

    printf ("\nCiphertext(%d) : ", nOutputTextLen);
    for (i=0;i<nOutputTextLen;i++)    {printf("%02X ",pbszOutputText[i]);}

    // Decryption Algorithm //
    nInputTextLen = HIGHT_CTR_Decrypt( pbszUserKey, pbszCounter, pbszOutputText, 0, nOutputTextLen, pbszInputText );

    printf ("\nPlaintext(%d)  : ", nInputTextLen);
    for (i=0;i<nInputTextLen;i++)    {printf("%02X ",pbszInputText[i]);}

    printf ("\n");

}
// method 1 end
*/

#if (defined(__BYTE_ORDER__ ) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    defined(__LITTLE_ENDIAN__)
# define HIGHT_LITTLE_ENDIAN 1
#endif

#if (defined(__BYTE_ORDER__ ) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
    defined(__BIG_ENDIAN__)
# define HIGHT_BIG_ENDIAN 1
#endif

// method 2 start
int main()
{
#ifndef HIGHT_BIG_ENDIAN
    printf("This program must be run on a big-endian machine to produce accurate test vectors.\n");
    return 1;
#endif

    BYTE pbszUserKey[16] = {0x088, 0x0e3, 0x04f, 0x08f, 0x008, 0x017, 0x079, 0x0f1, 0x0e9, 0x0f3, 0x094, 0x037, 0x00a, 0x0d4, 0x005, 0x089}; 
    BYTE pbszCounter[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe};
    BYTE InputText[71] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BYTE pbszOutputText[80] = {0x00};
    BYTE pbszInputText[80] = {0x00};
    KISA_HIGHT_INFO info;

    size_t lengths[] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        16,17,18,19,20,21,22,23,24,25,26,27,28,29,20,31,
        31,32,33 ,39,40,41, 47,48,49, 47,48,49, 55,56,57,
        55,56,57, 63,64,65, 71,72,73, 79,80,81, 87,88,89,
        95,96,97,103};

    size_t nInputTextLen = 0;
    size_t nOutputTextLen = 0;
    size_t message_length = 0;
    size_t i, len;

    int EncryptedMessage_length;
    unsigned int *outbuf;
    unsigned char *InputBytes = (BYTE *)(InputText);
    unsigned char *OutputBytes = (BYTE *)(pbszOutputText);
    unsigned int *data;
    unsigned char *cdata;
    int nOutLeng = 0;
    int remainleng = 0;
    int nEncRmainLeng = 0;

    nInputTextLen = 71;
    message_length = nInputTextLen;

    if (message_length == 0)
    {
        nOutputTextLen = 0;
    }
    else
    {
        HIGHT_CTR_init( &info, KISA_ENCRYPT, pbszUserKey, pbszCounter );
        outbuf = malloc(sizeof(unsigned int) * process_blockLeng);    
        for (i = 0; i < message_length - process_blockLeng; )
        {
            memcpy( pbszInputText, InputBytes + i, process_blockLeng );
            data = chartoint32_for_HIGHT_CTR(pbszInputText, process_blockLeng);
            HIGHT_CTR_Process( &info, data, process_blockLeng, outbuf, &nOutLeng );
            cdata = int32tochar_for_HIGHT_CTR( outbuf, nOutLeng);
            memcpy( OutputBytes + i, cdata, nOutLeng );
            i += nOutLeng;
        }
        remainleng = message_length % process_blockLeng;
        if (remainleng == 0)
        {
            remainleng = process_blockLeng;
        }
        memcpy( pbszInputText, InputBytes + i, remainleng );
        data = chartoint32_for_HIGHT_CTR(pbszInputText, remainleng);
        HIGHT_CTR_Process( &info, data, remainleng, outbuf, &nOutLeng );
        HIGHT_CTR_Close( &info, outbuf, nOutLeng, &nEncRmainLeng );
        cdata = int32tochar_for_HIGHT_CTR(outbuf, nOutLeng - nEncRmainLeng);
        memcpy(OutputBytes + i, cdata, nOutLeng - nEncRmainLeng);

        free(data);
        free(cdata);

        nOutputTextLen = i + nOutLeng - nEncRmainLeng;
    }

    for (len=0; len < sizeof(lengths) && lengths[len] < sizeof(InputText); ++len)
    {
        printf("#\n");
        printf("Source: HIGHT reference implementation\n");
        printf("Comment: HIGHT/CTR, 128-bit key\n");

        printf ("Key: ");
        for (i=0;i<16;i++)    {printf("%02X ",pbszUserKey[i]);}
        printf ("\n");

        printf ("IV: ");
        for (i=0;i<8;i++)    {printf("%02X ",pbszCounter[i]);}
        printf ("\n");

        printf ("Plaintext: ");
        for (i=0;i<lengths[len];i++)    {printf("%02X ",InputText[i]);}
        printf ("\n");

        printf ("Ciphertext: ");
        for (i=0;i<lengths[len];i++)    {printf("%02X ",OutputBytes[i]);}
        printf ("\n");

        printf("Test: Encrypt\n");
    }
    return 0;
}
// method 2 end
