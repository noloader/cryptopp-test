/*
** Phelix function and performance test module
**
** Public domain code.  Author:  Doug Whiting, Hifn, 2005
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>

#ifdef ECRYPT_API
#include "ecrypt-sync-ae.h"
/* map all local Phelix-related names to ECRYPT names */
#define PhelixValidityCheck ECRYPT_ValidityCheck
#define PhelixPerfTest      ECRYPT_PerfTest
#endif

#include "phelix.h"

typedef const char    * refStr;

/************************************************************
 ********** COMPILER/PLATFORM-SPECIFIC DEFINITIONS **********
 ************************************************************/
#if defined(_ANSI_CHK) || defined(__STRICT_ANSI__)
#define CompilerID                      "ANSI-C"
/************************************************************/
#elif defined(_MSC_VER) 
#define CompilerID                      "MSVC v%d.%d"
#define CompilerMajorVersion (_MSC_VER / 100)
#define CompilerMinorVersion (_MSC_VER % 100)
#define DO_PERF_TEST    1
#define USE_ASM         1
#define _IsX86_         1
#define _TRAP_          { if (_allowTrap_) _asm { int 3 }; }
u32b HighFreqCounter(void)
    {               /* use this to perform timing measurements  */
    u32b    x;
    _asm    /* counts CPU clocks (e.g., 1E9/sec for a 1GHz CPU) */
        {   
        _emit 0x0F
        _emit 0x31
        mov x,eax
        };
    return x;
    }

u32b Get_x86_CPU_ID(void)
    {
    u32b    x;
    _asm{
        push    ebx
        push    ecx
        mov     eax,1             /* eax == 1 --> get CPU type */
        _emit   0x0F
        _emit   0xA2
        mov   x,eax
        pop     ecx
        pop     ebx
        };
    return x;
    }
/************************************************************/
#elif defined(__BORLANDC__)
#define CompilerID                    "BorlandC v %X.%X"
#define CompilerMajorVersion (__BORLANDC__ / 256)
#define CompilerMinorVersion (__BORLANDC__ % 256)
#define CompilerVersion     
#define _TRAP_      { if (_allowTrap_) __emit__(0xCC); }
#define _IsX86_         1
#define DO_PERF_TEST    1
#define USE_ASM         1
u32b HighFreqCounter(void)
    {                               /* for performance timing */
    u32b    x;
    __emit__(0x0F);
    __emit__(0x31);
    _asm
        {
        mov x,eax
        };
    return x;
    }

u32b Get_x86_CPU_ID(void)
    {
    u32b    x;
    _asm{
        push    ebx
        push    ecx
        mov     eax,1             /* eax == 1 --> get CPU type */
        };
    __emit__(0x0F); __emit__(0xA2);     /* CPU_ID opcode */
    _asm
        {
        mov   x,eax
        pop     ecx
        pop     ebx
        };
    return x;
    }
/************************************************************/
#elif defined(__MINGW_H) || (defined(__GNUC__) && (defined(__i386__) || defined(__386)))
#define CompilerID                    "GCC v%d.%d"
#define CompilerMajorVersion (__GNUC__)
#define CompilerMinorVersion (__GNUC_MINOR__)
#define DO_PERF_TEST    1
#define _IsX86_         1
#define _TRAP_      { if (_allowTrap_) asm volatile ("int $3"); }
u32b HighFreqCounter(void)
    {
    u32b x[2];
    asm volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
    return x[0];
    }

u32b Get_x86_CPU_ID(void)
    {
    u32b    x;
    asm volatile("movl $1, %eax");
    asm volatile("cpuid" : "=a"(x));
    return x;
    }
/************************************************************/
#elif defined(sparc)
#define CompilerID                    "Solaris-GCC"
#define DO_PERF_TEST    1
#define CPU_INFO_STRING                 "SPARC CPU"
#include <sys/time.h>
u32b HighFreqCounter(void)
    {
    struct timezone tz;
    struct timeval  tv;
    gettimeofday(&tv,&tz);
    return tv.tv_usec;
    }
/************************************************************/
/* extend to other platforms by adding new "sections" here  */
#else 
#define CompilerID "Unknown compiler"
#endif
/************************************************************/
/* some catch-all definitions, if not previously defined    */
#ifndef DO_PERF_TEST    /* no performance tests by default  */
#define DO_PERF_TEST    0
u32b HighFreqCounter(void) { return 0; }
#endif

#ifndef _TRAP_          /* no debugger trap by default      */
#define _TRAP_
#endif

/*************************************************************
 ************ END OF PLATFORM-SPECIFIC DEFINITIONS ***********
 ************************************************************/

/* global configuration variables */
int         _verbose_       =   0;      /* verbose output                       */
int         _allowTrap_     =   0;      /* allow debugger trap (INT 3 for x86)  */
u32b        _timeAADcnt_    =   0;      /* # bytes of AAD to time               */
extern int  _debugCipher_;              /* instantiated in phelix.c             */

/* put out a formatted error message, then exit */
void FatalError(refStr formatStr,...)
    {
    va_list ap;

    printf("\n*** FATAL ERROR: ");
    va_start(ap,formatStr);
    vprintf(formatStr,ap);
    va_end(ap);
    printf("\n");

    _TRAP_;
    exit(2);
    }

/* print a message showing the CPU type and speed */
void ShowCPUinfo(void)
    {
#if defined(_IsX86_) && _IsX86_
    u32b cpuID,cpuFamily,cpuModel;

    cpuID     = Get_x86_CPU_ID();
    cpuFamily = (cpuID >> 8) & 0xF;
    cpuModel  = (cpuID >> 4) & 0xF;
    printf("CPU_ID = %08X ==> ",cpuID);
    switch (cpuFamily)
        {
        case  4:    printf("486");                  break;
        case  5:    printf("Pentium");              break;
        case  6:
            switch (cpuModel)
                {
                case  3:
                case  5:
                    printf("Pentium II");           break;
                case  6:
                    printf("Pentium II (Celeron)"); break;
                case  7:
                case  8:
                case 10:
                case 11:
                    printf("Pentium III");          break;
                case  9:
                case 13:
                    printf("Pentium M (III)");      break;
                default:
                    printf("Unknown CPU (II/III)"); break;
                }
            break;
        case 15:    printf("Pentium 4");            break;
        default:    printf("Unknown CPU");          break;
        }
#elif defined(CPU_INFO_STRING)
    printf(CPU_INFO_STRING);
#else
    printf("(Unknown CPU) ");
#endif

#if defined(DO_PERF_TEST) && DO_PERF_TEST
    /* now calibrate the HighFreqCounter frequency and display it */
    {
    enum    { FRAC = 10 };      /* calibrate for 1/FRAC second */
    u32b    x0,x1;
    clock_t t,t0,t1,dt;

    dt = CLOCKS_PER_SEC/FRAC;

    for (t=clock();;)           /* wait for clock() to change */
        if (t != (t0 = clock()))
            break;
    x0 = HighFreqCounter();     /* starting value of HiFreqCounter */
    do  { t1 = clock(); }       /* wait 1/10 of a second */
    while ((t1-t0) < dt);
    x1 = HighFreqCounter();     /* ending value */
        
    printf(" [PerfClk =%7.4f GHz.  clock() = %0.0f/sec]",
           ((x1-(double)x0)*FRAC)/1E9 , (double)CLOCKS_PER_SEC);
    }
#endif
    printf("\n");
    }


/**********************************************************************
 ********************* Phelix Definitions and Code ********************
 *********************************************************************/
typedef struct          /* test vector  (for KAT) */
    {
    u32b    keySize,msgLen,aadLen,macSize,nonceSize;
    u08b    key  [32];  /* "raw" key    */
    u08b    nonce[16];  /* nonce        */
    u08b    aad  [36];  /* aad          */
    u08b    pText[36];  /*  plaintext   */
    u08b    cText[36];  /* ciphertext   */
    u08b    mac  [16];  /* MAC result   */
    } TestVector;

const TestVector KAT[] =    /* known answer test vectors */
    {
#include "phelixKAT.h"
      {0,0,0,0,0} /* all zero lengths --> end of vector list */
    };

#define KAT_CNT (sizeof(KAT)/sizeof(KAT[0]))

/* cosmetic shortcuts for some of ProcessPacket function parms */
#define PPv &ctx,v.nonce,v.aad,v.aadLen
#define PP_ &ctx,  nonce,  aad,  aadLen

/* ASM function prototype definitions */
#if defined(USE_ASM) && USE_ASM && !defined(NO_ASM)
#define     TEST_ASM      1             /* both C & ASM language supported */
#include    "phelix_ASM.h"              /* ASM prototypes */
#else 
#define     TEST_ASM      0             /* just C, no ASM   */
    /* just a bunch of macros that point to dummy ASM functions */
#define     PhelixAssembler_Name                DummyAssemblerName
#define     PhelixCodeSize_ASM                  DummyProc
#define     PhelixIncrementalCodeSize_ASM       DummyProc
#define     PhelixEncryptPacket_ASM(ctx,nonce,aad,aadLen,src,dst,msgLen,mac) DummyProc()
#define     PhelixDecryptPacket_ASM(ctx,nonce,aad,aadLen,src,dst,msgLen,mac) DummyProc()
#define     PhelixNop_ASM(ctx,nonce,aad,aadLen,src,dst,msgLen,mac)           DummyProc()
#define     PhelixSetupKey_ASM(ctx,keyPtr,keySize,ivSize,macSize)            DummyProc()
#define     PhelixSetupNonce_ASM(ctx,noncePtr)                               DummyProc()
#define     PhelixProcessAAD_ASM(ctx,aadPtr,aadLen)                          DummyProc()
#define     PhelixEncryptBytes_ASM(ctx,pt,ct,msgLen)                         DummyProc()
#define     PhelixDecryptBytes_ASM(ctx,pt,ct,msgLen)                         DummyProc()
#define     PhelixFinalize_ASM(ctx,mac)                                      DummyProc()
    /* dummy functions (do not allow the string "Phelix" anywhere in the .MAP file) */
    u32b    DummyProc(void)             { return 0; }
    refStr  DummyAssemblerName(void)    { return "(none)"; }
#endif

/*
*********************************************************************
*   Portable PRNG functions/variables, same results across platforms
*********************************************************************
*/
static struct
    {
    u08b    i,j;                        /* RC4 variables */
    u08b    sbox[256];                  /* RC4 s-box */
    } RC4;

void RandFill(void *p,u32b byteCnt)
    {
    u32b n;
    u08b a,b;

    for (n=0;n<byteCnt;n++)             /* run the RC4 algorithm as long as it needs */
        {
        RC4.i++;
        a     =         RC4.sbox[RC4.i];
        RC4.j = (u08b) (RC4.j + a);     /* avoid MSVC picky compiler warning */
        b     =         RC4.sbox[RC4.j];
        RC4.sbox[RC4.i] = b;
        RC4.sbox[RC4.j] = a;
        ((u08b *)p)[n]  = RC4.sbox[(a+b) & 0xFF];
        }
    }

u32b Rand32(void)                       /* get a 32-bit word */
    {
    u08b    x[4];
    u32b    n;
    RandFill(x,sizeof(x));
    n   = x[3];                         /* convert to u32b in little-endian format */
    n   = x[2] + (n << 8);
    n   = x[1] + (n << 8);
    n   = x[0] + (n << 8);
    return n;
    }

u08b Rand08(void)                       /* get an 8-bit byte */
    {
    u08b    x[1];
    RandFill(x,1);
    return x[0];
    }

void RandReseed(u32b randSeed)              /* re-seed PRNG */
    {
    u32b i,j;
    u08b tmp;

    for (i=0;i<256;i++)                 /* initialize the permutation */
        RC4.sbox[i] = (u08b) i;
    for (i=j=0;i<256;i++)               /* run the RC4 key schedule */
        {                               /* use "randSeed" as 32-bit key */
        j           =(RC4.sbox[i] + j + (randSeed >> (8*(i%4)))) & 0xFF;
        tmp         = RC4.sbox[i];      /* swap sbox[i], sbox[j] */
        RC4.sbox[i] = RC4.sbox[j];
        RC4.sbox[j] = tmp;
        }
    RC4.i = RC4.j = 0;                  /* init i,j variables for RC4 */
    
    for (i=0;i<64;i++)
        Rand32();                       /* discard first 256 bytes of RC4 output */
    }

u32b RandMacSize(u32b mod)
    {
    u32b    i;
    static u32b macSizeCnt = 0;

    if (macSizeCnt == 0)
        {   /* count how many values are allowed */
#if PHELIX_MACSIZE(0) == PHELIX_MAXMACSIZE
        i = 1;
#else
        for (i=0;PHELIX_MACSIZE(i) <= PHELIX_MAXMACSIZE;i++)    ;
        assert(i > 0);
#endif
        macSizeCnt = i;
        }
    
    for (i = Rand32() % macSizeCnt;PHELIX_MACSIZE(i) % mod;)
        i=(i+1) % macSizeCnt;

    return PHELIX_MACSIZE(i);
    }

u32b RandKeySize(u32b mod)
    {
    static u32b keySizeCnt = 0;
    u32b    i;

    if (keySizeCnt == 0)
        {   /* count how many values are allowed */
#if PHELIX_KEYSIZE(0) == PHELIX_MAXKEYSIZE
        i = 1;
#else
        for (i=0;PHELIX_KEYSIZE(i) <= PHELIX_MAXKEYSIZE;i++)    ;
        assert(i > 0);
#endif
        keySizeCnt = i;
        }
    
    for (i = Rand32() % keySizeCnt;PHELIX_KEYSIZE(i) % mod;)
        i=(i+1) % keySizeCnt;

    return PHELIX_KEYSIZE(i);
    }

u32b RandNonceSize(u32b mod)
    {
    static u32b nonceSizeCnt = 0;
    u32b    i;

    if (nonceSizeCnt == 0)
        {   /* count how many values are allowed */
#if PHELIX_NONCESIZE(0) == PHELIX_MAXNONCESIZE
        i = 1;
#else
        for (i=0;PHELIX_NONCESIZE(i) <= PHELIX_MAXNONCESIZE;i++)    ;
        assert(i > 0);
#endif
        nonceSizeCnt = i;
        }
    
    for (i = Rand32() % nonceSizeCnt;PHELIX_NONCESIZE(i) % mod;)
        i=(i+1) % nonceSizeCnt;

    return PHELIX_NONCESIZE(i);
    }

u32b GetKeySize(u32b index)
    {
    static u32b keySizeCnt = 0;
    u32b    i;

    if (keySizeCnt == 0)
        {   /* count how many values are allowed */
        for (i=0;PHELIX_KEYSIZE(i) <= PHELIX_MAXKEYSIZE;i++)    ;
        keySizeCnt = i;
        assert(i > 0);
        }
    
    return PHELIX_KEYSIZE(index % keySizeCnt);
    }

/*
****************************************************************
* Generate formatted KAT vectors for inclusion in "PhelixKAT.h"
****************************************************************
*/
void GenerateKAT(refStr fmtStr)
    {
    enum    { ARRAY_CNT = 6 };
    u32b    j,k,n,r,xLen,vCnt;
    u08b    w[PHELIX_KEY_SIZE/8];       /* working key */
    u08b *  xPtr;
    refStr  xName;
    TestVector v;
    PhelixContext ctx;

    const TestVector texVec[] = /* vectors for TeX paper */
        {
            {  0,10,0,128,128,  /* keySize, msgLen, aadLen, macSize */
                /* key   */ {0},
                /* nonce */ {0},
                /* aad   */ {0},
                /* pText */ {0}
            },
            {256,32,0,128,128,  /* keySize, msgLen, aadLen, macSize */
                /* key   */ {0,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0,
                             4,0,0,0, 5,0,0,0, 6,0,0,0, 7,0,0,0},
                /* nonce */ {0,0,0,1, 1,0,0,1, 2,0,0,1, 3,0,0,1},
                /* aad   */ {0},
                /* pText */ {0,1,2,3, 1,2,3,4, 2,3,4,5, 3,4,5,6,
                             4,5,6,7, 5,6,7,8, 6,7,8,9, 7,8,9,10}
            },
            {128,0,0, 64,128,   /* keySize, msgLen, aadLen, macSize */
                /* key   */ {1,2,3,4, 5,6,7,8, 8,7,6,5, 4,3,2,1},
                /* nonce */ {4,0,0,0, 5,0,0,0, 6,0,0,0, 7,0,0,0},
                /* aad   */ {0},
                /* pText */ {0}
            },
            { 40,13,9, 96,128,  /* keySize, msgLen, aadLen, macSize */
                /* key   */ {9,7,5,3, 1},
                /* nonce */ {8,7,6,5, 4,3,2,1, 0,1,2,3, 4,5,6,7},
                /* aad   */ {0,2,4,6, 1,3,5,7, 8},
                /* pText */ {0,1,2,3, 1,2,3,4, 2,3,4,5, 0xFF}
            }
        };

    if (toupper(fmtStr[0]) == 'T')
        {   /* generate KAT vectors for TeX document */
        for (n=0;n<sizeof(texVec)/sizeof(texVec[0]);n++)
            {
            v = texVec[n];
            PhelixSetupKey       (  &ctx,v.key,v.keySize,v.nonceSize,v.macSize);
            PhelixProcessPacket_C(0,PPv,v.pText,v.cText,v.msgLen,v.mac);
            printf(" MAC tag:     %-3d bits\n",v.macSize);
            for (k=0;k<32;k++)      /* set up w[] to show processed key (little-endian) */
                w[k] = (u08b) ((ctx.ks.X_0[k/4] >> (8*(k%4))) & 0xFF);
            for (k=0;k<ARRAY_CNT;k++)
                {
                switch (k)
                    {
                    case 0: xPtr = v.key;   xLen = v.keySize/8;     xName = "Initial Key:"; break;
                    case 1: xPtr = w;       xLen = 32;              xName = "Working Key:"; break;
                    case 2: xPtr = v.nonce; xLen = sizeof(v.nonce); xName = "Nonce:";       break;
                    case 3: xPtr = v.aad;   xLen = v.aadLen;        xName = "AAD:";         break;
                    case 4: xPtr = v.pText; xLen = v.msgLen;        xName = "Plaintext:";   break;
                    case 5: xPtr = v.cText; xLen = v.msgLen;        xName = "Ciphertext:";  break;
                    case 6: xPtr = v.mac;   xLen =(v.macSize+7)/8;  xName = "MAC:";         break;
                    default:xPtr = NULL;    xLen = 0;               xName = NULL;           break;
                    }
                printf(" %-12s",xName);
                if (xLen == 0)
                    printf(" <empty string>");
                else for (j=0;j<xLen;j++)
                    {
                    if ((j % 4) == 0)       printf(" ");
                    printf("%02X",xPtr[j]);
                    if (j == xLen-1)        printf(" ");
                    else if ((j%16)==15)    printf("\n%13s","");
                    else                    printf(" ");
                    }
                printf("\n");
                }
            printf("\n");
            }
        return;
        }
    
    for (r=vCnt=0;r<4;r++)
    for (n=0;n<=sizeof(v.pText);n++)
        {
        memset(&v,0,sizeof(v));
        v.msgLen   =   sizeof(v.pText) - n;
        v.nonceSize=   PHELIX_NONCE_SIZE;
        switch (r)
            {
            case 0:     v.keySize   = PHELIX_KEY_SIZE;
                        v.macSize   = PHELIX_MAC_SIZE;
                        v.aadLen    = 0;                               break;
            case 1:     v.keySize   = GetKeySize(n);
                        v.macSize   = RandMacSize(32);
                        v.aadLen    = n        % (sizeof(v.aad)+1);    break;
            case 2:     v.keySize   = RandKeySize(8);
                        v.macSize   = RandMacSize(8);
                        v.aadLen    = Rand32() % (sizeof(v.aad)+1);    break;
            default:    v.keySize   = RandKeySize(8);
                        v.macSize   = RandMacSize(1);
                        v.nonceSize = RandNonceSize(1);
                        v.aadLen    = Rand32() % (sizeof(v.aad)+1);    break;
            }
        /* generate the (random) input data */
        for (j=0;j<v.keySize/8;    j++) v.key  [j] = (u08b) ((r)? Rand08() : j     );
        for (j=0;j<sizeof(v.nonce);j++) v.nonce[j] = (u08b) ((r)? Rand08() : j+0x20);
        for (j=0;j<v.aadLen;       j++) v.aad  [j] = (u08b) ((r)? Rand08() : j+0x40);
        for (j=0;j<v.msgLen;       j++) v.pText[j] = (u08b) ((r)? Rand08() : j+0x60);
        /* perform the encryption */
        PhelixSetupKey (  &ctx,v.key,v.keySize,v.nonceSize,v.macSize);
        PhelixProcessPacket_C(0,PPv,v.pText,v.cText,v.msgLen,v.mac);
        /* now output the vector in C structure format */
        printf("\n/* ---------- KAT vector #%3d ------------- */\n",++vCnt);
        printf("{%4d,%4d,%4d,%4d,%4d,  /* keySize, msgLen, aadLen, macSize, nonceSize */\n",
               v.keySize,v.msgLen,v.aadLen,v.macSize,v.nonceSize);
        for (k=0;k<ARRAY_CNT;k++)
            {
            switch (k)
                {
                case 0: xPtr = v.key;   xLen = v.keySize/8;     xName = "key";      break;
                case 1: xPtr = v.nonce; xLen = sizeof(v.nonce); xName = "nonce";    break;
                case 2: xPtr = v.aad;   xLen = v.aadLen;        xName = "aad";      break;
                case 3: xPtr = v.pText; xLen = v.msgLen;        xName = "pText";    break;
                case 4: xPtr = v.cText; xLen = v.msgLen;        xName = "cText";    break;
                case 5: xPtr = v.mac;   xLen =(v.macSize+7)/8;  xName = "mac";      break;
                    /* default case here just to avoid uninitialized variable warning */
                default:xPtr = NULL;    xLen = 0;               xName = NULL;       break;
                }
            printf("   {");
            for (j=0;j<xLen;j++)
                {
                printf("0x%02X",xPtr[j]);
                if (j == xLen-1)        printf("}");
                else if ((j%16)==15)    printf(",\n    ");
                else                    printf(",");
                }
            if (xLen == 0) printf("0x00}");
            printf("%c /* %s */\n",(k==ARRAY_CNT-1)?' ':',',xName);
            }
        printf("},\n");
#ifdef ALLOW_DEBUG_IO
        if (n == 16+r || vCnt == 1)
            {           /* show internal details (as a C comment) for some KAT vectors */
            _debugCipher_ = 1;
            printf("/**************************************************************\n"
                   " **** Phelix internal state (for debugging)\n"
                   " **************************************************************\n");
            PhelixSetupKey(&ctx,v.key,v.keySize,v.nonceSize,v.macSize);
            PhelixProcessPacket_C(0,PPv,v.pText,v.cText,v.msgLen,v.mac);
            printf("***************************************************************/\n\n");
            _debugCipher_ = 0;
            }
#endif
        }
    }
/*
****************************************************************
* Process one packet (speed doesn't matter -- just function)
****************************************************************
*/ 
refStr AlgoName(int algoSel)    /* name of the algorithm */
    {
    switch (algoSel)
        {
        case 0:     return "C (all-in-one)";
        case 1:     return "C (incremental)";
#if TEST_ASM
        case 2:     return "ASM (all-in-one)";
        case 3:     return "ASM (incremental)";
        case 4:     return "Mixed_C_ASM";
#endif
        default:    return NULL;
        }
    }

/* test the code of interest, map from ECRYPT to Phelix if necessary */
u32b ProcessPacket(int algoSel,int action,PhelixPacketParms)
    {
    int     doEncrypt = (action == 0);
    u08b    b,m[PHELIX_MAC_SIZE/8];
    u32b    k,n;
    PhelixContext pc = *ctx;

        /* generate small random steps toward the "full" length */
#define RandLen(k,n,len)                                \
    k = (Rand08() & 1) ? 4 : (Rand32() % (len-n)) & ~3; \
    if (k == 0)                                         \
        k = 4;          /* minimum step size */         \
    if (k > (len-n))    /* maximum step size */         \
        k =  len-n;

    switch (algoSel)
        {
        case 0: /* C all-in-one */
            if (doEncrypt)
                {
                PhelixProcessPacket_C(action,&pc,nonce,aad,aadLen,src,dst,msgLen,mac);
                return 0;
                }
            PhelixProcessPacket_C(action,&pc,nonce,aad,aadLen,src,dst,msgLen,m);
            break;
        case 1: /* C incremental */
            PhelixSetupNonce(&pc,nonce);
            if (aadLen)
                PhelixProcessAAD(&pc,aad,aadLen);
            if (doEncrypt)
                {
                PhelixEncryptBytes(&pc,src,dst,msgLen);
                PhelixFinalize(&pc,mac);
                return 0;
                }
            else
                {
                PhelixDecryptBytes(&pc,src,dst,msgLen);
                PhelixFinalize(&pc,m);
                break;      /* go do the final compare */
                }
        case 2: /* ASM all-in-one */
            if (doEncrypt)
                {
                PhelixEncryptPacket_ASM(&pc,nonce,aad,aadLen,src,dst,msgLen,mac);
                return 0;
                }
            PhelixDecryptPacket_ASM(&pc,nonce,aad,aadLen,src,dst,msgLen,m);
            break;
        case 3: /* ASM incremental */
            PhelixSetupNonce_ASM(&pc,nonce);
            for (n=0;n<aadLen;n+=k)     /* process AAD in variable-sized chunks */
                {
                RandLen(k,n,aadLen);
                PhelixProcessAAD(&pc,aad+n,k);
                }

            for (n=0;n<msgLen;n+=k)     /* process AAD in variable-sized chunks */
                {
                RandLen(k,n,msgLen);
                if (doEncrypt)
                    PhelixEncryptBytes(&pc,src+n,dst+n,k);
                else
                    PhelixDecryptBytes(&pc,src+n,dst+n,k);
                }

            if (doEncrypt)
                {
                PhelixFinalize_ASM(&pc,mac);
                return 0;
                }
            else
                {
                PhelixFinalize_ASM(&pc,m);
                break;      /* go do the final compare */
                }
        case 4: /* randomly intermix C and assembler calls to guarantee interoperability */
            if (Rand32() & 1)
                PhelixSetupNonce_ASM(&pc,nonce);
            else
                PhelixSetupNonce    (&pc,nonce);
                
            for (n=0;n<aadLen;n+=k)     /* process AAD in variable-sized chunks */
                {
                RandLen(k,n,aadLen);
                if (Rand32() & 1)
                    PhelixProcessAAD_ASM(&pc,aad+n,k);
                else
                    PhelixProcessAAD    (&pc,aad+n,k);
                }
            if (doEncrypt)
                {
                for (n=0;n<msgLen;n+=k)     /* process AAD in variable-sized chunks */
                    {
                    RandLen(k,n,msgLen);
                    if (Rand32() & 1)
                        PhelixEncryptBytes_ASM(&pc,src+n,dst+n,k);
                    else
                        PhelixEncryptBytes    (&pc,src+n,dst+n,k);
                    }
                if (Rand32() & 1)
                    PhelixFinalize_ASM(&pc,mac);
                else
                    PhelixFinalize    (&pc,mac);
                return 0;
                }
            else
                {
                for (n=0;n<msgLen;n+=k)     /* process AAD in variable-sized chunks */
                    {
                    RandLen(k,n,msgLen);
                    if (Rand32() & 1)
                        PhelixDecryptBytes_ASM(&pc,src+n,dst+n,k);
                    else
                        PhelixDecryptBytes    (&pc,src+n,dst+n,k);
                    }
                if (Rand32() & 1)
                    PhelixFinalize_ASM(&pc,m);
                else
                    PhelixFinalize    (&pc,m);
                break;      /* go do the final compare */
                }
        default:
            assert(algoSel == 0);
            return 1;
        }
    /* here only to do a decrypt MAC compare */
    if (memcmp(mac,m,pc.ks.macSize/8))  /* do all the "full" bytes compare? */
        return 1;
    if (pc.ks.macSize % 8)              /* any partial bytes? */
        {
        b = (u08b) (m[pc.ks.macSize/8] ^ mac[pc.ks.macSize/8]);
        if (b & ((1 << (pc.ks.macSize % 8)) - 1))
            return 1;
        }
    memcpy(mac,m,(pc.ks.macSize+7)/8);
    return 0;
    }

/*
****************************************************************
* Make sure the code functions properly
****************************************************************
*/ 
void PhelixValidityCheck(u32b checkCnt,u32b compareKATcnt)
    {
    enum    { MAX_BYTES=256 };
    u32b    i,j,k,n,res,aadLen,macSize,keySize,nonceSize,errBit,KATcnt;
    u08b    key[PHELIX_KEY_SIZE/8],nonce[PHELIX_NONCE_SIZE/8],
            mac[2][PHELIX_MAC_SIZE/8],
            pText[MAX_BYTES+4],cText[MAX_BYTES+4],dText[MAX_BYTES+4],
            aad  [MAX_BYTES+4],tmp[3][MAX_BYTES+4];
    u08b    b;
    u08b *  macPtr;
    refStr  lName;
    TestVector v;
    PhelixContext ctx;

    if (checkCnt == 0) return;
    
    /* finally, make sure that the KAT vectors match */
    for (k=0;k < compareKATcnt;k++)
        {
        v = KAT[k];
        if (0 == (v.keySize | v.msgLen | v.aadLen | v.macSize | v.nonceSize))
            break;      /* end of list? */
        memset(&ctx,0,sizeof(ctx));     /* for debug i/o cosmetics */
        PhelixSetupKey (&ctx,v.key,v.keySize,v.nonceSize,v.macSize);
        PhelixProcessPacket_C(0,PPv,v.pText,cText,v.msgLen,mac[0]);
        if (memcmp(cText,v.cText,v.msgLen))
            FatalError("KAT data miscompare on vector #%d",k+1);
        if (memcmp(mac  ,v.mac  ,(v.macSize+7)/8))
            FatalError("KAT MAC  miscompare on vector #%d",k+1);
        }
    KATcnt = k;
    if (compareKATcnt && compareKATcnt < (sizeof(KAT)/sizeof(KAT[0])) && _debugCipher_)
        exit(0);        /* just output some debug info and stop */

    /* first perform repeated, random self-consistency checks */
    for (j=0;j<checkCnt;j++)
        {
        RandFill(pText,sizeof(pText));
        RandFill(aad  ,sizeof(aad)  );  
        RandFill(nonce,sizeof(nonce));
        RandFill(key  ,sizeof(key)  );
        memcpy(tmp[2],aad,sizeof(aad)); /* save copy of AAD to make sure it's unchanged */

        aadLen = ((j < checkCnt/2) ?        j          : Rand32()) % MAX_BYTES;
        macSize=  (j < checkCnt/2) ? PHELIX_MAC_SIZE   : RandMacSize(1);
        keySize=  (j < checkCnt/2) ? PHELIX_KEY_SIZE   : RandKeySize(8);
        nonceSize=(j < checkCnt/2) ? PHELIX_NONCE_SIZE : RandNonceSize(1);

        PhelixSetupKey(&ctx,key,keySize,nonceSize,macSize);

        for (n=1;n<MAX_BYTES;n++)
            {
            b = Rand08();
            memset(dText,b,sizeof(dText));  /* fill with known data */
            memset(cText,b,sizeof(cText));
            memset(mac  ,0,sizeof(mac  ));

            for (k=0;;k++)
                {
#if TEST_ASM
                if (k && (Rand32() & 1))    /* intermix the C and ASM keying versions */
                    if (Rand32() & 1)
                        PhelixSetupKey_ASM(&ctx,key,keySize,nonceSize,macSize);
                    else
                        PhelixSetupKey    (&ctx,key,keySize,nonceSize,macSize);
#endif
                lName = AlgoName(k);    /* name of the implementation (e.g., "C") */
                if (lName == NULL) break;   /* stop when out of algorithms */
                macPtr = mac[(k) ? 1 : 0];
                memcpy(tmp,pText,n);
                res = ProcessPacket(k,0,PP_,pText,cText,n,macPtr);
                if (res)
                    FatalError("Encrypt_%s returned an error! [n=%d]",lName,n);
                if (memcmp(tmp,pText,n))
                    FatalError("Encrypt_%s modified the plaintext [n=%d]",lName,n);
                if (aadLen && memcmp(tmp[2],aad,aadLen))
                    FatalError("Encrypt_%s modified AAD [n=%d]",lName,n);
                for (i=n;i<sizeof(cText);i++)
                    if (((u08b *)cText)[i] != b)
                        FatalError("Encrypt_%s modified extra dest bytes [n=%d]",lName,n);
                if (k==0)
                    memcpy(tmp[1],cText,n);     /* save for later comparison vs. ASM */
                else
                    {
                    if (memcmp(tmp[1],cText,n))
                        FatalError("Ciphertext miscompare: %s vs. %s [n=%d]",AlgoName(0),lName,n);
                    if (memcmp(mac[0],macPtr,(macSize+7)/8))
                        FatalError("MAC miscompare: %s vs. %s [n=%d]",AlgoName(0),lName,n);
                    }
                memcpy(tmp[0],cText,n);
                res=ProcessPacket(k,1,PP_,cText,dText,n,macPtr);
                for (i=n;i<sizeof(dText);i++)
                    if (((u08b *)dText)[i] != b)
                        FatalError("Decrypt_%s modified extra dest bytes [n=%d]",lName,n);
                if (memcmp(tmp[0],cText,n))
                    FatalError("Decrypt_%s modified the input ciphertext [n=%d]",lName,n);
                if (aadLen && memcmp(tmp[2],aad,aadLen))
                    FatalError("Decrypt_%s modified AAD [n=%d]",lName,n);
                if (memcmp(pText,dText,n))
                    FatalError("Decrypt_%s miscompare [n=%d]",lName,n);
                if (res)
                    FatalError("Decrypt_%s generated a false MAC miscompare [n=%d]",lName,n);
                /* force a decrypt MAC error and make sure it gets detected */
                memcpy(tmp[0],macPtr,PHELIX_MAC_SIZE/8);
                errBit = Rand32() % macSize;
                tmp[0][errBit/8] ^= 1 << (errBit % 8); /* inject a bit error */
                res=ProcessPacket(k,1,PP_,cText,dText,n,tmp[0]);
                if (res == 0)
                    FatalError("Decrypt_%s missed a MAC miscompare [n=%d]",lName,n);
                
                if (macSize < PHELIX_MAC_SIZE)
                for (i=0;i<4;i++)
                    { /* insert decrypt MAC error just after the limit to make sure it's ignored */
                    memcpy(tmp[0],macPtr,PHELIX_MAC_SIZE/8);
                    errBit = macSize + ((i) ? (Rand32() % (PHELIX_MAC_SIZE-macSize)) : 0);
                    tmp[0][errBit/8] ^= 1 << (errBit % 8); /* inject a bit error */
                    res=ProcessPacket(k,1,PP_,cText,dText,n,tmp[0]);
                    if (res != 0)
                        FatalError("Decrypt_%s found false truncated MAC miscompare [n=%d]",lName,n);
                    }
                /* test encrypt and decrypt "in place" */
                memcpy(dText,cText,n);
                res=ProcessPacket(k,1,PP_,dText,dText,n,macPtr);
                if (res) FatalError("Decrypt_%s in-place failed (%d)\n",lName,n);
                if (memcmp(dText,pText,n))
                    FatalError("Decrypt_%s in-place miscompare (%d)\n",lName,n);
                res=ProcessPacket(k,0,PP_,dText,dText,n,tmp[0]);
                if (res) FatalError("Encrypt_%s in-place failed (%d)\n",lName,n);
                if (memcmp(dText,cText,n))
                    FatalError("Encrypt_%s in-place miscompare (%d)\n",lName,n);
                }
            }
        }
    printf("ValidityCheck OK: %s  [%d KAT vectors]\n",PHELIX_CIPHER_NAME,KATcnt);
    }
/*
****************************************************************
* Test the speed of various algorithm implementations
****************************************************************
*/ 
void PhelixPerfTest(u32b callCnt)
    {
    enum    { TEST_CNT=8,  MAX_FUNC=10, MAX_BYTES=1024 };
    refStr  TEST_NAME[MAX_FUNC]=
            {"Encrypt_C:","Decrypt_C:","Encrypt_C_inc:","Decrypt_C_inc:",
             "Encrypt_ASM:","Decrypt_ASM:","Encrypt_ASM_inc:","Decrypt_ASM_inc:",
             "KeySetup_C:","KeySetup_ASM:"};
    refStr  SHOW_EQN = "YYYYYYYYnn";
    u32b    i,j,k,n,N,a,t0,t1,p,codeSize;
    u32b    dt[TEST_CNT+1],dtMin,dtMax,dtSum;
    u08b    key[PHELIX_KEY_SIZE/8],nonce[PHELIX_NONCE_SIZE/8],
            mac[PHELIX_MAC_SIZE/8],pText[MAX_BYTES+4],cText[MAX_BYTES+4];
    struct  { u32b n,dt; } pts[8];
    double  denom;
    PhelixContext ctx;

    if (callCnt == 0) return;       

    RandFill(pText,sizeof(pText));
    RandFill(key  ,sizeof(key));
    RandFill(nonce,sizeof(nonce));

    dtMin = 0;  /* avoid MSVC compiler warning: uninitialized */

    if (_timeAADcnt_)
        printf("AAD cnt = %d bytes\n",_timeAADcnt_);
    printf(  "             Code Size|            Packet Size (N)          |   Clk equation");
    printf("\nVersion        (bytes)|");
    for (n=64;n<=MAX_BYTES;n*=4)
        printf("%6d bytes",n);
    printf(" |     (approx)\n");
    printf(  "----------------------|-------------------------------------|--------------------\n");

    for (k=0;k < MAX_FUNC;k++)
        {
        switch (k)
            {
            case 0:
            case 1: codeSize = PhelixProcessPacket_C_CodeSize();    break;
            case 2: 
            case 3: codeSize = Phelix_C_CodeSize();                 break;
            case 4: 
            case 5: codeSize = PhelixCodeSize_ASM();                break; 
            case 6:
            case 7: codeSize = PhelixIncrementalCodeSize_ASM();     break;
            default:codeSize = 0;                                   break;
            }
#if !TEST_ASM
        if (strstr(TEST_NAME[k],"_ASM"))
            continue;               /* skip ASM tests if not using ASM */
#endif

        printf("%-16s",TEST_NAME[k]);
        if (SHOW_EQN[k] == 'Y')
            printf((codeSize)?"%5d |":"      |",codeSize);

        PhelixSetupKey(&ctx,key,PHELIX_KEY_SIZE,PHELIX_NONCE_SIZE,PHELIX_MAC_SIZE);

        for (n=64,p=0;n<=MAX_BYTES;n*=4,p++)
            {
            a = (n < _timeAADcnt_) ? n : _timeAADcnt_;
            N =  n - a;
            for (j=0;j<TEST_CNT;j++)
                {
                t0=HighFreqCounter();
                switch (k)
                    {
                    case 0: 
                        for (i=0;i<callCnt;i++)
                            PhelixProcessPacket_C(0,&ctx,nonce,pText,a,pText+a,cText,N,mac);
                        break;
                    case 1: 
                        for (i=0;i<callCnt;i++)
                            PhelixProcessPacket_C(1,&ctx,nonce,pText,a,cText,pText,N,mac);
                        break;
                    case 2:
                        for (i=0;i<callCnt;i++)
                            {
                            PhelixSetupNonce  (&ctx,nonce);
                            if (a)
                                PhelixProcessAAD(&ctx,pText,a);
                            PhelixEncryptBytes(&ctx,pText+a,cText,N);
                            PhelixFinalize    (&ctx,mac);
                            }
                        break;
                    case 3:
                        for (i=0;i<callCnt;i++)
                            {
                            PhelixSetupNonce  (&ctx,nonce);
                            if (a)
                                PhelixProcessAAD(&ctx,pText,a);
                            PhelixDecryptBytes(&ctx,pText+a,cText,N);
                            PhelixFinalize    (&ctx,mac);
                            }
                        break;
                    case 4: 
                        for (i=0;i<callCnt;i++)
                            PhelixEncryptPacket_ASM(&ctx,nonce,pText,a,pText+a,cText,N,mac);
                        break;
                    case 5: 
                        for (i=0;i<callCnt;i++)
                            PhelixDecryptPacket_ASM(&ctx,nonce,pText,a,cText,pText,N,mac);
                        break;
                    case 6:
                        for (i=0;i<callCnt;i++)
                            {
                            PhelixSetupNonce_ASM(&ctx,nonce);
                            if (a)
                                PhelixProcessAAD_ASM(&ctx,pText,a);
                            PhelixEncryptBytes_ASM(&ctx,pText+a,cText,N);
                            PhelixFinalize_ASM  (&ctx,mac);
                            }
                        break;
                    case 7:
                        for (i=0;i<callCnt;i++)
                            {
                            PhelixSetupNonce_ASM(&ctx,nonce);
                            if (a)
                                PhelixProcessAAD_ASM(&ctx,pText,a);
                            PhelixDecryptBytes_ASM(&ctx,cText,pText,N);
                            PhelixFinalize_ASM  (&ctx,mac);
                            }
                        break;
                    case 8: 
                        for (i=0;i<callCnt;i++)
                            PhelixSetupKey(&ctx,key,PHELIX_KEY_SIZE,PHELIX_NONCE_SIZE,PHELIX_MAC_SIZE);
                        break;
                    case 9: 
                        for (i=0;i<callCnt;i++)
                            PhelixSetupKey_ASM(&ctx,key,PHELIX_KEY_SIZE,PHELIX_NONCE_SIZE,PHELIX_MAC_SIZE);
                        break;
                    }
                t1=HighFreqCounter();
                dt[j]=t1-t0;
                }
            /* show timing results */
            if (_verbose_)
                printf("  dt for %d calls (%d bytes each):\n",callCnt,n);
            for (i=0,dtMax=dtSum=0,dtMin=~0u;i<TEST_CNT;i++)
                {
                if (_verbose_) printf("%9d",dt[i]);
                if (dtMin > dt[i]) dtMin=dt[i];
                if (dtMax < dt[i]) dtMax=dt[i];
                dtSum+=dt[i];
                }
            if (_verbose_)
                printf("\nClocks per call = %d [min]\n",dtMin/callCnt);

            if (SHOW_EQN[k] != 'Y')
                {
                printf("%15d clocks",dtMin/callCnt);
                break;
                }
            denom = (double) (callCnt*n);
            printf("%8.2f cpb",dtMin/denom);
            pts[p].n  = n;
            pts[p].dt = dtMin;
            if (_verbose_)
                printf(", %5.2f [discard], %5.2f [all]",
                   (dtSum-dtMin-dtMax)/((TEST_CNT-2)*denom),dtSum/(TEST_CNT*denom));
            }
        if (p > 1)  /* need two points to define an equation */
            {       /* could do least squares, but it's not worth it */
            assert(pts[p-1].n > pts[p-2].n);
            denom = callCnt * (double)(pts[p-1].n - pts[p-2].n);
            printf(" |%6.0f +%6.2f * N",
                   (pts[p-1].n*pts[p-2].dt-pts[p-2].n*dtMin)/denom,
                   (dtMin-pts[p-2].dt)/denom);
            }
        printf("\n");
        }
    }

/* display a help message on command-line options and then exit */
void GiveHelp(void)
    {
    printf
        (
        "Syntax:  PhelixTest [option]*\n"
        "Purpose: Test Phelix function and performance\n"
        "Options: -A  = measure AAD speed\n"
        "         -D  = output debug info\n"
        "         -F  = do not validate functionality\n"
        "         -Fn = run n  validation loops\n"
        "         -G  = generate KAT vectors and exit\n"
        "         -K  = do not compare C to KAT vectors\n"
        "         -Sn = set initial random seed to n\n"
        "         -Tn = measure performance over n calls\n"
        "         -V  = verbose mode\n"
        "         -3  = allow debugger traps\n"
        );
    exit(2);    
    }


int main(int argc,char *argv[])
    {
    int     i;
    refStr  genKAT          =   NULL;
    u32b    funcTestCnt     =   64;
    u32b    compareKATcnt   =   KAT_CNT;    /* default is all of KAT vectors */
    u32b    perfCallCnt     =   (DO_PERF_TEST) ? 16 : 0;
    u32b    randSeed        =   time(NULL);
    char    compilerName[128];
    time_t  t;

#ifdef CompilerMajorVersion
    sprintf(compilerName,CompilerID,CompilerMajorVersion,CompilerMinorVersion);
#else
    sprintf(compilerName,"%s",CompilerID);
#endif
    time(&t);
    for (i=1;i<argc;i++)
        {
        if (argv[i][0] == '-' || argv[i][0] == '/')
            switch(toupper(argv[i][1]))
                {
                case '?':   GiveHelp();                             break;
                case '3':   _allowTrap_     = 1;                    break;
                case 'A':   _timeAADcnt_    = atoi(argv[i]+2);      break;
                case 'D':   _debugCipher_   = 1;                    break;
                case 'F':   funcTestCnt     = atoi(argv[i]+2);      break;
                case 'G':   genKAT          =      argv[i]+2;       break;
                case 'K':   compareKATcnt   = atoi(argv[i]+2);      break;
                case 'S':   randSeed        = atoi(argv[i]+2);      break;
                case 'T':   perfCallCnt     = atoi(argv[i]+2);      break;
                case 'V':   _verbose_       = 1;                    break;
                default:    FatalError("Unknown switch",argv[i]);   break;
                }
        else if (argv[i][0] == '?')
            GiveHelp();
        }
    RandReseed(randSeed);
    
    if (genKAT)
        {
        GenerateKAT(genKAT);  /* just output the vectors and return */
        return 0;             /* (i.e., can redirect output directly to PhelixKAT.h :-) */
        }

    ShowCPUinfo();      /* find out the CPU type and speed */
    printf("Compiled by %s, %s %s.  Assembler = %s.\nrandSeed=%d. callCnt = %d.  Run @ %s",
            compilerName,__DATE__,__TIME__,PhelixAssembler_Name(),
            randSeed,perfCallCnt,ctime(&t));

    PhelixInit();
    /* make sure the code functions properly */
    PhelixValidityCheck(funcTestCnt,compareKATcnt);
    /* time the code (in C and, if available, ASM) to see how fast it is */
    PhelixPerfTest(perfCallCnt);

    return 0;
    }
