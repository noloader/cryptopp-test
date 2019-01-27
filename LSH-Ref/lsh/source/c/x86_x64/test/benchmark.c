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

////////////////////////////////////////////////////////////////////////////
// The source of this code is from the Keccak(SHA-3) code,
// released in Keccak homepage(http://keccak.noekeon.org)
////////////////////////////////////////////////////////////////////////////

#include "stdio.h"
#include "stdlib.h"

#include "memory.h"
#include "time.h"

#include "benchmark.h"

/************** Timing routine (for performance measurements) ***********/
/* By Doug Whiting */
/* unfortunately, this is generally assembly code and not very portable */
#if defined(_M_IX86) || defined(__i386) || defined(_i386) || defined(__i386__) || defined(i386) || \
	defined(_X86_)   || defined(__x86_64__) || defined(_M_X64) || defined(__x86_64)
#define _Is_X86_    1
#endif
#if  defined(_Is_X86_) && (!defined(__STRICT_ANSI__)) && (defined(__GNUC__) || !defined(__STDC__)) && \
	(defined(__BORLANDC__) || defined(_MSC_VER) || defined(__MINGW_H) || defined(__GNUC__))
#define HI_RES_CLK_OK         1          /* it's ok to use RDTSC opcode */
#if defined(_MSC_VER) // && defined(_M_X64)
#include <intrin.h>
#pragma intrinsic(__rdtsc)         /* use MSVC rdtsc call where defined */
#endif
#endif

////////////////////////////////////////////////////////////////////////////////

unsigned int HiResTime(void)           /* return the current value of time stamp counter */
{
#if defined(HI_RES_CLK_OK)
	unsigned int x[2];
#if   defined(__BORLANDC__)
#define COMPILER_ID "BCC"
	__emit__(0x0F,0x31);           /* RDTSC instruction */
	_asm { mov x[0],eax };
#elif defined(_MSC_VER)
#define COMPILER_ID "MSC"
#if defined(_MSC_VER) // && defined(_M_X64)
	x[0] = (unsigned int) __rdtsc();
#else
	_asm { _emit 0fh }; _asm { _emit 031h };
	_asm { mov x[0],eax };
#endif
#elif defined(__MINGW_H) || defined(__GNUC__) 
#define COMPILER_ID "GCC"
	asm volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
#else
#error  "HI_RES_CLK_OK -- but no assembler code for this platform (?)"
#endif
	return x[0];
#else
	/* avoid annoying MSVC 9.0 compiler warning #4720 in ANSI mode! */
#if (!defined(_MSC_VER)||(!defined(__STDC__))||(_MSC_VER < 1300))
#error  "No Support for RDTSC on this CPU platform\n"             
#endif
	return 0;
#endif /* defined(HI_RES_CLK_OK) */
}

////////////////////////////////////////////////////////////////////////////////

unsigned int calibrate()
{
	unsigned int dtMin = 0xFFFFFFFF;        /* big number to start */
	unsigned int t0,t1,i;

	for (i=0;i < TIMER_SAMPLE_CNT;i++)  /* calibrate the overhead for measuring time */
	{
		t0 = HiResTime();
		t1 = HiResTime();
		if (dtMin > t1-t0)              /* keep only the minimum time */
			dtMin = t1-t0;
	}
	return dtMin;
}

float get_cpb(unsigned int cycle, unsigned int data_len)
{
	float cpb = cycle/(float)data_len;
	return cpb;
}
