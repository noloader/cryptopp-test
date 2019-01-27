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

#include <stdio.h>
#include <stdlib.h>

#include "../include/lsh.h"
#include "lsh_benchmark.h"
#include "benchmark.h"

unsigned int lsh256_benchmark(unsigned int databitlen)
{
	unsigned int calibration, tMin = 0xFFFFFFFF, t0, t1;
	int i;

	unsigned char hashval256[32];
	unsigned char data[TEST_MESSAGE_SIZE];
	
	if (databitlen > (TEST_MESSAGE_SIZE << 3)){
		printf("databitlen must be less than %d\n", TEST_MESSAGE_SIZE << 3);
		return 0;
	}	

	calibration = calibrate();
	

	for (i=0; i<TIMER_SAMPLE_CNT;i++)  
	{
		t0 = HiResTime();

		/*	function for test	*/				
		lsh_digest(LSH_TYPE_256, data, databitlen, hashval256);
		/*	function for test	*/

		t1 = HiResTime();

		if (tMin > t1 - t0 - calibration)       /* keep only the minimum time */
				tMin = t1 - t0 - calibration;
	}
	
	return tMin;
}
unsigned int lsh512_benchmark(unsigned int databitlen)
{
	unsigned int calibration, tMin = 0xFFFFFFFF, t0, t1;
	int i;

	unsigned char hashval512[64];
	unsigned char data[TEST_MESSAGE_SIZE];

	if (databitlen > (TEST_MESSAGE_SIZE << 3)){
		printf("databitlen must be less than %d\n", TEST_MESSAGE_SIZE << 3);
		return 0;
	}

	calibration = calibrate();	


	for (i = 0; i<TIMER_SAMPLE_CNT; i++)  
	{
		t0 = HiResTime();

		/*	function for test	*/
		lsh_digest(LSH_TYPE_512, data, databitlen, hashval512);
		/*	function for test	*/

		t1 = HiResTime();

		if (tMin > t1 - t0 - calibration)       /* keep only the minimum time */
			tMin = t1 - t0 - calibration;
	}
	
	return tMin;
}




