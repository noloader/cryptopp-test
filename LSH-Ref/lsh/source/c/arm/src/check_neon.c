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
 
#include "check_neon.h"

#if defined(ANDROID) || defined(__ANDROID__)
//#include <android/log.h>
#include "cpu-features.h"
int has_neon_feature() {
	AndroidCpuFamily family = android_getCpuFamily();
	uint64_t features = android_getCpuFeatures();
	
	if (family != ANDROID_CPU_FAMILY_ARM && family != ANDROID_CPU_FAMILY_ARM64) {
		//__android_log_print(ANDROID_LOG_VERBOSE, "LSH", "NOT_ARM_CPU");
		return 0;
	}
	
	if (features & ANDROID_CPU_ARM_FEATURE_NEON) {
		//__android_log_print(ANDROID_LOG_VERBOSE, "LSH", "HAS_NEON");
		return 1;
	}
	
	//__android_log_print(ANDROID_LOG_VERBOSE, "LSH", "NEON_UNABAILABLE");
	
	return 0;
}

#else

#include <sys/auxv.h>
#include <asm/hwcap.h>
int has_neon_feature() {
	long features = getauxval(AT_HWCAP);
	if (features & HWCAP_NEON) {
		return 1;
	}
	
	return 0;
}
#endif
