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

#include <stdlib.h>
#include "LshNative.h"
#include "LshWrapper.h"

/*
 * Class:     kr_re_nsr_crypto_hash_LshNative
 * Method:    init
 * Signature: (II)Ljava/lang/Object;
 */
JNIEXPORT jlong JNICALL Java_kr_re_nsr_crypto_hash_LshNative_init(JNIEnv *env, jobject thiz, jint wordbits, jint outbits) {
	CLshWrapper* lsh = new CLshWrapper();
	lsh->init(wordbits, outbits);
	return (jlong) lsh;
}

/*
 * Class:     kr_re_nsr_crypto_hash_LshNative
 * Method:    update
 * Signature: (Ljava/lang/Object;[BII)V
 */
JNIEXPORT void JNICALL Java_kr_re_nsr_crypto_hash_LshNative_update(JNIEnv *env, jobject thiz, jlong pctx, jbyteArray msg, jint offset, jint lenbits) {
	CLshWrapper* lsh = (CLshWrapper*) pctx;
	size_t len = lenbits >> 3;
	size_t rbits = lenbits & 0x7;
	if (rbits > 0) {
		++len;
	}	
	lsh_u8 *buf = (lsh_u8*) malloc(len * sizeof(lsh_u8));
	env->GetByteArrayRegion(msg, offset, len, (jbyte*)buf);
	free(buf);
	lsh->update(buf, offset, lenbits);
}

/*
 * Class:     kr_re_nsr_crypto_hash_LshNative
 * Method:    doFinal
 * Signature: (Ljava/lang/Object;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_kr_re_nsr_crypto_hash_LshNative_doFinal(JNIEnv *env, jobject thiz, jlong pctx) {
	CLshWrapper* lsh = (CLshWrapper*) pctx;
	int len = lsh->getOutputLength();
	jbyteArray result = env->NewByteArray(len);
	lsh_u8 hashval[64] = {0x00};
	lsh->doFinal(hashval);
	env->SetByteArrayRegion(result, 0, len, (jbyte*)hashval);
	delete lsh;
	return result;
}

