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
#include "HmacLshNative.h"
#include "HmacLshWrapper.h"

JNIEXPORT jlong JNICALL Java_kr_re_nsr_crypto_mac_HmacLshNative_init(JNIEnv *env, jobject thiz, jint wordbits, jint outbits, jbyteArray key, jint keylen) {
    CHmacLshWrapper* hmac = new CHmacLshWrapper();
    
    lsh_u8* buf = (lsh_u8*) malloc(keylen * sizeof(lsh_u8));
    env->GetByteArrayRegion(key, 0, keylen, (jbyte*) buf);    
    
    hmac->init(wordbits, outbits, buf, keylen);
    
    free(buf);    
    return (jlong) hmac;  
}

/*
 * Class:     kr_re_nsr_crypto_mac_HmacLshNative
 * Method:    update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_kr_re_nsr_crypto_mac_HmacLshNative_update(JNIEnv *env, jobject thiz, jlong pctx, jbyteArray msg, jint offset, jint lenbytes) {
    CHmacLshWrapper* hmac = (CHmacLshWrapper*) pctx;
    
    lsh_u8* buf = (lsh_u8*) malloc(lenbytes * sizeof(lsh_u8));
    env->GetByteArrayRegion(msg, offset, lenbytes, (jbyte*) buf);
    free(buf);
    hmac->update(buf, offset, lenbytes);
}

/*
 * Class:     kr_re_nsr_crypto_mac_HmacLshNative
 * Method:    doFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_kr_re_nsr_crypto_mac_HmacLshNative_doFinal(JNIEnv *env, jobject thiz, jlong pctx) {
    CHmacLshWrapper* hmac = (CHmacLshWrapper*) pctx;
    
    size_t len = hmac->getOutputLength();
    jbyteArray result = env->NewByteArray(len);    
    lsh_u8 out[64] = {0x00};
    
    hmac->doFinal(out);
    env->SetByteArrayRegion(result, 0, len, (jbyte*) out);    
    delete hmac;
    
    return result;
}
