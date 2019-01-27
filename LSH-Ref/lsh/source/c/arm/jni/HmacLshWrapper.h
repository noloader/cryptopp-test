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
 
#ifndef __HMAC_LSH_WRAPPER_H__
#define __HMAC_LSH_WRAPPER_H__

#include "../include/hmac.h" 
#include "../include/lsh.h"
#include "../include/lsh_def.h"

class CHmacLshWrapper {
    
private:
    struct HMAC_LSH_Context ctx;

public:
    CHmacLshWrapper();
    ~CHmacLshWrapper();
    
    size_t getOutputLength();
    
    void init(size_t wordbits, size_t outbits, const lsh_u8* key, size_t keylen);
    void update(lsh_u8* msg, size_t offset, size_t lenbytes);
    void doFinal(lsh_u8* out);
};
 
#endif
  