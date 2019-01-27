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

#include "LshWrapper.h"

CLshWrapper::CLshWrapper() {
}

CLshWrapper::~CLshWrapper() {
}

size_t CLshWrapper::getOutputLength() {
	return LSH_GET_HASHBYTE(ctx.algtype);
}

void CLshWrapper::init(size_t wordbits, size_t outbits) {
	lsh_type type = LSH_MAKE_TYPE(wordbits==512, outbits);
	lsh_init(&ctx, type);
}

void CLshWrapper::update(lsh_u8* msg, size_t offset, size_t lenbits) {
	lsh_update(&ctx, msg, lenbits);
}

void CLshWrapper::doFinal(lsh_u8* out) {
	lsh_final(&ctx, out);
}
