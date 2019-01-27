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

#include "../include/lsh.h"
#include "lsh_local.h"
#include "no_arch/lsh256.h"
#include "no_arch/lsh512.h"

#include "check_neon.h"
#include "neon/lsh256_neon.h"
#include "neon/lsh512_neon.h"

static const char * g_cszSIMD = "ndef";

static lsh_err lsh256_init_ndef(struct LSH256_Context * ctx, const lsh_type algtype);
static lsh_err lsh256_update_ndef(struct LSH256_Context * ctx, const lsh_u8 * data, size_t databitlen);
static lsh_err lsh256_final_ndef(struct LSH256_Context * ctx, lsh_u8 * hashval);
static lsh_err lsh256_digest_ndef(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

static lsh_err lsh512_init_ndef(struct LSH512_Context * ctx, const lsh_type algtype);
static lsh_err lsh512_update_ndef(struct LSH512_Context * ctx, const lsh_u8 * data, size_t databitlen);
static lsh_err lsh512_final_ndef(struct LSH512_Context * ctx, lsh_u8 * hashval);
static lsh_err lsh512_digest_ndef(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);


static PtrLSHInit256 g_pLSH256_init = lsh256_init_ndef;
static PtrLSHUpdate256 g_pLSH256_update = lsh256_update_ndef;
static PtrLSHFinal256 g_pLSH256_final = lsh256_final_ndef;
static PtrLSHDigest256 g_pLSH256_digest = lsh256_digest_ndef;

static PtrLSHInit512 g_pLSH512_init = lsh512_init_ndef;
static PtrLSHUpdate512 g_pLSH512_update = lsh512_update_ndef;
static PtrLSHFinal512 g_pLSH512_final = lsh512_final_ndef;
static PtrLSHDigest512 g_pLSH512_digest = lsh512_digest_ndef;

static lsh_err lsh256_init_ndef(struct LSH256_Context * ctx, const lsh_type algtype){ lsh_init_simd(); return g_pLSH256_init(ctx, algtype); }
static lsh_err lsh256_update_ndef(struct LSH256_Context * ctx, const lsh_u8 * data, size_t databitlen){ lsh_init_simd(); return g_pLSH256_update(ctx, data, databitlen); }
static lsh_err lsh256_final_ndef(struct LSH256_Context * ctx, lsh_u8 * hashval){ lsh_init_simd(); return g_pLSH256_final(ctx, hashval); }
static lsh_err lsh256_digest_ndef(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval){ lsh_init_simd(); return g_pLSH256_digest(algtype, data, databitlen, hashval); }

static lsh_err lsh512_init_ndef(struct LSH512_Context * ctx, const lsh_type algtype){ lsh_init_simd(); return g_pLSH512_init(ctx, algtype); }
static lsh_err lsh512_update_ndef(struct LSH512_Context * ctx, const lsh_u8 * data, size_t databitlen){ lsh_init_simd(); return g_pLSH512_update(ctx, data, databitlen); }
static lsh_err lsh512_final_ndef(struct LSH512_Context * ctx, lsh_u8 * hashval){ lsh_init_simd(); return g_pLSH512_final(ctx, hashval); }
static lsh_err lsh512_digest_ndef(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval){ lsh_init_simd(); return g_pLSH512_digest(algtype, data, databitlen, hashval); }

const char * lsh_get_simd_type(){
	if (g_pLSH256_init == lsh256_init_ndef) {
		lsh_init_simd();
	}
	return g_cszSIMD;
}

void lsh_init_simd() {

	if (has_neon_feature()) {
		g_cszSIMD = "neon";

		g_pLSH256_init = lsh256_neon_init;
		g_pLSH256_update = lsh256_neon_update;
		g_pLSH256_final = lsh256_neon_final;
		g_pLSH256_digest = lsh256_neon_digest;

		g_pLSH512_init = lsh512_neon_init;
		g_pLSH512_update = lsh512_neon_update;
		g_pLSH512_final = lsh512_neon_final;
		g_pLSH512_digest = lsh512_neon_digest;
		
	} else{
		g_cszSIMD = "ref";

		g_pLSH256_init = lsh256_init;
		g_pLSH256_update = lsh256_update;
		g_pLSH256_final = lsh256_final;
		g_pLSH256_digest = lsh256_digest;

		g_pLSH512_init = lsh512_init;
		g_pLSH512_update = lsh512_update;
		g_pLSH512_final = lsh512_final;
		g_pLSH512_digest = lsh512_digest;
	}

}

lsh_err lsh_init(union LSH_Context * state, const lsh_type algtype){
	if (state == NULL){
		return LSH_ERR_NULL_PTR;
	}

	if (LSH_IS_LSH256(algtype)){
		return g_pLSH256_init(&state->ctx256, algtype);
	}
	else if (LSH_IS_LSH512(algtype)){
		return g_pLSH512_init(&state->ctx512, algtype);
	}
	else{
		return LSH_ERR_INVALID_ALGTYPE;
	}
}

lsh_err lsh_update(union LSH_Context * state, const lsh_u8 * data, size_t databitlen){
	if (state == NULL){
		return LSH_ERR_NULL_PTR;
	}

	if (LSH_IS_LSH256(state->algtype)){
		return g_pLSH256_update(&state->ctx256, data, databitlen);
	}
	else{
		return g_pLSH512_update(&state->ctx512, data, databitlen);
	}
}

lsh_err lsh_final(union LSH_Context * state, lsh_u8 * hashval){
	if (state == NULL){
		return LSH_ERR_NULL_PTR;
	}

	if (LSH_IS_LSH256(state->algtype)){
		return g_pLSH256_final(&state->ctx256, hashval);
	}
	else{
		return g_pLSH512_final(&state->ctx512, hashval);
	}

}

lsh_err lsh_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval){
	if (LSH_IS_LSH256(algtype)){
		return g_pLSH256_digest(algtype, data, databitlen, hashval);
	}
	else if(LSH_IS_LSH512(algtype)){
		return g_pLSH512_digest(algtype, data, databitlen, hashval);
	}
	else{
		return LSH_ERR_INVALID_ALGTYPE;
	}
}
