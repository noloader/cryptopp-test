;
;----------------------------------------------------------------
; Phelix encryption/authentication algorithm, version 2
; Author: Doug Whiting, Hifn. 2002-2004.
;
; This source code is released to the public domain
;----------------------------------------------------------------
;
		.386
		.model	flat,c
		.code
		
		include	strucmac.inc		;structured programming macros (_if/_else/_endif, etc)

		page	,128				;format things nicely in listing
;
PHELIX_INCREMENTAL_API	equ		1	;undef this to exclude incremental calls
;
		public	PhelixAssembler_Name
		public	PhelixNop_ASM
		public	PhelixEncryptPacket_ASM
		public	PhelixDecryptPacket_ASM
		public	PhelixCodeSize_ASM
  ifdef PHELIX_INCREMENTAL_API
		public	PhelixSetupKey_ASM
		public	PhelixSetupNonce_ASM
		public	PhelixProcessAAD_ASM
		public	PhelixEncryptBytes_ASM
		public	PhelixDecryptBytes_ASM
		public	PhelixFinalize_ASM
		public	PhelixIncrementalCodeSize_ASM
  endif
;
  ifdef ??version					;Borland TASM32 pre-defined constant
%tabsize	4						;format things pretty
AsmName		db		"TASM32",0		;set the assembler name
  else
AsmName		db		"MASM",0
  endif
;
PhelixAssembler_Name proc			;show who assembled us
		lea		eax,AsmName
		ret
PhelixAssembler_Name endp
;
;----------------------------------------------------------------
; Macros and definitions
;----------------------------------------------------------------
;
; Phelix rotation constants
ROT_0a			equ		 9
ROT_1a			equ		10
ROT_2a			equ		17
ROT_3a			equ		30
ROT_4a			equ		13
;
ROT_0b			equ		20
ROT_1b			equ		11
ROT_2b			equ		 5
ROT_3b			equ		15
ROT_4b			equ		25
;
Z0				equ		eax				;register assignments
Z1				equ		ebx
Z2				equ		ecx
Z3				equ		edx
Z4				equ		esi
t0				equ		ebp				;"temp" scratch registers
t1				equ		edi
oldZreg			equ		Z4
;
UNROLL_CNT		equ		 8				;how many blocks to unroll in inner loop
ZERO_INIT_CNT	equ		 8				;number of words of init
MAGIC_MAC_XOR	equ		912d94f1h		;special constants
MAGIC_AAD_XOR	equ	   0aadaadaah
;
;
;----------------------------------------------------------------
; pseudo-instruction (assemble-time)
;----------------------------------------------------------------
;
_ASM_Assert macro	cnd,msg
	if (cnd)
		;; all is well -- no error
	else
	  ifb <msg>
		.err "ASSERTION FAILURE:  cnd"
	  else
		.err "ASSERTION FAILURE:  msg"
	  endif
	endif
endm
;
_ASM_Assert	<UNROLL_CNT eq (UNROLL_CNT and not (UNROLL_CNT-1))>,<Unroll count must be a power of 2>
;
;----------------------------------------------------------------
;
; Allocate and define local variables on the stack
; [Note:	We use esp for locals, not ebp, since we need ebp as a variable.
;			Thus, we can't use the assembler stack frame primitives.]
;
_maxPhelixStack_ =  0					;max locals usage in bytes
_stack_offs		 =	0					;current stack offset due to calls
_Phelix_LocalSize= 	0					;starting value: no locals allocated yet
;
_newLocal macro	wCnt,lName				;macro to define a local variable
		irp		_offs_,<%_Phelix_LocalSize>
lName	  equ	<dword ptr [esp + _offs_ + _stack_offs]>
lName&_Z4 equ	<dword ptr [Z4  + _offs_ - _cpOfs_    ]>
		endm
_Phelix_LocalSize = _Phelix_LocalSize + 4*(wCnt)
  ; keep running tabs on stack usage for locals
  if _maxPhelixStack_ lt _Phelix_LocalSize
	 _maxPhelixStack_  = _Phelix_LocalSize
  endif
endm
		; now define local variables for the Encrypt/Decrypt functions
		_newLocal	1,srcPtr			;pointer to  input data buffer
		_newLocal	1,dstPtr			;pointer to output data buffer
		_newLocal	1,loopByteCnt		;inner loop byte counter
		_newLocal	1,jmpTabPtr			;pointer to encrypt/decrypt jump table
		_newLocal	8,X_i_0				;local copy of the key values
		_newLocal	8,X_i_1
		_newLocal	4,oldZ				;"old" Z values
		_newLocal	1,_i_				;block number (+8)
		_newLocal	UNROLL_CNT  ,exitTab;local jump table for exiting unrolled loop
		_newLocal	UNROLL_CNT+4,tmpBuf	;local buffer encryption/decryption blocks
		_newLocal	1,aadLeft			;# bytes of aad remaining
		_newLocal	1,msgLen0			;initial value of src_ByteCnt
		_newLocal	1,dstPtr0			;initial dst pointer
		_newLocal	1,retAddr			;local "return" address
;
;----------------------------------------------------------------
; Define caller's parameters on the stack, relative to esp
;
_cpOfs_	=		4+8*4+_Phelix_LocalSize	;caller parms offset from esp
_pOfs_	=		_cpOfs_
;
_newParm macro	_pp_
		irp		_offs_,<%_pOfs_>
_pp_	  equ	<dword ptr [esp + _offs_ + _stack_offs]>
_pp_&_Z4  equ	<dword ptr [Z4  + _offs_ - _cpOfs_]>	;allow "short ofset" access via Z4
		endm
_pOfs_	  =		_pOfs_+4
endm
;
		irp		 _pp_,<ctxt_Ptr,nonce_Ptr,aad_Ptr,aad_Len,src_Ptr,dst_Ptr,src_ByteCnt,mac_Ptr>
		_newParm _pp_
		endm
;
callerParms	equ	<ctxt_Ptr>
;----------------------------------------------------------------
; Phelix context structure definition
pCtxt	STRUCT
  keySize	dd		?			;size of raw key in bits
  macSize	dd		?			;size of mac tag in bits
  X_1_Bump	dd		?			;4*(keySize/8) + 256*(macSize mod 128)
  X_0		dd		8 dup (?)	;subkeys
  X_1		dd		8 dup (?)	;subkeys
	; internal cipher state
  old_Z		dd		4 dup (?)	;previous Z[4] values for output
  _Z_		dd		5 dup (?)	;5 internal state words
  blkNum	dd		?			;block number (i)
  aadLen	dd		2 dup (?)	;64-bit aadLen counter (LSW first)
  msgLen	dd		?			;32-bit msgLen counter (mod 2**32)
  aadXor	dd		?			;aad Xor constant
pCtxt	ENDS
;
;----------------------------------------------------------------
;
_o_		macro	op1,op2,op3,cond3		;shorthand: instantiate 1-3 opcodes
		op1
		op2
	ifb <cond3>
		op3
	elseif cond3
		op3
	endif
endm
;----------------------------------------------------------------
; adjust _stack_offs with push/pop operations
_push	macro	r0,r1,r2,r3,r4,r5,r6
	irp	_reg_,<r0,r1,r2,r3,r4,r5,r6>
	  ifnb <_reg_>
		push	_reg_
		_stack_offs	=	_stack_offs + 4
	  endif
	endm
endm
;
_pop	macro	r0,r1,r2,r3,r4,r5,r6
	irp	_reg_,<r0,r1,r2,r3,r4,r5,r6>
	  ifnb <_reg_>
		pop		_reg_
		_stack_offs	=	_stack_offs - 4
	  endif
	endm
endm
;
;----------------------------------------------------------------
; concatenate text together (useful in building names inside macros)
Concat	macro	aa,bb,cc,dd,ee,ff,gg,hh
aa&bb&cc&dd&ee&ff&gg&hh
endm
;
;----------------------------------------------------------------
; Init code, jump tables (for lblName = Encrypt/Decrypt)
;----------------------------------------------------------------
;
PhelixAlgo macro lblName
		; first, set up the stack frame
		pushad							;save all regs on stack
		lea		t0,lblName&_jmpTab		;handle the encrypt/decrypt difference
		jmp		Phelix_Main				;go run the algorithm
		;
		; the jump table for this operation
		;
		align	4
lblName&_jmpTab label dword
		;first, a list of "block boundary" targets within unrolled processing loop
	_blkNum_ = 0
	rept	UNROLL_CNT	
		Concat	<dd  offset &lblName&Blk_>,%_blkNum_
	_blkNum_ = _blkNum_ + 1
	endm
		; next, successive "control" targets within Phelix_Main
		irp		_targetName_,<OddBytes>
		Concat	&_targetName_,<_OFFS = >,<($-lblName&_jmpTab)>
		Concat	<dd	 offset &lblName>,<_>,&_targetName_
		endm

endm	;PhelixAlso
;
;----------------------------------------------------------------
; Common unrolled loop end code for encrypt/decrypt
;----------------------------------------------------------------
;
PhelixEndLoop macro	CNT
		add		srcPtr	   ,(CNT)*4		;bump the pointers
		add		dstPtr	   ,(CNT)*4
		add		_i_		   ,(CNT)		;bump the count
		sub		loopByteCnt,(CNT)*4		;are we done yet?
endm	;leave here with flags set for loop jmp
;
;----------------------------------------------------------------
; Common "early exit" code for encrypt/decrypt inner loop
;----------------------------------------------------------------
; This functionality is required for splicing AAD/text/padding
;
PhelixEarlyExit macro	jTabReg,_bn_
	if _bn_ lt (UNROLL_CNT-1)			;don't need early exit at bottom of loop
		test jTabReg,jTabReg			;time to exit?
		_if  nz
		  mov oldZ[4*(_bn_ and 3)],oldZreg
		  jmp jTabReg					;go to "exit" address
		  ;align 4						;aligning -- doesn't seem to help!
		_endif
	endif
	mov oldZ[4*(_bn_ and 3)],oldZreg
endm
;
;****************************************************************
; start of actual code (i.e., end of macro definitions)
;****************************************************************
;
		align	4
_PhelixCodeStart_:
INIT_ZEROES	dd		ZERO_INIT_CNT dup (0)
MASK_TAB	dd		0,0ffh,0ffffh,0ffffffh

;
;----------------------------------------------------------------
; Common control path for Encrypt/Decrypt
;----------------------------------------------------------------
; In:	t0 --> (const) jump table (Encrypt_jmpTab or Decrypt_jmpTab)
; Out:	everything done
;
Phelix_Main:
_stack_offs		 = -_Phelix_LocalSize	;stack frame not built yet
		lea		Z4,callerParms			;point to callers first parameter (save code size below)
		sub		esp,_Phelix_LocalSize	;make room for locals on stack
_stack_offs		 =	0					;now at the "base" esp value
		mov		jmpTabPtr,t0			;save jump table pointer
		call	InitNonce
		;
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		; Finally ready to start running Phelix on some data
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		; First, process the initialization zeroes (loopByteCnt == 0 from PhelixInit)
		;
		_ASM_Assert <UNROLL_CNT ge ZERO_INIT_CNT>
		mov		exitTab[4*(ZERO_INIT_CNT-1)],offset _ret_InitZeroDone
		jmp		EncryptBlk_0
		;
		; "local" function
_stack_offs		=	4
InitNonce:
		; first, init the local keys on the stack
		mov		t0,ctxt_Ptr_Z4			;point to context structure
		mov		t1,[t0].pCtxt.X_1_Bump	;t1=4*(keySize/8)+256*(macSize mod 128)
		mov		Z3,nonce_Ptr_Z4			;(const) pointer to nonce words
		_push	Z4						;save Z4  (push/pop = smaller than lea Z4,callerParms)
		xor		Z4,Z4					;use Z4 as the variable i in SetTwoKeys
		inc		Z4						;start with i = 1, since t1 = X'_1 = 4*L(U) already
		call	SetTwoKeys				;set X_1_n, X_5_n, for n=0,1  [return w/t1 == 0]
		call	SetTwoKeys				;set X_2_n, X_6_n, for n=0,1
		call	SetTwoKeys				;set X_3_n, X_7_n, for n=0,1
		xor		Z4,Z4					;wrap to i = 0
		call	SetTwoKeys				;set X_0_n, X_4_n, for n=0,1
		_pop	Z4						;restore pointer to callerParms

		;set up for initialization phase
		xor		Z2,Z2	
		lea		t0,INIT_ZEROES			;use all zero input words, for i= -8 .. -1
		lea		t1,tmpBuf				;discard output
		mov		loopByteCnt,Z2			;initialize loop byte count counter = 0
		mov		_i_,Z2					;initialize i = 0 (block number + 8)
		mov		srcPtr,t0
		mov		dstPtr,t1

		; now initialize the Zn register values
		mov		t0,ctxt_Ptr_Z4
		mov		t1,nonce_Ptr_Z4
		irp		zNum,<0,1,2,3,4>
		  mov	Z&zNum,[t0+4*(3+zNum)].pCtxt.X_0
		endm
		irp		zNum,<0,1,2,3>
		  xor	Z&zNum,[t1+4*zNum]
		endm
		ret
_stack_offs		=	0
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		; done with the initial zeroes.
_ret_InitZeroDone:
	if UNROLL_CNT gt ZERO_INIT_CNT		;do we need to clear out the return point?
		xor		t0,t0					;(only if it's not already at the end)
		mov		exitTab[4*(ZERO_INIT_CNT-1)],t0
	endif
		;;;;;;;;;;;;;;;;;
		; handle AAD here, looping if needed
		xor		Z1,MAGIC_AAD_XOR
		mov		t0,aad_Len
		test	t0,t0
	_if nz,far							;if nothing there, skip all aad processing
		mov		t1,aad_Ptr
		mov		aadLeft,t0
		mov		srcPtr,t1				;src will come from aad_Ptr
_aad_Loop:								;here with t0 == aad_Len
		lea		t1,tmpBuf				;always use tmpBuf for aad dst (discard)
		mov		dstPtr,t1
		mov		t0,aadLeft
		sub		t0,4*UNROLL_CNT			;only do one unrolled loop each time
		_if ae							;(since we use tmpBuf to discard ciphertext)
		  mov	aadLeft,t0
		  xor	t1,t1
		  mov	loopByteCnt,t1
		  mov	exitTab[4*(UNROLL_CNT-1)],offset _aad_Loop
		  jmp	EncryptBlk_0
		_endif
		; here to handle final partial loop
_aad_PartialLoop:
		and		t0,4*(UNROLL_CNT-1)
		mov		loopByteCnt,t0
		cmp		t0,4
		_if ae
		  mov		exitTab[t0-4],offset _ret_aad_1
		  jmp		EncryptBlk_0
		_ret_aad_1:
		  mov		t0,loopByteCnt
		  xor		t1,t1
		  mov		exitTab[t0-4],t1		;clear the entry
		_endif
		; here to handle final partial word of AAD
		mov		t0,aadLeft
		mov		t1,t0
		and		t1,3					;any odd bytes?
		_ifbrk	z						;if not, we're done with AAD
		add		t0,4
		and		t0,4*(UNROLL_CNT-1)
		mov		loopByteCnt,t0
		_push	Z4
		sub		t0,4
		and		t0,4*(UNROLL_CNT-1)
		mov		Z4,srcPtr
		mov		Z4,[Z4+t0]				;get the last AAD word
		and		Z4,MASK_TAB[4*t1]		;clear out extra bits
		lea		t1,tmpBuf
		mov		[t1],Z4
		sub		t1,t0
		mov		dstPtr,t1
		mov		srcPtr,t1
		mov		exitTab[t0],offset _ret_aad_2
		mov		tmpBuf[4],t0			;save this
		_pop	Z4
		jmp		Encrypt_jmpTab[t0]
_ret_aad_2:
		mov		t0,tmpBuf[4]
		xor		t1,t1
		mov		exitTab[t0],t1
	_endif
		xor		Z1,MAGIC_AAD_XOR
		;;;;;;;;;;;;;;;;;
		; process the user data
		_push	Z4						;use Z4 as temp pointer 
		lea		Z4,callerParms			;  (to save code size in accessing caller parms below)
		lea		t0,_ret_MAC0
		mov		retAddr_Z4,t0
		mov		t0,src_Ptr_Z4
		mov		srcPtr,t0
		mov		t1,dst_Ptr_Z4
		mov		t0,src_ByteCnt_Z4
		; enter here from EncryptBytes_ASM
processUserData:
		mov		dstPtr,t1
		mov		dstPtr0_Z4,t1
		mov		msgLen0_Z4,t0
		_pop	Z4						;restore Z4
		mov		t1,loopByteCnt
		and		t1,4*(UNROLL_CNT-1)		;get the loop "phase"
		sub		dstPtr,t1				;adjust pointers accordingly
		sub		srcPtr,t1
		;;;;;;;;;;;;;;;;;
		; now process the bulk of the data in "full" loop chunks (t0 = src_ByteCnt)
		add		t0,t1
		sub		t0,UNROLL_CNT*4			;enough for one "full" loop?
		mov		loopByteCnt,t0			;save the pre-subtracted value for use in the loop
		_if ae	
		  add	t1,jmpTabPtr			;get ready to jump into block processing
		  mov	exitTab[4*(UNROLL_CNT-1)],offset _ret_DataDone1
		  jmp	dword ptr [t1]			;go encrypt or decrypt
_ret_DataDone1:
		  mov	t0,loopByteCnt			;restore t0 = loopByteCnt
		  xor	t1,t1					;starting phase is at ??crypt_0 now
		_endif
		;;;;;;;;;;;;;;;;;
		; now process the remainder of the data, if any (partial loop)
		and		t0,4*(UNROLL_CNT-1)		;compute t0 = end phase
		cmp		t0,t1					;any partial loop to do?
		_if nz
		  mov	loopByteCnt,t0			;make sure that the exit loop test falls thru
		  add	t1,jmpTabPtr			;get ready to jump
		  mov	exitTab[t0-4],offset _ret_DataDone2	;force an exit at the correct point
		  jmp	dword ptr [t1]			
_ret_DataDone2:
		  xor	t1,t1					;t1 = 0
		  mov	t0,loopByteCnt
		  and	t0,4*(UNROLL_CNT-1)		;recompute exitTab index
		  mov	exitTab[t0-4],t1		;clear the exitTab entry
		_endif
		;;;;;;;;;;;;;;;;;
		; special (i.e. UGLY!!) handling when src_ByteCnt isn't a multiple of 4
		; here with t0 = loopByteCnt AND 4*(UNROLL_CNT-1)
		mov		t1,msgLen0				;get original msgLen
		and		t1,3					;any partial words? (hopefully rare)
		_if nz,far
		  mov	exitTab[t0],offset _ret_OddBytes
		  or	t1,t0					;save word index and odd byte count
		  mov	loopByteCnt,t1			;	back into loopByteCnt
		  _push Z4
		  and	t1,3
		  mov	Z4,srcPtr
		  add	Z4,t0
		  _push	t0
		  mov	t1,MASK_TAB[4*t1]		;get the mask bits
		  mov	t0,dword ptr [Z4]		;and get the source word
		  lea	Z4,tmpBuf
		  and	t0,t1					;t0 = masked source word
		  mov	dword ptr [Z4+8],t1		;save the mask bits (for use in Decrypt_OddBytes)
		  mov	dword ptr [Z4  ],t0		;save the masked source word
		  _pop	t0
		  sub	Z4,t0					;adjust src/dst ptrs for hard coded offsets in block code
		  mov	srcPtr,Z4				;set up for "single-word" encrypt in tmpBuf[]
		  add	Z4,4
		  mov	dstPtr,Z4
		  mov	t1,jmpTabPtr			;dispatch to different handler for Encrypt & Decrypt
		  _pop	Z4
		  jmp	dword ptr OddBytes_OFFS[t1]
		  ;
		  ; here to handle the odd-byte encrypt case
Encrypt_OddBytes:
		  jmp	Encrypt_jmpTab[t0]		;go encrypt the single word
		  ;
		  ; here to handle the funky odd-byte decrypt case
Decrypt_OddBytes:
		  ; we have to encrypt halfway thru the block to compute keystream :-((
		  ;		(i.e., in order to produce the "full" ciphertext word)
		  _push Z0,Z1,Z2,Z3,Z4,t0
		  _o_ <add Z0,Z3>,<rol Z3,ROT_3b>,<mov t0,X_i_0[t0]>	;get the key word
		  _o_ <add Z1,Z4>,<rol Z4,ROT_4b>
		  _o_ <xor Z2,Z0>,<rol Z0,ROT_0a>
		  _o_ <xor Z3,Z1>                ,<add t0,Z3>
		  _o_ <add Z4,Z2>,<rol Z2,ROT_2a>,<mov t1,loopByteCnt>
		  
		  _o_ <xor Z0,t0>,<rol Z4,ROT_4a>,<and t1,4*3>
		  _o_ <add Z2,Z0>				 ,<mov t0,oldZ[t1]>
		  _o_ <xor Z4,Z2>
		  add	t0,Z4					;now t0 = keystream
		  mov	t1,tmpBuf[8]			;get the mask word
		  not	t1						;toggle the maskbits
		  and	t1,t0					;mask off unused maskbits
		  xor	tmpBuf,t1				;re-create the "full" ciphertext word @ tmp src buffer
		  _pop	t0,Z4,Z3,Z2,Z1,Z0
		  jmp	Decrypt_jmpTab[t0]		;go decrypt
		  ; "return" here with the dest word computed at [tmpBuf+4]
_ret_OddBytes:
		  _push	Z4,Z0
		  lea	Z4,callerParms
		  xor	t1,t1
		  mov	t0,loopByteCnt
		  and	t0,4*(UNROLL_CNT-1)
		  mov	exitTab[t0],t1			;clear out the exitTab entry we just used
		  mov	t1,msgLen0				;now output just the number of dst bytes specified
		  mov	t0,t1
		  and	t0,3
		  xor	t1,t0					;clear low 2 bits of count
		  add	t1,dstPtr0_Z4			;point to "final" word offset
		  mov	Z0,tmpBuf_Z4[4]			;get the dst output word (short offset)
		  xor	Z0,dword ptr [t1]		;do bit diddling to output just the odd bytes
		  and	Z0,MASK_TAB[4*t0]
		  xor	dword ptr [t1],Z0
		  _pop	Z0,Z4
		_endif
		jmp		retAddr				;"return" to whomever
_ret_MAC0:
		;;;;;;;;;;;;;;;;;
		; here to compute and output/compare the MAC
		mov		t0,mac_Ptr
		xor		Z4,aad_Len
processMAC:
		mov		dstPtr0,t0				;save MAC ptr
		xor		Z0,MAGIC_MAC_XOR		;toggle bits to start the MAC
		_push	Z4
		mov		t0,loopByteCnt
		mov		t1,t0
		add		t0,3					;advance to next full word, if odd bytes
		and		t0,4*(UNROLL_CNT-1)		;t0 = next word "offset" within block
		and		t1,3					;t1 = length of src mod 4 (plaintext for MAC)
		lea		Z4,tmpBuf
_ASM_Assert <UNROLL_CNT ge 8>
_bb_	=	0
	rept 8+4							;8 for padding, 4 for MAC size
		mov		[Z4+_bb_],t1			;fill tmpBuf with L(P) mod 4
_bb_	=	_bb_ + 4
	endm
		lea		t1,[t0+7*4]
		and		t1,4*(UNROLL_CNT-1)		;stop point is after 8 blocks (i+0..i+7)
		mov		exitTab[t1],offset _ret_MAC1
		sub		Z4,t0					;set up source/dest pointers
		mov		srcPtr,Z4
		mov		dstPtr,Z4
		add		t0,8*4-1				;FUNKY wrap logic requires -1
		mov		loopByteCnt,t0
		inc		t0						;undo adjustment
		and		t0,4*(UNROLL_CNT-1)
		_pop	Z4
		jmp		Encrypt_jmpTab[t0]		;go do the encryption
		; just finished eight blocks of "padding" using L(P) mod 4
		; now generate the MAC
_ret_MAC1:
		mov		t0,loopByteCnt
		inc		t0						;undo the -1 above
		and		t0,4*(UNROLL_CNT-1)
		lea		t1,[t0+3*4]				;do four more (0..3 -- stop after #3)
		and		t1,4*(UNROLL_CNT-1)
		mov		exitTab[t1],offset _ret_MAC2
		lea		t1,[t0+4*4-1]			;FUNKY wrap logic requires -1
		mov		loopByteCnt,t1
		jmp		Encrypt_jmpTab[t0]
		;
		; here with the MAC computed. Z0..Z4 now can be trashed
_ret_MAC2:
		lea		Z4,callerParms
		mov		t1,ctxt_Ptr_Z4
		mov		ecx,[t1].pCtxt.macSize	;ecx = # bits in MAC
		mov		edi,dstPtr0_Z4
		lea		esi,tmpBuf[8*4]
		test	ecx,31					;can we do it one word at a time?
		_if z
		  shr	ecx,5					;if so, it's faster
		  rep	movsd
		_else
		  add	ecx,7					;round up to byte boundary
		  shr	ecx,3					;non-word sizes get the slow treatment
		  rep	movsb
		_endif
		;;;;;;;;;;;;;;;;;
		;tear down the stack and return
		add		esp,_Phelix_LocalSize
		popad							;restore all of callers regs
		ret								;and return to caller
;;;;;;;;;;;;;;;;
if 0
PhelixCompareMAC:
		xor		Z0,[t0   ]				;do a comparison
		xor		Z1,[t0+ 4]	  
		xor		Z2,[t0+ 8]	  
		xor		Z3,[t0+12]	  
		mov		t0,ctxt_Ptr
		mov		t0,[t0].pCtxt.macSize
		cmp		t0,127					;are we doing a full MAC?
		_rept be						;if not, we must do some masking
		  mov	t1,1
		  xchg	ecx,t0
		  shl	t1,cl
		  xchg	ecx,t0
		  dec	t1						;t1 = mask bits
		  cmp	t0,96
		  _if ae
		    and	Z3,t1					;here for 96..127 bits
			_brk
		  _endif
		  cmp	t0,64
		  _if ae
		    xor	Z3,Z3					;here for 64..95  bits
			and	Z2,t1
			_brk
		  _endif
		  cmp	t0,32
		  _if ae
		    xor	Z3,Z3					;here for 32..63 bits
			xor	Z2,Z2
			and	Z1,t1
		  _else
		    xor	Z3,Z3					;here for  0..31 bits
			xor	Z2,Z2
			xor	Z1,Z1
			and	Z0,t1
		  _endif
		_until	;;always fall thru here (i.e., _rept == _if here)
		or		Z0,Z1
		or		Z2,Z3
		or		Z0,Z2
endif
;
;----------------------------------------------------------------
; Common subroutine (for use in Phelix_Main) to init subkeys
;----------------------------------------------------------------
; In:	t0		-->	pCtxt (const)	
;		Z3		--> nonce (const)
;		t1		=	X' value for I
;		Z4		=	value of I (0..3)
; Out:	Z4	incremented.  t0, Z3 unmodified
;		t1		= oldZ[I] = 0
;		X_i_0, X_i_1 set on stack for both i=I and i=I+4
;		t1
_stack_offs = 12						;one word on stack before call
SetTwoKeys proc
_ii_	equ		Z4
		mov	Z0,[t0+4*_ii_+4*0].pCtxt.X_0;load two key values
		mov	Z1,[t0+4*_ii_+4*4].pCtxt.X_0
		mov	X_i_0 [4*_ii_+4*0],Z0		;store the X_i_0 values
		mov	X_i_0 [4*_ii_+4*4],Z1
		mov	Z2,[Z3+4*_ii_]				;get Z2 = N_i
		add	Z0,t1						;add in 4*L(U), for _ii_ == 1
		add Z1,t1
		add	Z1,Z2						;add/sub the nonce value
		sub	Z0,Z2
		add	Z0,_ii_
		xor	t1,t1						;set t1 = 0
		mov	X_i_1 [4*_ii_+4*0],Z1		;store the X_i_1 values
		mov	X_i_1 [4*_ii_+4*4],Z0
		mov	oldZ  [4*_ii_],t1			;zero out the oldZ values
	_NN_ =	0
		_ASM_Assert <UNROLL_CNT ge 4>,<exitTab init code>
	rept UNROLL_CNT/4					;init the "block exit" jump table: all zeroes
		mov	exitTab  [4*_ii_+_NN_],t1
	_NN_ =	_NN_ + 16
	endm
		inc	_ii_						;bump the counter for next call
		ret
SetTwoKeys endp
;
_stack_offs = 0							;back to no offset
;
_CommonCodeEnd:
;
;----------------------------------------------------------------
; Encryption routines
;----------------------------------------------------------------
;
		align	4
PhelixEncryptPacket_ASM:
		PhelixAlgo	Encrypt				;instantiate the algorithm ocde
		;
		;the main block processing loop
		;
	_rept
	  _blkNum_		=	0				;compile-time variable
	  rept UNROLL_CNT					;compile-time macro expansion
Concat	EncryptBlk_,%_blkNum_,<:>		;make a label for re-entry points
		_bb_ = _blkNum_ and 7			;support UNROLL_CNT > 8

		_o_ <add Z0,Z3>,<rol Z3,ROT_3b>,<mov t0,X_i_0[4*_bb_]>
		_o_ <add Z1,Z4>,<rol Z4,ROT_4b>
		_o_ <xor Z2,Z0>,<rol Z0,ROT_0a>,<mov t1,srcPtr>
		_o_ <xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,Z3>		;does LEA opcode help here?
		_o_ <add Z4,Z2>,<rol Z2,ROT_2a>

		_o_ <xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,[t1+4*_bb_]>	;t0 = plaintext
		_o_ <xor Z1,Z4>,<rol Z4,ROT_4a>,<mov t1,oldZ[4*(_bb_ and 3)]>
		_o_ <add Z2,Z0>,<rol Z0,ROT_0b>
		_o_ <add Z3,Z1>,<rol Z1,ROT_1b>,<xor t0,Z3>
		_o_ <xor Z4,Z2>,<rol Z2,ROT_2b>

		add t1,Z4						;now t1 = keystream
		xor	t1,Z3						;set up to compute t1 = ciphertext below

		_o_ <add Z0,t0>,<rol Z3,ROT_3b>,<xor t1,t0>			;now t1 = ciphertext
		_o_ <add Z1,Z4>,<rol Z4,ROT_4b>,<mov t0,X_i_1[4*_bb_]>
		_o_ <xor Z2,Z0>,<rol Z0,ROT_0a>
		_o_ <xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,_i_>
		_o_ <add Z4,Z2>,<rol Z2,ROT_2a>,<lea t0,[t0+Z3+_bb_]>

		_o_ <xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,dstPtr>
		_o_ <xor Z1,Z4>,<rol Z4,ROT_4a>
		_o_ <add Z2,Z0>,<rol Z0,ROT_0b>,<mov [t0+4*_bb_],t1>	;save ciphertext
		_o_ <add Z3,Z1>,<rol Z1,ROT_1b>,<mov t1,exitTab[4*_blkNum_]>;?<_blkNum_ lt (UNROLL_CNT-1)>
		_o_ <xor Z4,Z2>,<rol Z2,ROT_2b>
		
		PhelixEarlyExit t1,_blkNum_		;do we need to do an early exit? If so, do it

	  _blkNum_		=  _blkNum_+1		;update compile-time variable
      endm								;end (compile-time) rept above
		PhelixEndLoop	UNROLL_CNT		;set condition code for _until below
	_until b
		jmp		exitTab[4*(UNROLL_CNT-1)]	;"return" to do more
;
;----------------------------------------------------------------
; Decryption routine
;----------------------------------------------------------------
;
		align	4
PhelixDecryptPacket_ASM:	;proc
		PhelixAlgo	Decrypt				;instantiate the algorithm ocde
		;
		;the main block processing loop
		;
	_rept
	  _blkNum_		=	0				;compile-time variable
	  rept UNROLL_CNT					;compile-time macro expansion
Concat	DecryptBlk_,%_blkNum_,<:>		;make a label for re-entry points
		_bb_ = _blkNum_ and 7			;support UNROLL_CNT > 8
		_o_ <add Z0,Z3>,<rol Z3,ROT_3b>,<mov t0,X_i_0[4*_bb_]>
		_o_ <add Z1,Z4>,<rol Z4,ROT_4b>
		_o_ <xor Z2,Z0>,<rol Z0,ROT_0a>,<mov t1,srcPtr>
		_o_ <xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,Z3>
		_o_ <add Z4,Z2>,<rol Z2,ROT_2a>

		_o_ <xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,[t1+4*_bb_]>	;t0 = ciphertext
		_o_ <xor Z1,Z4>,<rol Z4,ROT_4a>,<mov t1,oldZ[4*(_bb_ and 3)]>
		_o_ <add Z2,Z0>,<rol Z0,ROT_0b>
		_o_ <add Z3,Z1>,<rol Z1,ROT_1b>
		_o_ <xor Z4,Z2>,<rol Z2,ROT_2b>

		add t1,Z4						;set t1 = keystream
		xor t1,t0						;now t1 = plaintext
		mov	t0,Z3
		xor	t0,t1						;now t0 = plaintext ^ z3

		_o_ <add Z0,t0>,<rol Z3,ROT_3b>
		_o_ <add Z1,Z4>,<rol Z4,ROT_4b>,<mov t0,X_i_1[4*_bb_]>
		_o_ <xor Z2,Z0>,<rol Z0,ROT_0a>
		_o_ <xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,_i_>
		_o_ <add Z4,Z2>,<rol Z2,ROT_2a>,<lea t0,[t0+Z3+_bb_]>

		_o_ <xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,dstPtr>
		_o_ <xor Z1,Z4>,<rol Z4,ROT_4a>
		_o_ <add Z2,Z0>,<rol Z0,ROT_0b>,<mov [t0+4*_bb_],t1>	;save plaintext computed above
		_o_ <add Z3,Z1>,<rol Z1,ROT_1b>,<mov t1,exitTab[4*_blkNum_]>;?<_blkNum_ lt (UNROLL_CNT-1)>
		_o_ <xor Z4,Z2>,<rol Z2,ROT_2b>

		PhelixEarlyExit t1,_blkNum_		;do we need to do an early exit? If so, do it

	  _blkNum_		=  _blkNum_+1		;update compile-time variable
      endm								;end (compile-time) rept above
		PhelixEndLoop	UNROLL_CNT		;set condition code for _until below
	_until b
		jmp		exitTab[4*(UNROLL_CNT-1)]	;"return" to do more

_PhelixCodeEnd_:

ifdef PHELIX_INCREMENTAL_API
;
;----------------------------------------------------------------
; "Incremental" function: SetupNonce
;----------------------------------------------------------------
;	use same stack as EncryptPacket_ASM!
;
PhelixSetupNonce_ASM	proc
		pushad	
_stack_offs		 = -_Phelix_LocalSize	;stack frame not built yet
		lea		Z4,callerParms
		sub		esp,_Phelix_LocalSize
_stack_offs			=	0
		call	InitNonce
		_ASM_Assert <UNROLL_CNT ge ZERO_INIT_CNT>
		mov		exitTab[4*(ZERO_INIT_CNT-1)],offset _ret_SetupNonceDone
		jmp		EncryptBlk_0
_ret_SetupNonceDone:
	if UNROLL_CNT gt ZERO_INIT_CNT		;do we need to clear out the return point?
		error	<Replicate code here from _ret_InitZeroDone>
	endif
		mov		t0,ctxt_Ptr				;save our context
		;
		mov		t1,MAGIC_AAD_XOR
		xor		Z1,t1
		mov		[t0    ].pCtxt.aadXor,t1
		;
		mov		[t0+4*0].pCtxt._Z_,Z0
		mov		[t0+4*1].pCtxt._Z_,Z1
		mov		[t0+4*2].pCtxt._Z_,Z2
		mov		[t0+4*3].pCtxt._Z_,Z3
		mov		[t0+4*4].pCtxt._Z_,Z4

		irp		_nn_,<0,1,2,3>
		  mov	Z0,X_i_1[8*_nn_  ]
		  mov	Z1,X_i_1[8*_nn_+4]
		  mov	Z2,oldZ [4*_nn_]
		  mov	[t0+8*_nn_  ].pCtxt.X_1,Z0
		  mov	[t0+8*_nn_+4].pCtxt.X_1,Z1
		  mov	[t0+4*_nn_  ].pCtxt.old_Z,Z2
		endm
		;
		xor		t1,t1
		mov		[t0  ].pCtxt.msgLen,t1
		mov		[t0  ].pCtxt.aadLen,t1
		mov		[t0+4].pCtxt.aadLen,t1
		mov		t1,_i_
		mov		[t0  ].pCtxt.blkNum,t1
		;
		add		esp,_Phelix_LocalSize
		popad
		ret
PhelixSetupNonce_ASM	endp

;
;----------------------------------------------------------------
; "Incremental" function: EncryptBytes/DecryptBytes
;----------------------------------------------------------------
;	use same locals stack as EncryptPacket_ASM
;
_pOfs_	=		_cpOfs_
;
		irp		 _pp,<ctxt_Ptr,src_Ptr,dst_Ptr,bCnt>
		_newParm _pp 
		endm
PhelixEncryptBytes_ASM	proc
		pushad	
		lea		t0,Encrypt_jmpTab
PhelixBytes:
_stack_offs		 = -_Phelix_LocalSize	;stack frame not built yet
		lea		Z4,callerParms
		sub		esp,_Phelix_LocalSize
_stack_offs			=	0
		;
		mov		jmpTabPtr,t0
		; copy context to local on stack
		mov		t0,ctxt_Ptr_Z4
		_push	Z4
		lea		esi,[t0].pCtxt.X_0
		lea		edi,X_i_0
		mov		ecx,8+8+4			;X_0, X_1, and oldZ
		cld
		rep		movsd				;copy the context
		xor		eax,eax
		mov		ecx,UNROLL_CNT		;zero out exitTab
		rep		stosd
		_pop	Z4
		lea		t0,_ret_PhelixBytes
		mov		retAddr_Z4,t0		;set up return address
		mov		t0,src_Ptr_Z4		;copy srcPtr and dstPtr
		mov		srcPtr,t0
		mov		t0,dst_Ptr_Z4
		mov		dstPtr,t0
		mov		t0,ctxt_Ptr_Z4
		mov		t1,[t0].pCtxt.blkNum;convert blkNum from pCtxt to locals
		and		t1,NOT (UNROLL_CNT-1)
		mov		_i_,t1
		mov		t1,[t0].pCtxt.blkNum
		shl		t1,2				;convert blkNum to a word count
		mov		loopByteCnt,t1		;and save it as the "phase"
		irp		_zn_,<0,1,2,3,4>	;load the Z values
		  mov Z&_zn_,[t0+4*_zn_].pCtxt._Z_
		endm
		xor		Z1,[t0].pCtxt.aadXor
		mov		[t0].pCtxt.aadXor,0

		_push	Z4
		lea		Z4,callerParms
		mov		t0,src_Ptr_Z4
		mov		srcPtr,t0
		mov		t0,bCnt_Z4
		mov		t1,dst_Ptr_Z4
		jmp		processUserData
		_pop	Z4
_ret_PhelixBytes:

		; copy modified value back to context
		mov		t0,ctxt_Ptr
		irp		_zn_,<0,1,2,3,4>	;store the Z values
		  mov	[t0+4*_zn_].pCtxt._Z_,Z&_zn_
		endm

		mov		t1,msgLen0				;update pCtxt.blkNum
		mov		Z4,t1
		add		t1,3
		shr		t1,2
		add		[t0].pCtxt.blkNum,t1
		add		[t0].pCtxt.msgLen,Z4	;track low 2 bits of msgLen

		lea		edi,[t0].pCtxt.old_Z
		lea		esi,oldZ
		mov		ecx,4					;copy back the updated oldZ values
		rep		movsd

		add		esp,_Phelix_LocalSize
		popad
		ret
		;
		; handle decryption here
PhelixDecryptBytes_ASM::
		pushad
		lea		t0,Decrypt_jmpTab
		jmp		PhelixBytes
PhelixEncryptBytes_ASM	endp
;
;----------------------------------------------------------------
; "Incremental" function: Finalize (MAC)
;----------------------------------------------------------------
;	use same locals stack as EncryptPacket_ASM
;
_pOfs_	=		_cpOfs_
;
		irp		 _pp,<ctxt_Ptr,mac_Ptr>
		_newParm _pp 
		endm
PhelixFinalize_ASM	proc
		pushad	
_stack_offs		 = -_Phelix_LocalSize	;stack frame not built yet
		lea		Z4,callerParms
		sub		esp,_Phelix_LocalSize
_stack_offs			=	0
		lea		t0,Encrypt_jmpTab
		mov		jmpTabPtr,t0

		; copy context to local on stack
		mov		t0,ctxt_Ptr_Z4
		_push	Z4
		lea		esi,[t0].pCtxt.X_0
		lea		edi,X_i_0
		mov		ecx,8+8+4			;X_0, X_1, and oldZ
		cld
		rep		movsd				;copy the context
		xor		eax,eax
		mov		ecx,UNROLL_CNT		;zero out exitTab
		rep		stosd
		_pop	Z4

		mov		t0,ctxt_Ptr_Z4
		mov		t1,[t0].pCtxt.blkNum;convert blkNum from pCtxt to locals
		and		t1,NOT (UNROLL_CNT-1)
		mov		_i_,t1

		mov		Z0,[t0].pCtxt.msgLen
		sub		Z0,4
		neg		Z0
		and		Z0,3				;track the low 2 bits of msgLen
		
		mov		t1,[t0].pCtxt.blkNum
		shl		t1,2				;convert blkNum to a word count
		sub		t1,Z0
		mov		loopByteCnt,t1		;and save it as the "phase"
		irp		_zn_,<0,1,2,3,4>	;load the Z values
		  mov Z&_zn_,[t0+4*_zn_].pCtxt._Z_
		endm

		xor		Z1,[t0  ].pCtxt.aadXor
		xor		Z4,[t0  ].pCtxt.aadLen
		xor		Z2,[t0+4].pCtxt.aadLen
		mov		t0,mac_Ptr
		jmp		processMAC
PhelixFinalize_ASM	endp
;
;
;----------------------------------------------------------------
; "Incremental" function: ProcessAAD
;----------------------------------------------------------------
_Phelix_LocalSize	=	0
		_newLocal	1,aad_I
		_newLocal	1,aad_bb
		_newLocal	1,aad_tmp
;
_cpOfs_	=		4+8*4+_Phelix_LocalSize	;caller parms offset from esp
_pOfs_	=		_cpOfs_
;
		irp		 _pp,<ctxt_Ptr,aad_Ptr,aad_Len>
		_newParm _pp
		endm
;
PhelixProcessAAD_ASM	proc
		pushad	
		sub		esp,_Phelix_LocalSize
_stack_offs			=	0
		mov		t0,ctxt_Ptr			;point to context
		mov		t1,aad_Len
		add		[t0   ].pCtxt.aadLen,t1
		adc		[t0+4 ].pCtxt.aadLen,0
		mov		t1,[t0].pCtxt.blkNum
		mov		aad_I,t1
		irp		_zn_,<0,1,2,3,4>	;load the Z values
		  mov Z&_zn_,[t0+4*_zn_].pCtxt._Z_
		endm
		
		sub		aad_Len,4			;are we done yet?
		_rept ae,far
aad_Again:mov	t1,aad_I
		  and	t1,7
		  mov	t0,ctxt_Ptr
		  _o_	<add Z0,Z3>,<rol Z3,ROT_3b>,<mov t0,[t0+4*t1].pCtxt.X_0>
		  _o_	<add Z1,Z4>,<rol Z4,ROT_4b>,<mov aad_bb,t1>
		  _o_	<xor Z2,Z0>,<rol Z0,ROT_0a>,<mov t1,aad_Ptr>
		  _o_	<xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,Z3>		
		  _o_	<add Z4,Z2>,<rol Z2,ROT_2a>

		  _o_	<xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,[t1]>		;t0 = AAD plaintext
		  _o_	<xor Z1,Z4>,<rol Z4,ROT_4a>,<add t1,4>
		  _o_	<add Z2,Z0>,<rol Z0,ROT_0b>,<mov aad_Ptr,t1>
		  _o_	<add Z3,Z1>,<rol Z1,ROT_1b>,<xor t0,Z3>
		  _o_	<xor Z4,Z2>,<rol Z2,ROT_2b>,<mov t1,aad_bb>

		  _o_	<add Z0,t0>,<rol Z3,ROT_3b>,<mov t0,ctxt_Ptr>
		  _o_	<add Z1,Z4>,<rol Z4,ROT_4b>,<mov t0,[t0+4*t1].pCtxt.X_1>
		  _o_	<xor Z2,Z0>,<rol Z0,ROT_0a>
		  _o_	<xor Z3,Z1>,<rol Z1,ROT_1a>,<add t0,aad_I>
		  _o_	<add Z4,Z2>,<rol Z2,ROT_2a>,<add t0,Z3>

		  _o_	<xor Z0,t0>,<rol Z3,ROT_3a>,<mov t0,ctxt_Ptr>
		  _o_	<xor Z1,Z4>,<rol Z4,ROT_4a>,<and t1,3>
		  _o_	<add Z2,Z0>,<rol Z0,ROT_0b>,<inc aad_I>
		  _o_	<add Z3,Z1>,<rol Z1,ROT_1b>
		  _o_	<xor Z4,Z2>,<rol Z2,ROT_2b>,<mov [t0+4*t1].pCtxt.old_Z,oldZreg>
		  sub	aad_Len,4			;are we done yet?
		_until	b
		; note t0 == ctxt_Ptr here
		mov		t1,aad_Len			;at this point, -4 <= aad_Len < 0
		and		t1,3				;any odd bytes left?
		_if z						;if not, we're done
		  mov	t1,aad_I			;copy back the updated blkNum 
		  mov	[t0].pCtxt.blkNum,t1
		  irp	_zn_,<0,1,2,3,4>	;save the Z values
		    mov	[t0+4*_zn_].pCtxt._Z_,Z&_zn_
		  endm
		  ; clean up the stack and return
		  add	esp,_Phelix_LocalSize
		  popad
		  ret
		_endif
		; here to handle odd AAD bytes
		mov		t0,aad_Ptr			;get the final partial word
		mov		t0,[t0]
		and		t0,MASK_TAB[4*t1]	;mask off unused bits
		lea		t1,aad_tmp
		mov		aad_Ptr,t1			;point aad_Ptr to aad_Tmp
		mov		[t1],t0				;store zero-padded word there
		xor		t0,t0				;fix up the count to not come here again
		mov		aad_Len,t0
		jmp		aad_Again
PhelixProcessAAD_ASM	endp

;
;----------------------------------------------------------------
; "Incremental" function: SetupKey
;----------------------------------------------------------------
;
_Phelix_LocalSize	=	0
		_newLocal	1,sk_Z4
		_newLocal	1,sk_Cnt
;
_cpOfs_	=		4+8*4+_Phelix_LocalSize	;caller parms offset from esp
_pOfs_	=		_cpOfs_
;
		irp		 _pp,<ctxt_Ptr,key_Ptr,key_Size,iv_Size,mac_Size>
		_newParm _pp
		endm
;
PhelixSetupKey_ASM proc
		pushad	
		sub		esp,_Phelix_LocalSize
_stack_offs			=	0
	; assert(PHELIX_NONCE_SIZE==ivSize);/* Phelix only supports "full" nonces	*/
	; assert( 0  == (keySize%8));		/* Phelix only supports byte-sized keys	*/
	; assert(256 >=  keySize);			/* Phelix only supports keys <= 256 bits*/
		mov		t0,ctxt_Ptr				;point to the context to be built
		mov		Z0,key_Size				;copy keySize
		mov		[t0].pCtxt.keySize,Z0
		mov		Z1,mac_Size				;and macSize
		mov		[t0].pCtxt.macSize,Z1
		and		Z1,127					;and compute X1_Bump
		shl		Z1,8
		shr		Z0,1					;Z0 = keySize/2 (in bits)
		add		Z1,Z0
		mov		[t0].pCtxt.X_1_Bump,Z1	;then store it
		shr		Z0,2					;Z0 = keySize/8 (# bytes of key)
		; now copy in the key bits
		mov		t1,key_Ptr
		xor		Z1,Z1					;Z1 = counter
		_rept
		  cmp	Z1,Z0					;is this full word part of the key?
		  _brk	ae						;if not, go handle partial word (if any)
		  mov	Z2,[t1+Z1]				;else get next full word of key
		  mov	[t0+Z1].pCtxt.X_0,Z2	;and copy it to context
		  add	Z1,4					;bump counter
		_endr							;go back for more
		test	Z0,3					;if any partial words, handle that here
		_if	nz
		  mov	Z4,Z0
		  and	Z4,3					;Z4 = (keySize/8) mod 4
		  mov	Z2,MASK_TAB[4*Z4]		;mask off "unused" bits
		  and	[t0+Z1-4].pCtxt.X_0,Z2
		_endif
		xor		Z2,Z2					;zero out the rest of the context key
		_rept
		  cmp	Z1,8*4					;are we done yet?
		  _brk	ae
		  mov	[t0+Z1].pCtxt.X_0,Z2	;zero context key
		  add	Z1,4
		_endr
		; now run the Feistel network for initial key mixing
		add		Z0,64
		mov		sk_Z4,Z0				;precompute L(U)+64 "constant" for mixing
		mov		sk_Cnt,128				;use this as a counter
		_rept
		  mov	t1,sk_Cnt
		  and	t1,16					;isolate one bit
		  mov	Z0,[t0+t1   ].pCtxt.X_0
		  mov	Z1,[t0+t1+ 4].pCtxt.X_0
		  mov	Z2,[t0+t1+ 8].pCtxt.X_0
		  mov	Z3,[t0+t1+12].pCtxt.X_0
		  mov	Z4,sk_Z4
		  rept 2
		    _o_ <add Z0,Z3>,<rol Z3,ROT_3b>
			_o_ <add Z1,Z4>,<rol Z4,ROT_4b>
			_o_ <xor Z2,Z0>,<rol Z0,ROT_0a>
			_o_ <xor Z3,Z1>,<rol Z1,ROT_1a>
			_o_ <add Z4,Z2>,<rol Z2,ROT_2a>
	  
			_o_ <xor Z0,Z3>,<rol Z3,ROT_3a>
			_o_ <xor Z1,Z4>,<rol Z4,ROT_4a>
			_o_ <add Z2,Z0>,<rol Z0,ROT_0b>
			_o_ <add Z3,Z1>,<rol Z1,ROT_1b>
			_o_ <xor Z4,Z2>,<rol Z2,ROT_2b>
		  endm
		  xor	t1,16					;go to other half
		  xor	[t0+t1   ].pCtxt.X_0,Z0	;perform the Feistel xor
		  xor	[t0+t1+ 4].pCtxt.X_0,Z1
		  xor	[t0+t1+ 8].pCtxt.X_0,Z2
		  xor	[t0+t1+12].pCtxt.X_0,Z3
		  sub	sk_Cnt,16
		_until be
		;
		add		esp,_Phelix_LocalSize
		popad
		ret
PhelixSetupKey_ASM endp
;
;----------------------------------------------------------------
;
PhelixIncrementalCodeSize_ASM proc	
		mov		eax,($-offset _PhelixCodeStart_)
		ret
PhelixIncrementalCodeSize_ASM endp	
;
endif ; _INCREMENTAL_API
;
;----------------------------------------------------------------
; use this NOP routine to calibrate/check our timing tests
;----------------------------------------------------------------
;
PhelixNop_ASM proc
		pushad
		popad
		ret
PhelixNop_ASM endp
;
;----------------------------------------------------------------
; size statistics at compile time
;----------------------------------------------------------------
;
PhelixCodeSize_ASM proc	
		mov		eax,(offset _PhelixCodeEnd_-_PhelixCodeStart_)
		ret
PhelixCodeSize_ASM endp	

		irp	_cSize_,<%($-_PhelixCodeStart_)>
		irp	_lSize_,<%_maxPhelixStack_>
		irp	_uu_,<%UNROLL_CNT>
%out	+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
%out	Phelix ASM:  Total code = _cSize_ bytes.  Locals = _lSize_ bytes on stack.  UNROLL_CNT = _uu_
%out	+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		endm
		endm
		endm
	end
