;-----------------------------------------------------------------------------
;	STRUCMAC.INC
;
; This is a set of macros that allow structured programming constructs
; for the x86 instruction set. Works for Borland TASM32 and Microsoft ML
;
; Programming Constructs:
;----------------------------------------------------------------
; LOOPS: // how to use them
;----------------------------------------------------------------
;	_rept		[cnd]		;repeat, if [cnd] is true (blank --> TRUE)
;	[_reptStart:]			;virtual label
;	  ...
;	  _break	[cnd]		;exit the break loop if [cnd] is true
;	  ...
;	  _begin	[cnd]		;continue from _reptStart if [cnd] is true
;	  ...
;	_endr					;back to _reptStart (always)
;   ;OR
;	_until		[cnd]		;back to _reptStart if [cnd] is true
;
;----------------------------------------------------------------
; CONDITIONALS: // how to use them
;----------------------------------------------------------------
;	_if			[cnd]
;	  ...
;	  _ifbrk	[cnd]		;exit IF when cnd is true
;	  ...		
;	  _elbrk	[cnd]		;enter else clause when cnd is true
;	  ...
;	_else		[cnd]		;else clause. If [cnd] false, fall thru into else
;	  ...		
;	  _ifbrk	[cnd]		;exit IF when cnd is true
;	  ...		
;	_endif				;end of if statemment		
;
;-----------------------------------------------------------------------------
; Note: the _break, _ifbrk, and _elbrk take an optional second parmeter, after
;		the <cnd> parm, indicating how many levels to break out of. The default
;		value is 0, and a value of 1 means to break out of the surrounding level
;		(not the current level). A value of 2 means to break out of the second
;		surrounding level, etc.
;-----------------------------------------------------------------------------
;
jnna		equ	ja
jnnbe		equ	jbe
jnnae		equ	jae
jnnb		equ	jb
jnnc		equ	jc
jnne		equ	je
jnnz		equ	jz
jnng		equ	jg
jnnle		equ	jle
jnnge		equ	jge
jnnl		equ	jl
jnno		equ	jo
jnns		equ	js
jnnp		equ	jp
jnpe		equ	jpo
jnpo		equ	jpe
j			equ	jmp
jncxnz		equ	jcxz
jnecxnz		equ	<jecxz>
;
jn	macro	target
	;do nothing
endm
;
__sLabel macro	lName,aa,bb,cc,dd,ee
lName&aa&bb&cc&dd&ee:	
endm
;
__concat macro aa,bb,cc,dd,ee,ff,gg,hh
aa&bb&cc&dd&ee&ff&gg&hh
endm
;
;----------------------------------------------------------------
; general jump macro (show pseudocode as a comment)
_j_op	macro	opStr,target,jType,pCode1,pCode2,pCode3
  ifb <jType>				; short jump?
	opStr	short target	; &pCode1 &pCode2 &pCode3
  else
	opStr	      target	; &pCode1 &pCode2 &pCode3
  endif
endm
;
;----------------------------------------------------------------
; Assembly-time variables
;
__rpCnt		=	0	;total count of "_rept" blocks
__rpLvl		=	0	;current "_rept" level
__ifCnt		=	0	;total count of "_if" blocks
__ifLvl		=	0	;current "_if" level
;
;----------------------------------------------------------------
;	loop macros
;----------------------------------------------------------------
_rept	macro	cnd,jType	;start a loop block
__rpCnt	=	__rpCnt+1	;unique repeat block number
__rpLvl	=	__rpLvl+1	;current "stack" level
__concat __rpBlk_lvl_,%__rpLvl,< = >,%__rpCnt	;define the if block number for this level
__concat  <_j_op jn>,&cnd,<,__endr_>,%__rpCnt,<,&jType,_rept,&cnd>
__sLabel __rept_,%__rpCnt			;mark the start label
endm	;_rept
;----------------------------------------------------------------
_endr	macro			;back to beginning of loop block
__concat <__ry = __rpBlk_lvl_>,%__rpLvl	;find the start label number
__concat <_j_op jmp,__rept_>,%__ry,<,1,_endr>
__sLabel __endr_,%__ry			;output the end label
__rpLvl	=	__rpLvl-1
endm	;endr
;----------------------------------------------------------------
_until	macro	cnd		;conditional loop restart
__concat <__ry = __rpBlk_lvl_>,%__rpLvl	;find the start label number
__concat <_j_op jn>,&cnd,<,__rept_>,%__ry,<,1,_until,cnd>	;generate the jump back
__sLabel __endr_,%__ry			;output the end label
__rpLvl	=	__rpLvl-1
endm	;until
;----------------------------------------------------------------
_begin	macro	cnd,lvl		;loop restart (like C "continue")
__rx = __rpLvl - 0&lvl
__concat <__ry = __rpBlk_lvl_>,%__rx		;find the start label number
__concat <_j_op j&cnd,__rept_>,%__ry,<,1,_begin,&cnd,&lvl>
endm	;begin
;----------------------------------------------------------------
_break	macro	cnd,lvl,jType	;exit loop (like C "break")
__rx = __rpLvl - 0&lvl
__concat <__ry = __rpBlk_lvl_>,%__rx		;find the start label number
__concat <_j_op j&cnd,__endr_>,%__ry,<,&jType,_break,&cnd,&lvl>
endm	;break

_brk	equ		_break			;shorthand
;----------------------------------------------------------------
;	if/else macros
;----------------------------------------------------------------
_if	macro	cnd,jType								;start of conditional
__ifCnt	=	__ifCnt+1								;unique if block number
__ifLvl	=	__ifLvl+1								;current "stack" level
__concat <__ifblk_lvl_>,%__ifLvl,< = __ifCnt>		;define the if block number for this level
__concat <__got_else__>,%__ifLvl,< = 0>				;no else clause (yet)
__concat <_j_op jn&cnd,__else_>,%__ifCnt,<,&jType,_if,&cnd>	;insert the jump
endm	;if
;----------------------------------------------------------------
_else	macro	cnd,jType	;else clause. Fall thru if cnd is false
__concat <__got_else__>,%__ifLvl,< = 1>				;got an else clause now
__concat <__iy = __ifblk_lvl_>,%__ifLvl
__concat <_j_op j&cnd,__endif_>,%__iy,<,&jType,_else,&cnd>
__sLabel __else_,%__iy								;output the else label
endm	;else
;----------------------------------------------------------------
_endif	macro										;end of conditional
__concat <__ix = __got_else__>,%__ifLvl
__concat <__iy = __ifblk_lvl_>,%__ifLvl
  ife __ix
__sLabel  __else_,%__iy								;if no else clause, insert it here
  endif
__sLabel __endif_,%__iy								;put out the end label
__ifLvl	=	__ifLvl-1
endm	;endif
;----------------------------------------------------------------
_ifbrk	macro	cnd,lvl,jType	;exit conditional if cnd is true (or blank)
__ix		 = __ifLvl - 0&lvl						;adjust level, ifnb <lvl>
__concat <__iy = __ifblk_lvl_>,%__ix
__concat <_j_op j&cnd,__endif_>,%__iy,<,&jType,_ifbrk,&cnd,&lvl>
endm	;ifbrk
;----------------------------------------------------------------
_elbrk	macro	cnd,lvl,jType	;"break" to else clause if cnd is true
__ix		 = __ifLvl - 0&lvl							;adjust level, ifnb <lvl>
__concat <__iy = __ifblk_lvl_>,%__ix
__concat <_j_op j&cnd,__else_>,%__iy,<,&jType,_elbrk,&cnd,&lvl>
endm	;elbrk
;
;----------------------------------------------------------------
; pseudo-instructions (assemble-time)
;----------------------------------------------------------------
;
_ASM_Assert macro	cnd,msg
	if (cnd)
		;; all is well
	else
	  ifb <msg>
		.err "ASSERTION FAILURE:  cnd"
	  else
		.err "ASSERTION FAILURE:  cnd (&msg)"
	  endif
	endif
endm
;
;----------------------------------------------------------------
; pseudo-instructions (run-time)
;----------------------------------------------------------------
;
_assert	macro	cnd		;just hang if cnd not true
  ifdef __DEBUG__
    if  __DEBUG__
;	_j_op	jn&cnd,$
      _if cnd
      _else
        int 3
      _endif
    endif
  endif
endm

_trap	macro	cnd		;just hang if cnd true
  ifdef __DEBUG__
    if  __DEBUG__
;	_j_op	j&cnd,$
      _if cnd
	int 3
      _endif
    endif
  endif
endm
;
;----------------------------------------------------------------
; Assembler-specific macros
;----------------------------------------------------------------
;
_ASM_MASM_	equ		1
_ASM_TASM_	equ		2

  ifdef ??version
_ASM_NAME_	equ	_ASM_TASM_
_IS_TASM_	equ	1
  else
_ASM_NAME_	=	_ASM_MASM_
_IS_TASM_	equ	0
  endif

;
; MASM doesn't support tab size setting, but TASM does
;
Tab_Size	macro	n
  if _IS_TASM_
	%tabsize	n
  endif
endm
;
;-----------------------------------------------------------------------------
;	End of STRUCMAC.INC.
;-----------------------------------------------------------------------------
