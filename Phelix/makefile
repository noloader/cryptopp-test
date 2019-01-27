#
# Phelix makefile
#

!if defined(ECRYPT_API) || defined(ECRYPT)
_DEFINES_	=	-DECRYPT_API
_CIPHER_	=	"ECRYPT-Phelix"
_TASMDEF_	=	-TDECRYPT_API		# pass along the switch to assembler
_MASMDEF_	=	-DECRYPT_API
!else			# default is non-ECRYPT
_DEFINES_	=	
_CIPHER_	=	"Phelix"
_TASMDEF_	=
_MASMDEF_	=
!endif

C_FILES		=	testPhelix.c phelix.c
RUN_TEST	=	testPhelix.exe
GCC_32		=	\dos\MinGW32\bin\gcc
GCC_342		=	\dos\MinGW342\bin\gcc

BCC_OPT		=	-q -B -v -w-8057 -M -g1 $(_TASMDEF_) -Tm2 -Tt -Tl 
GCC_OPT		=	-O3 -Werror -Wall
MSC_OPT		=	/WX /W4 /G5 /Zi
MASM_OPT	=	/coff /c /Fl $(_MASMDEF_)

#++++++++++++++++++++++++++ Borland C++ compiler
bcc32:	$(C_FILES) pHelix86.asm
	bcc32  $(BCC_OPT) $(_DEFINES_) $(C_FILES) pHelix86.asm 
	$(RUN_TEST)

#++++++++++++++++++++++++++ gcc (MingW)
gcc320:	$(C_FILES) 
	$(GCC_32)  $(GCC_OPT) $(_DEFINES_) $(C_FILES)  -o testPhelix.exe 
	$(RUN_TEST)

#++++++++++++++++++++++++++ gcc342 (MingW)
gcc342:	$(C_FILES) 
	$(GCC_342) $(GCC_OPT)  $(_DEFINES_) $(C_FILES)  -o testPhelix.exe
	$(RUN_TEST)

#++++++++++++++++++++++++++ msvc42
msvc42:	$(C_FILES) 
	ml $(MASM_OPT) pHelix86.asm
	if exist testPhelix.pdb del testPhelix.pdb
	msvc42.bat $(MSC_OPT) $(_DEFINES_) $(C_FILES) pHelix86.obj
	$(RUN_TEST) 

#++++++++++++++++++++++++++ msvc60
msvc60:	$(C_FILES) 
	ml $(MASM_OPT) pHelix86.asm
	if exist testPhelix.pdb del testPhelix.pdb
	msvc60.bat $(MSC_OPT) $(_DEFINES_) $(C_FILES) pHelix86.obj
	$(RUN_TEST) 

#++++++++++++++++++++++++++ check ANSI C compliance (no timer code)
ansi:
	$(GCC_32)  -ansi -D_ANSI_CHK $(GCC_OPT)	$(_DEFINES_) -pedantic $(C_FILES) -o testPhelix.exe
	$(RUN_TEST)
	$(GCC_342) -ansi -D_ANSI_CHK $(GCC_OPT)	$(_DEFINES_) -pedantic $(C_FILES) -o testPhelix.exe
	$(RUN_TEST)
	if exist testPhelix.pdb del testPhelix.pdb
	msvc42.bat /Za   -D_ANSI_CHK $(MSC_OPT)	$(_DEFINES_) $(C_FILES) 
	$(RUN_TEST)
	if exist testPhelix.pdb del testPhelix.pdb
	msvc60.bat /Za   -D_ANSI_CHK $(MSC_OPT)	$(_DEFINES_) $(C_FILES) 
	$(RUN_TEST)
	bcc32 -A         -D_ANSI_CHK $(BCC_OPT) $(_DEFINES_) $(C_FILES) 
	$(RUN_TEST)

#++++++++++++++++++++++++++ test them all at once
test:	bcc32 gcc gcc342 msvc msvc60 ansi
	@echo ************************************************
	@echo ****** Test Successful: $(_CIPHER_)
	@echo ************************************************

all:	# recurse to try both settings: ECRYPT, Phelix
	make				test
	@echo .
	@echo .
	@echo .
	@echo .
	make  -DECRYPT_API	test	# ECRYPT compiles

#++++++++++++++++++++++++++ quick test
quickTest:	bcc32 gcc
	@echo ************************************************
	@echo ****** Quick Test Successful: $(_CIPHER_)
	@echo ************************************************

quick:	# recurse to try both settings: ECRYPT, Phelix
	make				quickTest
	@echo .
	@echo .
	@echo .
	@echo .
	make  -DECRYPT_API	quickTest

#++++++++++++++++++++++++++ debugging and vectors
noAsm:	$(C_FILES) 
	bcc32 $(BCC_OPT) -A -DALLOW_DEBUG_IO -D_ANSI_CHK -DNO_ASM=1  $(_DEFINES_) $(C_FILES)
	$(RUN_TEST) -k

vectors: noAsm
	$(RUN_TEST) -k -g    > phelixKAT.h
	$(RUN_TEST) -k -gTex > phelixKAT.tex


#++++++++++++++++++++++++++ debug the executable
db: 
	bcc32  $(BCC_OPT) -DALLOW_DEBUG_IO  $(_DEFINES_) $(C_FILES) pHelix86.asm

td32:	td
td:		db
	db.bat

#++++++++++++++++++++++++++ aliases
msvc:	msvc42
msc:	msvc42
bcc:	bcc32
gcc:	gcc320

#++++++++++++++++++++++++++ 
unix:
	copy *.c unix\*.*
	copy *.h unix\*.*
	dos2unix unix\phelix.c
	dos2unix unix\testPhelix.c
	dos2unix unix\phelix.h
	dos2unix unix\platform.h
	dos2unix unix\ecrypt-config.h
	dos2unix unix\ecrypt-machine.h
	dos2unix unix\ecrypt-portable.h
	dos2unix unix\ecrypt-sync-ae.h
	xcopy /y unix\*.c u:\phelix\*.c
	xcopy /y unix\*.h u:\phelix\*.h

#++++++++++++++++++++++++++ Put all the ecrypt files together
ecrypt:
	bcc32 $(BCC_OPT) -A -DECRYPT_API="ecrypt-sync-ae.h" -DANSI_CHK ecrypt-test.c phelix.c

	@-if exist ecrypt.zip del ecrypt.zip
	winzip    ecrypt.zip readme coversheet.txt IPstatement.txt
	winzip    ecrypt.zip tex\phelix.pdf tex\phelix.ps tex\*.tex tex\*.mp 
	winzip    ecrypt.zip tex\phelix.1 tex\phelix.2 tex\*.bbl tex\llncs.cls 
	winzip    ecrypt.zip makefile *.h *.c  *.inc *.asm phelix86.obj testphelix.exe 
	winzip -v ecrypt.zip
