makefile            C           makefile for various flavors of Phelix
ecrypt-config.h     C           ECRYPT header file (unmodified)
ecrypt-machine.h    C           ECRYPT header file (unmodified)
ecrypt-portable.h   C           ECRYPT header file (unmodified)
ecrypt-sync-ae.h    C           ECRYPT header file (modified for Phelix)
phelix.h            C           Phelix definitions
phelixKAT.h         C           Phelix KAT vectors
phelix_ASM.h        C           Phelix ASM interface definitions
platform.h          C           Phelix portable definitions (non-ECRYPT)
phelix.c            C           Phelix portable implementation (ANSI C)
testPhelix.c        C           Phelix test module (ANSI C)
ecrypt-test.c       C           ECRYPT test module
strucmac.inc        C           Structured programming macros for x86 ASM
phelix86.asm        C           Phelix optimized x86 ASM implementation
phelix86.obj        C           Phelix optimized x86 ASM object file

testPhelix.exe      C           Phelix test program (Windows console app).
                                Performs validity (KAT, self-consistency) checks
                                and measures speed of C and ASM implementations
