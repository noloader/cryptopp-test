CCPREFIX = arm-linux-gnueabi-
CC = $(CCPREFIX)gcc
AS = $(CCPREFIX)as
AR = $(CCPREFIX)ar
RANLIB = $(CCPREFIX)ranlib
LN = $(CCPREFIX)ln
MV = mv

CFLAGS=-O1 -std=c99
LDFLAGS=-L./
SIMD_NEON = -mfloat-abi=softfp -mfpu=neon

INCDIR = include

LIBOBJS = check_neon.o lsh.o lsh256.o lsh512.o lsh256_neon.o lsh512_neon.o hmac.o
EXAMPLEOBJS = example_simd.o

.SUFFIXES: .c .o
.PHONY: all liblsh test clean

all: liblsh example

	
liblsh: $(LIBOBJS)
	$(CC) -shared -o $@.so $(LIBOBJS)
	
example: $(EXAMPLEOBJS)
	$(CC) $(LDFLAGS) -o $@ $(EXAMPLEOBJS) -llsh
	
clean:
	rm -f $(LIBOBJS) liblsh.so
	
$(LIBOBJS):
check_neon.o: src/check_neon.c src/check_neon.h
	$(CC) $(CFLAG) -o $@ -c $<
lsh.o: src/lsh.c
	$(CC) $(CFLAG) $(SIMD_NEON) -o $@ -c $<
lsh256.o: src/no_arch/lsh256.c
	$(CC) $(CFLAG) -o $@ -c $<
lsh512.o: src/no_arch/lsh512.c
	$(CC) $(CFLAG) -o $@ -c $<
lsh256_neon.o: src/neon/lsh256_neon.c
	$(CC) $(CFLAG) $(SIMD_NEON) -o $@ -c $<
lsh512_neon.o: src/neon/lsh512_neon.c
	$(CC) $(CFLAG) $(SIMD_NEON) -o $@ -c $<
hmac.o: src/hmac.c include/hmac.h
	$(CC) $(CFLAG) $(SIMD_NEON) -o $@ -c $<
example_simd.o: test/example_simd.c
	$(CC) $(CFLAG) $(SIMD_NEON) -o $@ -c $<