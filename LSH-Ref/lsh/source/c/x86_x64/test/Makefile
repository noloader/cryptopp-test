#VARIABLE
CC=cc
AS=as
AR=ar
RANLIB=ranlib
LN=ln
MV=mv

TARGETDIR = ..

MAJOR_VERSION = 1
MINOR_VERSION = 0.0

CFLAGS=-O2
LDFLAGS=-Wl,-rpath '-Wl,$$ORIGIN' -L$(TARGETDIR)/

#COMPILE

.SUFFIXES:.c .o
.PHONY: all install clean objclean

TEST_OBJS = example.o example_simd.o benchmark.o lsh_benchmark.o

all: lsh_test

install: 

objclean: 
	$(RM) *.o

clean: objclean
	$(RM) $(TARGETDIR)/lsh_test $(TARGETDIR)/lsh_test.exe

lsh_test : $(TEST_OBJS)
	$(CC) -lm $(LDFLAGS) -o $(TARGETDIR)/$@ $(TEST_OBJS) -llsh


benchmark.o : benchmark.c benchmark.h
lsh_benchmark.o : lsh_benchmark.c lsh_benchmark.h benchmark.h

%.o: %.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ -c $<
