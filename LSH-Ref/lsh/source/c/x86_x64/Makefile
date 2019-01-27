#VARIABLE
CC=cc
AS=as
AR=ar
RANLIB=ranlib
LN=ln
MV=mv

#SHARED=TRUE

.SUFFIXES:.c .o
.PHONY: all install clean objclean

all: lib lsh_test

install: lib
	cd src && $(MAKE) install

objclean: 
	cd test && $(MAKE) objclean
	cd src && $(MAKE) objclean

clean: objclean
	$(RM) liblsh* lsh_test lsh_test.exe

lsh_test : 
	cd test && $(MAKE) lsh_test

lib:
	cd src && $(MAKE) lib
