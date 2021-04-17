# EXTRA_CPPFLAGS = -fsanitize=undefined

all: gen_lsh256.exe gen_lsh512.exe gen_lsh512_256.exe

gen_lsh256.exe: gen_lsh256.cpp
	-rm -f gen_lsh256.exe
	g++ -Wall $(EXTRA_CPPFLAGS) -O1 gen_lsh256.cpp lsh256.c -o gen_lsh256.exe

gen_lsh512.exe: gen_lsh512.cpp
	-rm -f gen_lsh512.exe
	g++ -Wall $(EXTRA_CPPFLAGS) -O1 gen_lsh512.cpp lsh512.c -o gen_lsh512.exe

gen_lsh512_256.exe: gen_lsh512_256.cpp
	-rm -f gen_lsh512.exe
	g++ -Wall $(EXTRA_CPPFLAGS) -O1 gen_lsh512_256.cpp lsh512.c -o gen_lsh512_256.exe

clean:
	rm -f gen_lsh256.exe gen_lsh512.exe gen_lsh512_256.exe

.PHONY: clean
