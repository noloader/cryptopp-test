all: test.exe test2.exe

LIBCRYPTO = -l:libcrypto.a

test.exe: test.cxx
	$(CXX) $(CXXFLAGS) -g2 -O0 -o test.exe test.cxx -pthread $(LIBCRYPTO) -ldl

test2.exe: test2.cxx
	$(CXX) $(CXXFLAGS) -g2 -O0 -o test2.exe test2.cxx -pthread $(LIBCRYPTO) -ldl

clean:
	rm -f *.exe *.obj
