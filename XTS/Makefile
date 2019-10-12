all: test.exe test2.exe test3.exe test4.exe test5.exe test6.exe

test.exe: test.cxx
	$(CXX) $(CXXFLAGS) -Wall -g2 -O0 -o test.exe test.cxx -pthread -l:libcrypto.a -ldl

test2.exe: test2.cxx
	$(CXX) $(CXXFLAGS) -Wall -g2 -O0 -o test2.exe test2.cxx -pthread -l:libcrypto.a -ldl

test3.exe: test3.cxx
	$(CXX) $(CXXFLAGS) -Wall -g2 -O0 -o test3.exe test3.cxx -pthread -l:libcrypto.a -ldl

test4.exe: test4.cxx
	$(CXX) $(CXXFLAGS) -Wall -I /usr/include/botan-2 -g2 -O0 -o test4.exe test4.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

test5.exe: test5.cxx
	$(CXX) $(CXXFLAGS) -Wall -I /usr/include/botan-2 -g2 -O0 -o test5.exe test5.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

test6.exe: test6.cxx
	$(CXX) $(CXXFLAGS) -Wall -I /usr/include/botan-2 -g2 -O0 -o test6.exe test6.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

clean:
	rm -f *.exe *.obj
