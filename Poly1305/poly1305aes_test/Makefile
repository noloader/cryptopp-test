all: poly1305aes_gen poly1305_gen

poly1305aes_gen: poly1305aes_gen.o poly1305aes.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) poly1305aes_gen.cxx -o poly1305aes_gen poly1305aes.a -l:libgmp.a -l:libcrypto.a

poly1305aes.a: aes_openssl.o poly1305_gmp.o poly1305aes_test_authenticate.o
	$(AR) $(ARFLAGS) -o poly1305aes.a aes_openssl.o poly1305_gmp.o poly1305aes_test_authenticate.o
	ranlib poly1305aes.a

poly1305_gen: poly1305_gen.o poly1305.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) poly1305_gen.cxx -o poly1305_gen poly1305.a -l:libgmp.a

poly1305.a: poly1305_gmpxx.o
	$(AR) $(ARFLAGS) -o poly1305.a poly1305_gmpxx.o
	ranlib poly1305.a

clean:
	rm -rf poly1305aes_gen poly1305_gen poly1305aes.a poly1305.a *.o

%.o : %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $<

%.o : %.cxx
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $<

%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<
