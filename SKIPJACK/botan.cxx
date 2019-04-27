// Botan program to generate test vectors. Compile with GCC in the Botan directory.
// Note: Botan removed SKIPJACK at 1.11.8. Checkout 1.11.7 and then build the library.
// g++ -I build/include/ -I build/include/botan botan.cxx ./libbotan-1.11.a -o botan.exe

#include "auto_rng.h"
#include "skipjack.h"
#include "ecb.h"
#include "cbc.h"
#include "hex.h"

#include <iostream>
#include <memory>
#include <cstdint>

void GenerateTestVector(
    const uint8_t k[10],
    const uint8_t p[8],
    uint8_t c[8])
{
    using namespace Botan;
    static size_t count=0;

    ECB_Encryption enc(new Skipjack, new Null_Padding);

    secure_vector<uint8_t> key(k, k+10);
    secure_vector<uint8_t> plain(p, p+8);
    secure_vector<uint8_t> cipher(8);

    enc.set_key(key);
    enc.start(NULL, 0);
    enc.finish(cipher);

    static bool once = false;
    if (once == false)
    {
        std::cout << "AlgorithmType: SymmetricCipher" << std::endl;
        std::cout << "Name: SKIPJACK/ECB" << std::endl;
        std::cout << "Source: SP800-17, Table 6, pp. 140-42" << std::endl;
        once = true;
    }

    std::cout << "#" << std::endl;
    std::cout << "Comment: Round " << count << " known answer" << std::endl;
    std::cout << "Key: " << hex_encode(key) << std::endl;
    std::cout << "Plaintext: " << hex_encode(plain) << std::endl;
    std::cout << "Ciphertext: " << hex_encode(cipher) << std::endl;
    std::cout << "Test: Encrypt" << std::endl;

    count++;
}

void shift_right(unsigned char v[10])
{
    for (size_t i=0; i<10; ++i)
    {
        if (v[i] == 0) {continue;}

        unsigned int x = (v[i] >> 1);
        unsigned int y = (v[i]  & 1) ? 0x80 : 0;
        
        v[i] = (unsigned char)x;
        if (i < 9)
            v[i+1] = (unsigned char)y;
        
        break;
    }
}

int main()
{
    // NIST test vector
    uint8_t k[10] = { 0x80,0, 0,0,0,0, 0,0,0,0 };
    const uint8_t p[8] = { 0,0,0,0, 0,0,0,0 };
    uint8_t c[8];
    
    for (size_t i=0; i<80; ++i)
    {
        GenerateTestVector(k, p, c);
        shift_right(k);
    }
    
    return 0;
}
