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

void GenerateTestVector(size_t plainLen)
{
    using namespace Botan;
    static size_t count=0;

    AutoSeeded_RNG rng;
    CBC_Encryption enc(new Skipjack, new Null_Padding);

    secure_vector<uint8_t> key = rng.random_vec(10);
    secure_vector<uint8_t> iv = rng.random_vec(8);
    secure_vector<uint8_t> plain = rng.random_vec(plainLen);
    secure_vector<uint8_t> cipher(plain);

    enc.set_key(key);
    enc.start(iv.data(), iv.size());
    enc.finish(cipher);

    static bool once = false;
    if (once == false)
    {
        //std::cout << "AlgorithmType: SymmetricCipher" << std::endl;
        std::cout  << std::endl;
        std::cout << "Name: SKIPJACK/CBC" << std::endl;
        std::cout << "Source: Botan library v1.11.7" << std::endl;
        once = true;
    }

#if 0
    if (count == 0)
    {
        // NIST test vector 0 from SP800-17
        std::cout << "#" << std::endl;
        std::cout << "Comment: Test " << count << std::endl;
        std::cout << "Key: " << "80000000000000000000" << std::endl;
        std::cout << "IV: " << "0000000000000000" << std::endl;
        std::cout << "Plaintext: " << "0000000000000000" << std::endl;
        std::cout << "Ciphertext: " << "7A00E49441461F5A" << std::endl;
        std::cout << "Test: Encrypt" << std::endl;
        
        count++;
    }

    if (count == 1)
    {
        // NIST test vector 79 from SP800-17
        std::cout << "#" << std::endl;
        std::cout << "Comment: Test " << count << std::endl;
        std::cout << "Key: " << "00000000000000000001" << std::endl;
        std::cout << "IV: " << "0000000000000000" << std::endl;
        std::cout << "Plaintext: " << "0000000000000000" << std::endl;
        std::cout << "Ciphertext: " << "74D0E7C2E3B450A8" << std::endl;
        std::cout << "Test: Encrypt" << std::endl;
        
        count++;
    }
#endif

    std::cout << "#" << std::endl;
    std::cout << "Comment: Test " << count << std::endl;
    std::cout << "Key: " << hex_encode(key) << std::endl;
    std::cout << "IV: " << hex_encode(iv) << std::endl;
    std::cout << "Plaintext: " << hex_encode(plain) << std::endl;
    std::cout << "Ciphertext: " << hex_encode(cipher) << std::endl;
    std::cout << "Test: Encrypt" << std::endl;

    count++;
}

int main()
{
    for (size_t i=0+1; i<10+1; ++i)
    {
        for (size_t j=0; j<8; ++j)
        {
            GenerateTestVector(i*8);
        }
    }
    
    return 0;
}
