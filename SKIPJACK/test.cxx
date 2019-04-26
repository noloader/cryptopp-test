// Botan program to generate test vectors. Compile with GCC in the Botan directory.
// Note: Botan removed SKIPJACK at 1.11.8. Checkout 1.11.7 and then build the library.
// g++ -I build/include/ -I build/include/botan test.cxx ./libbotan-1.11.a -o test.exe

#include "auto_rng.h"
#include "skipjack.h"
#include "cbc.h"
#include "hex.h"

#include <iostream>
#include <memory>

// Random step
uint8_t Step(uint8_t mask)
{
    using namespace Botan;
    AutoSeeded_RNG rng;

    uint8_t b;
    rng.randomize(&b, 1);
    return b & mask;
}

void GenerateTest(size_t plainLen, size_t aadLen)
{
    using namespace Botan;
    AutoSeeded_RNG rng;

	CBC_Encryption enc(new Skipjack, new PKCS7_Padding);

    const secure_vector<uint8_t> key = rng.random_vec(10);
    const secure_vector<uint8_t> iv = rng.random_vec(8);

    secure_vector<uint8_t> plain = rng.random_vec(plainLen);
	secure_vector<uint8_t> cipher;

    enc.set_key(key);
    enc.start(iv.data(), iv.size());

    enc.finish(cipher);

    static bool once = false;
    if (once == false)
    {
        std::cout << "AlgorithmType: SymmetricCipher" << std::endl;
        std::cout << "Name: SKIPJACK/CBC" << std::endl;
        std::cout << "Source: Botan 1.11.7 test program" << std::endl;
        once = true;
    }

    std::cout << "#" << std::endl;
    std::cout << "Key: " << hex_encode(key) << std::endl;
    std::cout << "IV: " << hex_encode(iv) << std::endl;
    std::cout << "Plaintext: " << hex_encode(plain) << std::endl;
    std::cout << "Ciphertext: " << hex_encode(cipher) << std::endl;
    std::cout << "Test: Encrypt" << std::endl;
}

int main()
{
    size_t i=0;
    while(i<256)
    {
        size_t j=0;
        while(j<128)
        {
            GenerateTest(i, j);

            if (j<16)
                j++;
            else
                j += Step(15);
        }

        if (i<16)
            i++;
        else
            i += Step(31);
    }
}
