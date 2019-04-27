// Botan program to generate test vectors. Compile with GCC in the Botan directory.
// Note: Botan removed SKIPJACK at 1.11.8. Checkout 1.11.7 and then build the library.
// g++ -I build/include/ -I build/include/botan test.cxx ./libbotan-1.11.a -o test.exe

#include "auto_rng.h"
#include "skipjack.h"
#include "ecb.h"
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

void GenerateECBTest(size_t plainLen)
{
    using namespace Botan;
    AutoSeeded_RNG rng;
    static size_t count=0;

    ECB_Encryption enc(new Skipjack, new Null_Padding);

    secure_vector<uint8_t> key = rng.random_vec(10);

    secure_vector<uint8_t> plain = rng.random_vec(plainLen);
    secure_vector<uint8_t> cipher(plain.size());

    if (count == 0)
    {
		// NIST test vector
        const uint8_t k[] = { 0x80, 0,0,0,0,0,0,0,0,0 };
        const uint8_t p[] = { 0,0,0,0 ,0,0,0,0 };

        key = secure_vector<uint8_t>(k, k+sizeof(k));
        plain = secure_vector<uint8_t>(p, p+sizeof(p));
        cipher.resize(plain.size());
    }
	else if (count == 1)
    {
        const uint8_t k[] = { 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        const uint8_t p[] = { 0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa };

        key = secure_vector<uint8_t>(k, k+sizeof(k));
        plain = secure_vector<uint8_t>(p, p+sizeof(p));
        cipher.resize(plain.size());
    }

    enc.set_key(key);
    enc.start(NULL, 0);

    enc.finish(cipher);

    static bool once = false;
    if (once == false)
    {
        std::cout << "AlgorithmType: SymmetricCipher" << std::endl;
        std::cout << "Name: SKIPJACK/ECB" << std::endl;
        std::cout << "Source: Botan 1.11.7 test program" << std::endl;
        once = true;
    }

    std::cout << "#" << std::endl;
    std::cout << "Key: " << hex_encode(key) << std::endl;
    std::cout << "Plaintext: " << hex_encode(plain) << std::endl;
    std::cout << "Ciphertext: " << hex_encode(cipher) << std::endl;
    std::cout << "Test: Encrypt" << std::endl;

    count++;
}

void GenerateCBCTest(size_t plainLen)
{
    using namespace Botan;
    AutoSeeded_RNG rng;
    static size_t count=0;

    CBC_Encryption enc(new Skipjack, new Null_Padding);

    secure_vector<uint8_t> key = rng.random_vec(10);
    secure_vector<uint8_t> iv = rng.random_vec(8);

    secure_vector<uint8_t> plain = rng.random_vec(plainLen);
    secure_vector<uint8_t> cipher(plain.size());

    if (count == 0)
    {
		// NIST test vector
        const uint8_t k[] = { 0x80, 0,0,0,0,0,0,0,0,0 };
        const uint8_t v[] = { 0,0,0,0 ,0,0,0,0 };
		const uint8_t p[] = { 0,0,0,0 ,0,0,0,0 };

        key = secure_vector<uint8_t>(k, k+sizeof(k));
        iv = secure_vector<uint8_t>(v, v+sizeof(v));
        plain = secure_vector<uint8_t>(p, p+sizeof(p));
        cipher.resize(plain.size());
    }
	else if (count == 1)
    {
        const uint8_t k[] = { 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        const uint8_t v[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        const uint8_t p[] = { 0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa };

        key = secure_vector<uint8_t>(k, k+sizeof(k));
        iv = secure_vector<uint8_t>(v, v+sizeof(v));
        plain = secure_vector<uint8_t>(p, p+sizeof(p));
        cipher.resize(plain.size());
    }

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
    
    count++;
}

int main()
{
    for (size_t i=8; i<128; i+=8)
    {
        for (size_t j=0; j++<8; j++)
        {
            GenerateECBTest(i);
        }
    }

	std::cout << std::endl;

    for (size_t i=8; i<128; i+=8)
    {
        for (size_t j=0; j++<8; j++)
        {
            GenerateCBCTest(i);
        }
    }

	std::cout << std::endl;
}
