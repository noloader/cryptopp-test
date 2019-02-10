// Botan program to generate test vectors. Compile with GCC in the Botan directory.
// g++ -I build/include/ -I build/include/botan test.cxx ./libbotan-2.a -o test.exe

#include "auto_rng.h"
#include "aead.h"
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

    std::unique_ptr<AEAD_Mode> enc =  AEAD_Mode::create("ChaCha20Poly1305", ENCRYPTION);

    const secure_vector<uint8_t> key = rng.random_vec(enc->maximum_keylength());
    const secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

    secure_vector<uint8_t> plain = rng.random_vec(plainLen);
    secure_vector<uint8_t> aad = rng.random_vec(aadLen);
    secure_vector<uint8_t> cipher(plain);

    enc->set_key(key);
    enc->set_ad(aad);
    enc->start(iv);

    enc->finish(cipher);

    secure_vector<uint8_t>::iterator where = cipher.end()-enc->tag_size();
    secure_vector<uint8_t> mac(where, cipher.end());
    cipher.erase(where, cipher.end());

    static bool once = false;
    if (once == false)
    {
        std::cout << "AlgorithmType: AuthenticatedSymmetricCipher" << std::endl;
        std::cout << "Name: ChaCha20/Poly1305" << std::endl;
        std::cout << "Source: Botan 2.10 test program" << std::endl;
        once = true;
    }

    std::cout << "#" << std::endl;
    std::cout << "Key: " << hex_encode(key) << std::endl;
    std::cout << "IV: " << hex_encode(iv) << std::endl;
    std::cout << "Header: " << hex_encode(aad) << std::endl;
    std::cout << "Plaintext: " << hex_encode(plain) << std::endl;
    std::cout << "Ciphertext: " << hex_encode(cipher) << std::endl;
    std::cout << "MAC: " << hex_encode(mac) << std::endl;
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
