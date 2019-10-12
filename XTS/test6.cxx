// g++ -Wall -I /usr/include/botan-2 -g2 -O0 -o test4.exe test4.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

#include <botan-2/botan/aes.h>
#include <botan-2/botan/xts.h>
#include <botan-2/botan/hex.h>
#include <botan-2/botan/cipher_mode.h>
#include <botan-2/botan/auto_rng.h>

#include <iostream>
#include <sstream>
#include <memory>

std::string Format(std::string line, std::string indent)
{
    std::ostringstream oss;

    while (! line.empty())
    {
        oss << line.substr(0, 64);
        line.erase(0, 64);

        if (! line.empty())
            oss << " \\" << "\n" << indent;
    }

    return oss.str();
}

int main (int argc, char* argv[])
{
    using namespace Botan;

    for (size_t size=16+1; size<=32*8; ++size)
    {
        std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

        secure_vector<uint8_t> key(32);
        rng->randomize(key.data(), key.size());

        secure_vector<uint8_t> iv(16);
        rng->randomize(iv.data(), iv.size());

        secure_vector<uint8_t> pt(size);
        rng->randomize(pt.data(), pt.size());

        secure_vector<uint8_t> ct(pt);

        std::unique_ptr<BlockCipher> aes = BlockCipher::create("AES-128");
        XTS_Encryption enc(aes.release());

        enc.set_key(key);
        enc.start(iv);
        enc.finish(ct);

        std::cout << "#" << "\n";
        std::cout << "Source: Botan 2.4" << "\n";
        std::cout << "Comment: see PR for test program" << "\n";
        std::cout << "Key: " << hex_encode(key) << "\n";
        std::cout << "IV: " << hex_encode(iv) << "\n";
        std::cout << "Plaintext: " << Format(hex_encode(pt), "           ") << "\n";
        std::cout << "Ciphertext: " << Format(hex_encode(ct), "            ") << "\n";
        std::cout << "Test: Encrypt" << "\n";
    }


    for (size_t size=16+1; size<=32*8; ++size)
    {
        std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

        secure_vector<uint8_t> key(64);
        rng->randomize(key.data(), key.size());

        secure_vector<uint8_t> iv(16);
        rng->randomize(iv.data(), iv.size());

        secure_vector<uint8_t> pt(size);
        rng->randomize(pt.data(), pt.size());

        secure_vector<uint8_t> ct(pt);

        std::unique_ptr<BlockCipher> aes = BlockCipher::create("AES-256");
        XTS_Encryption enc(aes.release());

        enc.set_key(key);
        enc.start(iv);
        enc.finish(ct);

        std::cout << "#" << "\n";
        std::cout << "Source: Botan 2.4" << "\n";
        std::cout << "Comment: see PR for test program" << "\n";
        std::cout << "Key: " << Format(hex_encode(key), "     ") << "\n";
        std::cout << "IV: " << hex_encode(iv) << "\n";
        std::cout << "Plaintext: " << Format(hex_encode(pt), "           ") << "\n";
        std::cout << "Ciphertext: " << Format(hex_encode(ct), "            ") << "\n";
        std::cout << "Test: Encrypt" << "\n";
    }

    return 0;
}
