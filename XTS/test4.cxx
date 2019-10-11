// g++ -Wall -I /usr/include/botan-2 -g2 -O0 -o test3.exe test3.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

#include <botan-2/botan/aes.h>
#include <botan-2/botan/xts.h>
#include <botan-2/botan/hex.h>
#include <botan-2/botan/cipher_mode.h>

#include <iostream>
#include <memory>

int main (int argc, char* argv[])
{
    using namespace Botan;

    // IEEE 1619, Appendix B, Vector 1
    {
        secure_vector<uint8_t> key(32);
        secure_vector<uint8_t>  iv(16);
        secure_vector<uint8_t>  pt(32);
        secure_vector<uint8_t>  ct(pt);

        std::unique_ptr<BlockCipher> aes = BlockCipher::create("AES-128");
        XTS_Encryption enc(aes.release());

        enc.set_key(key);
        enc.start(iv);
        enc.finish(ct);

        std::cout << "Botan says Vector 1 is: " << std::endl;

        std::cout << "Key: " << hex_encode(key) << "\n";
        std::cout << " IV: " << hex_encode(iv) << "\n";
        std::cout << "Plain:  " << hex_encode(pt) << "\n";
        std::cout << "Cipher: " << hex_encode(ct) << "\n";
    }

    // IEEE 1619, Appendix B, Vector 15
    {
        secure_vector<uint8_t> key = {
            0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
            0xbf,0xbe,0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4,0xb3,0xb2,0xb1,0xb0
        };
        secure_vector<uint8_t>  iv = {  // 0x9a78563412, little-endian
            0x12,0x34,0x56,0x78,0x9a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };

        secure_vector<uint8_t>  pt = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
        };

        secure_vector<uint8_t>  ct(pt);

        std::unique_ptr<BlockCipher> aes = BlockCipher::create("AES-128");
        XTS_Encryption enc(aes.release());

        enc.set_key(key);
        enc.start(iv);
        enc.finish(ct);

        std::cout << "Botan says Vector 15 is: " << std::endl;

        std::cout << "Key: " << hex_encode(key) << "\n";
        std::cout << " IV: " << hex_encode(iv) << "\n";
        std::cout << "Plain:  " << hex_encode(pt) << "\n";
        std::cout << "Cipher: " << hex_encode(ct) << "\n";
    }

    return 0;
}
