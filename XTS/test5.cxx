// g++ -Wall -I /usr/include/botan-2 -g2 -O0 -o test5.exe test5.cxx -pthread -l:libbotan-2.a -l:libcrypto.a -ldl

#include <botan-2/botan/aes.h>
#include <botan-2/botan/xts.h>
#include <botan-2/botan/hex.h>
#include <botan-2/botan/cipher_mode.h>

#include <iostream>
#include <memory>

int main (int argc, char* argv[])
{
    using namespace Botan;

    // IEEE 1619, Appendix B, Vector 4
    {
        secure_vector<uint8_t> key = hex_decode_locked("27182818284590452353602874713526"
                                                       "31415926535897932384626433832795");

        secure_vector<uint8_t>  iv = hex_decode_locked("00000000000000000000000000000000");

        secure_vector<uint8_t>  pt = hex_decode_locked(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        secure_vector<uint8_t> ct(pt);

        secure_vector<uint8_t> ex = hex_decode_locked(
            "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
            "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
            "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
            "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
            "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
            "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
            "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
            "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
            "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
            "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
            "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
            "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
            "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
            "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
            "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
            "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568");

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
        std::cout << "Expect: " << hex_encode(ex) << "\n";

        if (ct == ex)
        {
            std::cout << "Success" << std::endl;
        }
    }

    return 0;
}
