// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// C.1 Encryption of a data unit with a size that is a multiple of 16 bytes

// XTS_EncryptSector is from the IEEE reference implementation. Everything else
// was added to support running a test program compiled and linked with OpenSSL.

// g++ -o test.exe test.cxx -l:libcrypto.a -pthread -ldl

#include <openssl/evp.h>

#include <iostream>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <string>
#include <memory>

// From IEEE
#define GF_128_FDBK       0x87
#define AES_KEY_BYTES     16
#define AES_BLK_BYTES     16
#define DEV_BLK_BYTES     16

// C++
typedef uint64_t u64b;
typedef uint8_t  u08b;
typedef uint32_t uint;

typedef u08b AES_Key[AES_KEY_BYTES];
typedef u08b Msg[DEV_BLK_BYTES];

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void AES_ECB_Encrypt(const AES_Key key, Msg msg)
{
    const EVP_CIPHER *cipher = (AES_KEY_BYTES+0 == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key, NULL);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    #define NOPADDING 0
    rc = EVP_CIPHER_CTX_set_padding(ctx.get(), NOPADDING);
    if (rc != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");

    int out_len1 = sizeof(Msg);

    rc = EVP_EncryptUpdate(ctx.get(), msg, &out_len1, msg, sizeof(Msg));
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = 0;
    rc = EVP_EncryptFinal_ex(ctx.get(), msg+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
}

/////////////////////////////////////////////////////////////////////

void XTS_EncryptSector
(
     AES_Key &k2,                    // key used for tweaking
     AES_Key &k1,                    // key used for "ECB" encryption
     u64b  S,                        // data unit number (64 bits)
     uint  N,                        // sector size, in bytes
     const u08b *pt,                 // plaintext sector  input data
     u08b *ct                        // ciphertext sector output data
)
{
    uint    i,j;                    // local counters
    u08b    T[AES_BLK_BYTES];       // tweak value
    u08b    x[AES_BLK_BYTES];       // local work value
    u08b    Cin,Cout;               // "carry" bits for LFSR shifting

    assert(N % AES_BLK_BYTES == 0); // data unit is multiple of 16 bytes

    for (j=0;j<AES_BLK_BYTES;j++)
    {                               // convert sector number to tweak plaintext
        T[j] = (u08b) (S & 0xFF);
        S    = S >> 8;              // also note that T[] is padded with zeroes
    }
    AES_ECB_Encrypt(k2,T);          // encrypt the tweak

    for (i=0;i<N;i+=AES_BLK_BYTES)  // now encrypt the data unit, AES_BLK_BYTES at a time
    {
        // merge the tweak into the input block
        for (j=0;j<AES_BLK_BYTES;j++)
            x[j] = pt[i+j] ^ T[j];

        // encrypt one block
        AES_ECB_Encrypt(k1,x);

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            ct[i+j] = x[j] ^ T[j];

        // Multiply T by α
        Cin = 0;
        for (j=0;j<AES_BLK_BYTES;j++)
        {
            Cout =  (T[j] >> 7) & 1;
            T[j] = ((T[j] << 1) + Cin) & 0xFF;
            Cin  =  Cout;
        }
        if (Cout)
            T[0] ^= GF_128_FDBK;
    }
}

/////////////////////////////////////////////////////////////////////

std::string Print(const Msg msg)
{
    std::ostringstream oss;
    for (size_t i=0; i<sizeof(Msg); ++i)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)msg[i];
    }

    return oss.str();
}

const char tdata[] = "0123456789abcdef";
const char tkey [] = "0123456789abcdeffedcba9876543210";

int main (int argc, char* argv[])
{
    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_256_ecb());

    Msg msg;
    memcpy(msg, tdata, DEV_BLK_BYTES);

    AES_Key k1, k2;
    memcpy(k1, tkey+ 0, AES_KEY_BYTES);
    memcpy(k2, tkey+16, AES_KEY_BYTES);

    const u64b S = 1;

    std::cout << "Plain:  " << Print(msg) << std::endl;

    XTS_EncryptSector(k2, k1, S, DEV_BLK_BYTES, msg, msg);

    std::cout << "Cipher: " << Print(msg) << std::endl;

    return 0;
}
