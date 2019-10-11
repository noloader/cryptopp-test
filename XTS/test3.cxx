// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// C.2 Encryption of a data unit with a size that is not a multiple of 16 bytes

// XTS_EncryptSector is from the IEEE reference implementation. Everything else
// was added to support running a test program compiled and linked with OpenSSL.

// g++ -o test2.exe test2.cxx -l:libcrypto.a -pthread -ldl

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
#define ROUNDUP_BYTES(x)  ((((x)+AES_BLK_BYTES-1)/AES_BLK_BYTES)*AES_BLK_BYTES)

// C++
typedef uint64_t u64b;
typedef uint8_t  u08b;
typedef uint32_t uint;

typedef u08b AES_Key[AES_KEY_BYTES];

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void AES_ECB_Encrypt(const AES_Key key, u08b* data, size_t size)
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

    int out_len1 = (int)size;

    rc = EVP_EncryptUpdate(ctx.get(), data, &out_len1, data, size);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = (int)(size-out_len1);
    rc = EVP_EncryptFinal_ex(ctx.get(), data+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
}

void AES_ECB_Decrypt(const AES_Key key, u08b* data, size_t size)
{
    const EVP_CIPHER *cipher = (AES_KEY_BYTES+0 == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key, NULL);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    #define NOPADDING 0
    rc = EVP_CIPHER_CTX_set_padding(ctx.get(), NOPADDING);
    if (rc != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");

    int out_len1 = (int)size;

    rc = EVP_DecryptUpdate(ctx.get(), data, &out_len1, data, size);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = (int)(size-out_len1);
    rc = EVP_DecryptFinal_ex(ctx.get(), data+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
}

std::string Print(const u08b* data, size_t size)
{
    std::ostringstream oss;
    for (size_t i=0; i<size; ++i)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }

    return oss.str();
}

/////////////////////////////////////////////////////////////////////

void XTS_EncryptSector
(
    const AES_Key k2,               // key used for tweaking
    const AES_Key k1,               // key used for "ECB" encryption
    u64b  S,                        // sector number (64 bits)
    uint  N,                        // sector size, in bytes
    const u08b *pt,                 //  plaintext sector  input data
    u08b *ct                        // ciphertext sector output data
)
{
    uint    i,j;                    // local counters
    u08b    T[AES_BLK_BYTES];       // tweak value
    u08b    x[AES_BLK_BYTES];       // local work value
    u08b    Cin,Cout;               // "carry" bits for LFSR shifting

    assert(N >= AES_BLK_BYTES);     // need at least a full AES block

    for (j=0;j<AES_BLK_BYTES;j++)
    {                               // convert sector number to tweak plaintext
        T[j] = (u08b) (S & 0xFF);
        S    = S >> 8;              // also note that T[] is padded with zeroes
    }

    AES_ECB_Encrypt(k2,T,sizeof(T));    // encrypt the tweak

    for (i=0; i+AES_BLK_BYTES<=N; i+=AES_BLK_BYTES)  // now encrypt the sector data
    {
        // merge the tweak into the input block
        for (j=0;j<AES_BLK_BYTES;j++)
            x[j] = pt[i+j] ^ T[j];

        // encrypt one block
        AES_ECB_Encrypt(k1,x,sizeof(x));

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            ct[i+j] = x[j] ^ T[j];

        // LFSR "shift" the tweak value for the next location
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

    if (i < N)                               // is there a final partial block to handle?
    {
        for (j=0;i+j<N;j++)
        {
            x[j] = pt[i+j] ^ T[j];           // copy in the final plaintext bytes
            ct[i+j] = ct[i+j-AES_BLK_BYTES]; // and copy out the final ciphertext bytes
        }
        for (;j<AES_BLK_BYTES;j++)           // "steal" ciphertext to complete the block
            x[j] = ct[i+j-AES_BLK_BYTES] ^ T[j];

        // encrypt the final block
        AES_ECB_Encrypt(k1,x,sizeof(x));

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            ct[i+j-AES_BLK_BYTES] = x[j] ^ T[j];
    }
}

void XTS_DecryptSector
(
    const AES_Key k2,               // key used for tweaking
    const AES_Key k1,               // key used for "ECB" encryption
    u64b  S,                        // sector number (64 bits)
    uint  N,                        // sector size, in bytes
    const u08b *ct,                 // ciphertext sector output data
    u08b *pt                        //  plaintext sector  input data
)
{
    uint    i,j;                    // local counters
    u08b    T[AES_BLK_BYTES];       // tweak value
    u08b    x[AES_BLK_BYTES];       // local work value
    u08b    Cin,Cout;               // "carry" bits for LFSR shifting

    assert(N >= AES_BLK_BYTES);     // need at least a full AES block

    for (j=0;j<AES_BLK_BYTES;j++)
    {                               // convert sector number to tweak plaintext
        T[j] = (u08b) (S & 0xFF);
        S    = S >> 8;              // also note that T[] is padded with zeroes
    }

    AES_ECB_Encrypt(k2,T,sizeof(T));    // encrypt the tweak

    for (i=0; i+AES_BLK_BYTES<=N; i+=AES_BLK_BYTES)  // now encrypt the sector data
    {
        // merge the tweak into the input block
        for (j=0;j<AES_BLK_BYTES;j++)
            x[j] = ct[i+j] ^ T[j];

        // encrypt one block
        AES_ECB_Decrypt(k1,x,sizeof(x));

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            pt[i+j] = x[j] ^ T[j];

        // LFSR "shift" the tweak value for the next location
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

    if (i < N)                               // is there a final partial block to handle?
    {
        for (j=0;i+j<N;j++)
        {
            x[j] = ct[i+j] ^ T[j];           // copy in the final plaintext bytes
            pt[i+j] = pt[i+j-AES_BLK_BYTES]; // and copy out the final ciphertext bytes
        }
        for (;j<AES_BLK_BYTES;j++)           // "steal" ciphertext to complete the block
            x[j] = pt[i+j-AES_BLK_BYTES] ^ T[j];

        // encrypt the final block
        AES_ECB_Decrypt(k1,x,sizeof(x));

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            pt[i+j-AES_BLK_BYTES] = x[j] ^ T[j];
    }
}

/////////////////////////////////////////////////////////////////////

int main (int argc, char* argv[])
{
    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_256_ecb());

    // AES/XTS applied for a data unit of 16 bytes, 16 bytes key material.
    // IEEE 1619, Appendix B, Vector 15
    const size_t len = 17;

    const u08b pt[ROUNDUP_BYTES(len)] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };

    u08b ct[ROUNDUP_BYTES(len)];
    u08b rt[ROUNDUP_BYTES(len)];

    const AES_Key k1 = {
        0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0
    };

    const AES_Key k2 = {
        0xbf,0xbe,0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4,0xb3,0xb2,0xb1,0xb0
    };

    // const u64b S = 0x9a78563412;
    const u64b S = 0x123456789a;

    std::cout << "Plain:  " << Print(pt, len) << std::endl;

    XTS_EncryptSector(k2, k1, S, len, pt, ct);

    std::cout << "Cipher: " << Print(ct, len) << std::endl;

    std::cout << "Expect: " << "6c1625db4671522d3d7599601de7ca09ed" << std::endl;

    XTS_DecryptSector(k2, k1, S, len, ct, rt);

    std::cout << "Plain:  " << Print(rt, len) << std::endl;

    return 0;
}
