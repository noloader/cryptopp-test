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
#define DEV_BLK_BYTES     16

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

    int out_len1 = size;

    rc = EVP_EncryptUpdate(ctx.get(), data, &out_len1, data, size);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = 0;
    rc = EVP_EncryptFinal_ex(ctx.get(), data+out_len1, &out_len2);
    if (rc != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
}

/////////////////////////////////////////////////////////////////////

void XTS_EncryptSector
(
    AES_Key &k2,                    // key used for generating sector "tweak"
    AES_Key &k1,                    // key used for "ECB" encryption
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
        AES_ECB_Encrypt(k1,x, sizeof(x));

        // merge the tweak into the output block
        for (j=0;j<AES_BLK_BYTES;j++)
            ct[i+j-AES_BLK_BYTES] = x[j] ^ T[j];
    }
}

/////////////////////////////////////////////////////////////////////

std::string Print(const u08b* data, size_t size)
{
    std::ostringstream oss;
    for (size_t i=0; i<size; ++i)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }

    return oss.str();
}

const char tdata[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const char tkey [] = "0123456789abcdeffedcba9876543210";

int main (int argc, char* argv[])
{
    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_256_ecb());

    u08b msg[DEV_BLK_BYTES];
    memcpy(msg, tdata, sizeof(msg));

    AES_Key k1, k2;
    memcpy(k1, tkey+ 0, AES_KEY_BYTES);
    memcpy(k2, tkey+16, AES_KEY_BYTES);

    const u64b S = 1;

    std::cout << "Plain:  " << Print(msg, sizeof(msg)) << std::endl;

    XTS_EncryptSector(k2, k1, S, DEV_BLK_BYTES, msg, msg);

    std::cout << "Cipher: " << Print(msg, sizeof(msg)) << std::endl;

    return 0;
}
