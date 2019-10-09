// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// C.1 Encryption of a data unit with a size that is a multiple of 16 bytes

#define GF_128_FDBK       0x87
#define AES_BLK_BYTES     16

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
