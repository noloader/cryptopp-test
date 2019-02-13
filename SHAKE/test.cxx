// Botan program to generate test vectors. Compile with GCC in the Botan directory.
// g++ -I build/include/ -I build/include/botan test.cxx ./libbotan-2.a -o test.exe

#include "auto_rng.h"
#include "shake.h"
#include "hex.h"

#include <iostream>
#include <memory>

uint8_t Step(uint8_t mask)
{
    using namespace Botan;
    AutoSeeded_RNG rng;

    uint8_t b;
    rng.randomize(&b, 1);
    return b & mask;
}

void SHAKE128_Test(size_t length)
{
    using namespace Botan;
    AutoSeeded_RNG rng;

    SHAKE_128 hash(32*8);
	
	secure_vector<uint8_t> message = rng.random_vec(length);
	hash.update(message);
	secure_vector<uint8_t> digest = hash.final();

    static bool once = false;
    if (once == false)
    {
        std::cout << "AlgorithmType: MessageDigest" << std::endl;
        std::cout << "Name: SHAKE128" << std::endl;
        std::cout << "Source: Botan 2.10 library" << std::endl;
        once = true;
    }
    
    std::cout << "#" << std::endl;
    std::cout << "Message: " << hex_encode(message) << std::endl;
    std::cout << "Digest: " << hex_encode(digest) << std::endl;
    std::cout << "Test: Verify" << std::endl;
}

void SHAKE256_Test(size_t length)
{
    using namespace Botan;
    AutoSeeded_RNG rng;

    SHAKE_256 hash(64*8);
	
	secure_vector<uint8_t> message = rng.random_vec(length);
	hash.update(message);
	secure_vector<uint8_t> digest = hash.final();

    static bool once = false;
    if (once == false)
    {
        // std::cout << "AlgorithmType: MessageDigest" << std::endl;
        std::cout << "Name: SHAKE256" << std::endl;
        std::cout << "Source: Botan 2.10 library" << std::endl;
        once = true;
    }
    
    std::cout << "#" << std::endl;
    std::cout << "Message: " << hex_encode(message) << std::endl;
    std::cout << "Digest: " << hex_encode(digest) << std::endl;
    std::cout << "Test: Verify" << std::endl;
}

int main()
{
    size_t tests=0, i=0;
    while(tests < 150)
    {
        SHAKE128_Test(i);           

        if (i<32)
            i++;
        else if (i<128)
            i += Step(15);
        else
            i += Step(63);
		
		tests++;
    }

	tests=0, i=0;
	while(tests < 150)
    {
        SHAKE256_Test(i);           

        if (i<32)
            i++;
        else if (i<128)
            i += Step(15);
        else
            i += Step(63);

		tests++;
    }
}
