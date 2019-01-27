// This generates test vectors for Poly1305(AES).
// g++ poly1305aes_gen.cxx -o poly1305aes_gen -l:libgmpa -l:libcrypto.a

extern "C" {
#include "poly1305aes_test.h"
}

#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>

void rand_bytes(uint8_t* buffer, size_t size)
{
	static uint32_t add = (uint16_t)-1;

    srand(time(NULL) ^ (time_t)add);
	while (size--)
		*buffer++ = (uint8_t)rand();

	add = (uint32_t)rand();
}

uint8_t rand_bits(uint8_t mask)
{
	uint8_t one;
	rand_bytes(&one, 1);
	return one & mask;
}

void clamp_key(uint8_t key[32])
{
	key +=16;
	key[3] &= 15;
	key[7] &= 15;
	key[11] &= 15;
	key[15] &= 15;
	key[4] &= 252;
	key[8] &= 252;
	key[12] &= 252;
}

void print_preamble()
{
	std::ostringstream oss;
	
	oss << "AlgorithmType: MAC" << std::endl;
	oss << "Name: Poly1305(AES)" << std::endl;
	oss << "Source: https://cr.yp.to/mac/test.html, poly1305aes_test_authenticate.cpp" << std::endl;

	std::cout << oss.str();
}

enum {SUCCESS=0, TAMPER_KEY, TAMPER_IV, TAMPER_MSG, TAMPER_MAC};
void print_test(uint8_t out[16], const uint8_t k[32], const uint8_t n[16], 
            const uint8_t* m, unsigned int l, int tamper=SUCCESS)
{
	static uint32_t test=1;
	std::ostringstream oss;
	
	oss << "#" << std::endl;

	//////////////// Comment ////////////////
	
	oss << "Comment: Test Case " << test++;
	
	switch (tamper)
	{
		case TAMPER_KEY:
			oss << " (tamper key)";
			break;
		case TAMPER_IV:
			oss << " (tamper nonce)";
			break;
		case TAMPER_MSG:
			oss << " (tamper message)";
			break;
		case TAMPER_MAC:
			oss << " (tamper mac)";
			break;
		default:
		;;
	}

	oss << std::endl;
	
	//////////////// Key ////////////////

	oss << "Key: ";
	for (unsigned int i=0; i<32; ++i)
	{
		if (i && (i%8 == 0))
			oss << " ";
		
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)k[i];
	}
	
	oss << std::endl;

	//////////////// IV ////////////////

	oss << "IV: ";
	for (unsigned int i=0; i<16; ++i)
	{
		if (i && (i%8 == 0))
			oss << " ";
		
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)n[i];
	}
	
	oss << std::endl;

	//////////////// Message ////////////////
	
	if (l == 0)
		oss << "Message: \"\"";
	else if (l <= 32)
		oss << "Message: ";
	else
		oss << "Message: \\\n    ";

	for (unsigned int i=0; i<l; ++i)
	{
		if (i && (i%8 == 0))
			oss << " ";
		if (i && (i%32 == 0))
			oss << "\\\n    ";
		
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)m[i];
	}
	
	oss << std::endl;

	//////////////// MAC ////////////////
	
	oss << "MAC: ";
	
	for (unsigned int i=0; i<16; ++i)
	{
		if (i && (i%8 == 0))
			oss << " ";
		
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)out[i];
	}
	
	oss << std::endl;
	
	//////////////// Test ////////////////
	
	if (tamper == SUCCESS)
		oss << "Test: Verify" << std::endl;
	else
		oss << "Test: NotVerify" << std::endl;

	std::cout << oss.str();
}

int main(int argc, char* argv[])
{
	uint8_t out[16];
	uint8_t k[32], n[16];
	uint8_t m[512];
	
	print_preamble();

	unsigned int i=0;
	for ( ; i<32+1; ++i)
	{
		rand_bytes(k, sizeof(k));
		rand_bytes(n, sizeof(n));
		rand_bytes(m, sizeof(m));

		clamp_key(k);
		poly1305aes_test_authenticate(out, k, n, m, i);
		print_test(out, k, n, m, i);
		
		k[i%16] ^= 0xaa;
		print_test(out, k, n, m, i, TAMPER_KEY);
	}

	while (i<128+1)
	{
		rand_bytes(k, sizeof(k));
		rand_bytes(n, sizeof(n));
		rand_bytes(m, sizeof(m));

		clamp_key(k);
		poly1305aes_test_authenticate(out, k, n, m, i);
		print_test(out, k, n, m, i);
		
		n[i%16] ^= 0xaa;
		print_test(out, k, n, m, i, TAMPER_IV);
		
		i += 2+rand_bits(1);
	}

	while (i<255)
	{
		rand_bytes(k, sizeof(k));
		rand_bytes(n, sizeof(n));
		rand_bytes(m, sizeof(m));

		clamp_key(k);
		poly1305aes_test_authenticate(out, k, n, m, i);
		print_test(out, k, n, m, i);
		
		out[i%16] ^= 0xaa;
		print_test(out, k, n, m, i, TAMPER_MAC);

		i += 2+rand_bits(3);
	}

	return 0;
}
