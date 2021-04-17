// Test Vector generator program for LSH-256 and LSH-512
// Written and placed in public domain by Jeffrey Walton

#include "lsh256.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

#include <cstdio>
#include <climits>

#define LSH_UNUSED(x) ((void)(x))
#define COUNTOF(x) (sizeof(x)/sizeof(x[0]))
typedef unsigned char byte;

void PrintBuffer(const char* label, const byte* ptr, size_t size)
{
	if (label)
		printf("%s: ", label);

	for (size_t i=0; i<size; ++i)
	{
		if (i && i% 4 == 0)
			printf(" ");

		printf("%02x", ptr[i]);
	}
}

int main(int argc, char* argv[])
{
	const unsigned int repeat[] = {
		1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 512, 768,
		1024, 2048, 4096, 8192, 16384, 32768, 65536
	};

	// Used for all hashes
	byte digest[LSH256_HASH_VAL_MAX_BYTE_LEN];
	
	// Algorithm selector
	lsh_type alg;

	////////////////// LSH-224  //////////////////

	printf("AlgorithmType: MessageDigest\n");
	printf("Name: LSH-224\n");
	printf("Source: gen_lsh512.cpp, https://github.com/noloader/cryptopp-test/lsh\n");
	alg = LSH_TYPE_256_224;

	// Random messages
	for (size_t i=0; i<128; ++i)
	{
		std::vector<byte> data;
		data.resize(i);

		byte* ptr = data.size() ? &data[0] : digest;
		size_t size = data.size();

		std::ifstream urandom("/dev/urandom");
		urandom.read((char*)ptr, size);

		printf("#\n");
		printf("Comment: random test vector, size %u\n", (unsigned int)i);
		PrintBuffer("Message", ptr, size);
		printf("\n");

		lsh_err err = lsh256_digest(alg, ptr, size*8, digest);
		if (err != LSH_SUCCESS)
			throw std::runtime_error("lsh256_digest failed");

		PrintBuffer("Digest", digest, LSH_GET_HASHBYTE(alg));
		printf("\n");
		
		printf("Test: Verify\n");
	}

	// All 0's messages
	for (size_t i=0; i<COUNTOF(repeat); ++i)
	{
		std::vector<byte> data;
		data.resize(repeat[i]);

		byte* ptr = data.size() ? &data[0] : digest;
		size_t size = data.size();

		printf("#\n");
		printf("Comment: All 0's test vector, size %u\n", (unsigned int)repeat[i]);
		printf("Message: r%u 00", (unsigned int)size);
		printf("\n");

		lsh_err err = lsh256_digest(alg, ptr, size*8, digest);
		if (err != LSH_SUCCESS)
			throw std::runtime_error("lsh256_digest failed");

		PrintBuffer("Digest", digest, LSH_GET_HASHBYTE(alg));
		printf("\n");
		
		printf("Test: Verify\n");
	}

	////////////////// LSH-256  //////////////////

	printf("\n");
	printf("AlgorithmType: MessageDigest\n");
	printf("Name: LSH-256\n");
	printf("Source: gen_lsh512.cpp, https://github.com/noloader/cryptopp-test/lsh\n");
	alg = LSH_TYPE_256_256;

	// Random messages
	for (size_t i=0; i<128; ++i)
	{
		std::vector<byte> data;
		data.resize(i);

		byte* ptr = data.size() ? &data[0] : digest;
		size_t size = data.size();

		std::ifstream urandom("/dev/urandom");
		urandom.read((char*)ptr, size);

		printf("#\n");
		printf("Comment: random test vector, size %u\n", (unsigned int)i);
		PrintBuffer("Message", ptr, size);
		printf("\n");

		lsh_err err = lsh256_digest(alg, ptr, size*8, digest);
		if (err != LSH_SUCCESS)
			throw std::runtime_error("lsh256_digest failed");

		PrintBuffer("Digest", digest, LSH_GET_HASHBYTE(alg));
		printf("\n");
		
		printf("Test: Verify\n");
	}

	// All 0's messages
	for (size_t i=0; i<COUNTOF(repeat); ++i)
	{
		std::vector<byte> data;
		data.resize(repeat[i]);

		byte* ptr = data.size() ? &data[0] : digest;
		size_t size = data.size();

		printf("#\n");
		printf("Comment: All 0's test vector, size %u\n", (unsigned int)repeat[i]);
		printf("Message: r%u 00", (unsigned int)size);
		printf("\n");

		lsh_err err = lsh256_digest(alg, ptr, size*8, digest);
		if (err != LSH_SUCCESS)
			throw std::runtime_error("lsh256_digest failed");

		PrintBuffer("Digest", digest, LSH_GET_HASHBYTE(alg));
		printf("\n");
		
		printf("Test: Verify\n");
	}

	return 0;
}
