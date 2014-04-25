// Copyright (C) 2014       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include "utils.h"

// Auxiliary functions (endian swap and xor).
int se32(int i)
{
	return ((i & 0xFF000000) >> 24) | ((i & 0xFF0000) >>  8) | ((i & 0xFF00) <<  8) | ((i & 0xFF) << 24);
}

u64 se64(u64 i)
{
	return ((i & 0x00000000000000ff) << 56) | ((i & 0x000000000000ff00) << 40) |
		((i & 0x0000000000ff0000) << 24) | ((i & 0x00000000ff000000) <<  8) |
		((i & 0x000000ff00000000) >>  8) | ((i & 0x0000ff0000000000) >> 24) |
		((i & 0x00ff000000000000) >> 40) | ((i & 0xff00000000000000) >> 56);
}

void xor(unsigned char *dest, unsigned char *src1, unsigned char *src2, int size)
{
	int i;
	for(i = 0; i < size; i++)
	{
		dest[i] = src1[i] ^ src2[i];
	}
}

// Crypto functions (AES128-CBC, AES128-ECB, SHA1-HMAC and AES-CMAC).
void aescbc128_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aescbc128_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aesecb128_encrypt(unsigned char *key, unsigned char *in, unsigned char *out)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_ecb(&ctx, AES_ENCRYPT, in, out);
}

bool hmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	unsigned char *out = new unsigned char[key_len];

	sha1_hmac(key, key_len, in, in_len, out);

	for (int i = 0; i < 0x10; i++)
	{
		if (out[i] != hash[i])
		{
			delete[] out;
			return false;
		}
	}

	delete[] out;

	return true;
}

void hmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	sha1_hmac(key, key_len, in, in_len, hash);
}

bool cmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	unsigned char *out = new unsigned char[key_len];

	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_cmac(&ctx, in_len, in, out);

	for (int i = 0; i < key_len; i++)
	{
		if (out[i] != hash[i])
		{
			delete[] out;
			return false;
		}
	}

	delete[] out;

	return true;
}

void cmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_cmac(&ctx, in_len, in, hash);
}