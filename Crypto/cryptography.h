#pragma once

#include <openssl\evp.h>

class cryptography
{
public:
	int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
		unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
		unsigned char *ciphertext);
	int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
		unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
		unsigned char *plaintext);
	void get_pubKey_from_pem(const char* file_name, EVP_PKEY** key);
	void get_privateKey_from_pem(const char* file_name, EVP_PKEY** pubKey);
	void handleErrors();
	cryptography();
	~cryptography();
};

