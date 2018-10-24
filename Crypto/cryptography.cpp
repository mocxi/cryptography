#include "pch.h"
#include "cryptography.h"
#include <openssl/pem.h>
#include <openssl/applink.c>

cryptography::cryptography()
{
}

void cryptography::get_pubKey_from_pem(const char* file_name, EVP_PKEY** pubKey)
{
	FILE *pem_pubKey_file;
	//pem_pubKey_file = fopen(file_name, "rb");
	int error = fopen_s(&pem_pubKey_file, file_name, "rt");
	//if (error != 0)
	//{
	//	return;
	//}

	//int c;
	//while ((c = getc(pem_pubKey_file)) != EOF)
	//	putchar(c);
	//fclose(pem_pubKey_file);

	//fflush(pem_pubKey_file);

	//_setmode(_fileno(pem_pubKey_file), _O_U8TEXT);
	*pubKey = PEM_read_PUBKEY(pem_pubKey_file, NULL, NULL, NULL);
	if (!pubKey)
	{
		handleErrors();
	}
	else
	{
		//BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		//EVP_PKEY_print_public(bio, *pubKey, 3, NULL); //this will print this pubKey to the console
		//BIO_free(bio);
	}
}

int cryptography::envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int ciphertext_len;

	int len;


	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the envelope seal operation. This operation generates
	 * a key for the provided cipher, and then encrypts that key a number
	 * of times (one for each public key provided in the pub_key array). In
	 * this example the array size is just one. This operation also
	 * generates an IV and places it in iv. */
	if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_SealUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int cryptography::envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;


	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. The asymmetric private key is
	 * provided and priv_key, whilst the encrypted session key is held in
	 * encrypted_key */
	if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, priv_key))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_OpenUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void cryptography::handleErrors()
{

}

cryptography::~cryptography()
{
}
