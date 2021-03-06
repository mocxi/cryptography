// Crypto.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>


#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "crypto_app.h"

#include <fstream>

//#include <winsock.h> // For using htonl

int main(int argc, char** argv)
{
	crypto_app* crypto = new crypto_app();
	EVP_PKEY* pubKey;
	EVP_PKEY* privateKey;

	unsigned char* msg = (unsigned char*)"huy.lehuu@gameloft.com:abc!@#$";

	crypto->get_pubKey_from_pem("public.pem", &pubKey);
	crypto->get_privateKey_from_pem("private.pem", &privateKey);
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char buffer_out[MAX_MESSAGE_LENGTH + EVP_MAX_IV_LENGTH];

	if (pubKey)
	{
		std::cout << "read key done!\n";

		//still have no ideal what the fuck is ek (encrypted key...)
		unsigned char *ek = NULL;
		int eklen;


		//int * i = new int();
		//Init ek
		ek = new unsigned char[EVP_PKEY_size(pubKey)];

		int cipher_length = crypto->envelope_seal(&pubKey, msg, strlen((char*)msg), &ek, &eklen, iv, buffer_out);

		if (cipher_length < MAX_MESSAGE_LENGTH + EVP_MAX_IV_LENGTH)
		{
			buffer_out[cipher_length] = 0;
		}
		
		// For what???
		//uint32_t eklen_n;
		//eklen_n = htonl(eklen);

		std::ofstream out_file("ek", std::fstream::binary);
		out_file.write((char*)ek, eklen);
		out_file.close();
		//file.close();
	}
	else
	{
		std::cout << "key Null!\n";
	}

	// read message with private key
	unsigned char* plain_text = new unsigned char[MAX_MESSAGE_LENGTH + EVP_MAX_IV_LENGTH];


	if (privateKey)
	{
		std::cout << "read private key success!\n";


		//read ek
		unsigned char *ek = NULL;
		int eklen;

		std::ifstream in_file("ek", std::fstream::binary);

		in_file.seekg(0, std::ios::end);	// to to the end
		eklen= in_file.tellg();				// this should be the length of file
		in_file.seekg(0, std::ios::beg);	// go to the beginning
		ek = new unsigned char[eklen];		// here we go
		in_file.read((char *)ek, eklen);
		in_file.close();

		int plain_text_length = crypto->envelope_open(privateKey, buffer_out, strlen((char*)buffer_out), ek, eklen, iv, plain_text);

		unsigned char* result_text;
		if (plain_text_length > MAX_MESSAGE_LENGTH + EVP_MAX_IV_LENGTH)
		{
			plain_text_length = MAX_MESSAGE_LENGTH + EVP_MAX_IV_LENGTH;
		}

		result_text = new unsigned char[plain_text_length + 1];
		result_text[plain_text_length] = 0;

		strncpy((char*)result_text, (char*)plain_text, plain_text_length);


		std::cout << "result: " << result_text;
		delete(result_text);
	}
	if(pubKey)
		EVP_PKEY_free(pubKey);
	if(privateKey)
		EVP_PKEY_free(privateKey);
	delete plain_text;
	delete crypto;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
