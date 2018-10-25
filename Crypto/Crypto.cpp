// Crypto.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#include "cryptography.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <fstream>

//#include <winsock.h> // For using htonl

int main(int argc, char** argv)
{
	cryptography* crypto = new cryptography();
	EVP_PKEY* pubKey;
	EVP_PKEY* privateKey;

	unsigned char* msg = (unsigned char*)"user@name:pwd";

	crypto->get_pubKey_from_pem("public.pem", &pubKey);
	crypto->get_privateKey_from_pem("private.pem", &privateKey);
	if (pubKey)
	{
		std::cout << "read key done!\n";

		//still have no ideal what the fuck is ek (encrypted key...)
		unsigned char *ek = NULL;
		int eklen;
		unsigned char iv[EVP_MAX_IV_LENGTH];


		unsigned char buffer_out[256 + EVP_MAX_IV_LENGTH];
		//int * i = new int();
		//Init ek
		ek = new unsigned char[EVP_PKEY_size(pubKey)];

		crypto->envelope_seal(&pubKey, msg, strlen((char*)msg), &ek, &eklen, iv, buffer_out);
		
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

	EVP_PKEY_free(pubKey);
	EVP_PKEY_free(privateKey);
	
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
