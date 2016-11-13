#include "desencryptor.h"

	DataType DesEncryptor::encrypt(const DataType& plaintext, const DataType& key)  {

		const auto DES_BLOCK_SIZE = 8;
		DataType ciphertext(plaintext.size()+DES_BLOCK_SIZE);
		int outl,foutl;

		EVP_CIPHER_CTX ctx;

		/* ATTENTION: the _ex routines require an initialized context, i.e.
		 * EVP_CIPHER_CTX_init() must be called before Init_ex,
		 * it's enough to do this once before encryption, no need to call it a
		 * second time before decryption */
		EVP_CIPHER_CTX_init(&ctx);

		/* ----- encryption ----- */

		/* EVP_EncryptInit_ex() cleans up the context, it doesn't initialize it */
		auto ret = EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, key.data(), NULL);
		assert(ret == 1);

		/* this must be called after EVP_EncryptInit() because EVP_EncryptInit()
		 * reinitialises the ctx !!!
		 * 0 turns padding off, i.e. the input string must be exactly N blocks */
		//ret = EVP_CIPHER_CTX_set_padding(&ctx, 0);
		//assert(ret == 1);

		ret = EVP_EncryptUpdate(&ctx, &ciphertext[0], &outl, plaintext.data(), plaintext.size());
		assert(ret == 1);
		assert(outl == plaintext.size());    /* input must be exactly N blocks */

		ret = EVP_EncryptFinal_ex(&ctx, &ciphertext[outl], &foutl);
		assert(ret == 1);
		//assert(foutl == 0);   /* no remaining incomplete blocks */

		/* is this really necessary? -> it seems so*/
		ret = EVP_CIPHER_CTX_cleanup(&ctx);
		assert(ret == 1);

		return DataType(ciphertext.begin(), ciphertext.begin()+outl+foutl);
	}
	DataType DesEncryptor::decrypt(const DataType& ciphertext, const DataType& key)  {
		/* ----- decryption ----- */

		/* EVP_DecryptInit_ex() cleans up the context, it doesn't initialize it
		   -> no need to call EVP_CIPHER_CTX_init(&ctx) here,
			  but padding setting must be renewed */
		DataType plaintext(ciphertext.size());
		int outl,foutl;
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		auto ret = EVP_DecryptInit_ex(&ctx, EVP_des_ecb(), NULL, key.data(), NULL);
		assert(ret == 1);

		//ret = EVP_CIPHER_CTX_set_padding(&ctx, 0);
		//assert(ret == 1);

		/* out, outl == input data, back, backl == output data */
		ret = EVP_DecryptUpdate(&ctx, &plaintext[0], &outl, ciphertext.data(), ciphertext.size());
		assert(ret == 1);
		//assert(ciphertext.size() == outl);  /* input to decryption must be exactly N blocks */

		ret = EVP_DecryptFinal_ex(&ctx, &plaintext[outl], &foutl);
		//assert(ret == 1);
		//assert(backl == 0);  /* no remaining incomplete blocks */

		ret = EVP_CIPHER_CTX_cleanup(&ctx);
		assert(ret == 1);

		return DataType(plaintext.begin(), plaintext.begin()+outl+foutl);
	}
	bool DesEncryptor::checkKey(const DataType& key) {
		return key.size()==8;
	}
