#include "aesencryptor.h"

	DataType AesEncryptor::encrypt(const DataType& plaintext, const DataType& key)  {
		EVP_CIPHER_CTX *ctx;

		DataType ciphertext(plaintext.size()+AES_BLOCK_SIZE);

		int len,flen;

		/* Create and initialise the context */
		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw std::exception("Cannot create context");

		/* Initialise the encryption operation. IMPORTANT - ensure you use a key
		 * and IV size appropriate for your cipher
		 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
		 * IV size for *most* modes is the same as the block size. For AES this
		 * is 128 bits */
		if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL))
			throw std::exception("Cannot init context");

		/* Provide the message to be encrypted, and obtain the encrypted output.
		 * EVP_EncryptUpdate can be called multiple times if necessary
		 */
		if (1 != EVP_EncryptUpdate(ctx, &ciphertext[0], &len, plaintext.data(), plaintext.size()))
			throw std::exception("Cannot update context");

		/* Finalise the encryption. Further ciphertext bytes may be written at
		 * this stage.
		 */
		if (1 != EVP_EncryptFinal_ex(ctx, &ciphertext[len], &flen))
			throw std::exception("Cannot finalize context");

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		return DataType(ciphertext.begin(), ciphertext.begin()+len+flen);
	}

	DataType AesEncryptor::decrypt(const DataType& ciphertext, const DataType& key)  {
		EVP_CIPHER_CTX *ctx;

		DataType plaintext(ciphertext.size());

		int len,flen;

		/* Create and initialise the context */
		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw std::exception("Cannot create context");

		/* Initialise the Decryption operation. IMPORTANT - ensure you use a key
		 * and IV size appropriate for your cipher
		 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
		 * IV size for *most* modes is the same as the block size. For AES this
		 * is 128 bits */
		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL))
			throw std::exception("Cannot init context");

		/* Provide the message to be Decrypted, and obtain the Decrypted output.
		 * EVP_DecryptUpdate can be called multiple times if necessary
		 */
		if (1 != EVP_DecryptUpdate(ctx, &plaintext[0], &len, ciphertext.data(), ciphertext.size()))
			throw std::exception("Cannot update context");

		/* Finalise the Decryption. Further ciphertext bytes may be written at
		 * this stage.
		 */
		if (1 != EVP_DecryptFinal_ex(ctx, &plaintext[len], &flen))
			throw std::exception("Cannot finalize context");

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		return DataType(plaintext.begin(), plaintext.begin()+len+flen);
	}
	bool AesEncryptor::checkKey(const DataType& key)  {
		return key.size()==16;
	}