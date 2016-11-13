#include "otpencryptor.h"

	DataType OtpEncryptor::encrypt(const DataType& plaintext, const DataType& key) {
		DataType ciphertext(plaintext.size());
		std::transform(plaintext.begin(), plaintext.end(), key.begin(), ciphertext.begin(), [](auto elem, auto key) {return elem^key;});
		return ciphertext;
	}
	DataType OtpEncryptor::decrypt(const DataType& ciphertext, const DataType& key) {
		DataType plaintext(ciphertext.size());
		std::transform(ciphertext.begin(), ciphertext.end(), key.begin(), plaintext.begin(), [](auto elem, auto key) {return elem^key;});
		return plaintext;
	}
	bool OtpEncryptor::checkKey(const DataType& key) {
		return true;
	}