#include "otpencryptor.h"

	DataType OtpEncryptor::encrypt(const DataType& text, const DataType& key) {
		DataType ciphertext(text.size());
		std::transform(text.begin(), text.end(), key.begin(), ciphertext.begin(), [](auto elem, auto key) {return elem^key;});
		return ciphertext;
	}
	DataType OtpEncryptor::decrypt(const DataType& text, const DataType& key) {
		//DataType plaintext(text.size());
		//std::transform(text.begin(), text.end(), key.begin(), plaintext.begin(), [](auto elem, auto key) {return elem^key;});
		//return plaintext;
		return encrypt(text, key);
	}
	bool OtpEncryptor::checkKey(const DataType& key) {
		return true;
	}