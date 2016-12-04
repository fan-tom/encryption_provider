#include "rc4encryptor.h"

void RC4Encryptor::genS(const DataType& key) {
	std::iota(S.begin(), S.end(), 0);
	for (size_t j = 0, i = 0; i < S.size(); ++i) {
		j = (j + S[i] + key[i%key.size()]) % S.size();
		std::swap(S[i], S[j]);
	}
}

ubyte RC4Encryptor::genKey(size_t i) {
	i %= S.size();
	k = (k + S[i]) % S.size();
	std::swap(S[i], S[k]);
	auto t = (S[i] + S[k]) % S.size();
	return S[t];
}

DataType RC4Encryptor::encrypt(const DataType& text, const DataType& key) {
	genS(key);
	k = 0;
	DataType result(text.size());
	for (size_t i = 0; i < text.size(); i++) {
		result[i] = text[i] ^ genKey(i);
	}
	return result;
}

DataType RC4Encryptor::decrypt(const DataType& text, const DataType& key) {
	return encrypt(text, key);
}

bool RC4Encryptor::checkKey(const DataType& key) {
	return key.size() != 0;
}