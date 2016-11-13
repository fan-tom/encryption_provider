#include "Encryptor.h"

void Encryptor::read(std::istream& input) {
	std::istreambuf_iterator<char> it(input), end;
	text.assign(it, end);
}

void Encryptor::write(std::ostream& output) {
	output.write((char*)result.data(), result.size());
}

void Encryptor::encrypt() {
	result = encrypt(text, _key);
}

void Encryptor::decrypt() {
	result = decrypt(text, _key);
}

void Encryptor::key(const DataType& key) {
	if (checkKey(key))
		_key = key;
	else
		throw std::exception("Wrong key");
}

DataType Encryptor::key() const {
	return _key;
}