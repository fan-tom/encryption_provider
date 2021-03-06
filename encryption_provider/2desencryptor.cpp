#include "2desencryptor.h"

Des2Encryptor::Des2Encryptor():enc(DesEncryptor()){}

DataType Des2Encryptor::encrypt(const DataType& text, const DataType& key) {
	//auto& encryptor = static_cast<Encryptor&>(enc);
	enc.key({ key.begin(), key.begin() + 8 });
	std::string in(text.begin(), text.end());
	enc.read(std::stringstream(in));

	enc.Encryptor::encrypt();
	std::stringstream out;
	enc.write(out);
	enc.key({ key.begin() + 8, key.end() });
	enc.read(out);
	std::stringstream().swap(out);
	out.clear();
	enc.Encryptor::encrypt();
	enc.write(out);
	auto res=out.str();
	return DataType(res.begin(), res.end());
}

DataType Des2Encryptor::decrypt(const DataType& text, const DataType& key) {
	auto& encryptor = static_cast<Encryptor&>(enc);
	encryptor.key({ key.cbegin()+8, key.cend() });
	std::string in(text.begin(), text.end());
	encryptor.read(std::stringstream(in));

	encryptor.decrypt();
	std::stringstream out;
	encryptor.write(out);
	encryptor.key({ key.cbegin(), key.cbegin()+8 });
	encryptor.read(out);
	std::stringstream().swap(out);
	out.clear();
	encryptor.decrypt();
	encryptor.write(out);
	auto res=out.str();
	return DataType(res.begin(), res.end());
};

bool Des2Encryptor::checkKey(const DataType& key) {
	return key.size() == 16;
};
