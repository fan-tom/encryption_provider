#pragma once
#include "desencryptor.h"
#include <sstream>

class Des2Encryptor : public Encryptor {
private:
	DesEncryptor enc;
public:

	Des2Encryptor();
	virtual DataType encrypt(const DataType& text, const DataType& key);
	virtual DataType decrypt(const DataType& text, const DataType& key);
	virtual bool checkKey(const DataType& key);
};
