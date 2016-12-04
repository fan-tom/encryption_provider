#pragma once
#include <numeric>
#include <algorithm>

#include "Encryptor.h"

const auto BLOCK_SIZE = 8u;

class RC4Encryptor : public Encryptor {
private:
	size_t k = 0;
	DataType S=DataType(1<<BLOCK_SIZE);
	ubyte genKey(size_t i);
	void genS(const DataType& key);
public:
	virtual DataType encrypt(const DataType& text, const DataType& key) override;
	virtual DataType decrypt(const DataType& text, const DataType& key) override;
	virtual bool checkKey(const DataType& key) override;
};