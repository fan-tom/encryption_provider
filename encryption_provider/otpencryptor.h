#pragma once
#include "Encryptor.h"

class OtpEncryptor : public Encryptor {
private:
	virtual DataType encrypt(const DataType& text, const DataType& key) override;
	virtual DataType decrypt(const DataType& text, const DataType& key) override;
	virtual bool checkKey(const DataType& key) override;
};