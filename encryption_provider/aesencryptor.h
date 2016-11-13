#pragma once
#include "openssl_common_headers.h"
#include <openssl\aes.h>
#include "Encryptor.h"

class AesEncryptor : public Encryptor {
private:
	DataType encrypt(const DataType& text, const DataType& key) override;
	DataType decrypt(const DataType& text, const DataType& key) override;
	bool checkKey(const DataType& key) override;
};
