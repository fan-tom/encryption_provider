#pragma once
#include "openssl_common_headers.h"
#include <openssl\des.h>
#include "Encryptor.h"

class DesEncryptor : public Encryptor {
private:
	virtual DataType encrypt(const DataType& text, const DataType& key) override;
	virtual DataType decrypt(const DataType& text, const DataType& key) override;
	virtual bool checkKey(const DataType& key) override;
};