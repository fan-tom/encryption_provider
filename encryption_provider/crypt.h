#pragma once
#include <memory>
#include "Encryptor.h"

enum class Encryption {
	OTP,
	AES,
	DES,
	DES2,
	RC4
};

std::unique_ptr<Encryptor> getEncryptor(Encryption);