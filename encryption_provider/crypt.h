#pragma once
#include <memory>
#include "Encryptor.h"

enum class Encryption {
	OTP,
	AES,
	DES,
	RC4
};

std::unique_ptr<Encryptor> getEncryptor(Encryption);