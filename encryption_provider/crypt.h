#pragma once
#include <memory>
#include "Encryptor.h"

enum class Encryption {
	OTP,
	AES,
	DES
};

std::unique_ptr<Encryptor> getEncryptor(Encryption);