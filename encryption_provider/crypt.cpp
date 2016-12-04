#include "crypt.h"
#include "otpencryptor.h"
#include "desencryptor.h"
#include "aesencryptor.h"
#include "rc4encryptor.h"

std::unique_ptr<Encryptor> getEncryptor(Encryption e) {
	switch (e) {
	case Encryption::OTP:
		return std::make_unique<OtpEncryptor>();
	case Encryption::AES:
		return std::make_unique<AesEncryptor>();
	case Encryption::DES:
		return std::make_unique<DesEncryptor>();
	case Encryption::RC4:
		return std::make_unique<RC4Encryptor>();
	default:
		throw std::exception("Wrong encryption type");
	}
}