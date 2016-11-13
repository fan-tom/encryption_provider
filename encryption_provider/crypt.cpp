#include "crypt.h"
#include "otpencryptor.h"
#include "desencryptor.h"
#include "aesencryptor.h"

std::unique_ptr<Encryptor> getEncryptor(Encryption e) {
	switch (e) {
	case Encryption::OTP:
		return std::make_unique<OtpEncryptor>();
	case Encryption::AES:
		return std::make_unique<AesEncryptor>();
	case Encryption::DES:
		return std::make_unique<DesEncryptor>();
	default:
		throw std::exception("Wrong encryption type");
	}
}