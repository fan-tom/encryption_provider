#include "libotp.h"

	Generator::Generator() {
		std::default_random_engine engine;
		std::uniform_int_distribution<int> distr(1,255);
		auto gen = std::bind(distr,engine);
		//auto rand = [generator, distr]() {return distr(generator); };
		std::generate(key.begin(), key.end(), [&gen]() {return static_cast<char>(gen()); });
		key[key.size() - 1] = '\0';
	}

	RawPointerOtp::RawPointerOtp(const std::string& message) {
		this->mess = new char[MESS_SIZE];
		std::copy(message.cbegin(), message.cend(), this->mess);
	}

	RawPointerOtp::~RawPointerOtp() {
		delete[] mess;
	}

	void RawPointerOtp::encdec() {
		size_t i = 0;
		for(auto ch=mess, k=key.data();i<MESS_SIZE;++i,++ch,++k)
			(*ch) ^= *k;
	}

	const decltype(RawPointerOtp::mess)& RawPointerOtp::message() const {
		return mess;
	}

	VectorOtp::VectorOtp(const std::string& message) {
		std::copy(message.cbegin(), message.cend(), this->mess.begin());
	}

	void VectorOtp::encdec() {
		auto size = mess.size();
		for (auto i = 0; i < size; ++i)
			mess[i] ^= key[i];
	}

	const decltype(VectorOtp::mess)& VectorOtp::message() const {
		return mess;
	}

	IteratorOtp::IteratorOtp(const std::string& message):VectorOtp(message){}

	void IteratorOtp::encdec() {
		for (auto ch = mess.begin(), k = key.begin(); ch != mess.end(); ++ch, ++k)
			(*ch) ^= *k;
		//return std::transform(key.cbegin(), key.cend(), dest, [](auto key, auto mess) {return mess^key; });
	}

	const decltype(IteratorOtp::mess)& IteratorOtp::message() const {
		return mess;
	}
