#ifndef LIBOTP_H
#define LIBOTP_H

#include <vector>
#include <random>
#include <algorithm>
#include <functional>
#include <iterator>
#include <string>

const size_t MESS_SIZE = 5000;

class Generator {
protected:
	std::vector<char> key = std::vector<char>(MESS_SIZE);
public:
	Generator();
	virtual void encdec() = 0;
	virtual ~Generator() {};
};

class RawPointerOtp : public Generator {
	char* mess;
public:
	RawPointerOtp(const std::string& message);
	void encdec() override;
	const decltype(mess)& message() const;
	~RawPointerOtp();
};

class VectorOtp : public Generator {
protected:
	//using Generator::key;
	std::vector<char> mess=std::vector<char>(MESS_SIZE);
public:
	VectorOtp(const std::string& message);
	void encdec() override;
	const decltype(mess)& message() const;
	virtual ~VectorOtp() {};
};

class IteratorOtp : public VectorOtp {
public:
	IteratorOtp(const std::string& message);
	void encdec() override;
	const decltype(mess)& message() const;
};
#endif // !LIBOTP_H
