#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <fstream>
#include <vector>
#include <random>
#include <algorithm>
#include <functional>

using ubyte = unsigned char;
using DataType = std::vector<ubyte>;

class Encryptor {
private:
	DataType _key; //encryption key
	DataType text; //text from source
	DataType result; //result of encryption/decryption

	virtual DataType encrypt(const DataType& text, const DataType& key) = 0;
	virtual DataType decrypt(const DataType& text, const DataType& key) = 0;
	virtual bool checkKey(const DataType& key) = 0;

public:
	void key(const DataType& key);
	DataType key() const;
	void read(std::istream& input);
	void write(std::ostream& out);
	void encrypt();
	void decrypt();
	virtual ~Encryptor(){}
};
#endif // !ENCRYPTOR_H