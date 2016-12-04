#include <iostream>
#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <future>
#include <map>
#include <array>
#include <limits>

#include "printer.h"

#include <crypt.h>

class thread_joiner {
	std::vector<std::thread>& threads;
public:
	thread_joiner(std::vector<std::thread>& thr):threads(thr){}
	~thread_joiner() {
		for (auto& thread : threads) {
			if (thread.joinable())
				thread.join();
		}
	}
};

bool realKey(const std::string& plaintext, const std::string& ciphertext, const DataType& key) {
	std::istringstream plaint(plaintext), ciphert(ciphertext);

	auto enc = getEncryptor(Encryption::DES);
	auto dec = getEncryptor(Encryption::DES);

	enc->key({ key.begin(), key.begin() + 8 });
	dec->key({ key.begin() + 8, key.end() });

	enc->read(plaint);
	dec->read(ciphert);

	enc->encrypt();
	dec->decrypt();

	std::ostringstream encrypted, decrypted;

	enc->write(encrypted);
	dec->write(decrypted);

	return encrypted.str() == decrypted.str();
}

std::string form_key(const DataType& key) {
	std::stringstream ss;
	std::for_each(key.cbegin(), key.cend(), [&ss](auto& arg) {ss << std::hex << (int)arg; });
	return ss.str();
}


using ulonglong = unsigned long long;
using block = std::array<unsigned char, 8>;

const ulonglong MAX_KEY = (1ull << 24);

//key-encryption result
//value-key
std::map<DataType, block> firstStage;
auto enc = getEncryptor(Encryption::DES);

thread_local
union Key {
	ulonglong _key;
	block key;
}decKey;

//combines conditional variable,
//mutex
//and variable
//to represent signal
//and provide functions to notify and modify variable under mutex lock
template<typename T>
class Signal {
	std::condition_variable cv;
	std::mutex mu;
	T var;
	std::function<void(T&)> finalizer = [](auto&) {};

public:
	//Signal(std::condition_variable&& cv, std::mutex&& m, T&& v) {
	//	std::swap(this->cv, std::forward(cv));
	//	std::swap(mu, m);
	//	std::swap(var, v);
	//}
	Signal(T&& v, std::function<void(T&, T&)> loader = [](T& src, T& dst) {dst = src; }) {
		//std::swap(cv, std::condition_variable());
		//std::swap(mu, std::mutex());
		loader(v, var);
		//std::swap(var, v);
	}

	void notify_one() {
		cv.notify_one();
	}

	void notify_all() {
		cv.notify_all();
	}

	void wait(std::function<bool(T&)> f) {
		std::unique_lock<std::mutex> lock(mu);
		cv.wait(lock,[&f,this]{return f(this->var); });
	}
	void wait() {
		wait([](auto& v) {return !!v; });
	}

	void exec(std::function<void(T&)> f) {
		std::lock_guard<std::mutex> lock(mu);
		f(var);
	}

	void set(T&& newVal) {
		std::lock_guard<std::mutex> lock(mu);
		var = newVal;
	}

	const T& get() {
		return var;
	}

	~Signal() {
		finalizer(var);
	}

};

auto fill(std::unique_ptr<Encryptor>& enc, Key lastKey, ulonglong maxKey) {
	firstStage.clear();
	std::stringstream fs;
	//make key even
	lastKey._key - lastKey._key % 2;
	try {
		while (lastKey._key<maxKey) {
			std::stringstream().swap(fs);
			fs.clear();
			//skip every second key as must least bit is irrelevant
			lastKey._key += 2;
			enc->key(DataType(lastKey.key.begin(), lastKey.key.end()));
			enc->encrypt();
			enc->write(fs);
			auto res = fs.str();
			//save only ciphertext, without padding
			firstStage[DataType(res.cbegin(), res.cbegin()+8)] = lastKey.key;
		}
	}
	//shit
	catch (std::bad_alloc&) {
		return lastKey;
	}
}

auto find(std::unique_ptr<Encryptor> dec,
			unsigned int offset,
			const unsigned int increment,

			Signal<bool>* wantFind,

			//contains find success flag and
			//number of finished threads
			//incremented after end of find
			Signal<std::pair<std::atomic_bool, unsigned int>>* stop,
			
			//here result is stored
			std::promise<DataType>* result,
			ulonglong maxKey) {
	std::stringstream ss;
	auto end = firstStage.cend();
	auto resIt=end;

	decKey._key = 0;

	print(std::this_thread::get_id(), " Offset: ", offset, '\n');

	while (true) {
		decKey._key = offset;
		wantFind->wait();

		std::string decryptionResult;
		try {
			while (!stop->get().first && decKey._key < maxKey && resIt == end) {
				dec->key(DataType(decKey.key.cbegin(), decKey.key.cend()));
				dec->decrypt();
				dec->write(ss);
				//find first 8 bytes, skip padding
				decryptionResult = ss.str();
				//print(std::this_thread::get_id(), ":Key: ", form_key(dec->key()), " Result: ", form_key({ decryptionResult.begin(), decryptionResult.end() }), '\n');
				resIt = firstStage.find(DataType(decryptionResult.cbegin(), decryptionResult.cbegin()+8));
				std::stringstream().swap(ss);
				ss.clear();
				decKey._key += increment;
			}
			if (stop->get().first) {
				stop->exec([](auto& p) {p.second++; });
				stop->notify_one();
				return;
			}
			if (resIt != end) {
				auto res = DataType(resIt->second.cbegin(), resIt->second.cend());
				res.insert(res.end(), dec->key().cbegin(), dec->key().cend());
				print(std::this_thread::get_id(),
					":Possible key: ",
					form_key(res),
					" Decrypted: ",
					form_key(resIt->first),
					'\n');
				result->set_value(res);
				stop->exec([](auto& p) {p.first = true; p.second++; });
				//here we notify only controlling thread
				//as workers does not sleep on this condition variable
				stop->notify_one();
				return;
			}
		}
		catch (...) {
			try {
				result->set_exception(std::current_exception());
				//notify that we find exception))
				stop->exec([](auto& p) {p.first=true; });
				stop->notify_one();
			}
			catch (...) {}
		}
	}
}

auto crack_impl(std::string& plaintext, std::string& ciphertext, size_t thread_num=0) {
	DataType key(8);
	auto enc = getEncryptor(Encryption::DES);

	//read only first block
	//read part of ciphertext as padding
	std::istringstream plaint(std::string(plaintext, 0, 8)), ciphert(std::string(ciphertext, 0, 8*3));
	enc->read(plaint);

	Key lastKey;
	lastKey._key = 0UL;

	//find must start flag
	Signal<bool> wantFind(false);

	//find success flag and number of finished threads
	Signal<std::pair<std::atomic_bool, unsigned int>> findEnds(/*std::condition_variable(), std::mutex(),*/ std::make_pair(false,0u),
															   [](auto& src, auto& dst) {dst.first = src.first.load(); dst.second = src.second; });

	//find result
	std::promise<DataType> result;
	auto res_future = result.get_future();

	const auto num_workers = thread_num ? thread_num : (std::thread::hardware_concurrency()-1);
	//working threads
	std::vector<std::thread> threads(num_workers);
	//{
		thread_joiner joiner(threads);
		for (size_t i = 0; i < threads.size(); ++i) {
			auto dec = getEncryptor(Encryption::DES);
			dec->read(ciphert);
			ciphert.seekg(0);
			ciphert.clear();
			threads[i] = std::thread(find, std::move(dec), i*2, num_workers*2, &wantFind, &findEnds, &result, MAX_KEY);
		}
	//}

	while (true) {

		while (!findEnds.get().first) {
			//prepare data before find
			findEnds.exec([](auto& pair) {pair.first = pair.second = 0; });
			lastKey = fill(enc, lastKey, MAX_KEY);
			std::cout << "Filled" << std::endl;
			//std::cin >> std::string();
			wantFind.set(true);
			//run workers
			wantFind.notify_all();
			//sleep until find end
			findEnds.wait([&threads](auto& p) {return p.first || p.second == threads.size(); });
		}

		auto res=res_future.get();
		if (realKey(plaintext, ciphertext, res)) {
			print("Good key found: ", form_key(res));
			return res;
		}
		else {
			print("Wrong key found: ", form_key(res));
			return res;
		}
		break;
	}

}

void main(int argc, char* argv[]) {
	auto enc = getEncryptor(Encryption::DES);
	if (argc < 2) {
		std::cout << "Please, specify path to file and key" << std::endl;
		std::exit(1);
	}
	if (argc < 4) {
		std::cout << "Please, specify keys" << std::endl;
		std::exit(1);
	}
	std::cout << "Path to file: " << argv[1] << std::endl;
	auto file = std::ifstream(argv[1], std::ios::in|std::ios::binary);
	std::cout << "Keys: " << argv[2] << argv[3] << std::endl;
	DataType key1((std::istream_iterator<int>(std::stringstream(argv[2]))),
							std::istream_iterator<int>());
	DataType key2((std::istream_iterator<int>(std::stringstream(argv[3]))),
							std::istream_iterator<int>());

	//auto key=DataType(std::vector<ubyte>(argv[2], argv[2]+8));

	if (!file) {
		std::cerr << "Cannot open file" << argv[1] << std::endl;
		std::exit(2);
	}
	if (key1.size() != 8 || key2.size() != 8) {
		std::cerr << "Keys length must be 8" << std::endl;
		std::exit(3);
	}
	size_t thread_num = 0;
	if (argc == 5)
		std::stringstream(argv[4]) >> thread_num;

	std::string message;
	std::istreambuf_iterator<char> iter(file), end;
	message.assign(iter, end);
	file.seekg(0);
	file.clear();
	//message+='\0';
	std::cout << std::endl << "-------------Message-----------" << std::endl << message << std::endl;
	std::stringstream plaintext;
	plaintext << message;
	enc->read(plaintext);
	
	//auto key = DataType({1,2,3,4,5,6,7,8/*,9,0xA,0xB,0xC,0xD,0xE,0xF,0*/});

	enc->key(key1);
	enc->encrypt();

	std::stringstream cts;
	enc->write(cts);
	enc->read(cts);

	enc->key(key2);
	enc->encrypt();

	std::stringstream().swap(cts);
	cts.clear();

	enc->write(cts);
	std::string ciphertext=cts.str();

	/*
	std::cout << ciphertext;

	enc->read(cts);

	std::stringstream().swap(cts);
	cts.clear();

	enc->decrypt();
	enc->write(cts);
	enc->read(cts);
	enc->key(key1);
	enc->decrypt();

	std::stringstream().swap(cts);
	cts.clear();

	enc->write(cts);
	
	std::cout << cts.str();
	*/

	auto key=crack_impl(message, ciphertext, thread_num);
}