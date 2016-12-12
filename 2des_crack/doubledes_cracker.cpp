#include <iostream>
#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <future>
#include <map>
#include <array>
#include <limits>
#include <chrono>

#include <windows.h>
#include <psapi.h>

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

ulonglong MAX_KEY;//=(1ull << 26);

//key-encryption result
//value-key
std::map<DataType, block> firstStage;
auto enc = getEncryptor(Encryption::DES);

class DesKey {
private:
	//union just for debug purposes
	union {
		ulonglong counter;
		block bytes;
	};

	//union just for debug purposes
	union {
		block key;
		ulonglong _key;
	};

	void reflect() {
		for (auto i = 0; i < 8; i++) {
			key[i] = (counter&(0x7F << (7 * i))) >> ((7 * i) - 1);
		}
	}

public:
	explicit DesKey(ulonglong counter=0):counter(counter){
		reflect();
	}
	void operator++(int) {
		counter++;
		reflect();
	}
	bool operator<(ulonglong rhs) {
		return counter < rhs;
	}
	auto operator=(ulonglong rhs) {
		counter = rhs;
		reflect();
		return *this;
	}
	auto operator+=(ulonglong rhs) {
		counter += rhs;
		reflect();
		return *this;
	}
	operator block() { return key; }
	auto begin() { return key.begin(); }
	auto end() { return key.end(); }
	auto cbegin() { return key.cbegin(); }
	auto cend() { return key.cend(); }
};

thread_local DesKey decKey;

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

auto fill(std::unique_ptr<Encryptor>& enc, DesKey lastKey, ulonglong maxKey) {
	firstStage.clear();
	std::stringstream fs;
	try {
		while (lastKey<maxKey) {
			std::stringstream().swap(fs);
			fs.clear();
			enc->key(DataType(lastKey.cbegin(), lastKey.cend()));
			enc->encrypt();
			enc->write(fs);
			auto res = fs.str();
			//save only ciphertext, without padding
			firstStage[DataType(res.cbegin(), res.cbegin()+8)] = lastKey;
			lastKey++;
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

	print(std::this_thread::get_id(), " Offset: ", offset, '\n');

	while (true) {
		decKey = offset;
		wantFind->wait();

		std::string decryptionResult;
		try {
			while (!stop->get().first && decKey < maxKey && resIt == end) {
				dec->key(DataType(decKey.cbegin(), decKey.cend()));
				dec->decrypt();
				dec->write(ss);
				//find first 8 bytes, skip padding
				decryptionResult = ss.str();
				//print(std::this_thread::get_id(), ":Key: ", form_key(dec->key()), " Result: ", form_key({ decryptionResult.begin(), decryptionResult.end() }), '\n');
				resIt = firstStage.find(DataType(decryptionResult.cbegin(), decryptionResult.cbegin()+8));
				std::stringstream().swap(ss);
				ss.clear();
				decKey += increment;
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

	DesKey lastKey(0);

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
			threads[i] = std::thread(find, std::move(dec), i, num_workers, &wantFind, &findEnds, &result, MAX_KEY);
		}
	//}

	while (true) {

		while (!findEnds.get().first) {
			//prepare data before find
			findEnds.exec([](auto& pair) {pair.first = pair.second = 0; });
			std::cout << "Start filling" << std::endl;
			auto startTime = std::chrono::system_clock::now();
			lastKey = fill(enc, lastKey, MAX_KEY);
			std::cout << "Filled" << std::endl;
			std::cout << "Filling has taken " << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - startTime).count() << " seconds" << std::endl;

			PROCESS_MEMORY_COUNTERS_EX pmc;
			GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc), sizeof(pmc));
			SIZE_T virtualMemUsedByMe = pmc.PrivateUsage;

			std::cout << "Virtual memory usage: " << virtualMemUsedByMe << " bytes" << std::endl;
			//std::cin >> std::string();
			wantFind.set(true);
			//run workers
			startTime = std::chrono::system_clock::now();
			wantFind.notify_all();
			//sleep until find end
			findEnds.wait([&threads](auto& p) {return p.first || p.second == threads.size(); });
			std::cout << "Finding has taken " << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - startTime).count() << " seconds" << std::endl;
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
	auto enc = getEncryptor(Encryption::DES2);
	if (argc < 2) {
		std::cout << "Please, specify path to file and key" << std::endl;
		std::exit(1);
	}
	if (argc < 3) {
		std::cout << "Please, specify keys" << std::endl;
		std::exit(1);
	}
	if (argc < 4) {
		std::cout << "Please, specify the maximum number of keys to search against" << std::endl;
		std::exit(1);
	}
	std::cout << "Path to file: " << argv[1] << std::endl;
	auto file = std::ifstream(argv[1], std::ios::in|std::ios::binary);
	std::cout << "Key: " << argv[2] << std::endl;
	DataType key((std::istream_iterator<int>(std::stringstream(argv[2]))),
							std::istream_iterator<int>());

	std::cout << "Maximum number of keys: " << argv[3] << std::endl;
	std::stringstream(argv[3]) >> MAX_KEY;

	if (!file) {
		std::cerr << "Cannot open file" << argv[1] << std::endl;
		std::exit(2);
	}
	size_t thread_num = 0;
	if (argc == 5)
		std::stringstream(argv[4]) >> thread_num;

	std::string message;
	std::istreambuf_iterator<char> iter(file), end;
	message.assign(iter, end);
	file.seekg(0);
	file.clear();
	std::cout << std::endl << "-------------Message-----------" << std::endl << message << std::endl;
	std::stringstream plaintext;
	plaintext << message;
	enc->read(plaintext);
	
	//auto key = DataType({1,2,3,4,5,6,7,8/*,9,0xA,0xB,0xC,0xD,0xE,0xF,0*/});

	enc->key(key);
	enc->encrypt();

	std::stringstream cts;
	enc->write(cts);
	//enc->read(cts);

	//enc->key(key2);
	//enc->encrypt();

	//std::stringstream().swap(cts);
	//cts.clear();

	//enc->write(cts);
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

	auto foudKey=crack_impl(message, ciphertext, thread_num);
}