#include <iostream>
#include <fstream>
#include <sstream>
#include <crypt.h>
#include <atomic>
#include <thread>
#include <future>
#include <map>
#include <array>
#include <limits>

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

	enc->read(plaint);
	dec->read(ciphert);

	enc->encrypt();
	dec->decrypt();

	std::ostringstream encrypted, decrypted;

	enc->write(encrypted);
	dec->write(decrypted);

	return encrypted.str() == decrypted.str();
}

using lblock = unsigned long long;
using block = std::array<unsigned char, 8>;

std::map<DataType, block> firstStage;
auto enc = getEncryptor(Encryption::DES);

union Key {
	lblock _key;
	block key;
} decKey;

template<T>
class Signal {
	std::condition_variable cv;
	T var;
	std::mutex mu;

public:
	Signal(std::condition_variable cv, T v, std::mutex m):cv(cv),var(v),mu(m){}

	void notify_one() {
		cv.notify_one();
	}

	void notify_all() {
		cv.notify_all();
	}

	void wait() {
		std::unique_lock<std::mutex> lock(mu);
		cv.wait(lock, [] {return f(var); });
	}

	template<void(T&)>
	exec(f) {
		std::lock_guard<std::mutex> lock(mu);
		f(var);
	}

	T get() {
		return var;
	}

};

auto fill(std::unique_ptr<Encryptor>& enc, Key lastKey) {
	firstStage.clear();
	std::stringstream fs;
	try {
		while (true) {
			lastKey._key++;
			enc->key(DataType(&lastKey.key[0], &lastKey.key[lastKey.key.size()]));
			enc->encrypt();
			enc->write(fs);
			auto res = fs.str();
			firstStage[DataType(res.cbegin(), res.cend())] = lastKey.key;
		}
	}
	//shit
	catch (std::bad_alloc&) {
		return lastKey;
	}
}

auto find(std::unique_ptr<Encryptor> dec,
			unsigned int offset,
			unsigned int increment,

			//Signal& run,
			bool* wantFind,
			std::condition_variable* timeTofind,
			std::mutex* timeToFindMutex,
			//Signal& stop,
			//std::condition_variable 

			std::promise<DataType>* result,
			//should be atomic as we read and write it
			//in multiple threads
			//Signal& success,
			std::atomic_bool* found) {
	std::stringstream ss;
	decltype(firstStage)::const_iterator resIt;
	while (true) {
		decKey._key = 0ul;
		std::unique_lock<std::mutex> lock(*timeToFindMutex);
		timeTofind->wait(lock, [wantFind] {return *wantFind; });
		auto end = firstStage.end();

		while (!found && decKey._key < std::numeric_limits<lblock>::max() && resIt == end) {
			decKey._key+=offset;
			dec->key(DataType(&decKey.key[0], &decKey.key[decKey.key.size()]));
			dec->decrypt();
			dec->write(ss);
			auto decryptionResult = ss.str();
			resIt = firstStage.find(DataType(decryptionResult.begin(), decryptionResult.end()));
		}
		if (found) {

			return;
		}
		if (resIt != end) {
			found->store(true);
			auto res = resIt->second;
			result->set_value(DataType(res.cbegin(), res.cend()));
			return;
		}
	}
}

auto crack_impl(std::string& plaintext, std::string& ciphertext) {
	DataType key(8);
	auto enc = getEncryptor(Encryption::DES);

	std::istringstream plaint(std::string(plaintext, 0, 8)), ciphert(std::string(ciphertext, 0, 8));
	enc->read(plaint);

	Key lastKey;
	lastKey._key = 0UL;

	//find must start flag
	std::atomic_bool wantFind = false;
	std::mutex wantFindMutex;
	std::condition_variable timeToFind;

	//find success flag
	std::atomic_bool findSuccess(false);

	//number of finished threads
	unsigned int finishedThreads=0;
	//mutex to protect finishedThreads
	std::mutex findEndsMutex;
	//we have only one condition variable
	//as finished thread always notify it
	//regardless of it failed or succeed
	std::condition_variable findEnds;

	//find result
	std::promise<DataType> result;

	const auto num_threads = std::thread::hardware_concurrency();
	//working threads
	std::vector<std::thread> threads(num_threads - 1);
	{
		thread_joiner joiner(threads);
		for (size_t i = 0; i < threads.size(); ++i) {
			auto dec = getEncryptor(Encryption::DES);
			dec->read(ciphert);
			threads[i] = std::thread(find, std::move(dec), i, num_threads, &wantFind, &timeToFind, &wantFindMutex, &result, &findSuccess);
		}
	}

	while (!findSuccess) {
		//prepare data before find
		findSuccess = false;
		finishedThreads = 0;
		lastKey=fill(enc, lastKey);
		{
			std::unique_lock<std::mutex> lock(wantFindMutex);
			wantFind = true;
		}
		//run workers
		timeToFind.notify_all();
		std::unique_lock<std::mutex> lock(findEndsMutex);
		//sleep until find end
		findEnds.wait(lock, [&finishedThreads, &threads, &findSuccess] {return finishedThreads == threads.size() || findSuccess; });
	}

	auto res = result.get_future().get();
	std::cout << std::hex << res.data();

	std::istringstream plaint(std::string(plaintext, 0, 8)), ciphert(std::string(ciphertext, 0, 8));
	enc->read(plaint);
	dec->read(ciphert);

	std::ostringstream encrypted, decrypted;
	try {
		do {
			encrypted.seekp(0);
			encrypted.clear();
			decrypted.seekp(0);
			decrypted.clear();
			generate();
			enc->key(key);
			dec->key(key);
			enc->encrypt();
			dec->decrypt();
			enc->write(encrypted);
			dec->write(decrypted);
		} while (encrypted.str() != decrypted.str() && !findSuccess->load() && !realKey(plaintext, ciphertext, key));
		findSuccess->store(true);
		result->set_value(key);
		//encrypted.seekp(0);
		//encrypted.clear();
		//decrypted.seekp(0);
		//decrypted.clear();
		//
		//plaint.seekg(0);
		//plaint.clear();

		//ciphert.seekg(0);
		//ciphert.clear();

		//plaint.read(&plaintext[8], plaintext.size() - 8);
		//ciphert.read(&ciphertext[8], ciphertext.size() - 8);

		//enc->read(plaint);
		//dec->read(ciphert);

		//enc->encrypt();
		//dec->decrypt();

		//enc->write(encrypted);
		//dec->write(decrypted);

		//if (encrypted.str() == decrypted.str()) {
		//	done->store(true);
		//	result->set_value(key);
		//}
	}
	catch (...) {
		try {
			result->set_exception(std::current_exception());
			findSuccess->store(true);
		}
		catch(...){}
	}
}

void main(int argc, char* argv[]) {
	auto des = getEncryptor(Encryption::DES);
	if (argc < 2) {
		std::cout << "Please, specify path to file" << std::endl;
		std::exit(1);
	}
	std::cout << argv[1] << std::endl;
	auto file = std::ifstream(argv[1], std::ios::in|std::ios::binary);
	if (!file) {
		std::cout << "Cannot open file" << argv[1] << std::endl;
		std::exit(2);
	}
	bool mt = false;
	if (argc == 3)
		mt = true;

	std::string message;
	std::istreambuf_iterator<char> iter(file), end;
	message.assign(iter, end);
	file.seekg(0);
	file.clear();
	//message+='\0';
	std::cout << "Message:" << message << std::endl<<std::endl;
	std::stringstream plaintext;
	plaintext << message;
	des->read(plaintext);
	
	auto key = DataType({1,2,3,4,5,6,7,8});

	des->key(key);
	des->encrypt();
	std::stringstream cts;
	des->write(cts);
	des->read(cts);
	des->encrypt();

	std::stringstream().swap(cts);
	cts.clear();

	des->write(cts);
	std::string ciphertext=cts.str();
	std::cout << ciphertext;

	des->read(cts);

	std::stringstream().swap(cts);
	cts.clear();

	des->decrypt();
	des->write(cts);
	des->read(cts);
	des->decrypt();

	std::stringstream().swap(cts);
	cts.clear();

	des->write(cts);
	
	std::cout << cts.str();

	if (mt) {
		std::cout << "---------MULTITHREAD-----------" << std::endl;
		crack_impl();
	}
	else
	{
		//single-thread
		std::cout << "---------SINGLE THREAD-----------" << std::endl;
		std::default_random_engine engine;
		std::uniform_int_distribution<int> distr(0, 255);
		auto gen = std::bind(distr, engine);
		DataType possible_key(8);
		auto generate = [&key, &gen]() {
			std::generate(key.begin(), key.end(), [&gen]() {return static_cast<char>(gen()); });
		};
		auto enc = getEncryptor(Encryption::DES);
		auto dec = getEncryptor(Encryption::DES);
		std::istringstream plaint(message), ciphert(ciphertext);
		enc->read(plaint);
		dec->read(ciphert);
		std::ostringstream encrypted, decrypted;
		do {
			std::ostringstream().swap(encrypted);
			encrypted.clear();
			std::ostringstream().swap(decrypted);
			decrypted.clear();
			//generate();
			enc->key(possible_key);
			dec->key(possible_key);
			enc->encrypt();
			dec->decrypt();
			enc->write(encrypted);
			dec->write(decrypted);
			std::cout << ".";
		} while (encrypted.str() != decrypted.str());
		std::cout << std::hex << possible_key.data();
	}
}