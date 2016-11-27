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

template<typename T>
class Signal {
	std::condition_variable&& cv;
	std::mutex&& mu;
	T&& var;
	std::function<void(T&)> finalizer;

public:
	Signal(std::condition_variable&& cv, std::mutex&& m, T&& v):cv(std::move(cv)),mu(std::move(m)),var(std::move(v)){}
	Signal(T&& v):cv(std::move(std::condition_variable())),mu(std::move(std::mutex())),var(std::move(v)){}

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

	T& get() {
		return var;
	}

	~Signal() {
		finalizer(var);
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
			const unsigned int increment,

			Signal<bool>* wantFind,

			//contains find success flag and
			//number of finished threads
			//decremented after end of find
			Signal<std::pair<std::atomic_bool, unsigned int>>* stop,
			
			//here result is stored
			std::promise<DataType>* result) {
	std::stringstream ss;
	decltype(firstStage)::const_iterator resIt;

	auto end = firstStage.end();
	while (true) {
		decKey._key = 0ul;
		wantFind->wait();

		try {
			while (!stop->get().first && decKey._key < std::numeric_limits<lblock>::max() && resIt == end) {
				decKey._key += offset;
				dec->key(DataType(&decKey.key[0], &decKey.key[decKey.key.size()]));
				dec->decrypt();
				dec->write(ss);
				auto decryptionResult = ss.str();
				resIt = firstStage.find(DataType(decryptionResult.begin(), decryptionResult.end()));
			}
			if (stop->get().first) {
				stop->exec([](auto& p) {p.second++; });
				stop->notify_one();
				return;
			}
			if (resIt != end) {
				auto res = resIt->second;
				result->set_value(DataType(res.cbegin(), res.cend()));
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

auto crack_impl(std::string& plaintext, std::string& ciphertext) {
	DataType key(8);
	auto enc = getEncryptor(Encryption::DES);

	//read only first block
	std::istringstream plaint(std::string(plaintext, 0, 8)), ciphert(std::string(ciphertext, 0, 8));
	enc->read(plaint);

	Key lastKey;
	lastKey._key = 0UL;

	//find must start flag
	Signal<bool> wantFind(std::condition_variable(), std::mutex(), false);

	//find success flag and number of finished threads
	Signal<std::pair<std::atomic_bool, unsigned int>> findEnds(/*std::condition_variable(), std::mutex(),*/ std::make_pair(false,0u));

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
			threads[i] = std::thread(find, std::move(dec), i, num_threads, &wantFind, &findEnds, &result);
		}
	}

	while (true) {

		while (!findEnds.get().first) {
			//prepare data before find
			findEnds.exec([](auto& pair) {pair.first = pair.second = 0; });
			lastKey = fill(enc, lastKey);
			wantFind.set(true);
			//run workers
			wantFind.notify_all();
			//sleep until find end
			findEnds.wait([&threads](auto& p) {return p.first || p.second == threads.size(); });
		}

		auto res = result.get_future().get();
		if (realKey(plaintext, ciphertext, res)) {
			std::cout << std::hex << res.data();
			break;
		}
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
	
	auto key = DataType({1,2,3,4,5,6,7,8/*,9,0xA,0xB,0xC,0xD,0xE,0xF,0*/});

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
		crack_impl(message, ciphertext);
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