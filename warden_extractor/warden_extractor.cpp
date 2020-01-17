#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <string_view>

#include "cryptography/ARC4.hpp"
#include "cryptography/SHA256.hpp"
#include "cryptography/BigNumber.hpp"
#include "ByteBuffer.hpp"
#include "mio.hpp"
#include "zlib/zlib.h"

#include "BLL2.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#if _WIN64
# define HEXMOD(V) "0x" << std::hex << std::setfill('0') << std::setw(16) << std::uppercase << (V)
#else
# define HEXMOD(V) "0x" << std::hex << std::setfill('0') << std::setw(8) << std::uppercase << (V)
#endif

struct offset_info_t {
	size_t module;
	size_t moduleSize;
	size_t key;
	struct {
		size_t offset;
		size_t length;
	} pkMod;
	struct {
		size_t offset;
		size_t length;
	} pkExp;
};

void deconstruct(std::vector<uint8_t> const& buffer, size_t baseAdress);

static std::unordered_map<uint32_t, offset_info_t> offsets {
	// v                     module      size    key           pkMod        pkSz      exp         expSz
	{ (15595 << 8) | 0x86, { 0x007D76D0, 0x2A9D, 0x007DA170, { 0x007D7488, 0x200}, { 0x007D7484, 0x004 } } },
	{ (15595 << 8) | 0x64, { 0x009CC3C0, 0x1D96, 0x009CE358, { 0x009CC1A0, 0x200}, { 0x009CC194, 0x004 } } }
};

/// Reads hex value from cin
size_t read_hex_str(std::string_view prompt, std::string_view errorPrompt) {
	std::cout << prompt;
	while (true) {
		try {
			std::string str;
			std::cin >> str;
			if (str[0] != '0' && str[1] != 'x')
				throw std::runtime_error("");

			str[0] = ' ';
			str[1] = ' ';

			return std::stoull(str, nullptr, 16);
		}
		catch (std::runtime_error const& /* re */) {
			std::cout << errorPrompt;
		}
	}
}

std::unique_ptr<BLL2> loadFromExecutable(std::string const& filePath);
std::unique_ptr<BLL2> loadFromServer(std::string const& filePath, std::string const& architecture, uint32_t clientBuild);

int main(int argc, char* argv[])
{
	try {
		std::unique_ptr<BLL2> parser;

		std::vector<std::string> args(argv + 1, argv + argc);
		if (args[0] == "--client") {
			if (args.size() != 2)
				throw std::out_of_range("warden_extractor.exe --client <path-to-client-binary>");
			
			parser = loadFromExecutable(args[1]);
		}
		else if (args[0] == "--server") {
			try {
				if (args.size() != 4 || (args[2] != "x86" && args[2] != "x64"))
					throw std::runtime_error("");

				uint32_t clientBuild = std::stoi(args[3], nullptr, 10);
				parser = loadFromServer(args[1], args[2], clientBuild);
			}
			catch (std::runtime_error const&) {
				throw std::out_of_range("warden_extractor.exe --server <path-to-cpp-file> <x86|x64> <client-build>");
			}
		}
		else {
			throw std::out_of_range("warden_extractor.exe (--client <path-to-client-binary>) || (--server <path-to-cpp-file> <x86|x64> <client-build>)");
		}

		size_t exportBase = read_hex_str("[?] Please enter base adress for extraction: ", "[?] Invalid hexadecimal number. Please enter base adress for extraction: ");
		parser->process(exportBase);

		return 0;
	} catch (std::out_of_range const& oor) {
		std::cerr << oor.what() << std::endl;

		return -1;
	} catch (std::runtime_error const& re) {
		std::cerr << "[!] " << re.what() << std::endl;

		return -2;
	}
}

std::unique_ptr<BLL2> loadFromExecutable(std::string const& filePath) {
	BLL2* parser = new BLL2();
	parser->from_client_file(filePath);
	return std::unique_ptr<BLL2>(parser);
}

std::unique_ptr<BLL2> loadFromServer(std::string const& filePath, std::string const& architecture, uint32_t clientBuild) {
	BLL2* parser = new BLL2();
	parser->from_server_file(filePath);
	return std::unique_ptr<BLL2>(parser);
}