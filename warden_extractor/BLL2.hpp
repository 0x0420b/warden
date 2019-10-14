#pragma once

#include <vector>
#include <cstdint>
#include <string>

#define LOG_INFO std::cout << "[*] "
#define LOG_ERROR std::cout << "[!] "
#define LOG_DUMP std::cout << "[+] "
#define LOG std::cout << "    "
#define LOG_SKIP std::cout << std::endl
#define LOG_PROMPT std::cout << "[?] "

#if _WIN64
# define HEX(V) "0x" << std::hex << std::setfill('0') << std::setw(16) << std::uppercase << (V)
#else
# define HEX(V) "0x" << std::hex << std::setfill('0') << std::setw(8) << std::uppercase << (V)
#endif

#define DEC(x) std::dec << (x)
#define DECPAD(X, P) std::dec << std::setfill(' ') << std::setw(P) << (X)

struct BLL2 {
	void from_client_file(std::string const& filePath);
	void from_server_file(std::string const& filePath);

	void process(size_t exportBase);

private:
	std::vector<uint8_t> _moduleData;
};