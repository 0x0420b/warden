#include "BLL2.hpp"

#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>

#include "zlib.h"
#include "mio.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "cryptography/ARC4.hpp"
#include "ByteBuffer.hpp"


void BLL2::from_server_file(std::string const& filePath) {

	LOG_PROMPT << "Enter line at which module data starts (inclusive): ";
	int moduleStartLine;
	std::cin >> moduleStartLine;

	LOG_PROMPT << "Enter line at which module data ends (inclusive): ";
	int moduleEndLine;
	std::cin >> moduleEndLine;

	LOG_PROMPT << "Enter line containg ARC4 key data: ";
	int keyLine;
	std::cin >> keyLine;

	std::ifstream fstream(filePath);

	std::vector<uint8_t> moduleData(0x8000);

	std::string line;
	for (size_t i = 1; i < moduleStartLine; ++i)
		std::getline(fstream, line);

	for (size_t i = moduleStartLine; i <= moduleEndLine; ++i) {
		std::getline(fstream, line);

		std::string_view lineView = line;
		size_t ofs = 0;
		do {
			ofs = lineView.find('x', ofs);
			if (ofs == std::string::npos)
				break;

			size_t end = lineView.find(',', ofs + 1);

			std::string_view hexView = lineView.substr(ofs + 1, end - ofs - 1);
			uint32_t hexValue = std::stoi(std::string{ hexView }, nullptr, 16);
			moduleData.push_back(hexValue & 0xFF);

			ofs = end;
		} while (ofs != std::string::npos);
	}

	for (size_t i = moduleEndLine + 1; i < keyLine; ++i)
		std::getline(fstream, line);

	std::vector<uint8_t> keyData(16);

	std::getline(fstream, line); 
	std::string_view lineView = line;
	size_t ofs = 0;
	do {
		ofs = lineView.find('x', ofs);
		if (ofs == std::string::npos)
			break;

		size_t end = lineView.find(',', ofs + 1);
		std::string_view hexView = lineView.substr(ofs + 1, end - ofs - 1);
		uint32_t hexValue = std::stoi(std::string{ hexView }, nullptr, 16);
		keyData.push_back(hexValue & 0xFF);

		ofs = end;
	} while (ofs != std::string::npos);

	throw std::runtime_error("not implemented");
}