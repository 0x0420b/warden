#include "BLL2.hpp"

#include <unordered_map>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <fstream>

#include "zlib.h"
#include "mio.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "cryptography/ARC4.hpp"
#include "ByteBuffer.hpp"

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

static std::unordered_map<uint32_t, offset_info_t> offsets{
	// v                     module      size    key           pkMod       pkSz      exp         expSz
	{ (15595 << 8) | 0x86, { 0x007D76D0, 0x2A9D, 0x007DA170, { 0x007D7488, 0x200}, { 0x007D7484, 0x004 } } },
	{ (15595 << 8) | 0x64, { 0x009CC3C0, 0x1D96, 0x009CE158, { 0x009CC1A0, 0x200}, { 0x009CC194, 0x004 } } }
};

void BLL2::from_client_file(std::string const& filePath) {
	std::string fileName = std::filesystem::path{ filePath }.filename().string();

	mio::mmap_source fileSource(filePath);

	LOG_INFO << fileName << " opened." << std::endl;

	// TODO: Retrieve arch and build from file handle
#ifdef _WIN64
	offset_info_t const& offsetInfo = offsets[(15595 << 8) | 0x64];
#else
    offset_info_t const& offsetInfo = offsets[(15595 << 8) | 0x86];
#endif

	LOG_INFO << "Default module found at " << fileName << "+" << HEX(offsetInfo.module) << " (" << DEC(offsetInfo.moduleSize) << ")." << std::endl;
	LOG_INFO << "ARC4 key found at " << fileName << "+" << HEX(offsetInfo.key) << "." << std::endl;

	std::vector<uint8_t> compressedModuleData(offsetInfo.moduleSize);
	memcpy(compressedModuleData.data(), fileSource.data() + offsetInfo.module, offsetInfo.moduleSize);

	{ // ARC4 pass
        shared::crypto::ARC4 rcCipher(reinterpret_cast<const uint8_t*>(fileSource.data()) + offsetInfo.key, 16);
		rcCipher.UpdateData(compressedModuleData.size(), compressedModuleData.data());
	}

	{ // Parse
		ByteBuffer compressedModule(compressedModuleData);

		uint32_t decompressedSize;
		std::vector<uint8_t> compressedData(compressedModuleData.size() - 520); // (512 + 4 + 4) // zlib'd BLL2 archive
		uint32_t signatureMarker;

		std::vector<uint8_t> signatureBytes(512);

		compressedModule >> decompressedSize >> compressedData >> signatureMarker >> signatureBytes;

		if (signatureMarker != 'SIGN')
			throw std::runtime_error("Module enveloppe signature does not match.");

		// TODO: Figure out the crypto shiz

		{ // zlib
			_moduleData.resize(decompressedSize);

			z_stream stream;
			stream.zalloc = 0;
			stream.zfree = 0;
			stream.avail_in = uint32_t(compressedData.size());
			stream.next_in = compressedData.data();
			stream.avail_out = uint32_t(_moduleData.size());
			stream.next_out = _moduleData.data();
			auto inflateInitResult = inflateInit(&stream);
			if (inflateInitResult == Z_OK) {
				inflateInitResult = inflate(&stream, Z_FINISH);
				if (inflateInitResult == Z_STREAM_END)
					_moduleData.resize(stream.total_out);

				std::ofstream f("test.app", std::ios::binary);
				f.write(reinterpret_cast<char*>(_moduleData.data()), _moduleData.size());
				f.flush();
				f.close();
			}
			else
				throw std::runtime_error(std::string{ "Decompression error: " } + stream.msg + ".");
		}
	}
}
