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

			return std::stoul(str, nullptr, 16);
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

void deconstruct(std::vector<uint8_t> const& buffer, size_t baseAdress) {
	struct header_t {
		uint32_t m_magic;
		uint32_t m_major;
		uint32_t m_minor;
		uint32_t m_allocationSize;
		uint32_t m_dllMainRVA;
		struct {
			uint32_t m_rva;
			uint32_t m_count;
		} m_relocationData;
		struct {
			uint32_t m_rva;
			uint32_t m_max;
			uint32_t m_min;
		} m_exports;
		struct {
			uint32_t m_rva;
			uint32_t m_count;
		} m_moduleData;
		struct {
			uint32_t m_rva;
			uint32_t m_count;
		} m_rtlAddFunctionTable;
		uint32_t unk38;
		uint32_t unk3C;
		uint32_t m_protectionCount;
	};

	static_assert(sizeof(header_t) == 0x44, "Invalid header size");

	struct memory_protection_t {
		uint32_t m_rva;
		uint32_t m_size;
		uint32_t m_flags;
	};

	static_assert(sizeof(memory_protection_t) == 12, "Invalid protection size");

	struct fcc {
		fcc(char(&c)[4]) {
			memcpy(m_str, c, 4);
			m_str[4] = '\0';
		}

		fcc(uint32_t v) {
			memcpy(m_str, &v, 4);
			m_str[4] = '\0';
		}

		const char* c_str() const {
			return m_str;
		}

		char m_str[5];
	};

	ByteBuffer buf(buffer);
	header_t* header = buf.insitu<header_t>();

	std::cout << "\r\n[*] Deconstruction started.\n";
	std::cout << "[+] Magic: " << HEXMOD(header->m_magic) << " (" << fcc{ header->m_magic }.c_str() << ")\r\n";
	std::cout << "[+] Major: " << std::dec << header->m_major << "\r\n";
	std::cout << "[+] Minor: " << std::dec << header->m_minor << "\r\n";
	std::cout << "[+] Allocation size: " << std::dec << header->m_allocationSize << "\r\n";
	std::cout << "[+] DllMain RVA: " << HEXMOD(header->m_dllMainRVA) << "\r\n";
	std::cout << "[+] Exports RVA: " << HEXMOD(header->m_exports.m_rva) << "\r\n";
	std::cout << "[+] RTL Function table: " << HEXMOD(header->m_rtlAddFunctionTable.m_rva) << "\r\n";

	struct scoped_mem_t final {
	private:
		uint8_t* _ref;

	public:
		scoped_mem_t(uint32_t mem) noexcept {
			_ref = static_cast<uint8_t*>(VirtualAlloc(NULL, mem, MEM_COMMIT, PAGE_READWRITE));
		}

		~scoped_mem_t() noexcept {
			VirtualFree(_ref, 0, MEM_RELEASE);
		}

		operator uint8_t* () noexcept {
			return _ref;
		}

		uint8_t* operator + (size_t ofs) const {
			return _ref + ofs;
		}

		size_t ptr() {
			return reinterpret_cast<size_t>(_ref);
		}
	};

	scoped_mem_t allocatedMemory(header->m_allocationSize);

#pragma warning(disable : 6387 6386)
	memcpy(allocatedMemory, header, sizeof(header_t));
#pragma warning(enable : 6387 6386)

	std::vector<memory_protection_t> protections(header->m_protectionCount);

	std::cout << "[+] Reading memory protections:\r\n";
#if _WIN64
	std::cout << "    +--------------------+--------------------+\r\n";
	std::cout << "    |        RVA         |        Size        |\r\n";
	std::cout << "    +--------------------+--------------------+\r\n";
#else
	std::cout << "    +------------+------------+\r\n";
	std::cout << "    |    RVA     |    Size    |\r\n";
	std::cout << "    +------------+------------+\r\n";
#endif
	//                | 0x12345678 | 0x12345678 | 

	for (auto i = 0; i < header->m_protectionCount; ++i) {
		memory_protection_t& protection = protections[i];
		buf >> protection;

		std::cout << "    | " << HEXMOD(protection.m_rva) << " | " << HEXMOD(protection.m_size) << " | ";
		
		std::vector<std::string> flagNames;

#define CHECK_FLAG(V) if (protection.m_flags & V) flagNames.emplace_back(#V)

		CHECK_FLAG(PAGE_NOACCESS);
		CHECK_FLAG(PAGE_READONLY);
		CHECK_FLAG(PAGE_READWRITE);
		CHECK_FLAG(PAGE_WRITECOPY);
		CHECK_FLAG(PAGE_EXECUTE);
		CHECK_FLAG(PAGE_EXECUTE_READ);
		CHECK_FLAG(PAGE_EXECUTE_READWRITE);
		CHECK_FLAG(PAGE_EXECUTE_WRITECOPY);
		CHECK_FLAG(PAGE_GUARD);
		CHECK_FLAG(PAGE_NOCACHE);
		CHECK_FLAG(PAGE_WRITECOMBINE);
		CHECK_FLAG(PAGE_GRAPHICS_NOACCESS);
		CHECK_FLAG(PAGE_GRAPHICS_READONLY);
		CHECK_FLAG(PAGE_GRAPHICS_READWRITE);
		CHECK_FLAG(PAGE_GRAPHICS_EXECUTE);
		CHECK_FLAG(PAGE_GRAPHICS_EXECUTE_READ);
		CHECK_FLAG(PAGE_GRAPHICS_EXECUTE_READWRITE);
		CHECK_FLAG(PAGE_GRAPHICS_COHERENT);
		CHECK_FLAG(PAGE_ENCLAVE_THREAD_CONTROL);
		CHECK_FLAG(PAGE_REVERT_TO_FILE_MAP);
		CHECK_FLAG(PAGE_TARGETS_NO_UPDATE);
		CHECK_FLAG(PAGE_TARGETS_INVALID);
		CHECK_FLAG(PAGE_ENCLAVE_UNVALIDATED);
		CHECK_FLAG(PAGE_ENCLAVE_DECOMMIT);

#undef CHECK_FLAGS

		for (size_t itr = 0; itr < flagNames.size(); ++itr) {
			if (itr > 0)
				std::cout << " | ";
			std::cout << flagNames[itr];
		}

		if (protection.m_flags & 0xF0)
			std::cout << " (Flush instruction cache)";

		std::cout << "\r\n";
	}
	std::cout << "    +------------+------------+\r\n";

#define ADVANCE_BYTES(R, O, T) reinterpret_cast<T>(reinterpret_cast<uint8_t*>(R) + O)

	std::cout << "\r\n[+] Processing memory operations.\r\n";
	
	// Assumes protection 0 is always code section
	uint32_t writeOffset = protections[0].m_rva;

	// Every odd block is actually just a u16 representing an amount of bytes to skip in the output
	for (bool copyMemory = true; writeOffset < header->m_allocationSize; copyMemory = !copyMemory) {
		uint16_t blockSize;
		buf >> blockSize;

		uint8_t* codeRVA = allocatedMemory + writeOffset;

		if (copyMemory) {
			size_t pos = buf.pos();

			std::vector<uint8_t> codeChunk(blockSize);
			buf >> codeChunk;

			std::cout << "[+] Copying " << HEXMOD(pos) << " - "
				<< HEXMOD(pos + codeChunk.size()) << " (" << std::dec << std::setfill(' ') << std::setw(5) << codeChunk.size() << " bytes) to "
				<< HEXMOD(codeRVA - allocatedMemory) << " - "
				<< HEXMOD(codeRVA - allocatedMemory + codeChunk.size()) << ".\r\n";

			memcpy(codeRVA, codeChunk.data(), codeChunk.size());
		}
		// else {
		//	std::cout << "[+] Skipping " << std::dec << std::setfill(' ') << std::setw(5) << blockSize << " bytes on target RVA.\r\n";
		// }

		writeOffset += blockSize;
	}

	std::cout << "\r\n[+] Processing " << std::dec << header->m_relocationData.m_count << " relocation entries.\r\n";

	std::cout << "\r\n                          +-------------------------------------------------+------------------+";
	std::cout << "\r\n                          | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0123456789ABCDEF |";
	std::cout << "\r\n+-------------------------+-------------------------------------------------+------------------+";

	auto hexdiffRelocation = [&](uint8_t* ptr) {
		// xx xx xx xx xx xx ?? ?? ?? ?? xx xx xx xx xx xx
		uint8_t* start = reinterpret_cast<uint8_t*>(reinterpret_cast<size_t>(ptr) & static_cast<size_t>(~0xF));
		uint8_t* end = start + 0x10;

		std::stringstream hexStream;
		std::stringstream asciiStream;

		auto dump_range = [&](uint8_t* start, uint8_t* end, uint8_t* value) {
			std::stringstream hexStream;
			std::stringstream asciiStream;

			for (uint8_t* ptr = start; ptr < end; ++ptr) {
				uint32_t character = *ptr;
				hexStream << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << character << " ";
				if (character >= 32 && character <= 127)
					asciiStream << static_cast<char>(character);
				else
					asciiStream << ".";

			}

			size_t rebasedAdress = reinterpret_cast<uintptr_t>(start) - allocatedMemory.ptr() + baseAdress;

			std::cout << "\r\n| " << HEXMOD(rebasedAdress) << " (" << HEXMOD(reinterpret_cast<uintptr_t>(start) - allocatedMemory.ptr()) << ") | " << hexStream.str() << "| " << asciiStream.str() << " | "
				<< HEXMOD(*reinterpret_cast<uintptr_t*>(value));
		};

		dump_range(start, end, ptr);
		*reinterpret_cast<uintptr_t*>(ptr) += baseAdress;
		dump_range(start, end, ptr);
		std::cout << "\r\n+-------------------------+-------------------------------------------------+------------------+";
	};

	auto apply_relocations = [&](size_t ofs) {

		int8_t* relocData = reinterpret_cast<int8_t*>(allocatedMemory + header->m_relocationData.m_rva);
		int32_t relocationOffset = 0;
		for (size_t i = 0; i < header->m_relocationData.m_count; ++i) {
			if (relocData[0] >= 0) {
				// Relative offset
				relocationOffset += (static_cast<uint8_t>(relocData[0]) << 8) | static_cast<uint8_t>(relocData[1]);
				relocData += 2;
			}
			else {
				// Absolute offset
				relocationOffset = static_cast<uint8_t>(relocData[3])
					+ ((static_cast<uint8_t>(relocData[2])
					+ ((static_cast<uint8_t>(relocData[1]) + ((relocData[0] & 0x7F) << 8)) << 8)) << 8);
				relocData += 4;
			}
			
			uint8_t* value = reinterpret_cast<uint8_t*>(relocationOffset + allocatedMemory);
			hexdiffRelocation(value);
		}
	};

	apply_relocations(baseAdress);

	std::unordered_map<uintptr_t, std::string> importNames;

	std::cout << "\r\n[+] Loading imports and modules.\r\n";
	uint8_t* moduleData = allocatedMemory + header->m_moduleData.m_rva;
	for (size_t i = 0; i < header->m_moduleData.m_count; ++i) {
		const char* moduleName = reinterpret_cast<const char*>(allocatedMemory + *reinterpret_cast<uint32_t*>(&moduleData[8 * i]));
		
		HMODULE moduleHandle = LoadLibraryA(moduleName);
		if (moduleHandle == NULL) {
			throw std::runtime_error(std::string{ "[+] Loading handle to " } + moduleName + " failed.\r\n");
		}

		for (uintptr_t* itr = reinterpret_cast<uintptr_t*>(allocatedMemory + *reinterpret_cast<uint32_t*>(&moduleData[8 * i + 4])); /* not a typo */; ++itr) {
			if (!*itr)
				break;

			if (*itr >= 0) {
				const char* importName = reinterpret_cast<const char*>(allocatedMemory + *itr);
				uintptr_t procAddr = reinterpret_cast<uintptr_t>(GetProcAddress(moduleHandle, importName));

				std::cout << "[+] " << moduleName << "!" << importName << " : " << HEXMOD(procAddr) << ".\r\n";
				*itr = procAddr;

				importNames[reinterpret_cast<uintptr_t>(itr) - allocatedMemory.ptr() + baseAdress] = std::string{ moduleName } + "_" + importName;
			}
			else {
				// TODO: find ordinal name
				std::cout << "[+] Loading adress of " << moduleName << "!#" << *itr << ".\r\n";
				*itr = reinterpret_cast<uint32_t>(GetProcAddress(moduleHandle, reinterpret_cast<const char*>(*itr & ~0x80000000)));

				throw std::runtime_error("Ordinal imports not supported yet (I'm lazy)");
			}
		}
	}

	std::cout << "\r\n[+] Applying protections on allocated memory.\r\n";
	for (auto&& protection : protections) {
		DWORD flOldProtect;
		VirtualProtect(allocatedMemory + protection.m_rva, protection.m_size, protection.m_flags, &flOldProtect);
		if (protection.m_flags & 0xF0) {
			FlushInstructionCache(GetCurrentProcess(), allocatedMemory + protection.m_size, protection.m_size);
		}
	}

	size_t segmentSize = header->m_allocationSize;

	std::cout << "\r\n[+] Decommiting memory allocated for the relocation table.\r\n";
#pragma warning(disable : 6250)
	if (header->m_relocationData.m_rva < header->m_allocationSize) {
		uint32_t alignedOffset = (header->m_relocationData.m_rva + 0xFFF) & 0xFFFFF000;
		// Using DECOMMIT causes an RDA leak. Was this intended, Tigole Biggies?
		if (alignedOffset >= header->m_relocationData.m_rva && alignedOffset < header->m_allocationSize) {
			VirtualFree(allocatedMemory + alignedOffset, header->m_allocationSize - alignedOffset, MEM_DECOMMIT);

			// Adjust published size for hexdump
			header->m_allocationSize = alignedOffset;
		}
	}
#pragma warning(enable : 6250)

#if 0 // Can't be done; this function writes to memory
	std::cout << "\r\n[+] Executing static module initializer.\r\n";
	if (header->m_dllMainRVA) {
		typedef int(__stdcall* initializerFn)(char* baseAdress, uint32_t reason, uint32_t unused);
		if (!initializerFn(allocatedMemory + header->m_dllMainRVA)(allocatedMemory, DLL_PROCESS_ATTACH, 0)) {
			throw std::runtime_error("[!] Static initializer not found. Module failed to load.\r\n");
		}
	}
	else {
		throw std::runtime_error("[!] Static initializer not found. Module failed to load.\r\n");
	}
#endif

	// TODO: check if not size_t* for x64
	std::cout << "\r\n[i] Dumping exports:\r\n";
	uint8_t* exportsRVA = allocatedMemory;
	for (size_t i = header->m_exports.m_min; i - header->m_exports.m_min < header->m_exports.m_max; ++i) {
		size_t exportPtrOfs = (i - header->m_exports.m_min) * 4 + header->m_exports.m_rva;

		// Pointer to export offset
		size_t* exportRefPtr = reinterpret_cast<size_t*>(allocatedMemory + exportPtrOfs);

		// Export code
		size_t exportPtr = baseAdress + *exportRefPtr;

		std::cout << "[+] Export #" << std::dec << i << " found at " << HEXMOD(exportPtr) << " (RVA " << HEXMOD(*exportRefPtr) << ").\r\n";
	}

#if 0 && _WIN64
	if (header->m_rtlAddFunctionTable.m_rva != 0) {
		std::cout << "\r\n[+] Processing RTL function tables.\r\n";

		PRUNTIME_FUNCTION rtlData = reinterpret_cast<PRUNTIME_FUNCTION>(allocatedMemory + header->m_rtlAddFunctionTable.m_rva);
		if (!RtlAddFunctionTable(rtlData, header->m_rtlAddFunctionTable.m_count, static_cast<DWORD64>(allocatedMemory.ptr()))) {
			throw std::runtime_error("[!] Failed to add runtime functions.\r\n");
		}
	}
#endif

	std::cout << "\r\n[+] Extraction done.\r\n";

	std::ofstream idcFile("./dump.idc");
	idcFile << "static main() {" << std::endl;

	size_t tmpBase = baseAdress;
		
	for (size_t i = 0; i < header->m_allocationSize; i += 16) {
		std::stringstream hexStream;
		std::stringstream asciiStream;

		size_t j = 0;
		for (; j < 16 && j + i < header->m_allocationSize; ++j) {
			uint32_t character = allocatedMemory[i + j];
			hexStream << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << character << " ";
			if (character >= 32 && character <= 127)
				asciiStream << static_cast<char>(character);
			else
				asciiStream << ".";

			idcFile << "  patch_byte(" << HEXMOD(tmpBase++) << ", " << HEXMOD(character) << ");" << std::endl;
		}

		for (; j < 16; ++j) {
			hexStream << "   ";
			asciiStream << " ";
		}

		//std::cout << "\r\n| " << HEXMOD(i) << " | " << hexStream.str() << "| " << asciiStream.str() << " |";
	}
	//std::cout << "\r\n+------------+-------------------------------------------------+------------------+\r\n";

	idcFile << std::endl;
	for (auto pair : importNames) {
		idcFile << "  set_name(" << HEXMOD(pair.first) << ", \"" << pair.second << "\");" << std::endl;
	}

	idcFile << "}\r\n";
	idcFile.close();

	std::cout << "[*] Dump import script written to ./dump.idc.\r\n";
	std::cout << "    Usage guide: \r\n"
		<< "    - Create new segment at " << HEXMOD(baseAdress) << " - " << HEXMOD(baseAdress + segmentSize) << "\r\n"
		<< "      Base 0x0001, class DATA, RWX permissions.\r\n"
		<< "    - Execute script.\r\n"
		<< "    - Manually define functions and fix offsets into segment (ds:........ + x).";

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