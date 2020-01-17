#include "BLL2.hpp"

#include "ByteBuffer.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct header_t {
	uint32_t m_magic;
	uint32_t m_revision;
	uint32_t m_architecture;
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

std::vector<memory_protection_t> readProtections(ByteBuffer& parser, size_t protectionCount);
void copyMemory(scoped_mem_t& allocatedMemory, ByteBuffer& parser, size_t writeStart, size_t writeEnd);
void applyRelocations(scoped_mem_t& allocatedMemory, ByteBuffer& parser, size_t exportBase, header_t* bllHeader);
std::unordered_map<uintptr_t, std::string> dumpImports(scoped_mem_t& allocatedMemory, size_t exportBase, header_t* bllHeader);

void BLL2::process(size_t exportBase) {
	ByteBuffer byteBuffer(_moduleData);
	header_t* header = byteBuffer.insitu<header_t>();
	
	LOG_SKIP;
	LOG_INFO << "Magic: " << HEX(header->m_magic) << " (" << fcc{ header->m_magic }.c_str() << ")" << std::endl;
	LOG_INFO << "Revision: " << std::dec << header->m_revision << std::endl;
	LOG_INFO << "Architecture: " << std::hex << std::setw(4) << header->m_architecture << std::endl;
	LOG_INFO << "Allocation size: " << std::dec << header->m_allocationSize << std::endl;
	LOG_INFO << "DllMain RVA: " << HEX(header->m_dllMainRVA) << std::endl;
	LOG_INFO << "Exports RVA: " << HEX(header->m_exports.m_rva) << std::endl;
#if _WIN64
	LOG_INFO << "RTL Function table: " << HEX(header->m_rtlAddFunctionTable.m_rva) << "\r\n";
#endif
	LOG_SKIP;

	scoped_mem_t allocatedMemory(header->m_allocationSize);
	memcpy(static_cast<uint8_t*>(allocatedMemory), header, sizeof(header_t));
	
	LOG_SKIP;
	std::vector<memory_protection_t> protections = readProtections(byteBuffer, header->m_protectionCount);
	
	LOG_SKIP;
	copyMemory(allocatedMemory, byteBuffer, protections[0].m_rva, header->m_allocationSize);
	
	LOG_SKIP;
	applyRelocations(allocatedMemory, byteBuffer, exportBase, header);
	
	LOG_SKIP;
	std::unordered_map<uintptr_t, std::string> importNames = dumpImports(allocatedMemory, exportBase, header);

	// Decommit memory that contained the relocation table (VAD leak?)
	if (header->m_relocationData.m_rva < header->m_allocationSize) {
		uint32_t alignedOffset = (header->m_relocationData.m_rva + 0xFFF) & 0xFFFFF000;
		if (alignedOffset >= header->m_relocationData.m_rva && alignedOffset < header->m_allocationSize) {
			VirtualFree(allocatedMemory + alignedOffset, header->m_allocationSize - alignedOffset, MEM_DECOMMIT);

			// Publish new size for idc dump
			header->m_allocationSize = alignedOffset;
		}
	}

	// Dump exports
	LOG_SKIP;
	uint8_t* exportsRVA = allocatedMemory;
	for (size_t i = header->m_exports.m_min; i - header->m_exports.m_min < header->m_exports.m_max; ++i) {
		size_t exportPtrOfs = (i - header->m_exports.m_min) * 4 + header->m_exports.m_rva;

		// Pointer to export offset
		size_t* exportRefPtr = reinterpret_cast<size_t*>(allocatedMemory + exportPtrOfs);

		// Export code
		size_t exportPtr = exportBase + *exportRefPtr;

		LOG_DUMP << "Export #" << std::dec << i << " found at " << HEX(exportPtr) << " (RVA " << HEX(*exportRefPtr) << ").\r\n";
	}

	// Create IDB import script
	std::ofstream idcFile("./dump.idc");
	idcFile << "static main() {" << std::endl;

	for (size_t i = 0; i < header->m_allocationSize; ++i) {
		uint32_t character = allocatedMemory[i];
		idcFile << "  patch_byte(" << HEX(exportBase + i) << ", " << HEX(character) << ");" << std::endl;
	}

	idcFile << std::endl;
	for (auto pair : importNames)
		idcFile << "  set_name(" << HEX(pair.first) << ", \"" << pair.second << "\");" << std::endl;

	idcFile << "}\r\n";
	idcFile.close();

	LOG_INFO << "Dump import script written to ./dump.idc." << std::endl;
	std::cout << "    Usage guide: \r\n"
		<< "    - Create new segment at " << HEX(exportBase) << " - " << HEX(exportBase + header->m_allocationSize) << "\r\n"
		<< "      Base 0x0001, class DATA, RWX permissions.\r\n"
		<< "    - Execute script.\r\n"
		<< "    - Manually define functions and fix offsets into segment (ds:........ + x).";
}

std::vector<memory_protection_t> readProtections(ByteBuffer& parser, size_t protectionCount) {

	std::vector<memory_protection_t> protections(protectionCount);
	/*
#if _WIN64
	std::cout << "    +--------------------+--------------------+\r\n";
	std::cout << "    |        RVA         |        Size        |\r\n";
	std::cout << "    +--------------------+--------------------+\r\n";
#else
	std::cout << "    +------------+------------+\r\n";
	std::cout << "    |    RVA     |    Size    |\r\n";
	std::cout << "    +------------+------------+\r\n";
#endif
	*/

	for (size_t i = 0u; i < protectionCount; ++i) {
		memory_protection_t& protection = protections[i];
		parser >> protection;
		/*
		std::cout << "    | " << HEX(protection.m_rva) << " | " << HEX(protection.m_size) << " | ";

		std::vector<std::string> flagNames;

#define CHECK_FLAG(V) if (protection.m_flags & V) flagNames.emplace_back(#V)

		CHECK_FLAG(PAGE_NOACCESS);						CHECK_FLAG(PAGE_READONLY);
		CHECK_FLAG(PAGE_READWRITE);						CHECK_FLAG(PAGE_WRITECOPY);
		CHECK_FLAG(PAGE_EXECUTE);						CHECK_FLAG(PAGE_EXECUTE_READ);
		CHECK_FLAG(PAGE_EXECUTE_READWRITE);				CHECK_FLAG(PAGE_EXECUTE_WRITECOPY);
		CHECK_FLAG(PAGE_GUARD);							CHECK_FLAG(PAGE_NOCACHE);
		CHECK_FLAG(PAGE_WRITECOMBINE);					CHECK_FLAG(PAGE_GRAPHICS_NOACCESS);
		CHECK_FLAG(PAGE_GRAPHICS_READONLY);				CHECK_FLAG(PAGE_GRAPHICS_READWRITE);
		CHECK_FLAG(PAGE_GRAPHICS_EXECUTE);				CHECK_FLAG(PAGE_GRAPHICS_EXECUTE_READ);
		CHECK_FLAG(PAGE_GRAPHICS_EXECUTE_READWRITE);	CHECK_FLAG(PAGE_GRAPHICS_COHERENT);
		CHECK_FLAG(PAGE_ENCLAVE_THREAD_CONTROL);		CHECK_FLAG(PAGE_REVERT_TO_FILE_MAP);
		CHECK_FLAG(PAGE_TARGETS_NO_UPDATE);				CHECK_FLAG(PAGE_TARGETS_INVALID);
		CHECK_FLAG(PAGE_ENCLAVE_UNVALIDATED);			CHECK_FLAG(PAGE_ENCLAVE_DECOMMIT);

#undef CHECK_FLAG

		for (size_t itr = 0; itr < flagNames.size(); ++itr) {
			if (itr > 0)
				std::cout << " | ";
			std::cout << flagNames[itr];
		}

		if (protection.m_flags & 0xF0)
			std::cout << " (Flush instruction cache)";

		std::cout << "\r\n";
		*/
	}
	/*
#if _WIN64
	std::cout << "    +--------------------+--------------------+\r\n";
#else
	std::cout << "    +------------+------------+\r\n";
#endif
	*/

	return protections;
}

void copyMemory(scoped_mem_t& allocatedMemory, ByteBuffer& parser, size_t writeStart, size_t writeEnd)
{
	for (bool copyMemory = true; writeStart < writeEnd; copyMemory = !copyMemory) {
		uint16_t blockSize;
		parser >> blockSize;

		uint8_t* codeRVA = allocatedMemory + writeStart;

		if (copyMemory) {
			size_t pos = parser.pos();

			std::vector<uint8_t> codeChunk(blockSize);
			parser >> codeChunk;

			LOG_DUMP << "Copied " << HEX(pos) << " - " << HEX(pos + codeChunk.size()) << " (" << DECPAD(codeChunk.size(), 5) << " bytes) to "
				<< HEX(writeStart) << " - " << HEX(writeStart + codeChunk.size()) << "." << std::endl;

			memcpy(codeRVA, codeChunk.data(), codeChunk.size());
		}
		// else {
		//	std::cout << "[+] Skipping " << std::dec << std::setfill(' ') << std::setw(5) << blockSize << " bytes on target RVA.\r\n";
		// }

		writeStart += blockSize;
	}
}

void applyRelocations(scoped_mem_t& allocatedMemory, ByteBuffer& parser, size_t exportBase, header_t* header) {
	LOG_DUMP << "Processing " << DEC(header->m_relocationData.m_count) << " relocation entries." << std::endl;

#ifndef _WIN64
	LOG << "                              +-------------------------------------------------+------------------+" << std::endl;
	LOG << "                              | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0123456789ABCDEF |" << std::endl;
	LOG << "+-----------------------------+-------------------------------------------------+------------------+" << std::endl;
#else
    LOG << "                                              +-------------------------------------------------+------------------+" << std::endl;
    LOG << "                                              | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0123456789ABCDEF |" << std::endl;
    LOG << "+---------------------------------------------+-------------------------------------------------+------------------+" << std::endl;
#endif
	// Produces hex diff of relocation and patch it
	auto hexdiffRelocation = [&](uint8_t* ptr) {
		// xx xx xx xx xx xx ?? ?? ?? ?? xx xx xx xx xx xx
		uint8_t* start = ptr - 0x06;
		uint8_t* end = start + 0x10;

		std::stringstream hexStream;
		std::stringstream asciiStream;

		// Realigns to 0x10 boundary and dumps 16 bytes of data, highlighting modified value
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

			size_t rebasedAdress = reinterpret_cast<uintptr_t>(start) - allocatedMemory.ptr() + exportBase;

			LOG << "| " << HEX(rebasedAdress) << " (RVA " << HEX(reinterpret_cast<uintptr_t>(start) - allocatedMemory.ptr()) << ") "
				<< "| " << hexStream.str() << "| " << asciiStream.str() << " | " << HEX(*reinterpret_cast<uintptr_t*>(value)) << std::endl;
		};

		dump_range(start, end, ptr);
		*reinterpret_cast<uintptr_t*>(ptr) += exportBase;
		dump_range(start, end, ptr);

		// Generate highlight line
		std::stringstream line;

#ifndef _WIN64
		line << "+-----------------------------+-";
#else
        line << "+---------------------------------------------+-";
#endif

		for (auto i = start; i < ptr; ++i) line << "---";
		
		line << "^^-^^-^^-^^-";
		
		for (auto i = ptr + 4; i < end; ++i) line << "---";

		line << "+-";
		for (auto i = start; i < ptr; ++i) line << "-";
		line << "^^^^";
		for (auto i = ptr + 4; i < end; ++i) line << "-";
		line << "-+";

		LOG << line.str() << std::endl;
	};

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
}

std::unordered_map<uintptr_t, std::string> dumpImports(scoped_mem_t& allocatedMemory, size_t exportBase, header_t* header) {
	std::unordered_map<uintptr_t, std::string> importNames;

	uint8_t* moduleData = allocatedMemory + header->m_moduleData.m_rva;
	for (size_t i = 0; i < header->m_moduleData.m_count; ++i) {
		const char* moduleName = reinterpret_cast<const char*>(allocatedMemory + *reinterpret_cast<uint32_t*>(&moduleData[8 * i]));

		HMODULE moduleHandle = LoadLibraryA(moduleName);
		if (moduleHandle == NULL) {
			throw std::runtime_error(std::string{ "Loading handle to " } + moduleName + " failed.\r\n");
		}

		for (uintptr_t* itr = reinterpret_cast<uintptr_t*>(allocatedMemory + *reinterpret_cast<uint32_t*>(&moduleData[8 * i + 4])); /* not a typo */; ++itr) {
			if (!*itr)
				break;

			if (*itr >= 0) {
				const char* importName = reinterpret_cast<const char*>(allocatedMemory + *itr);
				uintptr_t procAddr = reinterpret_cast<uintptr_t>(GetProcAddress(moduleHandle, importName));

				LOG_DUMP << HEX(procAddr) << ": " << moduleName << "!" << importName << std::endl;
				*itr = procAddr;

				importNames[reinterpret_cast<uintptr_t>(itr) - allocatedMemory.ptr() + exportBase] = std::string{ moduleName } + "_" + importName;
			}
			else {
				// TODO: find ordinal name
				LOG_DUMP << "Loading adress of " << moduleName << "!#" << *itr << ".\r\n";
#ifdef _WIN64
                *itr = reinterpret_cast<uintptr_t>(GetProcAddress(moduleHandle, reinterpret_cast<const char*>(*itr & ~0x8000000000000000uLL)));
#else
				*itr = reinterpret_cast<uintptr_t>(GetProcAddress(moduleHandle, reinterpret_cast<const char*>(*itr & ~0x80000000)));
#endif

				throw std::runtime_error("Ordinal imports not supported yet (I'm lazy)");
			}
		}
	}

	return importNames;
}

