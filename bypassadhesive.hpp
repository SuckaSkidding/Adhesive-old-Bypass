#include <Windows.h>


//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 
typedef struct _VECTORED_HANDLER_ENTRY
{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

	LIST_ENTRY ExecuteHandlerList;
	union
	{
		struct
		{
			ULONG Refs;
			PVOID Handler;
		} Old;
		struct
		{
			PVOID Unknown1;
			ULONG Unknown2;
			PVOID Handler;
		} New;
	};
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST
{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

	SRWLOCK SrwLock;
	LIST_ENTRY ExecuteHandlerList;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;
class Adhesive
{
public:
	static inline std::uint64_t base;
	static inline std::uint64_t size;
	static inline bool running = true;
	static inline bool handlers_registered = false;
	static inline int status = -1;
	static inline std::vector<std::pair<std::uint64_t, std::vector<BYTE>>> functions;

	static uintptr_t FindPattern(uintptr_t pModuleBaseAddress, const char* szSignature, size_t nSelectResultIndex = NULL) {
		auto PatternToBytes = [](const char* szpattern) {
			auto       m_iBytes = std::vector<int>{};
			const auto szStartAddr = const_cast<char*>(szpattern);
			const auto szEndAddr = const_cast<char*>(szpattern) + strlen(szpattern);

			for (auto szCurrentAddr = szStartAddr; szCurrentAddr < szEndAddr; ++szCurrentAddr) {
				if (*szCurrentAddr == '?') {
					++szCurrentAddr;
					if (*szCurrentAddr == '?') ++szCurrentAddr;
					m_iBytes.push_back(-1);
				}
				else m_iBytes.push_back(strtoul(szCurrentAddr, &szCurrentAddr, 16));
			}
			return m_iBytes;
		};

		const auto pDosHeader = (PIMAGE_DOS_HEADER)pModuleBaseAddress;
		const auto pNTHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)pModuleBaseAddress + pDosHeader->e_lfanew);
		const auto dwSizeOfImage = pNTHeaders->OptionalHeader.SizeOfImage;
		auto       m_iPatternBytes = PatternToBytes(szSignature);
		const auto pScanBytes = reinterpret_cast<std::uint8_t*>(pModuleBaseAddress);
		const auto m_iPatternBytesSize = m_iPatternBytes.size();
		const auto m_iPatternBytesData = m_iPatternBytes.data();
		size_t nFoundResults = 0;

		for (auto i = 0ul; i < dwSizeOfImage - m_iPatternBytesSize; ++i) {
			bool bFound = true;

			for (auto j = 0ul; j < m_iPatternBytesSize; ++j) {
				if (pScanBytes[i + j] != m_iPatternBytesData[j] && m_iPatternBytesData[j] != -1) {
					bFound = false;
					break;
				}
			}

			if (bFound) {
				if (nSelectResultIndex != 0) {
					if (nFoundResults < nSelectResultIndex) {
						nFoundResults++;
						bFound = false;
					}
					else return reinterpret_cast<uintptr_t>(&pScanBytes[i]);
				}
				else return reinterpret_cast<uintptr_t>(&pScanBytes[i]);
			}
		}
		return NULL;
	}

	static long __stdcall exception_handler(PEXCEPTION_POINTERS exceptionInfo)
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		if (running)
		{
			status = 0;
			return (exceptionInfo->ExceptionRecord->ExceptionCode == STATUS_INVALID_HANDLE) ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
		}
		else
		{
			status = 1;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}


	static void exchange()
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 
	
	static std::uint64_t pattern = 0;
		if (!pattern)
		{
			pattern = FindPattern((uintptr_t)GetModuleHandleA("ntdll.dll"), "48 8D 3D ? ? ? ? 8A C8");
			pattern = (*(int*)(pattern + 3) + pattern + 7);
		}

		if (!pattern) return;

		PVECTORED_HANDLER_LIST vectoredHandlerList = (PVECTORED_HANDLER_LIST)pattern;

		auto forwardLink = vectoredHandlerList->ExecuteHandlerList.Flink;
		for (PLIST_ENTRY link = forwardLink; link != &vectoredHandlerList->ExecuteHandlerList; link = link->Flink)
		{
			PVECTORED_HANDLER_ENTRY entry = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(link);
			if (!entry) continue;

			std::uint64_t decodedPointer = (std::uint64_t)DecodePointer((PVOID)entry->New.Handler);
			void* encodedPointer = EncodePointer(exception_handler);
			entry->New.Handler = encodedPointer;
		}
	}

	static inline bool initialize()
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		base = (std::uint64_t)GetModuleHandleA("adhesive.dll");
		if (!base) return false;

		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
		PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);

		size = nt_headers->OptionalHeader.SizeOfImage;
		return (base > 0 && size > 0);
	}

	static inline void disable()
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		running = false;	
		exchange();

	}

	static inline void enable()
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		running = true;
	}

	static inline void patch(const char* module, std::uint64_t offset, std::vector<BYTE> bytes)
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		std::uint64_t base = (std::uint64_t)GetModuleHandleA(module);
		if (!base) return;

		void* addr = (void*)(base + offset);
		if (!addr) return;

		bool found = false;
		for (const auto& it : functions)
			if (it.first == (std::uint64_t)addr)
			{
				found = true;
				break;
			}

		if (!found)
		{
			std::vector<BYTE> buffer;
			for (int i = 0; i < bytes.size(); i++)
				buffer.push_back(((BYTE*)addr)[i]);

			functions.push_back({ (std::uint64_t)addr, buffer });
		}

		DWORD old;
		VirtualProtect(addr, bytes.size(), PAGE_EXECUTE_READWRITE, &old);
		memcpy(addr, bytes.data(), bytes.size());
		VirtualProtect(addr, bytes.size(), old, &old);
	}

	static inline void patch(std::uint64_t address, std::vector<BYTE> bytes)
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		DWORD old;
		VirtualProtect((void*)(address), bytes.size(), PAGE_EXECUTE_READWRITE, &old);
		memcpy((void*)(address), bytes.data(), bytes.size());
		VirtualProtect((void*)(address), bytes.size(), old, &old);
	}

	static inline void patch_hooks(bool restore = false)
	{
//// if you paid for this you got scam , made by xo1337 , released for free by suckatheskid 

		std::string metadata = "citizen-resources-metadata-lua.dll";
		std::string scripting = "citizen-scripting-core.dll";
		std::string scripting_lua = "citizen-scripting-lua.dll";
		std::string scripting_lua54 = "citizen-scripting-lua54.dll";
		std::string core = "citizen-resources-core.dll";
		std::string gta = "scripting-gta.dll";
		std::string vfs = "vfs-core.dll";
		std::string vfs_impl = "vfs-impl-rage.dll";

		if (!restore)
		{
			// citizen-resources-metadata-lua.dll
			// 48 83 EC ? 48 8B 41 ? 4D 8B D8
			patch(metadata.c_str(), 0x3D60, { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x41, 0x18 });
			// 48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 54
			patch(metadata.c_str(), 0x1C1D0, { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48 });
			// 48 8B 42 ? 48 85 C0 75
			patch(metadata.c_str(), 0x336E0, { 0x48, 0x8B, 0x42, 0x08, 0x48, 0x85, 0xC0, 0x75 });
			// 4C 8B DC 49 89 5B ? 57 48 83 EC
			patch(metadata.c_str(), 0x33700, { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x57 });
			// 40 55 56 57 41 56 41 57 48 81 EC
			patch(metadata.c_str(), 0x71720, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57 });
			// 40 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24
			patch(metadata.c_str(), 0x71A40, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 });

			// citizen-scripting-core.dll
			// 40 55 56 57 41 56 41 57 48 8B EC
			patch(scripting.c_str(), 0x463C0, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57 });

			// citizen-scripting-lua.dll
			// 40 57 48 83 EC ? 48 8B CA
			patch(scripting_lua.c_str(), 0x197E0, { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B });
			// 48 8B C4 48 89 48 ? 55 53
			patch(scripting_lua.c_str(), 0x72C70, { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x55 });

			// citizen-scripting-lua54.dll
			// 0F 11 02 F2 0F 11 4A ? 48 83 43
			patch(scripting_lua54.c_str(), 0x4CE70, { 0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x56, 0x48 });
			// E8 ? ? ? ? 48 89 44 24 ? EB ? 48 C7 44 24
			patch(scripting_lua54.c_str(), 0x4EDD0, { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B });
			patch(scripting_lua54.c_str(), 0x2C3140, { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x50, 0x10, 0x48 });

			// citizen-resources-core.dll
			// 48 89 4C 24 ? 57 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 89 74 24 ? 49 8B F8
			patch(core.c_str(), 0x15A20, { 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83 });
			// 48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B 89 ? ? ? ? E8 ? ? ? ? 8B 87
			patch(core.c_str(), 0x169D0, { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83 });
			// 40 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC
			patch(core.c_str(), 0x21650, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 });
			// 40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B EA 4C 8B E9
			patch(core.c_str(), 0x218C0, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 });
			// 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B E8
			patch(core.c_str(), 0x33E30, { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C });

			// scripting-gta.dll
			// 4C 8B DC 56
			patch(gta.c_str(), 0x1E5F0, { 0x4C, 0x8B, 0xDC, 0x56, 0x57, 0x41, 0x56, 0x48 });

			// vfs-core.dll
			// 48 89 4C 24 ? 55
			patch(vfs.c_str(), 0xF070, { 0x48, 0x89, 0x4c, 0x24, 0x8, 0x55, 0x56, 0x57 });
			// 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 1D ? ? ? ? 48 8B F2 48 8B F9 48 85 DB 75 ? E8 ? ? ? ? 4C 8B 40 ? 48 8B 05 ? ? ? ? 49 8B 1C C0 48 85 DB 75 ? 41 B8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 89 1D ? ? ? ? 48 8B 03 4C 8B C6 48 8B D7 48 8B CB FF 50 ? 48 8B 5C 24 ? 48 8B C7 48 8B 74 24 ? 48 83 C4 ? 5F C3 CC CC CC CC 48 89 5C 24
			patch(vfs.c_str(), 0xF200, { 0x48, 0x89, 0x5C, 0x24, 0x8, 0x48, 0x89, 0x74, 0x24, 0x10 });
			// 48 89 5C 24 ? 57 48 83 EC ? 48 8B 1D
			patch(vfs.c_str(), 0xF280, { 0x48, 0x89, 0x5C, 0x24, 0x8, 0x57, 0x48, 0x83 });
			// 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F1 48 8B DA
			patch(vfs.c_str(), 0x139E0, { 0x48, 0x89, 0x5C, 0x24, 0x8, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18 });
			// 48 8B C4 55 57
			patch(vfs.c_str(), 0x152E0, { 0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x54, 0x41 });

			// vfs-impl-rage.dll
			// 40 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 4D 8B F0
			patch(vfs_impl.c_str(), 0xDDE0, { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55 });
			// 48 8B C4 57 41 56
			patch(vfs_impl.c_str(), 0xE220, { 0x48, 0x8B, 0xC4, 0x57, 0x41, 0x56, 0x41, 0x57 });
			// sub - 0x10 from this to get the correct offset 40 57 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B 59 ? 48 8B 03 48 8B B8 ? ? ? ? 0F 57 C0 0F 11 44 24 ? 0F 57 C9 F3 0F 7F 4C 24 ? 49 C7 C0 ? ? ? ? 0F 1F 80 ? ? ? ? 49 FF C0 42 80 3C 02 ? 75 ? 48 8D 4C 24 ? E8 ? ? ? ? 90 48 8D 54 24 ? 48 8B CB FF D7 48 8B D8
			/*
			.text:0000000000010DCB                         algn_10DCB:                             ; DATA XREF: .pdata:0000000000030C78↓o
			.text:0000000000010DCB CC CC CC CC CC                          align 10h
			.text:0000000000010DD0 48 8B 49 20                             mov     rcx, [rcx+20h]
			.text:0000000000010DD4 48 8B 01                                mov     rax, [rcx]
			.text:0000000000010DD7 48 FF A0 98 00 00 00                    jmp     qword ptr [rax+98h]
			.text:0000000000010DDE                         ; ---------------------------------------------------------------------------
			.text:0000000000010DDE CC                                      int     3               ; Trap to Debugger
			.text:0000000000010DDF CC                                      int     3               ; Trap to Debugger
			*/
			patch(vfs_impl.c_str(), 0x10DD0, { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x70, 0x48, 0x8B, 0x05, 0x7D, 0xD2, 0x01, 0x00 });
		}
		else
		{
			for (auto it : functions)
			{
				patch(it.first, it.second);
			}
		}
	}
};