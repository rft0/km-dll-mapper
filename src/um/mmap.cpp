#include "mmap.h"
#include "com.h"

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MMData* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, NULL);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

bool MM::ManualMapDLL(DWORD pid, BYTE* pSrcData) {
	IMAGE_NT_HEADERS* pOldNtHeader = NULL;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = NULL;
	IMAGE_FILE_HEADER* pOldFileHeader = NULL;
	BYTE* pTargetBase = NULL;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
        MMAP_LOG("Invalid DOS header.");

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH)
        MMAP_LOG("Invalid target architecture.");
	
	pTargetBase = (BYTE*)Com::AllocVirtualMem(pid, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pTargetBase)
		MMAP_LOG("Failed to allocate memory in remote process! Error Code: %lx", GetLastError());

	DWORD oldp = 0;
	Com::ProtectVirtualMem(pid, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MMData data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    bool SEHExceptionSupport = true;
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
	bool SEHExceptionSupport = false;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = NULL;
	data.SEHSupport = SEHExceptionSupport;


	if (!Com::WriteVirtualMem(pid, pTargetBase, pSrcData, 0x1000)) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		MMAP_LOG("Failed to write to remote process! Error Code: %lx", GetLastError());
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!Com::WriteVirtualMem(pid, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData)) {
				Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
				MMAP_LOG("Failed to write to remote process! Error Code: %lx", GetLastError());
			}
		}
	}

	BYTE* MappingDataAlloc = (BYTE*)Com::AllocVirtualMem(pid, NULL, sizeof(MMData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!MappingDataAlloc) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		MMAP_LOG("Failed to allocate memory in remote process! Error Code: %lx", GetLastError());
	}

	if (!Com::WriteVirtualMem(pid, MappingDataAlloc, &data, sizeof(MMData))) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);
        MMAP_LOG("Failed to write to remote process! Error Code: %lx", GetLastError());
	}

	void* pShellcode = Com::AllocVirtualMem(pid, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);
        MMAP_LOG("Failed to allocate memory in remote process! Error Code: %lx", GetLastError());
	}

	if (!Com::WriteVirtualMem(pid, pShellcode, (PVOID)Shellcode, 0x1000)) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, pShellcode, 0, MEM_RELEASE);
        MMAP_LOG("Failed to write to remote process! Error Code: %lx", GetLastError());
	}

	HANDLE hThread = Com::CreateThreadEx(pid, pShellcode, MappingDataAlloc);
	if (!hThread) {
		Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);
		Com::FreeVirtualMem(pid, pShellcode, 0, MEM_RELEASE);
        MMAP_LOG("Failed to create remote thread! Error Code: %lx", GetLastError());
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		CUSTOM_PROCESS_BASIC_INFORMATION processInfo = { 0 };
		Com::QueryProcessInfo(pid, &processInfo);
		if (processInfo.ExitStatus != STILL_ACTIVE)
			return false;

		MMData data_checked{ 0 };
		Com::ReadVirtualMem(pid, MappingDataAlloc, &data_checked, sizeof(data_checked));
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			Com::FreeVirtualMem(pid, pTargetBase, 0, MEM_RELEASE);
			Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);
			Com::FreeVirtualMem(pid, pShellcode, 0, MEM_RELEASE);
			MMAP_LOG("Failed to inject DLL! Error Code: %lx", GetLastError());
		}

		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == NULL)
        MMAP_LOG("Failed to allocate memory in remote process! Error Code: %lx", GetLastError());

	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	Com::WriteVirtualMem(pid, pTargetBase, emptyBuffer, 0x1000);

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
				strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
				strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					Com::WriteVirtualMem(pid, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize);
			}
		}
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			DWORD old = 0;
			DWORD newP = PAGE_READONLY;

			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
				newP = PAGE_READWRITE;
			} else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
				newP = PAGE_EXECUTE_READ;
			}

			Com::ProtectVirtualMem(pid, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old);
		}
	}

	DWORD old = 0;
	Com::ProtectVirtualMem(pid, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);

	Com::WriteVirtualMem(pid, pShellcode, emptyBuffer, 0x1000);
    Com::FreeVirtualMem(pid, pShellcode, 0, MEM_RELEASE);
    Com::FreeVirtualMem(pid, MappingDataAlloc, 0, MEM_RELEASE);

	free(emptyBuffer);

	return true;
}