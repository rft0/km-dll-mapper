#ifndef __MMAP_H
#define __MMAP_H

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

#include "com.h"
#include "helpers.h"

#define MM_LOG(fmt, ...) { mmlog(fmt, ##__VA_ARGS__); }

#define FN_TO_HOOK "TranslateMessage"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#define RELOC_FLAG RELOC_FLAG64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#define RELOC_FLAG RELOC_FLAG32
#endif

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

typedef struct _MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	PBYTE pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;

	PVOID* pHkFnLocAddress;
	PVOID pHkFnAddress;
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

bool mmap(DWORD pid, PBYTE pSrcData, SIZE_T FileSize, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void mmlog(PCSTR fmt, ...);
void __stdcall Shellcode();

#endif