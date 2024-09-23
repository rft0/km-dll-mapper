#ifndef __MMAP_H
#define __MMAP_H

#include <string>
#include <vector>
#include <Windows.h>

#define MMAP_LOG(fmt, ...) { printf(fmt, __VA_ARGS__); return false; }

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

enum Arch {
	ARCH_X86 = 0,
	ARCH_X64
};

struct MMData
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

namespace MM {
	bool ManualMapDLL(DWORD pid, BYTE* pSrcData);
}

#endif