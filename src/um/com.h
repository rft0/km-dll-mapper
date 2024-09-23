#ifndef __COM_H
#define __COM_H

#include <Windows.h>
#include "def.h"

#define IO_REQ_READ       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x770, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_WRITE      				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x771, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_REQ_ALLOC       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x772, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_FREE       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x773, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_PROTECT  				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x774, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_REQ_MODULE_BASE  			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_CREATE_THREAD  			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_PROCESS_INFO  			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define DRIVER_REGISTRY_PATH			"\\\\.\\GenericDriverName"

typedef struct {
	DWORD pid;
	PVOID addr;
	PVOID buff;
	SIZE_T size;
	SIZE_T ret;
} REQ_RW, *PREQ_RW;

typedef struct {
	DWORD pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
	ULONG protect;
} REQ_ALLOC, *PREQ_ALLOC;

typedef struct {
	DWORD pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
} REQ_FREE, *PREQ_FREE;

typedef struct {
	DWORD pid;
	PVOID addr;
	SIZE_T size;
	ULONG protect;
} REQ_PROTECT, *PREQ_PROTECT;

typedef struct {
	DWORD pid;
	HANDLE handle;
	WCHAR name[MAX_PATH];
} REQ_MODULE_BASE, *PREQ_MODULE_BASE;

typedef struct {
	DWORD pid;
	HANDLE handle;
	PVOID startAddress;
	PVOID parameter;
} REQ_CREATE_THREAD, *PREQ_CREATE_THREAD;

typedef struct {
	DWORD pid;
	CUSTOM_PROCESS_BASIC_INFORMATION processInfo;
} REQ_PROCESS_INFO, *PREQ_PROCESS_INFO;

namespace Com {
	extern HANDLE hDriver;

	BOOL LoadDriverHandle(LPCSTR registryPath);

	BOOL ReadVirtualMem(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size);
	BOOL WriteVirtualMem(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size);

	PVOID AllocVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type, ULONG protect);
	BOOL FreeVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type);
	BOOL ProtectVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG protect, ULONG* oldProtect);

	PVOID GetModuleBase(DWORD pid, const WCHAR* moduleName);
	BOOL QueryProcessInfo(DWORD pid, CUSTOM_PROCESS_BASIC_INFORMATION* processInfo);
	HANDLE CreateThreadEx(DWORD pid, PVOID startAddress, PVOID parameter);
}

#endif