#ifndef __COM_H
#define __COM_H

#include <Windows.h>
#include "def.h"

#define IO_REQ_READ       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x770, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_WRITE      				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x771, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_REQ_ALLOC       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x772, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_FREE       				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x773, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQ_PROTECT  				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x774, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_REQ_PROCESS_INFO  			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define DEVICE_NAME						"\\\\.\\GenericDeviceName"

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
	PROCESS_BASIC_INFORMATION processInfo;
} REQ_PROCESS_INFO, *PREQ_PROCESS_INFO;

namespace Com {
	extern HANDLE hDriver;

	BOOL LoadDeviceHandle(LPCSTR registryPath);

	BOOL ReadVirtualMemBuffer(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size);
	BOOL WriteVirtualMemBuffer(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size);

	template <typename T>
	T ReadVirtualMem(DWORD pid, PVOID addr, SIZE_T size = sizeof(T)) {
		REQ_RW req;
		T buffer;

		req.pid = pid;
		req.addr = addr;
		req.buff = &buffer;
		req.size = size;

		DeviceIoControl(hDriver, IO_REQ_READ, &req, sizeof(req), &req, sizeof(req), 0, 0);

		return buffer;
	}

	template <typename T>
	BOOL WriteVirtualMem(DWORD pid, PVOID addr, T buffer, SIZE_T size = sizeof(T)) {
		REQ_RW req;

		req.pid = pid;
		req.addr = addr;
		req.buff = &buffer;
		req.size = size;

		return DeviceIoControl(hDriver, IO_REQ_WRITE, &req, sizeof(req), &req, sizeof(req), 0, 0);
	}

	PVOID AllocVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type, ULONG protect);
	BOOL FreeVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type);
	BOOL ProtectVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG protect, ULONG* oldProtect);

	BOOL QueryProcessInfo(DWORD pid, PROCESS_BASIC_INFORMATION* processInfo);
}

#endif