#ifndef __COM_H
#define __COM_H

#include <ntifs.h>
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

#define IO_DRIVER_NAME 					L"\\Driver\\GenericDriverName"

#define DEVICE_NAME 					L"\\Device\\GenericDeviceName"
#define DOS_DEVICE_NAME 				L"\\DosDevices\\GenericDeviceName"

typedef struct {
	ULONG pid;
	PVOID addr;
	PVOID buff;
	SIZE_T size;
	SIZE_T ret;
} REQ_RW, *PREQ_RW;

typedef struct {
	ULONG pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
	ULONG protect;
} REQ_ALLOC, *PREQ_ALLOC;

typedef struct {
	ULONG pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
} REQ_FREE, *PREQ_FREE;

typedef struct {
	ULONG pid;
	PVOID addr;
	SIZE_T size;
	ULONG protect;
} REQ_PROTECT, *PREQ_PROTECT;

typedef struct {
	ULONG pid;
	HANDLE handle;
	WCHAR name[MAX_PATH];
} REQ_MODULE_BASE, *PREQ_MODULE_BASE;

typedef struct {
	ULONG pid;
	PROCESS_BASIC_INFORMATION processInfo;
} REQ_PROCESS_INFO, *PREQ_PROCESS_INFO;

#endif

