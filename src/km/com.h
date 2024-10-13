#ifndef __COM_H
#define __COM_H

#include <ntifs.h>
#include "peb.h"

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

#define IO_DRIVER_NAME L"\\Driver\\justanotherdriver"

extern NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
extern NTSTATUS ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
// extern NTSTATUS ZwCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
extern NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
extern PPEB PsGetProcessPeb(PEPROCESS Process);

NTSTATUS IoControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoCreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

typedef struct {
	HANDLE pid;
	PVOID addr;
	PVOID buff;
	SIZE_T size;
	SIZE_T ret;
} REQ_RW, *PREQ_RW;

typedef struct {
	HANDLE pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
	ULONG protect;
} REQ_ALLOC, *PREQ_ALLOC;

typedef struct {
	HANDLE pid;
	PVOID addr;
	SIZE_T size;
	ULONG type;
} REQ_FREE, *PREQ_FREE;

typedef struct {
	HANDLE pid;
	PVOID addr;
	SIZE_T size;
	ULONG protect;
} REQ_PROTECT, *PREQ_PROTECT;

typedef struct {
	HANDLE pid;
	HANDLE handle;
	WCHAR name[MAX_PATH];
} REQ_MODULE_BASE, *PREQ_MODULE_BASE;

typedef struct {
	HANDLE pid;
	HANDLE handle;
	PVOID startAddress;
	PVOID parameter;
} REQ_CREATE_THREAD, *PREQ_CREATE_THREAD;

typedef struct {
	HANDLE pid;
	PROCESS_BASIC_INFORMATION processInfo;
} REQ_PROCESS_INFO, *PREQ_PROCESS_INFO;


#endif

