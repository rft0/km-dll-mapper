#include "com.h"

HANDLE Com::hDriver = NULL;

BOOL Com::LoadDriverHandle(LPCSTR registryPath) {
    Com::hDriver = CreateFileA(registryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (!Com::hDriver || Com::hDriver == INVALID_HANDLE_VALUE)
		return FALSE;

	return TRUE;
}

BOOL Com::ReadVirtualMem(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size) {
	REQ_RW req;

	req.pid = pid;
	req.addr = addr;
	req.buff = buffer;
	req.size = size;

	return DeviceIoControl(hDriver, IO_REQ_READ, &req, sizeof(req), &req, sizeof(req), 0, 0);
}

BOOL Com::WriteVirtualMem(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size) {
	REQ_RW req;

	req.pid = pid;
	req.addr = addr;
	req.buff = &buffer;
	req.size = size;

	return DeviceIoControl(hDriver, IO_REQ_WRITE, &req, sizeof(req), &req, sizeof(req), 0, 0);
}

PVOID Com::AllocVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type, ULONG protect) {
	REQ_ALLOC req;

	req.pid = pid;
	req.addr = addr;
	req.size = size;
	req.type = type;
	req.protect = protect;

	if (DeviceIoControl(hDriver, IO_REQ_ALLOC, &req, sizeof(req), &req, sizeof(req), 0, 0))
        return req.addr;
    
    return NULL;
}

BOOL Com::FreeVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG type) {
	REQ_FREE req;

	req.pid = pid;
	req.addr = addr;
	req.size = size;
	req.type = type;

	return DeviceIoControl(hDriver, IO_REQ_FREE, &req, sizeof(req), &req, sizeof(req), 0, 0);
}

BOOL Com::ProtectVirtualMem(DWORD pid, PVOID addr, SIZE_T size, ULONG protect, ULONG* oldProtect) {
    REQ_PROTECT req;

    req.pid = pid;
    req.addr = addr;
    req.size = size;
    req.protect = protect;

    BOOL status = DeviceIoControl(hDriver, IO_REQ_PROTECT, &req, sizeof(req), &req, sizeof(req), 0, 0);

    *oldProtect = req.protect;

    return status;
}

PVOID Com::GetModuleBase(DWORD pid, const WCHAR* moduleName) {
	REQ_MODULE_BASE req;

	req.pid = pid;
	req.handle = 0;
	wcscpy_s(req.name, moduleName);

	DeviceIoControl(hDriver, IO_REQ_MODULE_BASE, &req, sizeof(req), &req, sizeof(req), 0, 0);

	return req.handle;
}

BOOL Com::QueryProcessInfo(DWORD pid, CUSTOM_PROCESS_BASIC_INFORMATION* processInfo) {
	REQ_PROCESS_INFO req;

	req.pid = pid;
	req.processInfo = *processInfo;

	NTSTATUS status = DeviceIoControl(hDriver, IO_REQ_PROCESS_INFO, &req, sizeof(req), &req, sizeof(req), 0, 0);

	*processInfo = req.processInfo;

	return status;
}

HANDLE Com::CreateThreadEx(DWORD pid, PVOID startAddress, PVOID parameter) {
	REQ_CREATE_THREAD req;

	req.pid = pid;
	req.handle = NULL;
	req.startAddress = startAddress;
	req.parameter = parameter;

	DeviceIoControl(hDriver, IO_REQ_CREATE_THREAD, &req, sizeof(req), &req, sizeof(req), 0, 0);

	return req.handle;
}