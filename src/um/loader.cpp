#include "loader.h"

HANDLE iqvw64e_device_handle = NULL;

LONG WINAPI SomeCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		printf("[!] Crash at addr %p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
	else
		printf("[!] Crash\n");

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

void Loader::LoadDriver() {
    iqvw64e_device_handle = intel_driver::Load();
	NTSTATUS exitCode = 0;
	kdmapper::MapDriver(iqvw64e_device_handle, driver_bytes_res, 0, 0, false, true, kdmapper::AllocationMode::AllocatePool, false, NULL, &exitCode);
	intel_driver::Unload(iqvw64e_device_handle);
}

void Loader::UnloadDriver() {
    iqvw64e_device_handle = intel_driver::Load();
    intel_driver::Unload(iqvw64e_device_handle);
}

void Loader::EnableCrashHandler() {
    SetUnhandledExceptionFilter(SomeCrashHandler);
}