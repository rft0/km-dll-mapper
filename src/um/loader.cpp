#include "loader.h"

HANDLE iqvw64e_device_handle = NULL;

LONG WINAPI SomeCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	// if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
	// 	std::cout << "[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl;
	// else
	// 	std::cout << L"[!!] Crash" << std::endl;

	// if (iqvw64e_device_handle)
	// 	intel_driver::Unload(iqvw64e_device_handle);

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