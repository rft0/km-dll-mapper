#include "com.h"

static UNICODE_STRING deviceName, deviceSymLink;

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	IoDeleteSymbolicLink(&deviceSymLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS RealDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = UnloadDriver;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&deviceSymLink, DOS_DEVICE_NAME);

    PDEVICE_OBJECT deviceObject;
    IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    IoCreateSymbolicLink(&deviceSymLink, &deviceName);
    
	deviceObject->Flags |= DO_DIRECT_IO;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreateDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlDispatch;

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, IO_DRIVER_NAME);
    return IoCreateDriver(&driverName, &RealDriverEntry);
}