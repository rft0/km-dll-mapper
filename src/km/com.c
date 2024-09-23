#include "com.h"

NTSTATUS IoCreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DbgPrintEx(0, 0, "Connection started.\n");

	return STATUS_SUCCESS;
}

NTSTATUS IoCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrintEx(0, 0, "Connection Ended.\n");

	return STATUS_SUCCESS;
}

NTSTATUS IoControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG byteIO = 0;

	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IO_REQ_READ:
        {
            PREQ_RW input = (PREQ_RW)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                MmCopyVirtualMemory(process, input->addr, PsGetCurrentProcess(), input->buff, input->size, KernelMode, &input->ret);
                ObfDereferenceObject(process);
                status = STATUS_SUCCESS;
                byteIO = sizeof(REQ_RW);
            }
        }
        break;
    case IO_REQ_WRITE:
        {
            PREQ_RW input = (PREQ_RW)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                MmCopyVirtualMemory(PsGetCurrentProcess(), input->buff, process, input->addr, input->size, KernelMode, &input->ret);
                ObfDereferenceObject(process);
                status = STATUS_SUCCESS;
                byteIO = sizeof(REQ_RW);
            }
        }
        break;
    case IO_REQ_ALLOC:
        {
            PREQ_ALLOC input = (PREQ_ALLOC)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);
                status = ZwAllocateVirtualMemory(ZwCurrentProcess(), input->addr, 0, &input->size, input->type, input->protect);
                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                
                byteIO = sizeof(REQ_ALLOC);
            }
        }
        break;
    case IO_REQ_FREE:
        {
            PREQ_FREE input = (PREQ_FREE)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);
                status = ZwFreeVirtualMemory(ZwCurrentProcess(), input->addr, &input->size, input->type);
                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                
                byteIO = sizeof(REQ_FREE);
            }
        }
        break;
    case IO_REQ_PROTECT:
        {
            PREQ_PROTECT input = (PREQ_PROTECT)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;
                ULONG oldProtect;

                KeStackAttachProcess(process, &apc);
                status = ZwProtectVirtualMemory(ZwCurrentProcess(), &input->addr, &input->size, input->protect, &oldProtect);
                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                input->protect = oldProtect;
                
                byteIO = sizeof(REQ_PROTECT);
            }
        }
        break;
    case IO_REQ_MODULE_BASE:
        {
            PREQ_MODULE_BASE input = (PREQ_MODULE_BASE)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);

                PPEB peb = PsGetProcessPeb(process);
                if (peb && peb->Ldr && !peb->Ldr->Initialized) {
                    UNICODE_STRING wcModuleName;
                    RtlInitUnicodeString(&wcModuleName, input->name);

                    for (PLIST_ENTRY pListEntry = peb->Ldr->InLoadOrderModuleList.Flink; pListEntry != &peb->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink) {
                        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                        if (RtlCompareUnicodeString(&pEntry->BaseDllName, &wcModuleName, TRUE) == 0) {
                            status = STATUS_SUCCESS;
                            input->handle = pEntry->DllBase;
                            break;
                        }
                    }
                }

                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                
                byteIO = sizeof(REQ_MODULE_BASE);
            }
        }
        break;
    case IO_REQ_CREATE_THREAD:
        {
            PREQ_CREATE_THREAD input = (PREQ_CREATE_THREAD)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);

                OBJECT_ATTRIBUTES objAttributes;
                InitializeObjectAttributes(&objAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

                // status = ZwCreateThreadEx(&input->handle, THREAD_ALL_ACCESS, &objAttributes, ZwCurrentProcess(), input->startAddress, input->parameter, 0, 0, 0, 0, NULL);
                status = PsCreateSystemThread(&input->handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, input->startAddress, input->parameter);
                if (NT_SUCCESS(status))
                    ZwClose(input->handle);


                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                
                byteIO = sizeof(REQ_CREATE_THREAD);
            }
        }
        break;
    case IO_REQ_PROCESS_INFO:
        {
            PREQ_PROCESS_INFO input = (PREQ_PROCESS_INFO)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId(input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);

                status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, &input->processInfo, sizeof(input->processInfo), NULL);

                KeUnstackDetachProcess(&apc);   
                ObfDereferenceObject(process);
                
                byteIO = sizeof(REQ_PROCESS_INFO);
            }
        }
        break;
    default:
        byteIO = 0;
    }

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = byteIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}