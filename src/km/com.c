#include "com.h"

NTSTATUS IoCreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IoCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

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

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
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

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
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

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);
                status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &input->addr, 0, &input->size, input->type, input->protect);
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

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
                KAPC_STATE apc;

                KeStackAttachProcess(process, &apc);
                status = ZwFreeVirtualMemory(ZwCurrentProcess(), &input->addr, &input->size, input->type);
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

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
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
    case IO_REQ_PROCESS_INFO:
        {
            PREQ_PROCESS_INFO input = (PREQ_PROCESS_INFO)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;

            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONGLONG)input->pid, &process))) {
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