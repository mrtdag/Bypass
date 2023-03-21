#include <ntddk.h>
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define DEVICE_NAME L"\\Device\\MyDriver"
#define LINK_NAME L"\\DosDevices\\MyDriver"

PDEVICE_OBJECT DeviceObject;

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&UnicodeString(LINK_NAME));
    IoDeleteDevice(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

    if (IrpStack->Parameters.DeviceIoControl.IoControlCode == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS))
    {
        PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
        SIZE_T BufferSize = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

        // Inject DLL into the game here
        UNICODE_STRING ProcessName;
        RtlInitUnicodeString(&ProcessName, L"game.exe");
        PEPROCESS Process;
        if (NT_SUCCESS(PsLookupProcessByProcessName(&ProcessName, &Process)))
        {
            PVOID BaseAddress;
            SIZE_T Size;
            KAPC_STATE ApcState;

            KeStackAttachProcess(Process, &ApcState);

            ZwAllocateVirtualMemory(ZwCurrentProcess(), &BaseAddress, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            RtlCopyMemory(BaseAddress, Buffer, BufferSize);

            // EAC bypass
            PVOID EACBaseAddress = NULL;
            SIZE_T EACSize = 0;
            PEPROCESS CurrentProcess = PsGetCurrentProcess();
            PLIST_ENTRY CurrentListEntry = CurrentProcess->Pcb.ThreadListHead.Flink;
            while (CurrentListEntry != &CurrentProcess->Pcb.ThreadListHead)
            {
                PETHREAD CurrentThread = CONTAINING_RECORD(CurrentListEntry, ETHREAD, ThreadListEntry);
                if (PsGetProcessId(CurrentThread->ThreadsProcess) == (HANDLE)4)
                {
                    // Found the system process, get the EAC module address
                    PKAPC_STATE ApcState = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), 'BYP1');
                    if (ApcState != NULL)
                    {
                        KeStackAttachProcess(CurrentThread->ThreadsProcess, ApcState);

                        PVOID SystemBaseAddress = (PVOID)0x80000000;
                        SIZE_T SystemSize = 0x7FFFFFFF;
                        PVOID ModuleBaseAddress = NULL;

                        PPEB Peb = PsGetProcessPeb(CurrentThread->ThreadsProcess);
                        PPEB_LDR_DATA Ldr = Peb->Ldr;
                        for (PLIST_ENTRY ListEntry = Ldr->InMemoryOrderModuleList.Flink; ListEntry != &Ldr->InMemoryOrderModuleList; ListEntry = ListEntry->Flink)
                        {
                            PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                            if (wcsstr(LdrEntry->FullDllName.Buffer, L"EasyAntiCheat.sys") != NULL)
                            {
                                ModuleBaseAddress = LdrEntry->DllBase;
                                EACBaseAddress = ModuleBaseAddress;
                                EACSize = LdrEntry->SizeOfImage;
                                break;
                            }
                        }

                        KeUnstackDetachProcess(ApcState);
                        ExFreePoolWithTag(ApcState, 'BYP1');
                    }

                    break;
                }

                CurrentListEntry = CurrentListEntry->Flink;
            }

            if (EACBaseAddress != NULL)
            {
                // Patch EAC module to allow DLL injection
                UCHAR Patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                SIZE_T PatchSize = sizeof(Patch);
                PVOID PatchAddress = (PVOID)((ULONG_PTR)EACBaseAddress + 0x1C8D);

                KAPC_STATE ApcState;
                KeStackAttachProcess(Process, &ApcState);

                RtlCopyMemory(PatchAddress, Patch, PatchSize);

                KeUnstackDetachProcess(&ApcState);
            }

            // Load DLL into the game here
            UNICODE_STRING DllPath;
            RtlInitUnicodeString(&DllPath, L"\\??\\C:\\example.dll");

            PVOID DllBaseAddress;
            SIZE_T DllSize;
            NTSTATUS Status = ZwMapViewOfSection(Buffer, ZwCurrentProcess(), &DllBaseAddress, 0, 0, NULL, &DllSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(Status))
            {
                PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBaseAddress;
                PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
                PVOID ImageBase = (PVOID)NtHeaders->OptionalHeader.ImageBase;
                SIZE_T SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;

                ZwUnmapViewOfSection(ZwCurrentProcess(), DllBaseAddress);

                PVOID RemoteImageBase;
                ZwAllocateVirtualMemory(ZwCurrentProcess(), &RemoteImageBase, 0, &SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                RtlCopyMemory(RemoteImageBase, ImageBase, SizeOfImage);

                PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                ULONG_PTR Delta = (ULONG_PTR)RemoteImageBase - (ULONG_PTR)ImageBase;
                while (BaseRelocation->VirtualAddress != 0)
                {
                    PWORD RelocationData = (PWORD)((ULONG_PTR)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
                    ULONG_PTR NumberOfRelocations = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    for (ULONG_PTR i = 0; i < NumberOfRelocations; i++)
                    {
                        if (RelocationData[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                        {
                            PULONG_PTR RelocAddress = (PULONG_PTR)((ULONG_PTR)RemoteImageBase + (BaseRelocation->VirtualAddress + (RelocationData[i] & 0xFFF)));
                            *RelocAddress += Delta;
                        }
                    }

                    BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseRelocation + BaseRelocation->SizeOfBlock);
                }

                PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                while (ImportDescriptor->OriginalFirstThunk != 0)
                {
                    PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)RemoteImageBase + ImportDescriptor->OriginalFirstThunk);
                    PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)RemoteImageBase + ImportDescriptor->FirstThunk);
                    HMODULE Module = LoadLibraryA((LPCSTR)((ULONG_PTR)RemoteImageBase + ImportDescriptor->Name));
                    while (OriginalFirstThunk->u1.AddressOfData != 0)
                    {
                        PCHAR FunctionName = (PCHAR)((ULONG_PTR)RemoteImageBase + OriginalFirstThunk->u1.AddressOfData + 2);
                        PVOID FunctionAddress = GetProcAddress(Module, FunctionName);
                        FirstThunk->u1.Function = (ULONG_PTR)FunctionAddress;
                        OriginalFirstThunk++;
                        FirstThunk++;
                    }

                    ImportDescriptor++;
                }

                PVOID RemoteEntryPoint = (PVOID)((ULONG_PTR)RemoteImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
                HANDLE ThreadHandle = NULL;
                Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)RemoteEntryPoint, NULL);
                if (!NT_SUCCESS(Status))
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error creating system thread: %X\n", Status);
                }

                ZwClose(ThreadHandle);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &RemoteImageBase, &SizeOfImage, MEM_RELEASE);
            }

            KeUnstackDetachProcess(&ApcState);
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
    }
    else
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

    UNICODE_STRING DeviceName = UnicodeString(DEVICE_NAME);
    UNICODE_STRING LinkName = UnicodeString(LINK_NAME);

    NTSTATUS Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IoCreateSymbolicLink(&LinkName, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DbgPrint("Driver yuklendi\n");

    return STATUS_SUCCESS;
}

