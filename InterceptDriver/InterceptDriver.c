#define _CRT_SECURE_NO_WARNINGS

#include <ntddk.h>

#include "Utils.h"
#include "IODef.h"

PVOID GetImportSymbol(IN HMODULE ModuleHandle, IN PSTR SymbolName);
PSYSTEM_MODULE_INFORMATION GetSystemModulesInformation(void);
HMODULE GetModuleHandle(IN PSTR ModuleName);
NTSTATUS __stdcall MyCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, 
	OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER AllocationSize OPTIONAL, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer OPTIONAL, IN ULONG EaLength);

NTSTATUS DispatchDefaultIrp(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
void UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT deviceObject, PIRP irp);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath);

NTSTATUS(__stdcall *pNtCreateFile)(
	OUT PHANDLE                      FileHandle,
	IN ACCESS_MASK                   DesiredAccess,
	IN POBJECT_ATTRIBUTES            ObjectAttributes,
	OUT PIO_STATUS_BLOCK             IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG                         FileAttributes,
	IN ULONG                         ShareAccess,
	IN ULONG                         CreateDisposition,
	IN ULONG                         CreateOptions,
	IN PVOID EaBuffer                OPTIONAL,
	IN ULONG                         EaLength
	);

PSRVTABLE pKeServiceDescriptorTable;
DWORD Index = 0x3000;
PKEVENT	eventObject;
BOOL isEventHandleObtained = FALSE;
PWCH fileName;
WCHAR buf[BUF_SIZE];

NTSTATUS __stdcall MyCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer,
	IN ULONG EaLength
	)
{
	if (ObjectAttributes == NULL || ObjectAttributes->ObjectName == NULL || ObjectAttributes->ObjectName->Length == NULL)
		return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);

	size_t length = ObjectAttributes->ObjectName->Length / 2;

	fileName = ObjectAttributes->ObjectName->Buffer;
	UNICODE_STRING savedFileName = *ObjectAttributes->ObjectName;

	if (length > 2 && fileName != NULL)
	{
		if (fileName[length - 3] == L't' && fileName[length - 2] == L'x' && fileName[length - 1] == L't')
		{
			wcscpy(buf, savedFileName.Buffer);

			fileName[length - 2] = L't';

			NTSTATUS status = pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize OPTIONAL, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions, EaBuffer OPTIONAL, EaLength);

			if (isEventHandleObtained)
			{
				DbgPrint("My func\n");

				KeSetEvent(eventObject, 0, FALSE);
				KeResetEvent(eventObject);
			}

			return status;
		}
	}

	return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

PVOID GetImportSymbol(IN HMODULE ModuleHandle, IN PSTR SymbolName)
{
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_DATA_DIRECTORY ImageDirectory;
	PIMAGE_EXPORT_DIRECTORY Export;
	PDWORD SymbolsNames;
	PDWORD Symbols;
	PSHORT Ordinals;
	DWORD i;

	NtHeader = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ModuleHandle);

	if (!NtHeader)
		return NULL;

	ImageDirectory = NtHeader->OptionalHeader.DataDirectory;
	Export = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(ModuleHandle,	ImageDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	SymbolsNames = (PDWORD)RVATOVA(ModuleHandle, Export->AddressOfNames);
	Symbols = (PDWORD)RVATOVA(ModuleHandle, Export->AddressOfFunctions);
	Ordinals = (PSHORT)RVATOVA(ModuleHandle, Export->AddressOfNameOrdinals);

	for (i = 0; i < Export->NumberOfNames; i++)
	{
		if (!strcmp((PSTR)RVATOVA(ModuleHandle, SymbolsNames[i]), SymbolName))
			return (PVOID)RVATOVA(ModuleHandle, Symbols[Ordinals[i]]);
	}

	return NULL;
}

PSYSTEM_MODULE_INFORMATION GetSystemModulesInformation(void)
{
	PVOID SystemModulesInformation = NULL;
	ULONG SystemModulesInformationLength = 0;
	ULONG ReturnLength;

	do
	{
		if (SystemModulesInformation) 
			ExFreePool(SystemModulesInformation);

		SystemModulesInformationLength += 4096;
		SystemModulesInformation = ExAllocatePool(NonPagedPool, SystemModulesInformationLength);

		if (!SystemModulesInformation)
			return NULL;

	} while (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation,
		SystemModulesInformation, SystemModulesInformationLength, &ReturnLength)));

	return (PSYSTEM_MODULE_INFORMATION)SystemModulesInformation;
}

HMODULE GetModuleHandle(IN PSTR ModuleName)
{
	PVOID SystemModulesInformation;
	PSYSTEM_MODULE_INFORMATION ModulesInformation;
	ULONG ModulesCount;
	HMODULE ModuleHandle = NULL;

	if (!(SystemModulesInformation = GetSystemModulesInformation()))
		return NULL;

	ModulesCount = *((PULONG)SystemModulesInformation);
	ModulesInformation = (PSYSTEM_MODULE_INFORMATION)(PTR_OFFSET(SystemModulesInformation, sizeof(ULONG)));

	for (ULONG i = 0; i < ModulesCount; ++i)
	{
		if (strstr(_strlwr(ModulesInformation[i].ImageName), _strlwr(ModuleName)))
		{
			ModuleHandle = (HMODULE)ModulesInformation[i].Base;

			break;
		}
	}

	ExFreePool(SystemModulesInformation);

	DbgPrint("GetModuleHandle: %s - 0x%x\n", ModuleName, ModuleHandle);

	return ModuleHandle;
}

NTSTATUS DispatchDefaultIrp(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING DeviceLinkUnicodeString;

	if (Index != 0x3000)
		pKeServiceDescriptorTable->ServiceTable[Index] = pNtCreateFile;

	RtlInitUnicodeString(&DeviceLinkUnicodeString, DEVICE_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&DeviceLinkUnicodeString);

	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Unloaded\n");
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	DbgPrint("DeviceControlHandler\n");

	PIO_STACK_LOCATION pIrpStack;
	NTSTATUS status;

	pIrpStack = IoGetCurrentIrpStackLocation(irp);

	switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_EVENT_HANDLE:

		DbgPrint("IOCTL_EVENT_HANDLE\n");

		if (pIrpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HANDLE) ||
			pIrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE))
		{
			irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return  STATUS_BUFFER_TOO_SMALL;
		}

		irp->IoStatus.Status = ObReferenceObjectByHandle(*(HANDLE*)irp->AssociatedIrp.SystemBuffer, EVENT_MODIFY_STATE,
			*ExEventObjectType,	UserMode, &eventObject,	NULL);

		if (irp->IoStatus.Status != STATUS_SUCCESS)
		{
			DbgPrint("Wrong status: %08X\n", irp->IoStatus.Status);
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return irp->IoStatus.Status;
		}

		isEventHandleObtained = TRUE;

		status = STATUS_SUCCESS;

	case IOCTL_FILE_HOOK:

		DbgPrint("IOCTL_FILE_HOOK\n");

		int inputBufferLength = IoGetCurrentIrpStackLocation(irp)->Parameters.DeviceIoControl.InputBufferLength;
		int outputBufferLength = IoGetCurrentIrpStackLocation(irp)->Parameters.DeviceIoControl.OutputBufferLength;

		if (outputBufferLength < BUF_SIZE || inputBufferLength < BUF_SIZE)
		{
			irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_BUFFER_TOO_SMALL;
		}
		else
		{
			if (buf[0])
			{
				wcscpy(irp->AssociatedIrp.SystemBuffer, buf);

				irp->IoStatus.Information = wcslen(irp->AssociatedIrp.SystemBuffer) * 2;
			}
			else
			{
				buf[0] = L'\0';
				irp->IoStatus.Information = 0;
			}				

			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_SUCCESS;
		}

	default:
		status = STATUS_NOT_IMPLEMENTED;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{
	HMODULE hKernel;
	UNICODE_STRING deviceName;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING symbolicLink;
	NTSTATUS Status;

	hKernel = GetModuleHandle("ntoskrnl.exe");

	if (hKernel == NULL)
	{
		DbgPrint("No ntoskrnl.exe\n");
		hKernel = GetModuleHandle("ntkrnlmp.exe");
	}

	if (hKernel == NULL)
	{
		DbgPrint("No ntkrnlmp.exe\n");
		hKernel = GetModuleHandle("ntkrnlpa.exe");
	}

	if (hKernel == NULL)
		return STATUS_NO_SUCH_DOMAIN;

	pKeServiceDescriptorTable = GetImportSymbol(hKernel, "KeServiceDescriptorTable");

	DbgPrint("pKeServiceDescriptorTable = %08X\n", pKeServiceDescriptorTable);

	if (!pKeServiceDescriptorTable)
		return STATUS_PROCEDURE_NOT_FOUND;

	DbgPrint("pKeServiceDescriptorTable->LowCall = %08X\n"
		"pKeServiceDescriptorTable->HiCall = %08X\n",
		pKeServiceDescriptorTable->LowCall, pKeServiceDescriptorTable->HiCall);

	pNtCreateFile = GetImportSymbol(hKernel, "NtCreateFile");

	DbgPrint("pNtCreateFile = %08X\n", pNtCreateFile);

	if (!pNtCreateFile)
		return STATUS_PROCEDURE_NOT_FOUND;

	DbgPrint("*pNtCreateFile = %02X %02X %02X %02X %02X %02X %02X %02X\n", ((PBYTE)pNtCreateFile)[0],
		((PBYTE)pNtCreateFile)[1], ((PBYTE)pNtCreateFile)[2], ((PBYTE)pNtCreateFile)[3],
		((PBYTE)pNtCreateFile)[4], ((PBYTE)pNtCreateFile)[5], ((PBYTE)pNtCreateFile)[6],
		((PBYTE)pNtCreateFile)[7]);

	DbgPrint("pKeServiceDescriptorTable->ServiceTable[0xE0] = %08X\n", pKeServiceDescriptorTable->ServiceTable[0xE0]);

	for (Index = 0; Index < pKeServiceDescriptorTable->HiCall && pKeServiceDescriptorTable->ServiceTable[Index] != pNtCreateFile; ++Index);

	if (Index == pKeServiceDescriptorTable->HiCall)
		return STATUS_PROCEDURE_NOT_FOUND;

	DbgPrint("pNtCreateFile found at index %02X\n", Index);

	pKeServiceDescriptorTable->ServiceTable[Index] = MyCreateFile;

	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&symbolicLink, DEVICE_SYMBOLIC_LINK);

	if (!NT_SUCCESS(Status = IoCreateDevice(pDriverObject, 0, &deviceName, MY_DEVICE_TYPE, 0, FALSE, &deviceObject)))
	{
		DbgPrint("Cannot create device object. Error %i.", Status);

		return Status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;

	if (!NT_SUCCESS(Status = IoCreateSymbolicLink(&symbolicLink, &deviceName)))
	{
		DbgPrint("Cannot create link to device. Error %i.", Status);

		return Status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchDefaultIrp;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchDefaultIrp;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	return Status;
}