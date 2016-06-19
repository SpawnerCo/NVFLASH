
#include <ntddk.h>
#include <ntifs.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <Common.h>

DRIVER_INITIALIZE DriverEntry;

const WCHAR deviceNameBuffer[] = L"\\Device\\NVFLASH";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\NVFLASH";
PDEVICE_OBJECT g_NVFLASH;

PVOID commonPool;

ULONG test = 0x12345670;



NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	WDF_DRIVER_CONFIG config;
	DriverObject->DriverUnload = UnloadRoutine;

	AllocatePool_kdD(DriverObject, RegistryPath);

	DbgPrint("Loading\n");

	return STATUS_SUCCESS;

}


VOID UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject)
{
	DbgPrint("Stopping\n");
	
	__try
	{
	UNICODE_STRING DestinationString; // [sp+20h] [bp-48h]@2
	
	if (DriverObject->DeviceObject)
		{
		RtlInitUnicodeString(&DestinationString, deviceSymLinkBuffer);
		IoDeleteSymbolicLink(&DestinationString);
		IoDeleteDevice(DriverObject->DeviceObject);

		ExFreePoolWithTag(commonPool, 0);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	DbgPrint("Error %x\n", GetExceptionCode());
	}
	
}



VOID AllocatePool_kdD(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	SIZE_T poolSize = 5120;

	if (!DriverObject->DeviceObject)
	{
		commonPool = ExAllocatePoolWithTag(PagedPool, poolSize, ' kdD');// Pool Type = Paged. Pool Size = 5120. Pool Tag = ' kdD'
		if (commonPool)
		{  
			RtlZeroMemory(commonPool, poolSize);
			InitializeIoDevices(DriverObject->DeviceObject, DriverObject);
		}
	}
}

VOID InitializeIoDevices(_In_ PDEVICE_OBJECT DeviceObject, _In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceName; // [sp+48h] [bp-80h]@1 \\Device\\NVFLASH
	UNICODE_STRING DestinationString; // [sp+58h] [bp-70h]@2 \\DosDevices\NVFLASH



	RtlInitUnicodeString(&DeviceName, deviceNameBuffer);       // v6 = \\Device\\NVFLASH
	if (IoCreateDevice(DriverObject, 0, &DeviceName, 0x81DEu, 0, TRUE, &g_NVFLASH) >= 0)
	{
		DriverObject->MajorFunction[IRP_MJ_CREATE] = IRPCreate;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRPClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRPControl;

		RtlInitUnicodeString(&DestinationString, deviceSymLinkBuffer);
		if (IoCreateSymbolicLink(&DestinationString, &DeviceName) < 0)
			IoDeleteDevice(DeviceObject);
	}
}

NTSTATUS IRPCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	DbgPrint("NVFLASH: Irp Create\n");
	return STATUS_SUCCESS;
}

NTSTATUS IRPClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	DbgPrint("NVFLASH: Irp Close\n");
	return STATUS_SUCCESS;
}

NTSTATUS IRPControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{

	int OutputLength; // ST28_4@6
	int InputLength; // ST20_4@6

	NTSTATUS result; // eax@7
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (pDeviceObject)
	{
		if (pIoStackLocation)
		{
			InputLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
			OutputLength = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
			result = SwitchControlCode(pDeviceObject, pIoStackLocation->Parameters.DeviceIoControl.IoControlCode, pIoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer, Irp->UserBuffer);
		}
		IofCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;                        // STATUS_UNSUCCESSFUL
	}
	return result;
}

NTSTATUS SwitchControlCode(PDEVICE_OBJECT pDeviceObject, ULONG ControlCode, PVOID Type3InputBuffer, PVOID UserBuffer)
{

	NTSTATUS ntstatus; // eax@2


	
	if (*(ULONG*)Type3InputBuffer != 0x72626D41) // 'rbmA'
	{
		DbgPrint("Invalid Magic Header\n");
		return STATUS_INVALID_PARAMETER;
	}
	ULONGLONG InputAddress = *(ULONGLONG*)((PCHAR)Type3InputBuffer + 16);
	ULONGLONG InBusAddress = *(ULONGLONG*)((PCHAR)Type3InputBuffer + 8);
	switch (ControlCode)
	{
	case 2178842703:
		//Map Adapter
		if (InputAddress > 0x4000000)
		{
			return STATUS_INVALID_PARAMETER;
		}
		DbgPrint("MAP %x Bus address: %x\n", InputAddress, InBusAddress);
		ntstatus = MapAdapter(pDeviceObject, InBusAddress, InputAddress, UserBuffer);
		break;
	case 2178842707:
		DbgPrint("UNMAP %x Bus address: %x\n", InputAddress, InBusAddress);
		ntstatus = UnMapAdapter(pDeviceObject, InBusAddress);
		RtlZeroMemory(UserBuffer, 8);
		break;
	case 2178842711:
		ntstatus = STATUS_SUCCESS;
		ULONG output = __indword(InBusAddress);
		DbgPrint("READ %I64lx, OUTPUT is %x\n", InBusAddress, output);
		RtlZeroMemory(UserBuffer, 16);
		RtlCopyMemory(UserBuffer, &output, sizeof(output));
		break;
	case 2178842723:
		ntstatus = STATUS_SUCCESS;
		DbgPrint("WRITE %x to %I64lx\n", InputAddress, InBusAddress);
		__outdword(InBusAddress, InputAddress);
		break;
	default:
		ntstatus = STATUS_NOT_SUPPORTED;
		break;
	}
	return ntstatus;
}

NTSTATUS MapAdapter(PDEVICE_OBJECT DeviceObject, ULONGLONG InBusAddress, ULONGLONG InputAddress, PVOID UserBuffer)
{
	__try
	{
		NTSTATUS ntstatus; // eax@1
		NTSTATUS ReferenceStatus; // ebx@2

		BOOLEAN isOneTranslated;
		BOOLEAN isTwoTranslated;

		PHYSICAL_ADDRESS physAddressOne;
		PHYSICAL_ADDRESS physAddressTwo;

		PHYSICAL_ADDRESS mappingLength;




		POBJECT_HANDLE_INFORMATION HandleInformation; // ST28_8@16
		__int64 v15; // rdx@16

		__int64 AddressSpace1; // [sp+50h] [bp-98h]@3
		__int64 AddressSpace2; // [sp+54h] [bp-94h]@3


		HANDLE SectionHandle; // [sp+60h] [bp-88h]@1

		PVOID BaseAddress = NULL;

		PVOID PhysicalMemorySection = NULL;


		LARGE_INTEGER SectionOffset; // [sp+80h] [bp-68h]@15
		SIZE_T v24; // [sp+88h] [bp-60h]@15

		OBJECT_ATTRIBUTES ObjectAttributes; // [sp+90h] [bp-58h]@1

		UNICODE_STRING Device_PhysicalMemory; // [sp+C0h] [bp-28h]@1

		PVOID pbPhysMemLin = 0;



		RtlInitUnicodeString(&Device_PhysicalMemory, L"\\Device\\PhysicalMemory");
		ObjectAttributes.ObjectName = &Device_PhysicalMemory;
		ObjectAttributes.Length = 48;
		ObjectAttributes.RootDirectory = 0;
		ObjectAttributes.Attributes = 64;
		ObjectAttributes.SecurityDescriptor = 0;
		ObjectAttributes.SecurityQualityOfService = 0;
		SectionHandle = 0;

		ntstatus = ZwOpenSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes);
		DbgPrint("[NVFLASH] Status %x\n", ntstatus);

		if (NT_SUCCESS(ntstatus))
		{
			ReferenceStatus = ObReferenceObjectByHandle(SectionHandle, SECTION_ALL_ACCESS, (POBJECT_TYPE)NULL, KernelMode, &PhysicalMemorySection, (POBJECT_HANDLE_INFORMATION)NULL);
			DbgPrint("[NVFLASH] RefStatus %x\n", ReferenceStatus);
			if (!NT_SUCCESS(ReferenceStatus))
			{
			LABEL_19:
				ZwClose(SectionHandle);
				goto LABEL_20;
			}


			AddressSpace1 = 0;
			AddressSpace2 = 0;

			physAddressOne.QuadPart = InBusAddress;
			physAddressTwo = RtlLargeIntegerAdd(physAddressOne, RtlConvertUlongToLargeInteger(InputAddress));


			isOneTranslated = HalTranslateBusAddress(PCIBus, 0, physAddressOne, &AddressSpace1, &physAddressOne);
			isTwoTranslated = HalTranslateBusAddress(PCIBus, 0, physAddressTwo, &AddressSpace2, &physAddressTwo);
			if (!isOneTranslated || !isTwoTranslated)
			{
				isOneTranslated = HalTranslateBusAddress(PCIBus, 1, physAddressOne, &AddressSpace1, &physAddressOne);
				isTwoTranslated = HalTranslateBusAddress(PCIBus, 1, physAddressTwo, &AddressSpace2, &physAddressTwo);
			}
			if (!isOneTranslated || !isTwoTranslated)
			{
				isOneTranslated = HalTranslateBusAddress(Internal, 0, physAddressOne, &AddressSpace1, &physAddressOne);
				isTwoTranslated = HalTranslateBusAddress(Internal, 0, physAddressTwo, &AddressSpace2, &physAddressTwo);
			}
			if (!isOneTranslated || !isTwoTranslated || AddressSpace1 || AddressSpace2)
			{
				ReferenceStatus = STATUS_UNSUCCESSFUL;
			}
			else if (physAddressTwo.LowPart == physAddressOne.LowPart)
			{
				ReferenceStatus = STATUS_UNSUCCESSFUL;
			}
			else
			{
				mappingLength = RtlLargeIntegerSubtract(physAddressTwo, physAddressOne);
				SectionOffset = physAddressOne;


#ifdef _AMD64_
				v24 = mappingLength.QuadPart;
#else
				v24 = mappingLength.LowPart;
#endif

				ReferenceStatus = ZwMapViewOfSection(
					SectionHandle,
					(HANDLE)-1,
					&pbPhysMemLin,
					0L,
					v24,
					&SectionOffset,
					&v24,
					ViewShare,
					0,
					PAGE_READWRITE);



				if (NT_SUCCESS(ReferenceStatus))
				{
					HandleInformation = BaseAddress;

					v15 = (ULONGLONG)pbPhysMemLin + physAddressOne.QuadPart - SectionOffset.QuadPart;
					DbgPrint("[NVFLASH] Base(phys) %x CommitSize %x Viewbase %x Output %x\n", pbPhysMemLin, v24, SectionOffset.QuadPart, v15);
					RtlZeroMemory(UserBuffer, 16);
					RtlCopyMemory(UserBuffer, &v15, sizeof(ULONGLONG));
					sub_11010(DeviceObject, v15, SectionHandle, PhysicalMemorySection, InBusAddress, HandleInformation);
					goto LABEL_20;
				}
			}
			ObfDereferenceObject(PhysicalMemorySection);
			if (!NT_SUCCESS(ReferenceStatus))
			{
				goto LABEL_19;
			}
		LABEL_20:
			ntstatus = ReferenceStatus;
		}
		return ntstatus;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[NVFLASH] Error %x\n", GetExceptionCode());
	}
}

NTSTATUS UnMapAdapter(PDEVICE_OBJECT DeviceObject, __int64 a2)
{
	NTSTATUS v2; // ebx@1
	PCHAR v3; // rax@1
	__int64 v5; // r9@1
	NTSTATUS result; // eax@4
	PVOID BaseAddressV7; // rdx@5
	PVOID SectionHandleV8;
	PVOID objectV9;


	v2 = 0;
	v3 =  ((PCHAR)commonPool + 24);

	v5 = 0;
	while (a2 != *(__int64*)v3)
	{
		++v5;
		v3 += 40i64;
		if (v5 >= 128)
		{
			return STATUS_SUCCESS;
		}
	}
	
	BaseAddressV7 = *(PVOID*)(((PCHAR)commonPool) + 40 * v5 + 32);
	SectionHandleV8 = *(PVOID*)(((PCHAR)commonPool) + 40 * v5);
	objectV9 = *(PVOID*)(((PCHAR)commonPool) + 40 * v5 + 8);
	RtlZeroMemory(((PCHAR)commonPool) + 40 * v5 + 24, 16);
	if (BaseAddressV7)
	{
		v2 = ZwUnmapViewOfSection((HANDLE)-1, BaseAddressV7);
	}
	if (objectV9 && NT_SUCCESS(v2))
	{
		ObfDereferenceObject(objectV9);
	}
	if (SectionHandleV8 && NT_SUCCESS(v2))
	{
		result = ZwClose(SectionHandleV8);
	}
	else
	{
		result = v2;
	}
	return result;
}

signed __int64 sub_11010(PDEVICE_OBJECT a1, PVOID BaseAddress, PVOID SectionHandle, PVOID object, PVOID InBusAddress, POBJECT_HANDLE_INFORMATION HandleInformation)
{

	signed __int64 result; // rax@1
	__int64 v9; // r11@1

	signed __int64 v11; // rcx@5


	result = a1 + 24;
	v9 = 0;


	while (*(__int64*)result)
	{
		++v9;
		result += 40i64;
		if (v9 >= 128)
		{
			return result;
		}
	}


	v11 = 5 * v9;

	RtlCopyMemory((PCHAR)commonPool + (8 * v11), &SectionHandle, sizeof(SectionHandle));
	RtlCopyMemory((PCHAR)commonPool + (8 * v11 + 8), &object, sizeof(object));
	RtlCopyMemory((PCHAR)commonPool + (8 * v11 + 16), &InBusAddress, sizeof(InBusAddress));
	RtlCopyMemory((PCHAR)commonPool + (8 * v11 + 24), &BaseAddress, sizeof(BaseAddress));
	RtlCopyMemory((PCHAR)commonPool + (8 * v11 + 32), &HandleInformation, sizeof(HandleInformation));



	result = HandleInformation;
	return result;
}