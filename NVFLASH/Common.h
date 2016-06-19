#include <ntddk.h>

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	);

VOID UnloadRoutine(
	_In_ PDRIVER_OBJECT DriverObject
	);

NTSTATUS IRPControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
VOID AllocatePool_kdD(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
VOID InitializeIoDevices(_In_ PDEVICE_OBJECT DeviceObject, _In_ PDRIVER_OBJECT DriverObject);
NTSTATUS SwitchControlCode(PDEVICE_OBJECT pDeviceObject, ULONG ControlCode, PVOID Type3InputBuffer, PVOID UserBuffer);
NTSTATUS IRPCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS IRPClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS MapAdapter(PDEVICE_OBJECT DeviceObject, ULONGLONG InBusAddress, ULONGLONG InputAddress, PVOID UserBuffer);
NTSTATUS UnMapAdapter(PDEVICE_OBJECT DeviceObject, __int64 a2);
signed __int64 sub_11010(PDEVICE_OBJECT a1, PVOID BaseAddress, PVOID SectionHandle, PVOID object, PVOID InBusAddress, POBJECT_HANDLE_INFORMATION HandleInformation);
