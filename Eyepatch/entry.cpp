#include "includes.h"
#include "entry.h"
#include "driver_abuse.h"
#include "xor.h"
#include "clean.h"

// TODO: Load unsigned w/ vuln driver and see if driver in proclists
//	https://github.com/z175/kdmapper
//	maybe https://github.com/alxbrn/gdrv-loader?
// TODO: Remove self and abusable driver from kernel module list
//	https://www.unknowncheats.me/forum/c-and-c-/167462-kernel-writing-battleye-dayz-sa-patchguard-ssdt-function.html
//		See: GetModuleArray(), GetNumberOfModules(), 
//	https://github.com/NMan1/Rainbow-Six-Cheat/blob/a0cb718624d7880ede95f4a252345dae9e816fc7/OverflowDriver/OverflowDriver/Clean.c
//		this is sigged as fuck so rewrite
//		also xor the the hardcode timestamps and the pattern so that they can't be sigged
//	maybe instead of removing them just overwrite the timestamp and name
// TODO: use different communication method since I'm pretty sure devices are detected as fuck

UNICODE_STRING EYEPATCH_DEVICE_NAME = RTL_CONSTANT_STRING(xcw(L"\\Device\\eyepatch"));
UNICODE_STRING EYEPATCH_SYMLINK_NAME = RTL_CONSTANT_STRING(xcw(L"\\??\\eyepatchlink"));
DRIVER_OBJECT *selfDriverGlobal = nullptr;

// https://github.com/alxbrn/km-um-communication
// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
#define EYEPATCH_IOCTL_WALK_DRIVERS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_HIDE_DRIVER	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_EXIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS IRPDistpatch(DEVICE_OBJECT *device, IRP *irp) {
	DPrint("Called");

	UNREFERENCED_PARAMETER(device);
	NTSTATUS status = STATUS_SUCCESS;
	auto irpsp = IoGetCurrentIrpStackLocation(irp);

	switch (irpsp->MajorFunction) {
		case IRP_MJ_CREATE:
			DPrint("IRP_MJ_CREATE");
			break;
		case IRP_MJ_CLOSE:
			DPrint("IRP_MJ_CLOSE");
			break;
		case IRP_MJ_READ:
			DPrint("IRP_MJ_READ");
			break;
		case IRP_MJ_DEVICE_CONTROL:
			DPrint("IRP_MJ_DEVICE_CONTROL");
			switch (irpsp->Parameters.DeviceIoControl.IoControlCode) {
				case EYEPATCH_IOCTL_WALK_DRIVERS:
					crim::WalkDrivers();
					break;
				case EYEPATCH_IOCTL_HIDE_DRIVER:
					crim::HideDriverSelf(selfDriverGlobal);
					break;
				case EYEPATCH_IOCTL_EXIT:
					DriverUnload(selfDriverGlobal);
					break;
				default:
					DPrint("Unknown IoControlCode: %d", irpsp->Parameters.DeviceIoControl.IoControlCode);
					break;
			}
			break;
		default:
			DPrint("Unknown MajorFunction: %d", irpsp->MajorFunction);
			break;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DPrint("Return");
	return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING RegistryPath) {
	// Driver object
	DPrint("Loading driver, PDRIVER_OBJECT @ %p RegistryPath %wZ", driver, RegistryPath);
	driver->DriverUnload = DriverUnload;
	selfDriverGlobal = driver;

	// xor
	crypt::check();

	// IOCTL
	PDEVICE_OBJECT deviceObject;
	auto status = IoCreateDevice(driver, 0, &EYEPATCH_DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(status)) {
		DPrint("IoCreateDevice failed");
		return status;
	}

	status = IoCreateSymbolicLink(&EYEPATCH_SYMLINK_NAME, &EYEPATCH_DEVICE_NAME);
	if (!NT_SUCCESS(status)) {
		DPrint("IoCreateSymbolicLink failed");
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driver->MajorFunction[i] = IRPDistpatch;
	}

	DPrint("Driver loaded");
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT driver) {
	DPrint("Unloading driver, PDRIVER_OBJECT @ %p", driver);

	NTSTATUS status = IoDeleteSymbolicLink(&EYEPATCH_SYMLINK_NAME);
	if (!NT_SUCCESS(status)) {
		DPrint("IoDeleteSymbolicLink failed");
	}

	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iodeletedevice
	// "When a driver calls IoDeleteDevice, the I/O manager deletes the target device object if there are
	// no outstanding references to it. However, if any outstanding references remain, the I/O manager marks
	// the device object as "delete pending" and deletes the device object when the references are released."
	// TODO: force close the user handle
	if (driver->DeviceObject != NULL) {
		IoDeleteDevice(driver->DeviceObject);
	}

	DPrint("Driver unloaded");
}
