#include "includes.h"
#include "entry.h"
#include "driver_abuse.h"
#include "xor.h"
#include "clean.h"
#include "helpers.h"

// todo: try to load unsigned
//	check if it shows up in the list if loaded w/ these
//	https://github.com/z175/kdmapper
//	maybe https://github.com/alxbrn/gdrv-loader

// todo: use different communication method w/ usermode since I'm pretty sure io dispatch is detected as fuck
//	examples: https://github.com/alxbrn/km-um-communication

// todo: use these to test if the bypasses work
//	test detection w/ this driver: https://github.com/ApexLegendsUC/anti-cheat-emulator
//	info: https://secret.club/2020/03/31/battleye-developer-tracking.html

// todo: maybe turn driver signing off so that $WDKTestSign isn't in the binary to be sigged

DRIVER_OBJECT *selfDriverGlobal = nullptr;

// https://github.com/alxbrn/km-um-communication
// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
#define EYEPATCH_IOCTL_WALK_DRIVERS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_HIDE_DRIVER	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_EXIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_CLEAN		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
				case EYEPATCH_IOCTL_CLEAN:
					__try {
						if (clean::ClearPidDb() == false) {
							DPrint("clean::ClearPidDb() failed");
						}
					} __except (EXCEPTION_EXECUTE_HANDLER) {
						DPrint("clean::ClearPidDb() mem err");
					}
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

void testing() {
	DPrint("testing thread entry");

	__try {
		if (clean::ClearPidDb() == false) {
			DPrint("clean::ClearPidDb() failed");
		}
		if (clean::ClearMmUnloadDrivers() == false) {
			DPrint("clean::ClearMmUnloadDrivers() failed");
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DPrint("testing thread: memory access error");
	}

	DPrint("testing thread ret");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING RegistryPath) {
	DPrint("Loading driver, PDRIVER_OBJECT @ %p RegistryPath %wZ", driver, RegistryPath);

	// driver object
	driver->DriverUnload = DriverUnload;
	selfDriverGlobal = driver;

	// check xor works (only in dbg)
	crypt::check();

	// ioctl + dispatch
	PDEVICE_OBJECT deviceObject;
	auto dname = helpers::String(xcw(L"\\Device\\eyepatch"));
	auto sname = helpers::String(xcw(L"\\??\\eyepatchlink"));

	auto status = IoCreateDevice(driver, 0, &dname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		DPrint("IoCreateDevice failed");
		return status;
	}

	status = IoCreateSymbolicLink(&sname, &dname);
	if (!NT_SUCCESS(status)) {
		DPrint("IoCreateSymbolicLink failed");
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driver->MajorFunction[i] = IRPDistpatch;
	}

	// todo: make inline
	HANDLE threadhandle;
	if (NT_SUCCESS(PsCreateSystemThread(&threadhandle, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)&testing, NULL))) {
		ZwClose(threadhandle);
	} else {
		DPrint("failed to creating testing thread");
	}

	DPrint("Driver loaded");
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT driver) {
	DPrint("Unloading driver, PDRIVER_OBJECT @ %p", driver);

	auto sname = helpers::String(xcw(L"\\??\\eyepatchlink"));
	NTSTATUS status = IoDeleteSymbolicLink(&sname);
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
