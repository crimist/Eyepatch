#include "includes.h"
#include "clean.h"
#include "helpers.h"
#include "xor.h"
#include "nt.h"

// https://github.com/NMan1/Rainbow-Six-Cheat/blob/a0cb718624d7880ede95f4a252345dae9e816fc7/OverflowDriver/OverflowDriver/Clean.c#L5
unsigned __int64 dereference(unsigned __int64 address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

bool clean::ClearPidDb() {
	// todo
	//	https://github.com/NMan1/Rainbow-Six-Cheat/blob/a0cb718624d7880ede95f4a252345dae9e816fc7/OverflowDriver/OverflowDriver/Clean.c
	//		rewrite this cause it's sigged
	//	https://github.com/ApexLegendsUC/anti-cheat-emulator/blob/master/Source.cpp#L609
	//		or try this one
	//
	//	either way try remove the entry instead of overwrite if possible
	//	and make sure to xor everything to avoid sigs :)
	//
	//	test with `lm` command in kd
	//	CE pattern: 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 83
	//	CE attempts (dbvm physical read):
	//		48 8D 0D 16 11 2E 00 E8 11 4B AA FF 3D 00 01 00 00 0F 83
	//		48 8D 0D 16 11 2E 00 E8 11 4B AA FF 3D 00 01 00 00 0F 83
	//		48 8D 0D 16 11 2E 00 E8 11 4B AA FF 3D 00 01 00 00 0F 83

	auto sig = helpers::FindInModule(xc("ntoskrnl.exe"), xc("\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83"), xc("xxx????x????x????xx"));
	DPrint("using sig virtual: %p physical: %p", sig, MmGetPhysicalAddress((void*)sig).QuadPart);

	auto pidDbCache = (RTL_AVL_TABLE*)dereference(sig, 3);
	if (pidDbCache == 0) {
		DPrint("failed to find pid db cache");
		return false;
	}

	//auto entryaddr = (uintptr_t)(pidDbCache->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
	auto entry = (nt::piddbcache*)((uintptr_t)(pidDbCache->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS));
	auto selfname = helpers::String(xcw(L"Eyepatch.sys")); // name of our own driver

	#define OVERWRITE 0
	#if OVERWRITE
	UNICODE_STRING fakename = {28, 28};
	fakename.Buffer = (wchar_t*)ExAllocatePool(NonPagedPoolNx, 28); // leaks mem lol
	auto kdriver = xcw(L"e2xw10x64.sys");
	memcpy((void*)fakename.Buffer, kdriver, 28);
	auto fakedate = xci(0x57D9B88A);
	#endif

	// killer driver: CheckSum: 00026842, ImageSize: 00029000
	// capcom.sys(drvmap)		0x57CD1415
	// iqvw64e.sys(kdmapper)	0x5284EAC3
	// clean.cpp:80 [clean::ClearPidDb] Entry FFFFA2023C9CB940 stamp: 5EC085F7 name: Eyepatch.sys
	// clean.cpp:80 [clean::ClearPidDb] Entry FFFFA2023C9CB940 stamp: 5EC08D15 name: Eyepatch.sys

	DPrint("Got entry @ %p", entry);

	auto cache_entry = entry;
	auto count = 0;
	do {
		if (count > 300) {
			DPrint("count > 300: breaking in case of inf loop");
			return true;
		}

		UNICODE_STRING name = helpers::String(L"<null>");
		if (cache_entry->DriverName.Length > 0 && cache_entry->DriverName.Buffer != NULL && MmIsAddressValid(cache_entry->DriverName.Buffer)) {
			name = cache_entry->DriverName;
		}

		DPrint("Entry %p stamp: %X name: %wZ", cache_entry, cache_entry->TimeDateStamp, &name);

		// first check = our driver name
		// second/third check = cpuz/intel
		if (RtlCompareUnicodeString(&name, &selfname, TRUE) == 0 || cache_entry->TimeDateStamp == xci(0x57CD1415U) || cache_entry->TimeDateStamp == xci(0x5284EAC3U)) {
			DPrint("bad driver detected, fixxing");

			#if OVERWRITE
			cache_entry->TimeDateStamp = fakedate + (int)crypt::random(count / 2, count * 2);
			cache_entry->DriverName = fakename;
			//delete cache_entry->DriverName.Buffer;
			//cache_entry->DriverName.Length = 0;
			//cache_entry->DriverName.MaximumLength = 0;
			#else

			// todo:
			//	test if removing ourself bsods sys
			//	test if modifying the list bsods sys
			auto selfEntry = (nt::piddbcache*)cache_entry;
			auto prevEntry = (nt::piddbcache*)cache_entry->List.Blink;
			auto nextEntry = (nt::piddbcache*)cache_entry->List.Flink;

			cache_entry->TimeDateStamp = 0;
			cache_entry->DriverName.Length = 0;
			cache_entry->DriverName.MaximumLength = 0;
			delete cache_entry->DriverName.Buffer;

			cache_entry = nextEntry;
			count++;

			prevEntry->List.Flink = selfEntry->List.Flink;
			nextEntry->List.Blink = selfEntry->List.Blink;

			selfEntry->List.Flink = (PLIST_ENTRY)selfEntry;
			selfEntry->List.Blink = (PLIST_ENTRY)selfEntry;

			continue;
			#endif
		}

		cache_entry = (nt::piddbcache*)cache_entry->List.Flink;
		count++;
	} while (cache_entry != entry && MmIsAddressValid(cache_entry));

	return true;
}

extern "C" uintptr_t ResolveRelativeAddress(uintptr_t instruction, uint32_t offsetOffset, uint32_t instructionSize) {
	auto instr = (uint64_t)instruction;
	int32_t ripOffset = *(uint32_t*)(instr + offsetOffset);
	auto ResolvedAddr = (uintptr_t)(instr + instructionSize + ripOffset);

	return ResolvedAddr;
}

bool clean::ClearMmUnloadDrivers() {
	// credit: https://github.com/frankie-11/eft-external/blob/master/EFT%20Kernel/socket-km/clean.hpp#L199
	// https://github.com/Zer0Mem0ry/ntoskrnl/blob/a1eded2d8efb071685e1f3cc59a1054f8545b73a/Mm/sysload.c#L42

	auto info = helpers::GetModuleInfo(xc("ntoskrnl.exe"));
	if (info.addr == 0 || info.size == 0) {
		DPrint("Failed to find ntoskrnl.exe module");
		return false;
	}

	auto MmUnloadedDriversInstr = helpers::AOBScan(info.addr, info.size, xc("\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"), xc("xxx????xxx"));
	auto MmLastUnloadedDriverInstr = helpers::AOBScan(info.addr, info.size, xc("\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"), xc("xx????xxx"));

	if (MmUnloadedDriversInstr == 0 && MmLastUnloadedDriverInstr == 0) {
		DPrint("Failed to find instructions");
		return false;
	}

	DPrint("found instruction MmUnloadedDrivers @ %p", MmUnloadedDriversInstr);
	DPrint("found instruction MmLastUnloadedDriver @ %p", MmLastUnloadedDriverInstr);

	auto MmUnloadedDrivers = *(nt::MM_UNLOADED_DRIVER**)ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
	auto MmLastUnloadedDriver = (ULONG*)ResolveRelativeAddress(MmLastUnloadedDriverInstr, 2, 6);

	DPrint("found MmUnloadedDrivers @ %p", MmUnloadedDrivers);
	DPrint("found MmLastUnloadedDriver @ %p = %d", MmLastUnloadedDriver, *MmLastUnloadedDriver);

	// todo: clean more vuln drivers
	UNICODE_STRING vulnNames[] = {
		helpers::String(xcw(L"iqvw64e.sys")), // kdmapper
		helpers::String(xcw(L"Capcom.sys")),
		helpers::String(xcw(L"Eyepatch.sys")), // self
		helpers::String(xcw(L"gdrv.sys")),  // gdrv loader
		//helpers::String(xcw(L"WinRing0x64.sys")), // for testing only
	};
	auto vulnLen = sizeof(vulnNames) / sizeof(vulnNames[0]);

	for (auto i = 0; i < MI_UNLOADED_DRIVERS; i++) {
		nt::MM_UNLOADED_DRIVER* entry = &MmUnloadedDrivers[i];

		DPrint("MmUnloadedDrivers [%d]<%p>: name: %wZ time: %llu start: %p end: %p", i, entry, &entry->Name, entry->UnloadTime, entry->ModuleStart, entry->ModuleEnd);

		for (auto z = 0; z < vulnLen; z++) {
			if (RtlCompareUnicodeString(&entry->Name, &vulnNames[z], TRUE) == 0) {
				DPrint("Clearing malicious driver");

				// Clear
				memset(entry->Name.Buffer, 0x00, entry->Name.Length); // zero out name from heap
				ExFreePoolWithTag(entry->Name.Buffer, 'TDmM'); // free name ptr using tag for Mm section of kernel
				memset(entry, 0x00, sizeof(nt::MM_UNLOADED_DRIVER)); // zero out entry

				// shift array
				for (auto c = i; c < MI_UNLOADED_DRIVERS - 1; c++) {
					memcpy(&MmUnloadedDrivers[c], &MmUnloadedDrivers[c + 1], sizeof(nt::MM_UNLOADED_DRIVER));
				}
				(*MmLastUnloadedDriver)--; // move new entries a step back
				/* asm:
				*x++;
					add QWORD PTR [rbp-8], 4
				(*x)++;
					mov     rax, QWORD PTR [rbp-8]
					mov     eax, DWORD PTR [rax]
					lea     edx, [rax+1]
					mov     rax, QWORD PTR [rbp-8]
					mov     DWORD PTR [rax], edx
				*/

				// step back
				i--;
				break;
			}
		}
	}

	DPrint("Cleard MmUnloadedDrivers, MmLastUnloadedDriver = %d", *MmLastUnloadedDriver);
	return true;
}

bool clean::HidePsLoadedModuleList(uintptr_t driversection) {
	// https://community.osr.com/discussion/56128/psloadedmodulelist
	// http://www.rohitab.com/discuss/topic/41522-hiding-loaded-driver-with-dkom/

	DPrint("this might bugcheck from patchguard");
	KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

	auto self = (nt::PLDR_DATA_TABLE_ENTRY)driversection;
	auto prev = (nt::PLDR_DATA_TABLE_ENTRY)self->InLoadOrderLinks.Blink;
	auto next = (nt::PLDR_DATA_TABLE_ENTRY)self->InLoadOrderLinks.Flink;

	// clear name for unload
	DPrint("clearing basename: %wZ fullname: %wZ", &self->BaseDllName, &self->FullDllName);
	self->BaseDllName.Length = 0;
	self->BaseDllName.MaximumLength = 0;
	self->FullDllName.Length = 0;
	self->FullDllName.MaximumLength = 0;
	// todo: null the ptr?

	// remove from LL
	prev->InLoadOrderLinks.Flink = self->InLoadOrderLinks.Flink;
	next->InLoadOrderLinks.Blink = self->InLoadOrderLinks.Blink;

	// wrap self with inf LL for safety
	self->InLoadOrderLinks.Flink = (PLIST_ENTRY)self;
	self->InLoadOrderLinks.Blink = (PLIST_ENTRY)self;

	KeLowerIrql(oldIrql);
	// to unhide:
	//prevEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)selfEntry;
	//nextEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)selfEntry;
	//selfEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)nextEntry;
	//selfEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)prevEntry;

	DPrint("Module hidden");
	return true;
}

bool ClearName() {
	HANDLE handle;
	OBJECT_ATTRIBUTES attributes;
	UNICODE_STRING dirName;
	PVOID directory;

	RtlInitUnicodeString(&dirName, L"\\Driver");
	InitializeObjectAttributes(&attributes, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	auto status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
	if (!NT_SUCCESS(status)) {
		DPrint("ZwOpenDirectoryObject failed %X", status);
		return false;
	}

	status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
	if (!NT_SUCCESS(status)) {
		DPrint("ObReferenceObjectByHandle failed %X", status);
		ZwClose(handle);
		return false;
	}

	const auto directory_object = nt::POBJECT_DIRECTORY(directory);
	ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

	for (auto entry : directory_object->HashBuckets) {
		if (entry == nullptr)
			continue;


		while (entry != nullptr && entry->Object != nullptr) {
			auto driver = PDRIVER_OBJECT(entry->Object);

			for (auto i = 0; i < clean::vulnLen; i++) {
				if (RtlCompareUnicodeString(&driver->DriverName, &helpers::String(clean::vulnNames[i].decrypt()), TRUE) == 0) {
					entry = entry->ChainLink;
					continue;
				}
			}

			entry = entry->ChainLink;
		}

	}

	ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);

	// Release the acquired resources back to the OS
	ObDereferenceObject(directory);
	ZwClose(handle);

	return true;
}
