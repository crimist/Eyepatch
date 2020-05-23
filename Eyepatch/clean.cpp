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
	//		rewrite this cause it's sigged as fuck
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
		// last check = our driver by using dates newer than 2020 May 23
		if (RtlCompareUnicodeString(&name, &selfname, TRUE) == 0 || cache_entry->TimeDateStamp == xci(0x57CD1415U) || cache_entry->TimeDateStamp == xci(0x5284EAC3U) || cache_entry->TimeDateStamp > xci(0x5EC8DFA3)) {
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
			//	test if fucking with the list bsods sys
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

bool clean::ClearMmUnloadDrivers() {
	// credit: https://www.unknowncheats.me/forum/anti-cheat-bypass/231400-clearing-mmunloadeddrivers-mmlastunloadeddriver.html

	// not actually nessisary for our own driver but needed for cpuz/intel vuln drivers
	// https://github.com/Zer0Mem0ry/ntoskrnl/blob/a1eded2d8efb071685e1f3cc59a1054f8545b73a/Mm/sysload.c#L3399
	// basically if the module has a DriverName with length 0 than it thinks the driver failed to load and doesn't add it to the unloaded list

	struct _ {
		static uintptr_t GetRelativeOffset(uint32_t* relAddress) {
			return (uintptr_t)relAddress + sizeof(uint32_t) + *relAddress;
		}
	};

	auto offset = (uint8_t*)MmCopyMemory;
	DPrint("MmCopyMemory: virt: %p physical: %p", offset, MmGetPhysicalAddress((void*)offset));
	// MmCopyMemory:
	//	FFFFF8040C534040
	//	FFFFF80107140040

	// found proper offset (physical) @ 024BC09E from 233B040
	// 24BC09E - 233B040 = 18105E

	for (auto max = offset + 0xFFFFFF; offset < max && MmIsAddressValid((void*)offset); offset++) {
		if (*(int64_t*)offset == 0x74D2854DC98B4C00) {
			DPrint("got offset match @ %p", offset);

			auto MmUnloadedDrivers = _::GetRelativeOffset((uint32_t*)(offset - 3));
			if (MmIsAddressValid((void*)MmUnloadedDrivers)) {
				DPrint("valid offset match address");
				//*MmUnloadedDrivers = 0;

				auto unloaded = (nt::UNLOADED_DRIVERS*)MmUnloadedDrivers;
				auto i = 0;
				while (MmIsAddressValid((void*)unloaded) && unloaded->StartAddress != 0 && unloaded->EndAddress != 0 && unloaded->CurrentTime.QuadPart != 0) {
					if (i++ > 50) {
						DPrint("detected inf loop, breaking");
						break;
					}

					DPrint("unloaded %d: name: %wZ time: %llu start: %p end: %p", i, &unloaded->Name, unloaded->CurrentTime.QuadPart, unloaded->StartAddress, unloaded->EndAddress);

					unloaded++;
				}
			}
			return true;
		}
	}

	DPrint("ClearMmUnloadDrivers failed to find sig");
	return false;
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
