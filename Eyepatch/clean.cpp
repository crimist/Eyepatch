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

	auto sig = helpers::FindInModule(xc("ntoskrnl.exe"), xc("\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83"), xc("xxx????x????x????xx"));
	DPrint("got sig virtual: %p physical: %p", sig, MmGetPhysicalAddress((void*)sig).QuadPart);

	auto pidDbCache = (RTL_AVL_TABLE*)dereference(sig, 3);
	if (pidDbCache == 0) {
		DPrint("failed to find pid db cache");
		return false;
	}

	auto entry = (nt::piddbcache*)pidDbCache->BalancedRoot.RightChild + sizeof(RTL_BALANCED_LINKS);
	auto selfname = helpers::String(xcw(L"eyepatch.sys")); // name of our own driver
	auto fakename = helpers::String(xcw(L"e2xw10x64.sys")); // Killer e2400 PCI-E Gigabit Ethernet Controller
	auto fakedate = xci(0x57D9B88A, int);
	// killer driver: CheckSum: 00026842, ImageSize: 00029000
	// capcom.sys(drvmap)		0x57CD1415
	// iqvw64e.sys(kdmapper)	0x5284EAC3

	DPrint("Got entry @ %p", entry);

	//auto count = 0;
	//for (auto cache_entry = entry; cache_entry != (nt::piddbcache*)entry->List.Blink; cache_entry = (nt::piddbcache*)cache_entry->List.Flink, count++) {
	//	if (count > 300) {
	//		DPrint("count > 300: breaking in case of inf loop");
	//		return true;
	//	}
	//	
	//	UNICODE_STRING name = RTL_CONSTANT_STRING(L"<null>");
	//	if (cache_entry->DriverName.Length > 0 && cache_entry->DriverName.Buffer != NULL && MmIsAddressValid(cache_entry->DriverName.Buffer)) {
	//		name = cache_entry->DriverName;
	//	}

	//	DPrint("Entry %p stamp: %X name: %wZ", cache_entry, cache_entry->TimeDateStamp, &name);
	//}

	auto cache_entry = entry;
	auto count = 0;
	do {
		if (count > 300) {
			DPrint("count > 300: breaking in case of inf loop");
			return true;
		}

		UNICODE_STRING name = RTL_CONSTANT_STRING(L"<null>");
		if (cache_entry->DriverName.Length > 0 && cache_entry->DriverName.Buffer != NULL && MmIsAddressValid(cache_entry->DriverName.Buffer)) {
			name = cache_entry->DriverName;
		}

		DPrint("Entry %p stamp: %X name: %wZ", cache_entry, cache_entry->TimeDateStamp, &name);

		cache_entry = (nt::piddbcache*)cache_entry->List.Flink;
		count++;
	} while (cache_entry != entry);
	return true;

	// todo: check and replace the first entry cause it's skipped by the for loop below
	//int count = 0;
	for (LIST_ENTRY* link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++) {
		auto cache_entry = (nt::piddbcache*)(link);

		UNICODE_STRING name = RTL_CONSTANT_STRING(L"<null>");
		if (cache_entry->DriverName.Buffer != nullptr && cache_entry->DriverName.Length > 0) {
			name = cache_entry->DriverName;
	}

		DPrint("Entry %p stamp: %X name: %wZ", cache_entry, cache_entry->TimeDateStamp, &name);
		continue;

		if (RtlCompareUnicodeString(&name, &selfname, TRUE) == 0 || cache_entry->TimeDateStamp == xci(0x57CD1415, int) || cache_entry->TimeDateStamp == xci(0x5284EAC3, int)) {
			DPrint("Entry %p stamp: %X name: %wZ", cache_entry, cache_entry->TimeDateStamp, &name);

			#if 0 
			entry->TimeDateStamp = fakedate + count;
			entry->DriverName = fakename;
			#else
			// todo:
			//	test if removing ourself bsods sys
			//	test if fucking with the list bsods sys

			auto selfEntry = (nt::piddbcache*)cache_entry;
			auto prevEntry = (nt::piddbcache*)cache_entry->List.Blink;
			auto nextEntry = (nt::piddbcache*)cache_entry->List.Flink;

			// remove 
			prevEntry->List.Flink = selfEntry->List.Flink;
			nextEntry->List.Blink = selfEntry->List.Blink;

			// wrap with self for safety
			selfEntry->List.Flink = (PLIST_ENTRY)selfEntry;
			selfEntry->List.Blink = (PLIST_ENTRY)selfEntry;
			#endif
		}
}

	return true;
}

bool clean::ClearMmUnloadDrivers() {
	// todo: clear MmUnloadDrivers() list
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/231400-clearing-mmunloadeddrivers-mmlastunloadeddriver.html
	return true;
}
