#include "includes.h"
#include "helpers.h"
#include "memory.h"
#include "nt.h"
#include <string.h>

UNICODE_STRING helpers::String(const wchar_t *data) {
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, data);
	return str;
}

// need to use struct since we can't use std::tuple
helpers::modinfo helpers::GetModuleInfo(const char* name) {
	helpers::modinfo nfo = {0};
	auto modules = new(NonPagedPoolNx) nt::RTL_PROCESS_MODULES;
	ULONG retlen;

	auto status = ZwQuerySystemInformation(nt::SystemModuleInformation, modules, sizeof(*modules), &retlen);
	if (!NT_SUCCESS(status)) {
		DPrint("ZwQuerySystemInformation(SystemModuleInformation...) failed with code %x", status);
		delete modules;
		return nfo;
	}

	for (auto i = 0U; i < modules->NumberOfModules; i++) {
		if (strstr(modules->Modules[i].FullPathName, name) != NULL) {
			nfo.addr = (uintptr_t)modules->Modules[i].ImageBase;
			nfo.size = modules->Modules[i].ImageSize;
			break;
		}
	}

	DPrint("Found module %s @ %p size %X", name, nfo.addr, nfo.size);

	delete modules;
	return nfo;
}

uintptr_t helpers::AOBScan(uintptr_t addr, uint64_t len, const char* pattern, const char* mask) {
	// todo: optimise -> ez optimise prefixed wildcards
	auto patLen = strlen(mask);
	auto matches = 0;
	auto ptr = addr, optr = addr;

	while (ptr < addr + len) {
		if (*(uint8_t*)ptr == (uint8_t)pattern[matches] || (uint8_t)mask[matches] == '?') {
			if (matches == 0) {
				optr = ptr;
			}
			if (matches == patLen - 1) {
				return optr;
			}
			matches++;
		} else {
			if (matches > 0) {
				matches = 0;
				ptr = optr;
			}
		}

		ptr++;
	}

	return 0;
}

helpers::mutliaddrs helpers::AOBScanMulti(uintptr_t addr, uint64_t len, const char* pattern, const char* mask) {
	auto patLen = strlen(mask);
	auto matches = 0;
	auto ptr = addr, optr = addr;
	mutliaddrs addrs = {0};

	while (ptr < addr + len) {
		if (*(uint8_t*)ptr == (uint8_t)pattern[matches] || (uint8_t)mask[matches] == '?') {
			if (matches == 0) {
				optr = ptr;
			}
			if (matches == patLen - 1) {
				addrs.addr[addrs.len] = optr;
				if (++addrs.len > 0xF) {
					DPrint("found more than 0xF matches, breaking out");
					break;
				}
			}
			matches++;
		} else {
			if (matches > 0) {
				matches = 0;
				ptr = optr;
			}
		}

		ptr++;
	}

	return addrs;
}

uintptr_t helpers::FindInModule(const char* name, const char* pattern, const char* mask) {
	auto info = GetModuleInfo(name);
	if (info.addr == 0 || info.size == 0) {
		DPrint("Failed to find module");
		return 0;
	}

	return AOBScan(info.addr, info.size, pattern, mask);
}

bool helpers::IsAddressValid(uintptr_t addr) {
	return MmIsAddressValid((void*)addr) == TRUE;
}
