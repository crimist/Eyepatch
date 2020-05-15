#pragma once

namespace helpers {
	UNICODE_STRING String(const wchar_t *data);
	auto GetModuleInfo(const char* name);
	uintptr_t AOBScan(uintptr_t addr, uint64_t len, const char* pattern, const char* mask);
	uintptr_t FindInModule(const char* name, const char* pattern, const char* mask);
	bool IsAddressValid(uintptr_t addr);
}
