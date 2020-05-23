#pragma once

namespace helpers {
	struct modinfo {
		uintptr_t addr;
		uint32_t size;
	};
	struct mutliaddrs {
		uintptr_t addr[0xF];
		uint8_t len;
	};

	UNICODE_STRING String(const wchar_t *data);
	modinfo GetModuleInfo(const char* name);
	uintptr_t AOBScan(uintptr_t addr, uint64_t len, const char* pattern, const char* mask);
	mutliaddrs AOBScanMulti(uintptr_t addr, uint64_t len, const char* pattern, const char* mask);
	uintptr_t FindInModule(const char* name, const char* pattern, const char* mask);
	bool IsAddressValid(uintptr_t addr);

	//#include <stdlib.h>
	//template<class T>
	//T Rand(T min, T max) {
	//	auto init = [] {srand(0xDEADA55); DPrint("init srand"); return true; };
	//	static auto _ = init();

	//	return rand() % max + min;
	//}
}
