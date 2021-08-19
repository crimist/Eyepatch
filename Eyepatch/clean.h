#pragma 
#include "xor.h"

namespace clean {
	crypt::XorString<5, wchar_t> vulnNames[] = {
		crypt::XorString<(sizeof(L"test") / sizeof(wchar_t)), wchar_t>(L"test"),
	};
	const auto vulnLen = sizeof(vulnNames) / sizeof(vulnNames[0]);

	bool ClearPidDb();
	bool ClearMmUnloadDrivers();
	bool HidePsLoadedModuleList(uintptr_t driversection);
}
