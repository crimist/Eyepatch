#pragma once

namespace clean {
	bool ClearPidDb();
	bool ClearMmUnloadDrivers();
	bool HidePsLoadedModuleList(uintptr_t driversection);
}
