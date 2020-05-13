#pragma once

namespace crim {
	void WalkDrivers();
	void HideDriverSelf(DRIVER_OBJECT *driver);
	NTSTATUS ForceUnloadDriver(char name[]);
}
