#pragma once

// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
#define EYEPATCH_IOCTL_WALK_DRIVERS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_HIDE_DRIVER	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_EXIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace crim {
	void WalkDrivers();
	void HideDriver(DRIVER_OBJECT *driver);
}
