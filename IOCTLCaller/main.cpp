#include "pch.h"
#include "ignore.h"

template<typename ... T>
uint64_t call_hook(const T ... arguments) {
	void* control_function = GetProcAddress(LoadLibraryA("win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics");
	const auto control = static_cast<uint64_t(__stdcall*)(T...)>(control_function);

	return control(arguments ...);
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
#define EYEPATCH_IOCTL_WALK_DRIVERS	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_HIDE_DRIVER	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_EXIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EYEPATCH_IOCTL_CLEANPIDDB	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
	const std::map<int, int> opMap{
		{1, EYEPATCH_IOCTL_WALK_DRIVERS},
	{2, EYEPATCH_IOCTL_HIDE_DRIVER},
	{3, EYEPATCH_IOCTL_EXIT},
	{4, EYEPATCH_IOCTL_CLEANPIDDB},
	};

	printf("Attempting IOCTL on eyepatch driver...\n");

	// Get the link
	auto deviceHandle = CreateFile(L"\\\\.\\eyepatchlink", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open handle to eyepatch driver\n";
		getchar();
		return EXIT_FAILURE;
	}
	std::cout << "Got handle to eyepatch\n";

	int op;
	while (true) {
		std::cout << "> ";
		std::cin >> op;

		if (op == 0) {
			break;
		}

		auto controlCode = opMap.find(op);
		auto result = DeviceIoControl(deviceHandle, opMap.find(op)->second, nullptr, 0, nullptr, 0, nullptr, (LPOVERLAPPED)nullptr);
		if (result == 0) {
			std::cout << "Failed to perform DeviceIoControl() with error: " << GetLastError << "\n";
		}
	}

	CloseHandle(deviceHandle);
	std::cout << "Closed handle to eyepatch\n";

	return EXIT_SUCCESS;
}
