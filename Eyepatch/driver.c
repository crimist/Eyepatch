#include "includes.h"
#include "driver.h"
#include "callbacks.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	DbgPrint("DriverEntry: %p %ls\n", DriverObject, RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

VOID NTAPI DriverUnload(IN PDRIVER_OBJECT driver) {
	DbgPrint("DriverUnload: %p\n", driver);
	return;
}
