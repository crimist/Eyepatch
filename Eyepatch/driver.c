#include "includes.h"
#include "driver.h"
#include "callbacks.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	DbgPrint("DriverEntry: %p %ls\n", DriverObject, RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	registerCallback();

	return STATUS_SUCCESS;
}

VOID NTAPI DriverUnload(IN PDRIVER_OBJECT driver) {
	DbgPrint("DriverUnload: %p\n", driver);

	return;
}
