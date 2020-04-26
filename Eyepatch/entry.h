#pragma once

extern "C" {
	NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING RegistryPath);
	VOID NTAPI DriverUnload(IN PDRIVER_OBJECT driver);
}
