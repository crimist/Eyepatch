#pragma once
#include "includes.h"
#include "nt.h"

// https://j00ru.vexillium.org/syscalls/win32k/64/
// https://j00ru.vexillium.org/syscalls/nt/64/

// Hooking win32u!NtUserDeferWindowDpiChanges

// usermode> u win32u!NtUserDeferWindowDpiChanges
// win32u!NtUserDeferWindowDpiChanges:
// 00007ffb`42dc82b0 4c8bd1          mov     r10,rcx
// 00007ffb`42dc82b3 b894130000      mov     eax,1394h
// 00007ffb`42dc82b8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
// 00007ffb`42dc82c0 7503            jne     win32u!NtUserDeferWindowDpiChanges+0x15 (00007ffb`42dc82c5)
// 00007ffb`42dc82c2 0f05            syscall
// 00007ffb`42dc82c4 c3              ret
// 00007ffb`42dc82c5 cd2e            int     2Eh
// 00007ffb`42dc82c7 c3              ret

//							   1809   1903   1909   2004
// NtUserDeferWindowDpiChanges 0x1394 0x1398 0x1398 0x13c2

void* get_system_module_base(const char* module_name) {
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(nt::SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return 0;

	auto modules = (nt::RTL_PROCESS_MODULES*)ExAllocatePool(NonPagedPool, bytes);
	status = ZwQuerySystemInformation(nt::SystemModuleInformation, modules, bytes, &bytes);
	if (!NT_SUCCESS(status))
		return 0;

	nt::RTL_PROCESS_MODULE_INFORMATION* module = modules->Modules;
	void* module_base = 0, *module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		DPrint("fullpathname: %s", (char*)module[i].FullPathName);
		if (strcmp((char*)module[i].FullPathName, module_name) == 0) {
			module_base = module[i].ImageBase;
			module_size = (void*)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 0);

	if (module_base <= 0)
		return 0;

	return module_base;
}

void* get_system_module_export(const char* module_name, LPCSTR routine_name) {
	void* lpModule = get_system_module_base(module_name);

	if (!lpModule)
		return NULL;

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

BOOLEAN write_memory(void* address, void* buffer, size_t size) {
	if (!RtlCopyMemory(address, buffer, size)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

BOOLEAN write_to_read_only_memory(void* address, void* buffer, size_t size) {
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl)
		return FALSE;

	// Locking and mapping memory with RW-rights:
	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	// Write your buffer to mapping:
	write_memory(Mapping, buffer, size);

	// Resources freeing:
	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return TRUE;
}

bool call_kernel_function(void* kernel_function_address, const char* funcName) {
	// 
	void** function = (void**)(get_system_module_export("\\SystemRoot\\System32\\win32k.sys", funcName));

	if (!function) {
		DPrint("failed to find sys export for %s", funcName);
		return false;
	} else {
		DPrint("%s: [f**]%p [f*]%p", function, *function);
	}

	uintptr_t our_func = (uintptr_t)(kernel_function_address);
	if (!our_func)
		return false;

	DPrint("our func? %p", our_func);

	uint8_t shell_code[] = {
		0x89, 0xC0, // mov eax, eax
		0x90, // nop
		0x48, 0xB8, // movabs rax,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty ptr
		0x90, // nop
		0x48, 0xB8, // movabs rax,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// empty ptr (filled by memcpy)
		0xFF, 0xE0, // jmp rax // d0 for call
		0xCC, // int3
	};

	memcpy(shell_code + 16, &our_func, sizeof(our_func));
	write_to_read_only_memory(function, &shell_code, sizeof(shell_code));

	return true;
}

void hook(void* param) {
	DPrint("hook %p %X", param, *(uint64_t*)param);
}

bool doKernHook() {
	// todo: call orignal? is it called after our jmp w/ the hook funcs ret?

	// attach to proc with win32k so we can get the export and overwrite
	auto targetName = L"winlogon.exe";
	PEPROCESS proc = 0;
	unsigned long needed = 0;
	ZwQuerySystemInformation(nt::SystemFullProcessInformation, 0, 0, &needed);
	auto proccesses = (nt::SYSTEM_PROCESS_INFORMATION*)ExAllocatePool(NonPagedPool, needed);
	auto status = ZwQuerySystemInformation(nt::SystemFullProcessInformation, proccesses, needed, &needed);
	if (!NT_SUCCESS(status)) {
		DPrint("ZwQuerySystemInformation failed code: %X", status);
	}

	DPrint("needed: %X, sizeof: %X, needed / sizeof: %X", needed, sizeof(nt::SYSTEM_PROCESS_INFORMATION), needed / sizeof(nt::SYSTEM_PROCESS_INFORMATION));

	for (auto i = 0; i < (needed / sizeof(nt::SYSTEM_PROCESS_INFORMATION)); i++) {
		auto p = proccesses[i];
		wchar_t name[260] = {0}; // path name
		if (p.ImageName.Buffer == 0 || !memory::Valid(p.ImageName.Buffer)) {
			continue;
		}
		memcpy(&name, p.ImageName.Buffer, p.ImageName.Length * 2); // copy over the str with 0s

		DPrint("name: %ws", name);
		if (wcsstr((const wchar_t*)&name, targetName) != 0) {
			PsLookupProcessByProcessId(p.UniqueProcessId, &proc);
			if (!NT_SUCCESS(status)) {
				DPrint("PsLookupProcessByProcessId failed pid: %lld", p.UniqueProcessId);
			}
			break;
		}
	}
	// todo: if this method doesn't work than loop over pids with `PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process)`
	// from 0->0x1000 and look for winlogon.exe
	// NOTE: This is assuming that pid from user->kern is the same and it's just in the 500dec range

	if (proc == 0) {
		DPrint("proc null");
		return false;
	}

	KAPC_STATE apcState;
	KeStackAttachProcess(proc, &apcState);
	auto success = call_kernel_function(&hook, "NtUserDeferWindowDpiChanges");
	KeUnstackDetachProcess(&apcState);

	return success;
}
