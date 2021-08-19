#pragma once

// todo: this might be sigged https://www.unknowncheats.me/forum/anti-cheat-bypass/367444-getting-banned-clearing-piddb-table.html

extern "C" {
	NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength); // http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);
}

namespace nt {
	const enum {
		SystemProcessInformation = 0x05,
		SystemModuleInformation = 0x0B,
		SystemExtendedProcessInformation = 0x39,
		SystemFullProcessInformation = 0x94,
	};

	struct RTL_PROCESS_MODULE_INFORMATION {
		PVOID Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		CHAR FullPathName[0x0100];
	};

	struct RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[0xFF]; // arr size not defined in NT, 255 is safe bet
	};

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		union {
			LIST_ENTRY HashLinks;
			struct {
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union {
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
		struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
		PVOID PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef struct _piddbcache {
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
	} _piddbcache, piddbcache;

	typedef struct _UNLOADED_DRIVERS {
		UNICODE_STRING Name;
		PVOID StartAddress;
		PVOID EndAddress;
		LARGE_INTEGER CurrentTime;
	} UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;

	// if exceeded it'll start to overwrite existing entries
	// https://github.com/Zer0Mem0ry/ntoskrnl/blob/a1eded2d8efb071685e1f3cc59a1054f8545b73a/Mm/sysload.c#L3427
	#define MI_UNLOADED_DRIVERS 50

	typedef struct _MM_UNLOADED_DRIVER {
		UNICODE_STRING 	Name;
		PVOID 			ModuleStart;
		PVOID 			ModuleEnd;
		ULONG64 		UnloadTime;
	} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		PVOID Reserved2;
		ULONG HandleCount;
		ULONG SessionId;
		PVOID Reserved3;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG Reserved4;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		PVOID Reserved5;
		SIZE_T QuotaPagedPoolUsage;
		PVOID Reserved6;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved7[6];
	} SYSTEM_PROCESS_INFORMATION;

	typedef struct _DEVICE_MAP *PDEVICE_MAP;

	typedef struct _OBJECT_DIRECTORY_ENTRY {
		_OBJECT_DIRECTORY_ENTRY* ChainLink;
		PVOID Object;
		ULONG HashValue;
	} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

	typedef struct _OBJECT_DIRECTORY {
		POBJECT_DIRECTORY_ENTRY HashBuckets[37];
		EX_PUSH_LOCK Lock;
		PDEVICE_MAP DeviceMap;
		ULONG SessionId;
		PVOID NamespaceEntry;
		ULONG Flags;
	} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;
}
