#pragma once

namespace nt {
	const auto SystemModuleInformation = 0x0B;

	// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
	extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

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
}
