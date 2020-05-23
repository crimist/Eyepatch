#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>


extern "C" {
	#define POOL_TAG 'enoN'

	#define DWORD UINT32
	#define WORD UINT16

	#define IMAGE_SIZEOF_SHORT_NAME              8

	typedef struct _IMAGE_SECTION_HEADER {
		BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
		union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;
		DWORD   VirtualAddress;
		DWORD   SizeOfRawData;
		DWORD   PointerToRawData;
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

	extern NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID ModuleAddress);

	const auto SystemModuleInformation = 0x0B;

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

	PVOID GetKernelBase() {
		auto modules = (RTL_PROCESS_MODULES*)ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_PROCESS_MODULES) + 0x1000, POOL_TAG);
		ULONG retlen;

		auto status = ZwQuerySystemInformation(SystemModuleInformation, modules, sizeof(*modules), &retlen);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(modules, POOL_TAG);
			return 0;
		}

		for (auto i = 0U; i < modules->NumberOfModules; i++) {
			if (strstr(modules->Modules[i].FullPathName, "ntoskrnl.exe") != NULL) {
				ExFreePoolWithTag(modules, POOL_TAG);
				return (PVOID)modules->Modules[i].ImageBase;
				break;
			}
		}

		ExFreePoolWithTag(modules, POOL_TAG);
		return 0;
	}

	typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY {
		DWORD   VirtualAddress;
		DWORD   Size;
	} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

	#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

	typedef struct _IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

	typedef struct {
		ULONG Reserved1;
		ULONG Reserved2;
		union {
			PVOID ImageBaseAddress;
			PVOID Base;
		};
		union {
			ULONG ImageSize;
			ULONG Size;
		};
		ULONG Flags;
		WORD Id;
		WORD Rank;
		WORD w018;
		union {
			WORD NameOffset;
			WORD ModuleNameOffset;
		};
		union {
			BYTE Name[256];
			BYTE ImageName[256];
		};
	} SYSTEM_MODULE, *PSYSTEM_MODULE;

	typedef struct {
		union {
			ULONG ModulesCount;
			ULONG ulModuleCount;
		};
		SYSTEM_MODULE Modules[0];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	extern NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL);

	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
		DWORD BeginAddress;
		DWORD EndAddress;
		union {
			DWORD UnwindInfoAddress;
			DWORD UnwindData;
		} DUMMYUNIONNAME;
	} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

	typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
		ULONG64 ImageBase;
		PRUNTIME_FUNCTION FunctionEntry;
	} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

	#define UNWIND_HISTORY_TABLE_SIZE 12
	#define UNWIND_HISTORY_TABLE_NONE 0
	#define UNWIND_HISTORY_TABLE_GLOBAL 1
	#define UNWIND_HISTORY_TABLE_LOCAL 2

	typedef struct _UNWIND_HISTORY_TABLE {
		ULONG Count;
		UCHAR Search;
		ULONG64 LowAddress;
		ULONG64 HighAddress;
		UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
	} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

	extern NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);

	typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
		union {
			PM128A FloatingContext[16];
			struct {
				PM128A Xmm0;
				PM128A Xmm1;
				PM128A Xmm2;
				PM128A Xmm3;
				PM128A Xmm4;
				PM128A Xmm5;
				PM128A Xmm6;
				PM128A Xmm7;
				PM128A Xmm8;
				PM128A Xmm9;
				PM128A Xmm10;
				PM128A Xmm11;
				PM128A Xmm12;
				PM128A Xmm13;
				PM128A Xmm14;
				PM128A Xmm15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME1;
		union {
			PULONG64 IntegerContext[16];
			struct {
				PULONG64 Rax;
				PULONG64 Rcx;
				PULONG64 Rdx;
				PULONG64 Rbx;
				PULONG64 Rsp;
				PULONG64 Rbp;
				PULONG64 Rsi;
				PULONG64 Rdi;
				PULONG64 R8;
				PULONG64 R9;
				PULONG64 R10;
				PULONG64 R11;
				PULONG64 R12;
				PULONG64 R13;
				PULONG64 R14;
				PULONG64 R15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME2;
	} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

	extern NTSYSAPI PEXCEPTION_ROUTINE RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc, PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID *HandlerData, PDWORD64 EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers);

	#define SystemBigPoolInformation 0x42
	#define SystemHandleInformation 0x10

	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION Threads[1];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFO;

	#define SystemProcessInformation 0x05

	// https://github.com/google/rekall/blob/master/tools/windows/winpmem/pte_mmap.h
	#pragma pack(push, 1)
	typedef unsigned __int64 pte_uint64;

	typedef union CR3_ {
		pte_uint64 value;
		struct {
			pte_uint64 ignored_1 : 3;
			pte_uint64 write_through : 1;
			pte_uint64 cache_disable : 1;
			pte_uint64 ignored_2 : 7;
			pte_uint64 pml4_p : 40;
			pte_uint64 reserved : 12;
		};
	} PTE_CR3;

	typedef union VIRT_ADDR_ {
		pte_uint64 value;
		void *pointer;
		struct {
			pte_uint64 offset : 12;
			pte_uint64 pt_index : 9;
			pte_uint64 pd_index : 9;
			pte_uint64 pdpt_index : 9;
			pte_uint64 pml4_index : 9;
			pte_uint64 reserved : 16;
		};
	} VIRT_ADDR;

	typedef union PML4E_ {
		pte_uint64 value;
		struct {
			pte_uint64 present : 1;
			pte_uint64 rw : 1;
			pte_uint64 user : 1;
			pte_uint64 write_through : 1;
			pte_uint64 cache_disable : 1;
			pte_uint64 accessed : 1;
			pte_uint64 ignored_1 : 1;
			pte_uint64 reserved_1 : 1;
			pte_uint64 ignored_2 : 4;
			pte_uint64 pdpt_p : 40;
			pte_uint64 ignored_3 : 11;
			pte_uint64 xd : 1;
		};
	} PML4E;

	typedef union PDPTE_ {
		pte_uint64 value;
		struct {
			pte_uint64 present : 1;
			pte_uint64 rw : 1;
			pte_uint64 user : 1;
			pte_uint64 write_through : 1;
			pte_uint64 cache_disable : 1;
			pte_uint64 accessed : 1;
			pte_uint64 dirty : 1;
			pte_uint64 page_size : 1;
			pte_uint64 ignored_2 : 4;
			pte_uint64 pd_p : 40;
			pte_uint64 ignored_3 : 11;
			pte_uint64 xd : 1;
		};
	} PDPTE;
	#pragma pack(pop)

	typedef UINT64 uint64_t;

	#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)

	#define SystemBootEnvironmentInformation 0x5A

	extern NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);

	extern NTSTATUS ObOpenObjectByName(
		__in POBJECT_ATTRIBUTES ObjectAttributes,
		__in_opt POBJECT_TYPE ObjectType,
		__in KPROCESSOR_MODE AccessMode,
		__inout_opt PACCESS_STATE AccessState,
		__in_opt ACCESS_MASK DesiredAccess,
		__inout_opt PVOID ParseContext,
		__out PHANDLE Handle
	);

	#define WINAPI NTAPI

	extern NTSTATUS WINAPI ZwQueryDirectoryObject(
		_In_      HANDLE  DirectoryHandle,
		_Out_opt_ PVOID   Buffer,
		_In_      ULONG   Length,
		_In_      BOOLEAN ReturnSingleEntry,
		_In_      BOOLEAN RestartScan,
		_Inout_   PULONG  Context,
		_Out_opt_ PULONG  ReturnLength
	);

	// https://www.unknowncheats.me/forum/c-and-c-/274073-iterating-driver_objects.html
	typedef NTSTATUS(NTAPI OBREFERENCEOBJECTBYNAME) (
		PUNICODE_STRING ObjectPath,
		ULONG Attributes,
		PACCESS_STATE PassedAccessState OPTIONAL,
		ACCESS_MASK DesiredAccess OPTIONAL,
		POBJECT_TYPE ObjectType,
		KPROCESSOR_MODE AccessMode,
		PVOID ParseContext OPTIONAL,
		PVOID *ObjectPtr);

	__declspec(dllimport) OBREFERENCEOBJECTBYNAME ObReferenceObjectByName;
	__declspec(dllimport) POBJECT_TYPE *IoDriverObjectType;

	#define is_lazy_hypervisor_running() FALSE

	void get_ntoskrnl_text_section(uintptr_t* addr, PULONG len) {
		// todo
		*addr = 0;
		*len = 0;
	}
}
