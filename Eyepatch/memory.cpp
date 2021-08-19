#include "includes.h"
#include "memory.h"
#include "nt.h"

// overload the default op
void* __cdecl operator new(size_t size) {
	#if DBG
	return ExAllocatePoolWithTag(NonPagedPoolNx, size, EYEPATCH_MEMORY_TAG);
	#else 
	return ExAllocatePool(NonPagedPoolNx, size);
	#endif
}

// provide an overloader for pool & tag definition
void* __cdecl operator new(size_t size, POOL_TYPE pool, uint32_t tag) {
	#if DBG
	return ExAllocatePoolWithTag(pool, size, tag);
	#else 
	return ExAllocatePool(pool, size);
	#endif
}

void __cdecl operator delete(void* p) {
	// use `/Zc:sizedDealloc-` in the C++ build command line to get our single argument delete operator back
	// than we can overload it without the dummy and without bombing the linker
	ExFreePool(p);
}

void memory::test() {
	#if DBG
	// scope
	[]() {
		auto one = heaped<int>();
		auto val = one.ptr;

		DPrint("one: %p %d", val, *val);
	}();
	#endif

	return;
}

// https://www.unknowncheats.me/forum/anti-cheat-bypass/296455-battleye-reading-memory-driver.html

// free after use
uint8_t* memory::ReadUser(PEPROCESS proccess, void* address, size_t len) {
	auto buffer = new uint8_t[len];

	KAPC_STATE apcState;
	KeStackAttachProcess(proccess, &apcState);
	memcpy(buffer, address, len);
	KeUnstackDetachProcess(&apcState);

	return buffer;
}

void memory::WriteUser(uint8_t* data, size_t len, PEPROCESS proccess, void* address) {
	KAPC_STATE apcState;
	KeStackAttachProcess(proccess, &apcState);
	memcpy(address, data, len);
	KeUnstackDetachProcess(&apcState);
}

bool memory::CopyUser(PEPROCESS master, void* from, PEPROCESS target, void* to, size_t len) {
	SIZE_T bytes = 0;
	auto status = MmCopyVirtualMemory(master, from, target, to, len, UserMode, &bytes);
	if (!NT_SUCCESS(status)) {
		return false;
	}

	return true;
}

bool memory::Valid(void* addr) {
	return (bool)MmIsAddressValid(addr);
}
