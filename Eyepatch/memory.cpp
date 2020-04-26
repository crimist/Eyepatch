#include "includes.h"
#include "memory.h"

// overload the default op
void* __cdecl operator new(size_t size) {
	return ExAllocatePoolWithTag(NonPagedPoolNx, size, EYEPATCH_MEMORY_TAG);
}

// provide an overloader for pool & tag definition
void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag) {
	return ExAllocatePoolWithTag(pool, size, tag);
}

void __cdecl operator delete(void* p/*, unsigned int dummy*/) {
	//UNREFERENCED_PARAMETER(dummy);
	// we use `/Zc:sizedDealloc-` in the C++ build command line to get our single argument delete operator back
	// than we can overload it without the dummy and without bombing the linker
	ExFreePool(p);
}
