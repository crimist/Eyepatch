#include "includes.h"
#include "memory.h"

// overload the default op
void* __cdecl operator new(size_t size) {
	#if DBG
	return ExAllocatePoolWithTag(NonPagedPoolNx, size, EYEPATCH_MEMORY_TAG);
	#else 
	return ExAllocatePool(NonPagedPoolNx, size);
	#endif
}

// provide an overloader for pool & tag definition
void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag) {
	#if DBG
	return ExAllocatePoolWithTag(pool, size, tag);
	#else 
	return ExAllocatePool(pool, size);
	#endif
}

void __cdecl operator delete(void* p) {
	// we use `/Zc:sizedDealloc-` in the C++ build command line to get our single argument delete operator back
	// than we can overload it without the dummy and without bombing the linker
	ExFreePool(p);
}
