#pragma once

// only tag mem on debug builds
#if DBG
#define EYEPATCH_MEMORY_TAG 'seyE'
#else
#define EYEPATCH_MEMORY_TAG NULL
#endif

void* __cdecl operator new(size_t size);
void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag = EYEPATCH_MEMORY_TAG);
void __cdecl operator delete(void* p/*, unsigned int dummy*/);
