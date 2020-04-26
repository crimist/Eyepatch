#pragma once

#define EYEPATCH_MEMORY_TAG 'seyE'

void* __cdecl operator new(size_t size);
void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag = EYEPATCH_MEMORY_TAG);
void __cdecl operator delete(void* p/*, unsigned int dummy*/);
