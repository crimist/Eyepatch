#pragma once

// only tag mem on debug builds
#if DBG
#define EYEPATCH_MEMORY_TAG 'seyE'
#else
#define EYEPATCH_MEMORY_TAG NULL
#endif

void* __cdecl operator new(size_t size);
void* __cdecl operator new(size_t size, POOL_TYPE pool, uint32_t tag = EYEPATCH_MEMORY_TAG);
void __cdecl operator delete(void* p);

namespace memory {
	// todo: check if works
	template <class T>
	class heaped {
	public:
		T* ptr;

		heaped() {
			DPrint("heaped\n");
			ptr = new T;
		}
		~heaped() {
			DPrint("~heaped\n");
			delete ptr;
		}
	};

	void test();

	uint8_t* ReadUser(PEPROCESS proccess, void* address, size_t len);
	void WriteUser(uint8_t* data, size_t len, PEPROCESS proccess, void* address);
	bool CopyUser(PEPROCESS master, void* from, PEPROCESS target, void* to, size_t len);
	bool Valid(void* addr);
}
