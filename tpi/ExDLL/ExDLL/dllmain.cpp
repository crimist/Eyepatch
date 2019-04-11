#include "stdafx.h"

void main() {
	while (1) {
		printf("-");
		Sleep(50);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		printf("Hello!\n");
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, NULL, NULL, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
