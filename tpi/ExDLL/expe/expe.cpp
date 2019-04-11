#include "pch.h"
#include <iostream>

int main() {
	std::cout << "Hello World!\n";
	auto i = TlsAlloc();
	while (1) {
		TlsGetValue(i);
		printf(".");
		Sleep(50);
	}
}
