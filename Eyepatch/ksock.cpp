#include "includes.h"
#include "ksock.h"

ksock::ksock(uint16_t port) {
	static bool init = true;
	if (init) {
		// init wsk
		init = false;
	}

	// bind and listen on port

	return;
}

ksock::~ksock() {
	// close sock
	// cleanup wsk

	return;
}

bool recv(uintptr_t* buff, uint32_t len) {
	// recv off listen
	return true;
}
