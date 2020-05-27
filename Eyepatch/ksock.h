#pragma once

class ksock {
public:
	ksock(uint16_t port);
	~ksock();

	bool recv(uintptr_t* buff, uint32_t len);
private:
	int sock;
};

