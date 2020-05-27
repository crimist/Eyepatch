#pragma once

class socket {
public:
	socket();
	~socket();

	NTSTATUS socket::create();
	NTSTATUS socket::close();
	NTSTATUS socket::bind();
private:
	WSK_REGISTRATION registration;
	WSK_CLIENT_NPI clientNpi;
	WSK_PROVIDER_NPI providerNpi;
	PWSK_SOCKET socketFd;
};
