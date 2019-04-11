#pragma once

#include "includes.h"

class socket {
public:
	socket();
	~socket();

	NTSTATUS socket::registerWSK();
	NTSTATUS socket::create();
	NTSTATUS socket::close();
	NTSTATUS socket::bind();
private:
	WSK_REGISTRATION wskRegistration;
	WSK_CLIENT_NPI wskClientNpi;
	WSK_PROVIDER_NPI wskProviderNpi;
	PWSK_SOCKET WskSocket = NULL;
};
