#include "includes.h"
#include "socket.h"

socket::socket() {
	const WSK_CLIENT_DISPATCH WskAppDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};
	this->clientNpi.ClientContext = NULL;
	this->clientNpi.Dispatch = &WskAppDispatch;

	auto status = WskRegister(&this->clientNpi, &this->registration);
	if (!NT_SUCCESS(status)) {
		DPrint("WskRegister failed %x", status);
		return;
	}

	status = WskCaptureProviderNPI(&this->registration, WSK_INFINITE_WAIT, &this->providerNpi);
	if (!NT_SUCCESS(status)) {
		DPrint("WskCaptureProviderNPI failed %x", status);
	}
}

socket::~socket() {
	// close socket
}

// https://github.com/hsluoyz/wskudp/blob/master/wsktcp/simplewsk.c

static NTSTATUS NTAPI CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PKEVENT CompletionEvent) {
	ASSERT(CompletionEvent);

	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS InitWskData(IRP** pIrp, KEVENT* CompletionEvent) {
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	*pIrp = IoAllocateIrp(1, FALSE);
	if (!*pIrp) {
		DPrint("IoAllocateIrp failed");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, (PIO_COMPLETION_ROUTINE)CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS socket::create() {
	KEVENT CompletionEvent = {0};
	PIRP Irp = NULL;
	NTSTATUS status;

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = this->providerNpi.Dispatch->WskSocket(this->providerNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}

	this->socketFd = (PWSK_SOCKET)Irp->IoStatus.Information;
	IoFreeIrp(Irp);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS socket::close() {
	KEVENT CompletionEvent = {0};
	PIRP Irp = NULL;
	NTSTATUS status;

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ((PWSK_PROVIDER_BASIC_DISPATCH)this->socketFd->Dispatch)->WskCloseSocket(this->socketFd, Irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS socket::bind() {
	KEVENT CompletionEvent = {0};
	PIRP Irp = NULL;
	NTSTATUS status;
	SOCKADDR_IN addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0x479C; // port # 40007

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)this->socketFd->Dispatch)->WskBind(this->socketFd, (PSOCKADDR)&addr, 0, Irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

