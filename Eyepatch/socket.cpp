#include "includes.h"
#include "socket.h"

socket::socket() {}
socket::~socket() {}

// Maybe use macro
#define NT_OK if (!NT_SUCCESS(status)) { return status; }

NTSTATUS socket::registerWSK() {
	NTSTATUS status;
	const WSK_CLIENT_DISPATCH WskAppDispatch = {
		MAKE_WSK_VERSION(1,0), // Use WSK version 1.0
		0,    // Reserved
		NULL  // WskClientEvent callback not required for WSK version 1.0
	};

	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &WskAppDispatch;

	status = WskRegister(&wskClientNpi, &wskRegistration);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = WskCaptureProviderNPI(&wskRegistration, WSK_INFINITE_WAIT, &wskProviderNpi);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

// https://github.com/hsluoyz/wskudp/blob/master/wsktcp/simplewsk.c

static NTSTATUS NTAPI CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PKEVENT CompletionEvent) {
	ASSERT(CompletionEvent);

	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS InitWskData(PIRP* pIrp, PKEVENT CompletionEvent) {
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	*pIrp = IoAllocateIrp(1, FALSE);
	if (!*pIrp) {
		DbgPrint("InitWskData(): IoAllocateIrp() failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, (PIO_COMPLETION_ROUTINE)CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS socket::create() {
	KEVENT CompletionEvent = { 0 };
	PIRP Irp = NULL;
	NTSTATUS status;

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = wskProviderNpi.Dispatch->WskSocket(wskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}

	WskSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

	IoFreeIrp(Irp);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS socket::close() {
	KEVENT CompletionEvent = { 0 };
	PIRP Irp = NULL;
	NTSTATUS status;

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
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
	KEVENT CompletionEvent = { 0 };
	PIRP Irp = NULL;
	NTSTATUS status;
	SOCKADDR_IN addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0x479C; // port # 40007

	status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskBind(WskSocket, (PSOCKADDR)&addr, 0, Irp);
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
