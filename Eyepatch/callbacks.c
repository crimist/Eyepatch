#include "callbacks.h"

void registerCallback() {
	OB_CALLBACK_REGISTRATION callback;
	void *handle = NULL;
	UNICODE_STRING altitude = { 0 };
	OB_OPERATION_REGISTRATION operationRegistration[1] = { { 0 } };

	RtlInitUnicodeString(&altitude, L"1337");

	operationRegistration[0].ObjectType = PsProcessType;
	operationRegistration[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	operationRegistration[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration[0].PreOperation = preOperationCallback;
	operationRegistration[0].PostOperation = postOperationCallback; 

	callback.Version = OB_FLT_REGISTRATION_VERSION;
	callback.OperationRegistrationCount = 1;
	callback.Altitude = altitude;
	callback.RegistrationContext = NULL;
	callback.OperationRegistration = operationRegistration;

	ObRegisterCallbacks(&callback, handle);
}

OB_PREOP_CALLBACK_STATUS preOperationCallback(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo) {
	DbgPrint("preOperationCallback(): %p %p\n", RegistrationContext, PreInfo);
	return OB_PREOP_SUCCESS;
}

VOID postOperationCallback(_In_ PVOID RegistrationContext, _In_ POB_POST_OPERATION_INFORMATION PostInfo) {
	DbgPrint("postOperationCallback(): %p %p\n", RegistrationContext, PostInfo);
	return;
}
