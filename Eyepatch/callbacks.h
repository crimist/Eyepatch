#pragma once
#include "includes.h"

// https://www.unknowncheats.me/forum/anti-cheat-bypass/148364-obregistercallbacks-countermeasures.html

void registerCallback();

OB_PREOP_CALLBACK_STATUS preOperationCallback(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);
VOID postOperationCallback(_In_ PVOID RegistrationContext, _In_ POB_POST_OPERATION_INFORMATION PostInfo);
