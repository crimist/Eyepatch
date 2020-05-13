#pragma once

#include <ntddk.h>
#include <wdf.h>
//#include <wsk.h> // winsock kernel
//#pragma comment(lib, "netio.lib")

// debug print macro
// https://docs.microsoft.com/en-us/cpp/preprocessor/predefined-macros?view=vs-2019
// https://stackoverflow.com/questions/3046889/optional-parameters-with-c-macros

#if DBG
#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define DPrint(fmt, ...) DbgPrint(__FILE__ ":" STRINGIZE(__LINE__) " [" __FUNCTION__ "] " fmt "\n", __VA_ARGS__)
#else 
#define DPrint
#endif
