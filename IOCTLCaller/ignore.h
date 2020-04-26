#pragma once

/* Reversing notes:
drivers list actually gets set to the pointers for nt!_DRIVER_OBJECT
WHERE DOES IT GET THIS LIST?
Use cheat engine to search for pointers?
try to break into win32 function: https://stackoverflow.com/questions/3080624/debug-break-on-win32-api-functions
lives in `Kernel32!` or `Psapi!`

K32EnumDeviceDrivers:
00007FFCEA2BB8C0 48 89 5C 24 10       mov         qword ptr [rsp+10h],rbx
00007FFCEA2BB8C5 48 89 74 24 18       mov         qword ptr [rsp+18h],rsi
00007FFCEA2BB8CA 48 89 4C 24 08       mov         qword ptr [rsp+8],rcx
00007FFCEA2BB8CF 57                   push        rdi
00007FFCEA2BB8D0 41 54                push        r12
00007FFCEA2BB8D2 41 55                push        r13
00007FFCEA2BB8D4 41 56                push        r14
00007FFCEA2BB8D6 41 57                push        r15
00007FFCEA2BB8D8 48 83 EC 30          sub         rsp,30h
00007FFCEA2BB8DC 4D 8B E8             mov         r13,r8
00007FFCEA2BB8DF 44 8B E2             mov         r12d,edx
00007FFCEA2BB8E2 BE 30 05 00 00       mov         esi,530h
00007FFCEA2BB8E7 33 DB                xor         ebx,ebx
00007FFCEA2BB8E9 8B D6                mov         edx,esi
00007FFCEA2BB8EB 33 C9                xor         ecx,ecx
00007FFCEA2BB8ED E8 EE 19 FC FF       call        LocalAlloc (07FFCEA27D2E0h)
00007FFCEA2BB8F2 48 8B F8             mov         rdi,rax
00007FFCEA2BB8F5 48 89 44 24 20       mov         qword ptr [rsp+20h],rax
00007FFCEA2BB8FA 48 85 C0             test        rax,rax
00007FFCEA2BB8FD 0F 84 63 16 04 00    je          _guard_dispatch_icall_nop+1D5E6h (07FFCEA2FCF66h)
00007FFCEA2BB903 4C 8D 4C 24 78       lea         r9,[rsp+78h]
00007FFCEA2BB908 44 8B C6             mov         r8d,esi
00007FFCEA2BB90B 48 8B D0             mov         rdx,rax
00007FFCEA2BB90E B9 0B 00 00 00       mov         ecx,0Bh
00007FFCEA2BB913 48 FF 15 1E B0 13 00 call        qword ptr [__imp_NtQuerySystemInformation (07FFCEA3F6938h)]
00007FFCEA2BB91A 0F 1F 44 00 00       nop         dword ptr [rax+rax]
00007FFCEA2BB91F 44 8B F0             mov         r14d,eax
00007FFCEA2BB922 44 8B 3F             mov         r15d,dword ptr [rdi]
00007FFCEA2BB925 85 C0                test        eax,eax
00007FFCEA2BB927 0F 88 B4 00 00 00    js          K32EnumDeviceDrivers+121h (07FFCEA2BB9E1h)
00007FFCEA2BB92D 41 C1 EC 03          shr         r12d,3
00007FFCEA2BB931 4C 8B 44 24 60       mov         r8,qword ptr [rsp+60h]
00007FFCEA2BB936 41 3B DF             cmp         ebx,r15d
00007FFCEA2BB939 73 49                jae         K32EnumDeviceDrivers+0C4h (07FFCEA2BB984h)
00007FFCEA2BB93B 41 3B DC             cmp         ebx,r12d
00007FFCEA2BB93E 74 44                je          K32EnumDeviceDrivers+0C4h (07FFCEA2BB984h)
00007FFCEA2BB940 8B D3                mov         edx,ebx
00007FFCEA2BB942 48 69 C2 28 01 00 00 imul        rax,rdx,128h
00007FFCEA2BB949 48 8B 4C 38 18       mov         rcx,qword ptr [rax+rdi+18h]
00007FFCEA2BB94E 49 89 0C D0          mov         qword ptr [r8+rdx*8],rcx
00007FFCEA2BB952 EB 2C                jmp         K32EnumDeviceDrivers+0C0h (07FFCEA2BB980h)
00007FFCEA2BB954 8B D8                mov         ebx,eax
00007FFCEA2BB956 48 8B 4C 24 20       mov         rcx,qword ptr [rsp+20h]
00007FFCEA2BB95B E8 20 22 FC FF       call        LocalFree (07FFCEA27DB80h)
00007FFCEA2BB960 8B CB                mov         ecx,ebx
00007FFCEA2BB962 48 FF 15 6F B0 13 00 call        qword ptr [__imp_RtlNtStatusToDosError (07FFCEA3F69D8h)]
00007FFCEA2BB969 0F 1F 44 00 00       nop         dword ptr [rax+rax]
00007FFCEA2BB96E 8B C8                mov         ecx,eax
00007FFCEA2BB970 48 FF 15 99 AF 13 00 call        qword ptr [__imp_RtlSetLastWin32Error (07FFCEA3F6910h)]
00007FFCEA2BB977 0F 1F 44 00 00       nop         dword ptr [rax+rax]
00007FFCEA2BB97C 33 C0                xor         eax,eax
00007FFCEA2BB97E EB 49                jmp         K32EnumDeviceDrivers+109h (07FFCEA2BB9C9h)
00007FFCEA2BB980 FF C3                inc         ebx
00007FFCEA2BB982 EB B2                jmp         K32EnumDeviceDrivers+76h (07FFCEA2BB936h)
00007FFCEA2BB984 41 8B C7             mov         eax,r15d
00007FFCEA2BB987 C1 E0 03             shl         eax,3
00007FFCEA2BB98A 41 89 45 00          mov         dword ptr [r13],eax
00007FFCEA2BB98E EB 2C                jmp         K32EnumDeviceDrivers+0FCh (07FFCEA2BB9BCh)
00007FFCEA2BB990 8B D8                mov         ebx,eax
00007FFCEA2BB992 48 8B 4C 24 20       mov         rcx,qword ptr [rsp+20h]
00007FFCEA2BB997 E8 E4 21 FC FF       call        LocalFree (07FFCEA27DB80h)
00007FFCEA2BB99C 8B CB                mov         ecx,ebx
00007FFCEA2BB99E 48 FF 15 33 B0 13 00 call        qword ptr [__imp_RtlNtStatusToDosError (07FFCEA3F69D8h)]
00007FFCEA2BB9A5 0F 1F 44 00 00       nop         dword ptr [rax+rax]
00007FFCEA2BB9AA 8B C8                mov         ecx,eax
00007FFCEA2BB9AC 48 FF 15 5D AF 13 00 call        qword ptr [__imp_RtlSetLastWin32Error (07FFCEA3F6910h)]
00007FFCEA2BB9B3 0F 1F 44 00 00       nop         dword ptr [rax+rax]
00007FFCEA2BB9B8 33 C0                xor         eax,eax
00007FFCEA2BB9BA EB 0D                jmp         K32EnumDeviceDrivers+109h (07FFCEA2BB9C9h)
00007FFCEA2BB9BC 48 8B CF             mov         rcx,rdi
00007FFCEA2BB9BF E8 BC 21 FC FF       call        LocalFree (07FFCEA27DB80h)
00007FFCEA2BB9C4 B8 01 00 00 00       mov         eax,1
00007FFCEA2BB9C9 48 8B 5C 24 68       mov         rbx,qword ptr [rsp+68h]
00007FFCEA2BB9CE 48 8B 74 24 70       mov         rsi,qword ptr [rsp+70h]
00007FFCEA2BB9D3 48 83 C4 30          add         rsp,30h
00007FFCEA2BB9D7 41 5F                pop         r15
00007FFCEA2BB9D9 41 5E                pop         r14
00007FFCEA2BB9DB 41 5D                pop         r13
00007FFCEA2BB9DD 41 5C                pop         r12
00007FFCEA2BB9DF 5F                   pop         rdi
00007FFCEA2BB9E0 C3                   ret
00007FFCEA2BB9E1 48 8B CF             mov         rcx,rdi
00007FFCEA2BB9E4 E8 97 21 FC FF       call        LocalFree (07FFCEA27DB80h)
00007FFCEA2BB9E9 B9 04 00 00 C0       mov         ecx,0C0000004h
00007FFCEA2BB9EE 44 3B F1             cmp         r14d,ecx
00007FFCEA2BB9F1 75 19                jne         K32EnumDeviceDrivers+14Ch (07FFCEA2BBA0Ch)
00007FFCEA2BB9F3 41 69 C7 28 01 00 00 imul        eax,r15d,128h
00007FFCEA2BB9FA 83 C0 08             add         eax,8
00007FFCEA2BB9FD 3B C6                cmp         eax,esi
00007FFCEA2BB9FF 0F 86 68 15 04 00    jbe         _guard_dispatch_icall_nop+1D5EDh (07FFCEA2FCF6Dh)
00007FFCEA2BBA05 8B F0                mov         esi,eax
00007FFCEA2BBA07 E9 DD FE FF FF       jmp         K32EnumDeviceDrivers+29h (07FFCEA2BB8E9h)
00007FFCEA2BBA0C 41 8B CE             mov         ecx,r14d
00007FFCEA2BBA0F E9 59 15 04 00       jmp         _guard_dispatch_icall_nop+1D5EDh (07FFCEA2FCF6Dh)
00007FFCEA2BBA14 CC                   int         3
00007FFCEA2BBA15 CC                   int         3
00007FFCEA2BBA16 CC                   int         3
00007FFCEA2BBA17 CC                   int         3
00007FFCEA2BBA18 CC                   int         3
00007FFCEA2BBA19 CC                   int         3
00007FFCEA2BBA1A CC                   int         3
00007FFCEA2BBA1B CC                   int         3
00007FFCEA2BBA1C CC                   int         3
00007FFCEA2BBA1D CC                   int         3
00007FFCEA2BBA1E CC                   int         3
00007FFCEA2BBA1F CC                   int         3
*/

#include <psapi.h>
#include <tchar.h>
#define DRIVER_LIST_SIZE 512

void enumDrivers() {
	LPVOID drivers[DRIVER_LIST_SIZE];
	DWORD cbNeeded;
	int cDrivers, i;

	auto ret = EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
	if (ret && cbNeeded < sizeof(drivers)) {
		TCHAR szDriver[DRIVER_LIST_SIZE];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		_tprintf(TEXT("There are %d drivers:\n"), cDrivers);
		for (i = 0; i < cDrivers; i++) {
			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
				_tprintf(TEXT("%d: %s\n"), i + 1, szDriver);
			}
		}
	} else {
		_tprintf(TEXT("EnumDeviceDrivers failed; array size needed is %d\n"), cbNeeded / sizeof(LPVOID));
		return;
	}

	return;
}
