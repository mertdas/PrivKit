#include <windows.h>
#include <stdio.h>
#include "beacon.h"

DECLSPEC_IMPORT const char* WINAPI MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT LONG WINAPI  WINAPI Advapi32$LookupPrivilegeNameA(LPCSTR,PLUID,LPSTR,LPDWORD);
DECLSPEC_IMPORT LONG WINAPI WINAPI Advapi32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
DECLSPEC_IMPORT LONG WINAPI WINAPI Advapi32$GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
DECLSPEC_IMPORT LONG WINAPI  WINAPI Kernel32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI Kernel32$HeapFree (HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT WINBASEAPI PVOID WINAPI Kernel32$HeapAlloc (HANDLE, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI Kernel32$GetProcessHeap (VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI Kernel32$GetCurrentProcess (void);


void DisplayPrivileges(TOKEN_PRIVILEGES* tokenPrivileges) {
    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        LUID privilegeLuid = tokenPrivileges->Privileges[i].Luid;
        char privilegeNameBuffer[256];
        DWORD bufferSize = sizeof(privilegeNameBuffer);
        if (Advapi32$LookupPrivilegeNameA(NULL, &privilegeLuid, privilegeNameBuffer, &bufferSize)) {
            BOOL isEnabled = (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED;
            BeaconPrintf(CALLBACK_OUTPUT,"%s : %s\n", privilegeNameBuffer, isEnabled ? "Enabled" : "Disabled");
        }
    }
}

void go() {
    HANDLE tokenHandle;
    if (!Advapi32$OpenProcessToken(Kernel32$GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        BeaconPrintf(CALLBACK_OUTPUT,"Failed to open process token. Error: %lu\n");

    }

    DWORD tokenInfoSize = 0;
    Advapi32$GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &tokenInfoSize);
    if (tokenInfoSize == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,"Failed to get token information size. Error: %lu\n");
        Kernel32$CloseHandle(tokenHandle);

    }

    PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize);
    if (!Advapi32$GetTokenInformation(tokenHandle, TokenPrivileges, tokenPrivileges, tokenInfoSize, &tokenInfoSize)) {
        BeaconPrintf(CALLBACK_OUTPUT,"Failed to get token privileges. Error: %lu\n");
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, tokenPrivileges);
        Kernel32$CloseHandle(tokenHandle);

    }

    DisplayPrivileges(tokenPrivileges);

    Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, tokenPrivileges);
    Kernel32$CloseHandle(tokenHandle);

}
