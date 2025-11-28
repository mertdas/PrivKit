#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD TokenPrivilegesCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    DWORD dwSize = 0;
    DWORD i = 0;
    char szPrivName[256];
    DWORD dwNameSize = 0;
    BOOL bEnabled = FALSE;
    HANDLE hHeap = NULL;

    internal_printf("=== Token Privileges Check ===\n\n");

    // Open current process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    // Get required buffer size
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token info size. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    // Allocate buffer
    hHeap = KERNEL32$GetProcessHeap();
    pTokenPrivs = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);
    if (pTokenPrivs == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory\n");
        goto TokenPrivilegesCheck_end;
    }

    // Get token privileges
    if (!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwSize, &dwSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token privileges. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    internal_printf("[*] Found %lu privileges:\n\n", pTokenPrivs->PrivilegeCount);

    // Display privileges
    for (i = 0; i < pTokenPrivs->PrivilegeCount; i++)
    {
        dwNameSize = sizeof(szPrivName);
        if (ADVAPI32$LookupPrivilegeNameA(NULL, &pTokenPrivs->Privileges[i].Luid, szPrivName, &dwNameSize))
        {
            bEnabled = (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? TRUE : FALSE;

            if (bEnabled)
            {
                internal_printf("[+] %s : Enabled\n", szPrivName);
            }
            else
            {
                internal_printf("[-] %s : Disabled\n", szPrivName);
            }
        }
    }

    internal_printf("\n[*] Privilege enumeration complete\n");
    dwErrorCode = ERROR_SUCCESS;

TokenPrivilegesCheck_end:
    if (pTokenPrivs != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenPrivs);
        pTokenPrivs = NULL;
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
        hToken = NULL;
    }

    return dwErrorCode;
}

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    if (!bofstart())
    {
        return;
    }

    dwErrorCode = TokenPrivilegesCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "TokenPrivilegesCheck failed: %lX\n", dwErrorCode);
        goto go_end;
    }

go_end:
    printoutput(TRUE);
    bofstop();
}
#else
int main(int argc, char **argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    dwErrorCode = TokenPrivilegesCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "TokenPrivilegesCheck failed: %lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif