#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD CheckAlwaysInstallElevated(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    BOOL bHkcuSet = FALSE;
    BOOL bHklmSet = FALSE;
    LONG lResult = 0;

    // Check HKEY_CURRENT_USER
    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );
    
    if (lResult == ERROR_SUCCESS)
    {
        dwSize = sizeof(DWORD);
        lResult = ADVAPI32$RegQueryValueExA(
            hKey,
            "AlwaysInstallElevated",
            NULL,
            NULL,
            (LPBYTE)&dwValue,
            &dwSize
        );
        
        if (lResult == ERROR_SUCCESS && dwValue == 1)
        {
            bHkcuSet = TRUE;
            internal_printf("[*] HKCU\\...\\Installer\\AlwaysInstallElevated = 1\n");
        }
        else
        {
            internal_printf("[*] HKCU\\...\\Installer\\AlwaysInstallElevated not set or != 1\n");
        }
        
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    else
    {
        internal_printf("[*] HKCU\\...\\Installer key not found\n");
    }

    // Check HKEY_LOCAL_MACHINE
    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );
    
    if (lResult == ERROR_SUCCESS)
    {
        dwSize = sizeof(DWORD);
        lResult = ADVAPI32$RegQueryValueExA(
            hKey,
            "AlwaysInstallElevated",
            NULL,
            NULL,
            (LPBYTE)&dwValue,
            &dwSize
        );
        
        if (lResult == ERROR_SUCCESS && dwValue == 1)
        {
            bHklmSet = TRUE;
            internal_printf("[*] HKLM\\...\\Installer\\AlwaysInstallElevated = 1\n");
        }
        else
        {
            internal_printf("[*] HKLM\\...\\Installer\\AlwaysInstallElevated not set or != 1\n");
        }
        
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    else
    {
        internal_printf("[*] HKLM\\...\\Installer key not found\n");
    }

    // Both must be set for exploitation
    internal_printf("\n");
    if (bHkcuSet && bHklmSet)
    {
        internal_printf("[+] VULNERABLE: AlwaysInstallElevated is set in both HKCU and HKLM\n");
    }
    else
    {
        internal_printf("[-] NOT VULNERABLE: AlwaysInstallElevated requires both HKCU and HKLM set to 1\n");
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

    internal_printf("=== AlwaysInstallElevated Check ===\n\n");

    dwErrorCode = CheckAlwaysInstallElevated();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CheckAlwaysInstallElevated failed: %lX\n", dwErrorCode);
        goto go_end;
    }

go_end:
    printoutput(TRUE);
    bofstop();
}
#else
int main(int argc, char** argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    internal_printf("=== AlwaysInstallElevated Check ===\n\n");

    dwErrorCode = CheckAlwaysInstallElevated();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CheckAlwaysInstallElevated failed: %lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif