#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD ModifiableAutorunCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    LONG lResult = 0;
    char szValueName[256];
    char szValueData[512];
    char szPath[512];
    DWORD dwValueNameSize = 0;
    DWORD dwValueDataSize = 0;
    DWORD dwType = 0;
    DWORD dwIndex = 0;
    int nFound = 0;
    int i = 0;
    int k = 0;
    int p = 0;
    int q = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    const char* pszHives[] = { "HKLM", "HKCU" };
    HKEY hRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    const char* pszSubkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    internal_printf("=== Modifiable Autorun Check ===\n\n");

    // Check both HKLM and HKCU
    for (i = 0; i < 2; i++)
    {
        for (k = 0; k < 4; k++)
        {
            lResult = ADVAPI32$RegOpenKeyExA(
                hRoots[i],
                pszSubkeys[k],
                0,
                KEY_READ,
                &hKey);

            if (lResult != ERROR_SUCCESS)
            {
                continue;
            }

            dwIndex = 0;
            while (1)
            {
                dwValueNameSize = sizeof(szValueName);
                dwValueDataSize = sizeof(szValueData);

                lResult = ADVAPI32$RegEnumValueA(
                    hKey,
                    dwIndex,
                    szValueName,
                    &dwValueNameSize,
                    NULL,
                    &dwType,
                    (LPBYTE)szValueData,
                    &dwValueDataSize);

                if (lResult != ERROR_SUCCESS)
                {
                    break;
                }

                if (dwType == REG_SZ || dwType == REG_EXPAND_SZ)
                {
                    szValueData[dwValueDataSize] = '\0';

                    // Extract executable path
                    p = 0;
                    q = 0;

                    // Skip leading spaces
                    while (szValueData[p] == ' ') p++;

                    // Handle quoted path
                    if (szValueData[p] == '"')
                    {
                        p++;
                        while (szValueData[p] != '\0' && szValueData[p] != '"' && q < 510)
                        {
                            szPath[q++] = szValueData[p++];
                        }
                    }
                    else
                    {
                        // Unquoted - take until space or end
                        while (szValueData[p] != '\0' && szValueData[p] != ' ' && q < 510)
                        {
                            szPath[q++] = szValueData[p++];
                        }
                    }
                    szPath[q] = '\0';

                    // Try to open file for write access
                    hFile = KERNEL32$CreateFileA(
                        szPath,
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

                    if (hFile != INVALID_HANDLE_VALUE)
                    {
                        KERNEL32$CloseHandle(hFile);
                        internal_printf("[+] WRITABLE: %s\\%s\n", pszHives[i], pszSubkeys[k]);
                        internal_printf("    Name: %s\n", szValueName);
                        internal_printf("    Path: %s\n\n", szValueData);
                        nFound++;
                    }
                }

                dwIndex++;
            }

            ADVAPI32$RegCloseKey(hKey);
            hKey = NULL;
        }
    }

    internal_printf("[*] Scan complete\n");

    if (nFound > 0)
    {
        internal_printf("[+] VULNERABLE: %d modifiable autorun(s) found!\n", nFound);
    }
    else
    {
        internal_printf("[-] Not Vulnerable: No modifiable autoruns found\n");
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

    dwErrorCode = ModifiableAutorunCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ModifiableAutorunCheck failed: %lX\n", dwErrorCode);
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

    dwErrorCode = ModifiableAutorunCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ModifiableAutorunCheck failed: %lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif