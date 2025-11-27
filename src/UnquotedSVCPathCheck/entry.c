#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD UnquotedSVCPathCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hServicesKey = NULL;
    HKEY hServiceKey = NULL;
    char szServiceName[256];
    char szImagePath[512];
    DWORD dwIndex = 0;
    DWORD dwNameSize = 0;
    DWORD dwValueSize = 0;
    LONG lResult = 0;
    int nFound = 0;
    int i = 0;
    int len = 0;
    BOOL bHasSpace = FALSE;
    BOOL bHasQuote = FALSE;
    BOOL bIsSystem = FALSE;
    BOOL bIsSysDriver = FALSE;
    char c;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Unquoted Service Path Check ===\n\n");

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services",
        0,
        KEY_READ,
        &hServicesKey);

    if (lResult != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open Services registry key. Error: %ld\n", lResult);
        dwErrorCode = (DWORD)lResult;
        goto UnquotedSVCPathCheck_end;
    }

    dwIndex = 0;
    while (1)
    {
        dwNameSize = sizeof(szServiceName);
        lResult = ADVAPI32$RegEnumKeyExA(
            hServicesKey,
            dwIndex,
            szServiceName,
            &dwNameSize,
            NULL,
            NULL,
            NULL,
            NULL);

        if (lResult != ERROR_SUCCESS)
        {
            break;
        }

        dwIndex++;

        // Open service subkey
        lResult = ADVAPI32$RegOpenKeyExA(
            hServicesKey,
            szServiceName,
            0,
            KEY_READ,
            &hServiceKey);

        if (lResult != ERROR_SUCCESS)
        {
            continue;
        }

        // Get ImagePath value
        dwValueSize = sizeof(szImagePath) - 1;
        lResult = ADVAPI32$RegGetValueA(
            hServiceKey,
            NULL,
            "ImagePath",
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            NULL,
            szImagePath,
            &dwValueSize);

        ADVAPI32$RegCloseKey(hServiceKey);
        hServiceKey = NULL;

        if (lResult != ERROR_SUCCESS)
        {
            continue;
        }

        szImagePath[dwValueSize] = '\0';

        // Reset flags
        bHasSpace = FALSE;
        bHasQuote = FALSE;
        bIsSystem = FALSE;
        bIsSysDriver = FALSE;
        len = 0;

        // Get length and check for space/quote in one pass
        for (i = 0; szImagePath[i] != '\0'; i++)
        {
            if (szImagePath[i] == ' ')
            {
                bHasSpace = TRUE;
            }
            if (szImagePath[i] == '"')
            {
                bHasQuote = TRUE;
            }
            len++;
        }

        // Check for System32/SysWOW64 (case insensitive)
        for (i = 0; i < len - 6; i++)
        {
            c = szImagePath[i];
            if (c >= 'A' && c <= 'Z') c += 32;

            if (c == 's')
            {
                char c2 = szImagePath[i + 1];
                char c3 = szImagePath[i + 2];
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c3 >= 'A' && c3 <= 'Z') c3 += 32;

                if (c2 == 'y' && c3 == 's')
                {
                    bIsSystem = TRUE;
                    break;
                }
            }
        }

        // Check for .sys driver extension
        if (len >= 4)
        {
            char e1 = szImagePath[len - 4];
            char e2 = szImagePath[len - 3];
            char e3 = szImagePath[len - 2];
            char e4 = szImagePath[len - 1];

            if (e1 >= 'A' && e1 <= 'Z') e1 += 32;
            if (e2 >= 'A' && e2 <= 'Z') e2 += 32;
            if (e3 >= 'A' && e3 <= 'Z') e3 += 32;
            if (e4 >= 'A' && e4 <= 'Z') e4 += 32;

            if (e1 == '.' && e2 == 's' && e3 == 'y' && e4 == 's')
            {
                bIsSysDriver = TRUE;
            }
        }

        // Vulnerable: has space, no quote, not in system folder, not a driver
        if (bHasSpace && !bHasQuote && !bIsSystem && !bIsSysDriver)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] VULNERABLE: %s\n", szServiceName);
            BeaconPrintf(CALLBACK_OUTPUT, "    ImagePath: %s\n\n", szImagePath);
            nFound++;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scan complete\n");

    if (nFound > 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VULNERABLE: %d unquoted service path(s) found!\n", nFound);
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Not Vulnerable: No unquoted service paths found\n");
    }

UnquotedSVCPathCheck_end:
    if (hServiceKey != NULL)
    {
        ADVAPI32$RegCloseKey(hServiceKey);
    }
    if (hServicesKey != NULL)
    {
        ADVAPI32$RegCloseKey(hServicesKey);
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

    dwErrorCode = UnquotedSVCPathCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "UnquotedSVCPathCheck failed: %lX\n", dwErrorCode);
    }
}
#else
int main(int argc, char **argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    dwErrorCode = UnquotedSVCPathCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "UnquotedSVCPathCheck failed: %lX\n", dwErrorCode);
    }

    return dwErrorCode;
}
#endif