#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD UACStatusCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    LONG lResult = 0;
    DWORD dwEnableLUA = 0;
    DWORD dwConsentPrompt = 0;
    DWORD dwSecureDesktop = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType = 0;
    HANDLE hToken = NULL;
    DWORD dwIntegrityLevel = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    DWORD dwLengthNeeded = 0;
    HANDLE hHeap = NULL;
    BOOL bIsAdmin = FALSE;
    BOOL bIsElevated = FALSE;
    PUCHAR pCount = NULL;
    PDWORD pLevel = NULL;
    DWORD i = 0;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "=== UAC Status Check ===\n\n");

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,
        KEY_READ,
        &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open registry key. Error: %ld\n", lResult);
        dwErrorCode = (DWORD)lResult;
        goto UACStatusCheck_end;
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, &dwType, (LPBYTE)&dwEnableLUA, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] UAC Enabled (EnableLUA): %s\n", dwEnableLUA ? "Yes" : "No");
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] UAC Enabled (EnableLUA): Unknown (not found)\n");
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", NULL, &dwType, (LPBYTE)&dwConsentPrompt, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ConsentPromptBehaviorAdmin: %lu ", dwConsentPrompt);
        switch (dwConsentPrompt)
        {
            case 0: BeaconPrintf(CALLBACK_OUTPUT, "(Elevate without prompting)\n"); break;
            case 1: BeaconPrintf(CALLBACK_OUTPUT, "(Prompt for credentials on secure desktop)\n"); break;
            case 2: BeaconPrintf(CALLBACK_OUTPUT, "(Prompt for consent on secure desktop)\n"); break;
            case 3: BeaconPrintf(CALLBACK_OUTPUT, "(Prompt for credentials)\n"); break;
            case 4: BeaconPrintf(CALLBACK_OUTPUT, "(Prompt for consent)\n"); break;
            case 5: BeaconPrintf(CALLBACK_OUTPUT, "(Prompt for consent for non-Windows binaries)\n"); break;
            default: BeaconPrintf(CALLBACK_OUTPUT, "(Unknown)\n"); break;
        }
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "PromptOnSecureDesktop", NULL, &dwType, (LPBYTE)&dwSecureDesktop, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] PromptOnSecureDesktop: %s\n", dwSecureDesktop ? "Yes" : "No");
    }

    ADVAPI32$RegCloseKey(hKey);
    hKey = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto UACStatusCheck_end;
    }

    hHeap = KERNEL32$GetProcessHeap();

    // Get Integrity Level
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0)
    {
        pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTIL != NULL)
        {
            if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
            {
                pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
                if (pCount != NULL && *pCount > 0)
                {
                    pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*pCount - 1));
                    if (pLevel != NULL)
                    {
                        dwIntegrityLevel = *pLevel;
                    }
                }
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Integrity Level: ");
    if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Untrusted\n");
    }
    else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Low\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Medium\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "High (Elevated)\n");
        bIsElevated = TRUE;
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "System\n");
        bIsElevated = TRUE;
    }

    // Create Admin SID
    if (!ADVAPI32$AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &pAdminSid))
    {
        dwErrorCode = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create Admin SID. Error: %lu\n", dwErrorCode);
        goto UACStatusCheck_end;
    }

    // Check token groups for admin membership (works even with filtered token)
    dwLengthNeeded = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0)
    {
        pTokenGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTokenGroups != NULL)
        {
            if (ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLengthNeeded, &dwLengthNeeded))
            {
                for (i = 0; i < pTokenGroups->GroupCount; i++)
                {
                    if (ADVAPI32$EqualSid(pAdminSid, pTokenGroups->Groups[i].Sid))
                    {
                        bIsAdmin = TRUE;
                        break;
                    }
                }
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Local Admin Group Member: %s\n", bIsAdmin ? "Yes" : "No");

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Summary:\n");

    if (bIsElevated)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Process is running with elevated privileges\n");
    }
    else if (bIsAdmin && dwEnableLUA)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User is local admin but NOT elevated (UAC filtered token)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] UAC bypass may be possible\n");
    }
    else if (bIsAdmin && !dwEnableLUA)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User is local admin and UAC is disabled\n");
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] User is NOT a local admin\n");
    }

    dwErrorCode = ERROR_SUCCESS;

UACStatusCheck_end:
    if (pAdminSid != NULL)
    {
        ADVAPI32$FreeSid(pAdminSid);
    }
    if (pTokenGroups != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenGroups);
    }
    if (pTIL != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTIL);
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
    }
    if (hKey != NULL)
    {
        ADVAPI32$RegCloseKey(hKey);
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

    dwErrorCode = UACStatusCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "UACStatusCheck failed: %lX\n", dwErrorCode);
    }
}
#else
int main(int argc, char **argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    dwErrorCode = UACStatusCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "UACStatusCheck failed: %lX\n", dwErrorCode);
    }

    return dwErrorCode;
}
#endif