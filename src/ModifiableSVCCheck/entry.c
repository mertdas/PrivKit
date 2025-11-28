#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

BOOL CheckSidInToken(HANDLE hToken, PSID pSid)
{
    BOOL bIsMember = FALSE;
    
    if (ADVAPI32$CheckTokenMembership(hToken, pSid, &bIsMember))
    {
        return bIsMember;
    }
    
    return FALSE;
}

BOOL HasModifyRights(ACCESS_MASK mask)
{
    if (mask & SERVICE_CHANGE_CONFIG)  return TRUE;
    if (mask & WRITE_DAC)              return TRUE;
    if (mask & WRITE_OWNER)            return TRUE;
    if (mask & GENERIC_ALL)            return TRUE;
    if (mask & GENERIC_WRITE)          return TRUE;
    if (mask & SERVICE_ALL_ACCESS)     return TRUE;
    
    return FALSE;
}

const char* GetServiceState(DWORD state)
{
    switch (state)
    {
        case SERVICE_STOPPED:          return "Stopped";
        case SERVICE_START_PENDING:    return "StartPending";
        case SERVICE_STOP_PENDING:     return "StopPending";
        case SERVICE_RUNNING:          return "Running";
        case SERVICE_CONTINUE_PENDING: return "ContinuePending";
        case SERVICE_PAUSE_PENDING:    return "PausePending";
        case SERVICE_PAUSED:           return "Paused";
        default:                       return "Unknown";
    }
}

const char* GetStartType(DWORD startType)
{
    switch (startType)
    {
        case SERVICE_BOOT_START:   return "Boot";
        case SERVICE_SYSTEM_START: return "System";
        case SERVICE_AUTO_START:   return "Auto";
        case SERVICE_DEMAND_START: return "Manual";
        case SERVICE_DISABLED:     return "Disabled";
        default:                   return "Unknown";
    }
}

DWORD ModifiableSVCCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hToken = NULL;
    HANDLE hHeap = NULL;
    LPBYTE pServices = NULL;
    LPENUM_SERVICE_STATUS_PROCESSA pServiceStatus = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPQUERY_SERVICE_CONFIGA pConfig = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;
    DWORD dwSDSize = 0;
    DWORD dwConfigSize = 0;
    DWORD dwTokenInfoSize = 0;
    DWORD i = 0;
    DWORD j = 0;
    int nVulnerable = 0;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    PACL pDacl = NULL;
    PACE_HEADER pAceHeader = NULL;
    PACCESS_ALLOWED_ACE pAce = NULL;
    PSID pAceSid = NULL;

    hHeap = KERNEL32$GetProcessHeap();

    internal_printf("=== Modifiable Services Check ===\n\n");

    // Open process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    // Get token user size
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwTokenInfoSize);
    if (pTokenUser == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for token user\n");
        goto ModifiableSVCCheck_end;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token user. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    // Open SCManager
    hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open Service Control Manager. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    // Get required buffer size
    ADVAPI32$EnumServicesStatusExA(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        NULL,
        0,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL);

    dwBufferSize = dwBytesNeeded;
    pServices = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    if (pServices == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for services\n");
        goto ModifiableSVCCheck_end;
    }

    // Enumerate services
    dwResumeHandle = 0;
    if (!ADVAPI32$EnumServicesStatusExA(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        pServices,
        dwBufferSize,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to enumerate services. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    internal_printf("[*] Checking %lu services...\n\n", dwServicesReturned);

    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESSA)pServices;

    for (i = 0; i < dwServicesReturned; i++)
    {
        // Open service with READ_CONTROL to query security
        hService = ADVAPI32$OpenServiceA(hSCManager, pServiceStatus[i].lpServiceName, READ_CONTROL | SERVICE_QUERY_CONFIG);
        if (hService == NULL)
        {
            continue;
        }

        // Query security descriptor size
        dwSDSize = 0;
        ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &dwSDSize);
        if (dwSDSize == 0)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pSD = (PSECURITY_DESCRIPTOR)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSDSize);
        if (pSD == NULL)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        // Query security descriptor
        if (!ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, dwSDSize, &dwSDSize))
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        // Get DACL
        pDacl = NULL;
        if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (!bDaclPresent || pDacl == NULL)
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        // Check each ACE
        for (j = 0; j < pDacl->AceCount; j++)
        {
            if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader))
            {
                continue;
            }

            // Only check ACCESS_ALLOWED_ACE
            if (pAceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
            {
                continue;
            }

            pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
            pAceSid = (PSID)&pAce->SidStart;

            // Check if we have modify rights
            if (!HasModifyRights(pAce->Mask))
            {
                continue;
            }

            // Check if ACE applies to current user or their groups
            if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) || CheckSidInToken(hToken, pAceSid))
            {
                // Get service config for more details
                dwConfigSize = 0;
                ADVAPI32$QueryServiceConfigA(hService, NULL, 0, &dwConfigSize);
                if (dwConfigSize > 0)
                {
                    pConfig = (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwConfigSize);
                    if (pConfig != NULL)
                    {
                        if (ADVAPI32$QueryServiceConfigA(hService, pConfig, dwConfigSize, &dwConfigSize))
                        {
                            internal_printf("[+] VULNERABLE: %s\n", pServiceStatus[i].lpServiceName);
                            internal_printf("    Display Name: %s\n", pConfig->lpDisplayName ? pConfig->lpDisplayName : "N/A");
                            internal_printf("    State: %s\n", GetServiceState(pServiceStatus[i].ServiceStatusProcess.dwCurrentState));
                            internal_printf("    Start Type: %s\n", GetStartType(pConfig->dwStartType));
                            internal_printf("    Binary Path: %s\n\n", pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : "N/A");
                            
                            nVulnerable++;
                        }
                        KERNEL32$HeapFree(hHeap, 0, pConfig);
                        pConfig = NULL;
                    }
                }
                break;
            }
        }

        KERNEL32$HeapFree(hHeap, 0, pSD);
        pSD = NULL;
        ADVAPI32$CloseServiceHandle(hService);
        hService = NULL;
    }

    if (nVulnerable > 0)
    {
        internal_printf("[+] Found %d modifiable service(s)!\n", nVulnerable);
    }
    else
    {
        internal_printf("[-] No modifiable services found\n");
    }

    dwErrorCode = ERROR_SUCCESS;

ModifiableSVCCheck_end:
    if (pConfig != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pConfig);
    }
    if (pSD != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pSD);
    }
    if (pServices != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pServices);
    }
    if (pTokenUser != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    }
    if (hService != NULL)
    {
        ADVAPI32$CloseServiceHandle(hService);
    }
    if (hSCManager != NULL)
    {
        ADVAPI32$CloseServiceHandle(hSCManager);
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
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

    dwErrorCode = ModifiableSVCCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ModifiableSVCCheck failed: %lX\n", dwErrorCode);
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

    dwErrorCode = ModifiableSVCCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "ModifiableSVCCheck failed: %lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif