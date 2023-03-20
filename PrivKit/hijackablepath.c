#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include <string.h>

DECLSPEC_IMPORT const char* WINAPI MSVCRT$strstr(const char*, const char*);
WINBASEAPI char * __cdecl MSVCRT$strtok(char *str, const char *delim);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, LPFILETIME);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegGetValueA(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegQueryValueExA(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI Kernel32$GetFileAttributesA(LPCSTR lpFileName);

void go() {
    HKEY hKey;
    LONG openResult;
    LONG queryResult;
    DWORD valueType;
    DWORD dataSize;
    char data[1024];

    openResult = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey);
    if (openResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,"Error opening registry key: %d\n", openResult);
    }

    queryResult = Advapi32$RegQueryValueExA(hKey, "Path", NULL, &valueType, (LPBYTE)data, &dataSize);
    if (queryResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,"Error querying registry value: %d\n", queryResult);
        Advapi32$RegCloseKey(hKey);
    }

    char* pathToken = MSVCRT$strtok(data, ";");
    while (pathToken != NULL) {
        DWORD attributes = Kernel32$GetFileAttributesA(pathToken);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            BeaconPrintf(CALLBACK_OUTPUT,"Hijackable Path Check Result: Found writable directory in path: %s\n", pathToken);
            Advapi32$RegCloseKey(hKey);
            return;
        }
        pathToken = MSVCRT$strtok(NULL, ";");
    }

    BeaconPrintf(CALLBACK_OUTPUT,"Hijackable Path Check Result: No writable directory found in path\n");
    Advapi32$RegCloseKey(hKey);
}
