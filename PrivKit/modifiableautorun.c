#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include "beacon.h"

DECLSPEC_IMPORT const char* WINAPI MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY);

void go() {
    HKEY hKey;
    const char* regkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
    };

    for (int i = 0; i < sizeof(regkeys) / sizeof(regkeys[0]); i++) {
        if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, regkeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char valueName[256];
            DWORD valueNameSize, valueType, valueDataSize = 256;
            BYTE valueData[256];
            int j = 0;

            while (true) {
                valueNameSize = sizeof(valueName);
                valueDataSize = sizeof(valueData);
                if (Advapi32$RegEnumValueA(hKey, j, valueName, &valueNameSize, NULL, &valueType, valueData, &valueDataSize) != ERROR_SUCCESS) {
                    break;
                }
                if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                    BeaconPrintf(CALLBACK_OUTPUT, "Modifiable Autorun Check Result: %s: %s\n", valueName, valueData);
                }
                j++;
            }
            Advapi32$RegCloseKey(hKey);
        }
    }
}
