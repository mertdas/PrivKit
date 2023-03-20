#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include "beacon.h"
#include <string.h>

DECLSPEC_IMPORT const char* WINAPI MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, LPFILETIME);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegGetValueA(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY);

void go() {
    HKEY servicesKey;
    bool foundVulnerablePath = false;
    if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        while (Advapi32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY imagePathKey;
            if (Advapi32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                char imagePathValue[1024];
                DWORD valueSize = sizeof(imagePathValue);
                if (Advapi32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) == ERROR_SUCCESS) {
                    if (MSVCRT$strstr(imagePathValue, " ") != NULL && MSVCRT$strstr(imagePathValue, "\"") == NULL) {
                        if (MSVCRT$strstr(imagePathValue, "System32") == NULL && MSVCRT$strstr(imagePathValue, "system32") == NULL && MSVCRT$strstr(imagePathValue, "SysWow64") == NULL) {
                            if (MSVCRT$strstr(imagePathValue, ".sys") == NULL) {
                                BeaconPrintf(CALLBACK_OUTPUT, "Unquoted Service Path Check Result: Vulnerable service path found: %s\n", imagePathValue);
                                foundVulnerablePath = true;
                            }
                        }
                    }
                }
                Advapi32$RegCloseKey(imagePathKey);
            }
            subkeyNameSize = sizeof(serviceSubkeyName);
        }
        Advapi32$RegCloseKey(servicesKey);
    }

    if (!foundVulnerablePath) {
        BeaconPrintf(CALLBACK_OUTPUT, "Unquoted Service Path Check Result: Unquoted Service Path Not Found");
    }
}
