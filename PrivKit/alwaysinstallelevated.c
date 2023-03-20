#include <windows.h>
#include <stdio.h>
#include "beacon.h"

DECLSPEC_IMPORT const char* WINAPI MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, LPFILETIME);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegGetValueA(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegCloseKey(HKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI Advapi32$RegQueryValueExA(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);


void go() {
    HKEY hKey;
    DWORD alwaysInstallElevated;
    DWORD bufferSize = sizeof(DWORD);
    const TCHAR* subkeys[] = {
        TEXT("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Installer"),
        TEXT("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer")
    };

    for (int i = 0; i < sizeof(subkeys) / sizeof(subkeys[0]); i++) {
        if (Advapi32$RegOpenKeyExA((i == 0) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE,
            TEXT("Software\\Policies\\Microsoft\\Windows\\Installer"),
            0,
            KEY_QUERY_VALUE,
            &hKey) == ERROR_SUCCESS) {

            if (Advapi32$RegQueryValueExA(hKey,
                TEXT("AlwaysInstallElevated"),
                NULL,
                NULL,
                (LPBYTE)&alwaysInstallElevated,
                &bufferSize) == ERROR_SUCCESS) {

                if (alwaysInstallElevated == 1) {
                    BeaconPrintf(CALLBACK_OUTPUT,"Always Install Elevated Check Result: Vulnerable\n");
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT,"Always Install Elevated Check Result: Not Vulnerable\n");
                }

            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT,"Unable to query AlwaysInstallElevated value.\n");
            }

            Advapi32$RegCloseKey(hKey);

        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT,"Unable to open registry key.\n");
        }
    }

}
