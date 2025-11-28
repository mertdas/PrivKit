#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD PowerShellHistoryCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    char szPath[MAX_PATH];
    char szAppData[MAX_PATH];
    DWORD dwSize = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER liFileSize;
    int i = 0;
    int j = 0;

    const char* pszSubPath = "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    BeaconPrintf(CALLBACK_OUTPUT, "=== PowerShell History Check ===\n\n");

    // Get APPDATA environment variable
    dwSize = KERNEL32$GetEnvironmentVariableA("APPDATA", szAppData, sizeof(szAppData));
    if (dwSize == 0 || dwSize >= sizeof(szAppData))
    {
        dwErrorCode = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get APPDATA path. Error: %lu\n", dwErrorCode);
        goto PowerShellHistoryCheck_end;
    }

    // Build full path manually (no strcat)
    i = 0;
    while (szAppData[i] != '\0' && i < MAX_PATH - 1)
    {
        szPath[i] = szAppData[i];
        i++;
    }

    j = 0;
    while (pszSubPath[j] != '\0' && i < MAX_PATH - 1)
    {
        szPath[i] = pszSubPath[j];
        i++;
        j++;
    }
    szPath[i] = '\0';

    // Check if file exists
    hFile = KERNEL32$CreateFileA(
        szPath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        if (dwErrorCode == ERROR_FILE_NOT_FOUND || dwErrorCode == ERROR_PATH_NOT_FOUND)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] PowerShell history file not found\n");
            BeaconPrintf(CALLBACK_OUTPUT, "    Path: %s\n", szPath);
            dwErrorCode = ERROR_SUCCESS;
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Error accessing file. Error: %lu\n", dwErrorCode);
        }
        goto PowerShellHistoryCheck_end;
    }

    // Get file size
    liFileSize.QuadPart = 0;
    if (!KERNEL32$GetFileSizeEx(hFile, &liFileSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get file size. Error: %lu\n", dwErrorCode);
        goto PowerShellHistoryCheck_end;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PowerShell history file found!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Path: %s\n", szPath);

    // Display file size
    if (liFileSize.QuadPart >= 1048576)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    Size: %lu MB\n", (DWORD)(liFileSize.QuadPart / 1048576));
    }
    else if (liFileSize.QuadPart >= 1024)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    Size: %lu KB\n", (DWORD)(liFileSize.QuadPart / 1024));
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    Size: %lu bytes\n", (DWORD)liFileSize.QuadPart);
    }

    if (liFileSize.QuadPart == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] History file is empty\n");
    }

    dwErrorCode = ERROR_SUCCESS;

PowerShellHistoryCheck_end:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hFile);
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

    dwErrorCode = PowerShellHistoryCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "PowerShellHistoryCheck failed: %lX\n", dwErrorCode);
    }
}
#else
int main(int argc, char **argv)
{
    DWORD dwErrorCode = ERROR_SUCCESS;

    dwErrorCode = PowerShellHistoryCheck();
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "PowerShellHistoryCheck failed: %lX\n", dwErrorCode);
    }

    return dwErrorCode;
}
#endif