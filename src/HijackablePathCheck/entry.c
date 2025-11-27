#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

void go(char *args, int len)
{
    HKEY hKey = NULL;
    LONG lResult = 0;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char *szPath = NULL;
    char szDir[260];
    char szTestFile[280];
    int i, j, k;
    int nWritable = 0;
    int nChecked = 0;
    DWORD dwAttr;
    HANDLE hFile;
    HANDLE hHeap;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Hijackable PATH Check ===\n\n");

    // Allocate PATH buffer on heap instead of stack
    hHeap = KERNEL32$GetProcessHeap();
    szPath = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 4096);
    if (szPath == NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] HeapAlloc failed\n");
        return;
    }

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        0,
        KEY_READ,
        &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] RegOpenKeyExA failed: %ld\n", lResult);
        KERNEL32$HeapFree(hHeap, 0, szPath);
        return;
    }

    dwSize = 4095;
    lResult = ADVAPI32$RegQueryValueExA(hKey, "Path", NULL, &dwType, (LPBYTE)szPath, &dwSize);
    ADVAPI32$RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] RegQueryValueExA failed: %ld\n", lResult);
        KERNEL32$HeapFree(hHeap, 0, szPath);
        return;
    }

    szPath[dwSize] = '\0';

    // Parse PATH manually
    j = 0;
    for (i = 0; i <= (int)dwSize; i++)
    {
        if (szPath[i] == ';' || szPath[i] == '\0')
        {
            if (j > 0 && j < 260)
            {
                szDir[j] = '\0';
                nChecked++;

                dwAttr = KERNEL32$GetFileAttributesA(szDir);
                if (dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
                {
                    // Build test path
                    for (k = 0; k < j && k < 250; k++)
                        szTestFile[k] = szDir[k];
                    szTestFile[k++] = '\\';
                    szTestFile[k++] = 'x';
                    szTestFile[k++] = '.';
                    szTestFile[k++] = 't';
                    szTestFile[k++] = 'm';
                    szTestFile[k++] = 'p';
                    szTestFile[k] = '\0';

                    hFile = KERNEL32$CreateFileA(szTestFile, GENERIC_WRITE, 0, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

                    if (hFile != INVALID_HANDLE_VALUE)
                    {
                        KERNEL32$CloseHandle(hFile);
                        KERNEL32$DeleteFileA(szTestFile);
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] WRITABLE: %s\n", szDir);
                        nWritable++;
                    }
                }
            }
            j = 0;
        }
        else if (j < 259)
        {
            szDir[j++] = szPath[i];
        }
    }

    KERNEL32$HeapFree(hHeap, 0, szPath);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Checked %d directories\n", nChecked);

    if (nWritable > 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VULNERABLE: %d writable path(s) found!\n", nWritable);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Not Vulnerable: No writable paths found\n");
}