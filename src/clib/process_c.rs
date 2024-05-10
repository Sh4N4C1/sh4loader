pub const PROCESS_C: &str = r#"

#include "../include/Process.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>


ENUMRATOR_STATUS EnumProcessByName(IN LPCSTR lpProcessName,
                                   OUT DWORD *pdwProcessId) {
    if (lpProcessName == NULL || pdwProcessId == NULL)
        return ENUMRATOR_STATUS_INVALID_PARAMETER;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return ENUMRATOR_STATUS_FAILED;

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return ENUMRATOR_STATUS_FAILED;
    }

    do {
        // print process name
        // wprintf(L"%s\n", pe32.szExeFile);
        if (stricmp(pe32.szExeFile, lpProcessName) == 0) {
            *pdwProcessId = pe32.th32ProcessID;
            printf("Process ID: %d\n", *pdwProcessId);
            CloseHandle(hSnapshot);
            return ENUMRATOR_STATUS_SUCCESS;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return ENUMRATOR_STATUS_FAILED;
}
"#;
