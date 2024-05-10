pub const ANTI_C: &str = r#"
#include <stdio.h>
#include <windows.h>


#include <psapi.h>

#include "../include/Anti.h"
BOOL CheckCPU() {
    SYSTEM_INFO SysInfo = {0};
    GetSystemInfo(&SysInfo);

    // Check CPU numbers
    if (SysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    return FALSE;
}

BOOL CheckProcess() {
    DWORD adwProcess[1024];
    DWORD dwReturneLen = 0, dwNumberOfPids = 0;

    if (!EnumProcesses(adwProcess, sizeof(adwProcess), &dwReturneLen)) {
        return FALSE;
    }

    dwNumberOfPids = dwReturneLen / sizeof(DWORD);

    // Check Process Numbers
    if (dwNumberOfPids < 50) return TRUE;

    return FALSE;
}

BOOL CheckAll() {
    if (CheckCPU()) {
        return TRUE;
    } else {
    }
    if (CheckProcess()) {
        return TRUE;
    } else {
        return FALSE;
    }
}
"#;
