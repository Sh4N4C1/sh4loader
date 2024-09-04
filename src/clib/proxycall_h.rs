pub const PROXYCALL_H: &str = r#"#pragma once
#include <windows.h>

/* proxy call function struct */
typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID *address;
    SIZE_T zeroBits;
    PSIZE_T size;
    ULONG allocationType;
    ULONG permissions;
    DWORD ssn;
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID address;
    PVOID buffer;
    ULONG numberOfBytesToWrite;
    PULONG numberOfBytesWritten;
    DWORD ssn;
} NTWRITEVIRTUALMEMORY_ARGS, *PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTPROTECTVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID *address;
    PULONG size;
    ULONG permissions;
    PULONG old_permissions;
    DWORD ssn;
} NTPROTECTVIRTUALMEMORY_ARGS, *PNTPROTECTVIRTUALMEMORY_ARGS;

typedef struct _NTCREATETHREADEX_ARGS {
    PHANDLE threadHandle;
    ACCESS_MASK desiredAccess;
    PVOID objectAttributes;
    HANDLE processHandle;
    PVOID lpStartAddress;
    PVOID lpParameter;
    ULONG flags;
    SIZE_T stackZeroBits;
    SIZE_T sizeOfStackCommit;
    SIZE_T sizeOfStackReserve;
    PVOID lpBytesBuffer;
    DWORD ssn;
} NTCREATETHREADEX_ARGS, *PNTCREATETHREADEX_ARGS;
extern VOID CALLBACK CBNtAllocateVirtualMemory(PTP_CALLBACK_INSTANCE Instance,
                                               PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtWriteVirtualMemory(PTP_CALLBACK_INSTANCE Instance,
                                            PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtCreateThreadEx(PTP_CALLBACK_INSTANCE Instance,
                                        PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtProtectVirtualMemory(PTP_CALLBACK_INSTANCE Instance,
                                              PVOID Context, PTP_WORK Work);
extern VOID Search_For_Syscall_Ret(HANDLE ntdllHandle);
extern VOID Search_For_Add_Rsp_Ret(HANDLE ntdllHandle);
void PCNtAllocateVirtualMemory(HANDLE hProcess, PVOID *address, SIZE_T zeroBits,
                               PSIZE_T size, ULONG allocationType,
                               ULONG permissions);
void PCNtWriteVirtualMemory(HANDLE hProcess, PVOID address, PVOID buffer,
                            ULONG numberOfBytesToWrite,
                            PULONG numberOfBytesWritten);
void PCNtProtectVirtualMemory(HANDLE hProcess, PVOID *address, PULONG size,
                              ULONG permissions, PULONG old_permissions);
void PCNtCreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess,
                        PVOID objectAttributes, HANDLE processHandle,
                        PVOID lpStartAddress, PVOID lpParameter, ULONG flags,
                        SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit,
                        SIZE_T sizeOfStackReserve, PVOID lpBytesBuffer);

"#;