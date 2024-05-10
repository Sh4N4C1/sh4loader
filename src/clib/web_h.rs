pub const WEB_H: &str = r#"
#ifndef _WEB_H_
#define _WEB_H_
#include <windows.h>
#include <wininet.h>
#include "cJSON.h"
VOID DownloadFromUrl(IN LPCWSTR url, OUT PBYTE pFileContent, IN SIZE_T DownloadLength);
VOID ParseJsonObject(IN PBYTE WebBuffer, OUT CHAR* UuidArray[]);
#endif // DEBUG
"#;
