pub const TOOL_H: &str = r#"
#pragma once

#include <windows.h>

VOID PrintBuffer(PBYTE pBuffer, SIZE_T sBufferSize);
VOID PrintHex(IN PBYTE pBuffer, IN SIZE_T sBufferSize);
SIZE_T GetSize(PBYTE pArray);
"#;
