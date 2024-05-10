pub const PROCESS_H: &str = r#"
#pragma once

#include <windows.h>

typedef enum ENUMRATOR_STATUS
{
	ENUMRATOR_STATUS_FAILED,
	ENUMRATOR_STATUS_SUCCESS,
	ENUMRATOR_STATUS_INVALID_PARAMETER,

} ENUMRATOR_STATUS; 
// Enumeration process by name
ENUMRATOR_STATUS WINAPI EnumProcessByName(IN LPCSTR lpProcessName, OUT DWORD* pdwProcessId);
"#;
