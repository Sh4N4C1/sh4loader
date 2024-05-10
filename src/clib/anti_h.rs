pub const ANTI_H: &str = r#"
#ifdef _ANTI_H_
#define _ANTI_H_
#include <windows.h>

BOOL CheckCPU();
BOOL CheckProcess();
BOOL CheckAll();
#endif
"#;
