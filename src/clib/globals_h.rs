pub const GLOBALS_H: &str = r#"
#pragma once


#ifdef DEBUG
#define PrintInfo(msg, ...) printf("[*]: " msg "\n", ##__VA_ARGS__);
#define PrintError(msg, ...) printf("[-]: " msg "\n", ##__VA_ARGS__);
#define PrintSuccess(msg, ...) printf("[+]: " msg "\n", ##__VA_ARGS__);
#define PrintBuffer(buffer, size) PrintBuffer(buffer, size);
#else
#define PrintInfo(msg)
#define PrintError(msg)
#define PrintSuccess(msg)
#define PrintBuffer(buffer, size)
#endif
// #define PrintInfo(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__);
// #define PrintError(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__);
// #define PrintSuccess(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__);
// #define PrintBuffer(buffer, size) PrintBuffer(buffer, size);
"#;
