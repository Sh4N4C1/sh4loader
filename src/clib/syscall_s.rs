pub const SYSCALL_S: &str = r#"GLOBAL SysCall
GLOBAL SetSsn

SECTION .data
    dwSsn    dd  0
    qAddr    dq  0

SECTION .text
SetSsn:
    mov dword [rel dwSsn], ecx 
    mov qword [rel qAddr], rdx 
    ret
SysCall:
    mov r10, rcx
    mov eax, [rel dwSsn ]
    jmp qword [rel qAddr]
    ret

"#;