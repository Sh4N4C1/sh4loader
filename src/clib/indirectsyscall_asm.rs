pub const INDIRECTSYSCALL_ASM: &str = r#"
GLOBAL RunSyscall
GLOBAL SetSSn

SECTION .data
    dwSSN    dd  0
    qAddr    dq  0

SECTION .text
SetSSn:
    mov dword [rel dwSSN], ecx 
    mov qword [rel qAddr], rdx 
    ret
RunSyscall:
    mov r10, rcx
    mov eax, [rel dwSSN ]
    jmp qword [rel qAddr]
    ret
"#;
