section .text
global CheckBreakpoint
CheckBreakpoint:
    mov     rax, qword [rdi] ; Load a QWORD (8 bytes) from the memory address
    cmp     byte [rax], 0xCC  ; Compare the first byte of the QWORD with 0xCC
    sete    al                 ; Set AL to 1 if equal (breakpoint found), 0 otherwise
    ret
