bits 64
section .data
msg db "Hello", 0
section .text
global _start
_start:
    mov rax, 60
    xor rdi, rdi
    syscall
