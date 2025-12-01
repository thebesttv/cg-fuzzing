%define SIZE 100
%macro PRINT 1
    mov eax, %1
%endmacro

section .text
PRINT 1
