%define SIZE 100
%macro push_all 0
    push eax
    push ebx
%endmacro
section .text
    times SIZE nop
