; Real Win64 returned-flags capture used by the DLL/EXE per-build runtime gate.
; CaptureBinaryFunctionFlags calls an existing protected two-argument export
; and executes PUSHFQ as the very next instruction, before stack cleanup can
; overwrite flags.

bits 64
default rel

section .text

global CaptureBinaryFunctionFlags

; uintptr_t CaptureBinaryFunctionFlags(
;     int (*function)(int, int), int left, int right, int* returnedValue)
; RCX=function, EDX=left, R8D=right, R9=returnedValue.
CaptureBinaryFunctionFlags:
    sub rsp, 0x28
    mov [rsp + 0x20], r9
    mov rax, rcx
    mov ecx, edx
    mov edx, r8d
    call rax
    pushfq
    pop rdx
    mov r8, [rsp + 0x20]
    mov [r8], eax
    mov rax, rdx
    add rsp, 0x28
    ret
CaptureBinaryFunctionFlags_end:

; Win64 function discovery and the OS unwinder both require real RUNTIME_FUNCTION
; records even for a measurement helper that is not itself VM-selected.
section .xdata rdata align=4

CaptureBinaryFunctionFlags_unwind:
    db 0x01, 0x04, 0x01, 0x00
    db 0x04, 0x42, 0x00, 0x00

section .pdata rdata align=4

    dd CaptureBinaryFunctionFlags wrt ..imagebase
    dd CaptureBinaryFunctionFlags_end wrt ..imagebase
    dd CaptureBinaryFunctionFlags_unwind wrt ..imagebase
