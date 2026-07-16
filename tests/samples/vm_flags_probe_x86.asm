; Real Win32 returned-flags capture used by the DLL/EXE per-build runtime gate.
; CaptureBinaryFunctionFlags calls an existing protected two-argument export
; and executes PUSHFD as the very next instruction.  The selected Win32 sub2
; target is a real stdcall function, so RET 8 has already restored ESP.

bits 32

section .text

global _CaptureBinaryFunctionFlags

; uintptr_t __cdecl CaptureBinaryFunctionFlags(
;     int (__stdcall *function)(int, int), int left, int right,
;     int* returnedValue)
_CaptureBinaryFunctionFlags:
    push ebx
    mov eax, [esp + 8]
    push dword [esp + 16]
    push dword [esp + 16]
    call eax
    pushfd
    pop ecx
    mov edx, [esp + 20]
    mov [edx], eax
    mov eax, ecx
    pop ebx
    ret
