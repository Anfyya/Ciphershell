; Real Win32 stdcall ABI probe for the per-build DLL/EXE gate.
;
; EBX/EBP/ESI/EDI are seeded before CALL.  ESP and all seeded registers are
; copied to the output immediately after the callee's RET 8, before the helper
; restores its own caller state.  Globals keep the recovery anchor independent
; of a broken callee's register or stack preservation.

bits 32

section .data align=4
vm_abi_output:       dd 0
vm_abi_resume_esp:   dd 0
vm_abi_function:     dd 0
vm_abi_left:         dd 0
vm_abi_right:        dd 0
vm_abi_return_value: dd 0

section .text

global _CaptureBinaryFunctionAbi

; int __cdecl CaptureBinaryFunctionAbi(
;     int (__stdcall *function)(int, int), int left, int right,
;     Snapshot* output)
_CaptureBinaryFunctionAbi:
    push ebp
    push ebx
    push esi
    push edi

    mov eax, [esp + 20]
    mov [vm_abi_function], eax
    mov eax, [esp + 24]
    mov [vm_abi_left], eax
    mov eax, [esp + 28]
    mov [vm_abi_right], eax
    mov eax, [esp + 32]
    mov [vm_abi_output], eax
    mov [vm_abi_resume_esp], esp
    mov [eax + 0], esp

    mov ebx, 0B16B00B5h
    mov ebp, 0E8B0F00Dh
    mov esi, 051A5C0DEh
    mov edi, 0D1A1FACEh

    push dword [vm_abi_right]
    push dword [vm_abi_left]
    call dword [vm_abi_function]

    ; Snapshot first.  Do not restore a single seeded register before this.
    mov [vm_abi_return_value], eax
    mov eax, [vm_abi_output]
    mov [eax + 4], esp
    mov [eax + 8], ebx
    mov [eax + 12], ebp
    mov [eax + 16], esi
    mov [eax + 20], edi
    mov edx, [vm_abi_return_value]
    mov [eax + 24], edx

    mov esp, [vm_abi_resume_esp]
    pop edi
    pop esi
    pop ebx
    pop ebp
    mov eax, [vm_abi_return_value]
    ret
