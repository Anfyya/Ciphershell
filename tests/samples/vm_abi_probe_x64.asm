; Real Win64 ABI probe for the per-build DLL/EXE gate.
;
; The target sees seeded values in every ABI nonvolatile GPR and XMM register.
; The post-CALL state is copied to the caller-provided snapshot before this
; helper restores its own saved state, so helper preservation cannot hide a
; callee/trampoline clobber.

bits 64
default rel

section .data align=8
vm_abi_output:       dq 0
vm_abi_resume_rsp:   dq 0
vm_abi_function:     dq 0
vm_abi_return_value: dd 0

section .rdata rdata align=16
vm_abi_xmm_seeds:
    db 060h,061h,062h,063h,064h,065h,066h,067h,068h,069h,06Ah,06Bh,06Ch,06Dh,06Eh,06Fh
    db 070h,071h,072h,073h,074h,075h,076h,077h,078h,079h,07Ah,07Bh,07Ch,07Dh,07Eh,07Fh
    db 080h,081h,082h,083h,084h,085h,086h,087h,088h,089h,08Ah,08Bh,08Ch,08Dh,08Eh,08Fh
    db 090h,091h,092h,093h,094h,095h,096h,097h,098h,099h,09Ah,09Bh,09Ch,09Dh,09Eh,09Fh
    db 0A0h,0A1h,0A2h,0A3h,0A4h,0A5h,0A6h,0A7h,0A8h,0A9h,0AAh,0ABh,0ACh,0ADh,0AEh,0AFh
    db 0B0h,0B1h,0B2h,0B3h,0B4h,0B5h,0B6h,0B7h,0B8h,0B9h,0BAh,0BBh,0BCh,0BDh,0BEh,0BFh
    db 0C0h,0C1h,0C2h,0C3h,0C4h,0C5h,0C6h,0C7h,0C8h,0C9h,0CAh,0CBh,0CCh,0CDh,0CEh,0CFh
    db 0D0h,0D1h,0D2h,0D3h,0D4h,0D5h,0D6h,0D7h,0D8h,0D9h,0DAh,0DBh,0DCh,0DDh,0DEh,0DFh
    db 0E0h,0E1h,0E2h,0E3h,0E4h,0E5h,0E6h,0E7h,0E8h,0E9h,0EAh,0EBh,0ECh,0EDh,0EEh,0EFh
    db 0F0h,0F1h,0F2h,0F3h,0F4h,0F5h,0F6h,0F7h,0F8h,0F9h,0FAh,0FBh,0FCh,0FDh,0FEh,0FFh

section .text

global CaptureBinaryFunctionAbi

; int CaptureBinaryFunctionAbi(
;     int (*function)(int, int), int left, int right, Snapshot* output)
; RCX=function, EDX=left, R8D=right, R9=output.
CaptureBinaryFunctionAbi:
    push rbx
CaptureBinaryFunctionAbi_push_rbx:
    push rbp
CaptureBinaryFunctionAbi_push_rbp:
    push rsi
CaptureBinaryFunctionAbi_push_rsi:
    push rdi
CaptureBinaryFunctionAbi_push_rdi:
    push r12
CaptureBinaryFunctionAbi_push_r12:
    push r13
CaptureBinaryFunctionAbi_push_r13:
    push r14
CaptureBinaryFunctionAbi_push_r14:
    push r15
CaptureBinaryFunctionAbi_push_r15:
    sub rsp, 0C8h
CaptureBinaryFunctionAbi_alloc:
    movdqu [rsp + 020h], xmm6
CaptureBinaryFunctionAbi_save_xmm6:
    movdqu [rsp + 030h], xmm7
CaptureBinaryFunctionAbi_save_xmm7:
    movdqu [rsp + 040h], xmm8
CaptureBinaryFunctionAbi_save_xmm8:
    movdqu [rsp + 050h], xmm9
CaptureBinaryFunctionAbi_save_xmm9:
    movdqu [rsp + 060h], xmm10
CaptureBinaryFunctionAbi_save_xmm10:
    movdqu [rsp + 070h], xmm11
CaptureBinaryFunctionAbi_save_xmm11:
    movdqu [rsp + 080h], xmm12
CaptureBinaryFunctionAbi_save_xmm12:
    movdqu [rsp + 090h], xmm13
CaptureBinaryFunctionAbi_save_xmm13:
    movdqu [rsp + 0A0h], xmm14
CaptureBinaryFunctionAbi_save_xmm14:
    movdqu [rsp + 0B0h], xmm15
CaptureBinaryFunctionAbi_save_xmm15:
CaptureBinaryFunctionAbi_prolog_end:

    mov [rel vm_abi_output], r9
    mov [rel vm_abi_resume_rsp], rsp
    mov [rel vm_abi_function], rcx
    mov [rsp + 00h], edx
    mov [rsp + 08h], r8d
    mov [r9 + 00h], rsp

    mov rbx, 01122334455667788h
    mov rbp, 08877665544332211h
    mov rsi, 00F1E2D3C4B5A6978h
    mov rdi, 089ABCDEF01234567h
    mov r12, 013579BDF2468ACE0h
    mov r13, 0FEDCBA9876543210h
    mov r14, 055AA55AAAA55AA55h
    mov r15, 0C3C3F00D5A5AA5A5h
    movdqu xmm6,  [rel vm_abi_xmm_seeds + 000h]
    movdqu xmm7,  [rel vm_abi_xmm_seeds + 010h]
    movdqu xmm8,  [rel vm_abi_xmm_seeds + 020h]
    movdqu xmm9,  [rel vm_abi_xmm_seeds + 030h]
    movdqu xmm10, [rel vm_abi_xmm_seeds + 040h]
    movdqu xmm11, [rel vm_abi_xmm_seeds + 050h]
    movdqu xmm12, [rel vm_abi_xmm_seeds + 060h]
    movdqu xmm13, [rel vm_abi_xmm_seeds + 070h]
    movdqu xmm14, [rel vm_abi_xmm_seeds + 080h]
    movdqu xmm15, [rel vm_abi_xmm_seeds + 090h]

    mov ecx, [rsp + 00h]
    mov edx, [rsp + 08h]
    call [rel vm_abi_function]

    ; Snapshot first.  Do not restore a single seeded register before this.
    mov [rel vm_abi_return_value], eax
    mov r10, [rel vm_abi_output]
    mov [r10 + 008h], rsp
    mov [r10 + 010h], rbx
    mov [r10 + 018h], rbp
    mov [r10 + 020h], rsi
    mov [r10 + 028h], rdi
    mov [r10 + 030h], r12
    mov [r10 + 038h], r13
    mov [r10 + 040h], r14
    mov [r10 + 048h], r15
    movdqu [r10 + 050h], xmm6
    movdqu [r10 + 060h], xmm7
    movdqu [r10 + 070h], xmm8
    movdqu [r10 + 080h], xmm9
    movdqu [r10 + 090h], xmm10
    movdqu [r10 + 0A0h], xmm11
    movdqu [r10 + 0B0h], xmm12
    movdqu [r10 + 0C0h], xmm13
    movdqu [r10 + 0D0h], xmm14
    movdqu [r10 + 0E0h], xmm15
    mov eax, [rel vm_abi_return_value]
    mov [r10 + 0F0h], eax

    mov rsp, [rel vm_abi_resume_rsp]
    movdqu xmm6,  [rsp + 020h]
    movdqu xmm7,  [rsp + 030h]
    movdqu xmm8,  [rsp + 040h]
    movdqu xmm9,  [rsp + 050h]
    movdqu xmm10, [rsp + 060h]
    movdqu xmm11, [rsp + 070h]
    movdqu xmm12, [rsp + 080h]
    movdqu xmm13, [rsp + 090h]
    movdqu xmm14, [rsp + 0A0h]
    movdqu xmm15, [rsp + 0B0h]
    add rsp, 0C8h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    mov eax, [rel vm_abi_return_value]
    ret
CaptureBinaryFunctionAbi_end:

; The probe is itself a real non-leaf Win64 function.  Publish complete unwind
; codes for its eight pushes, allocation and ten XMM saves.
section .xdata rdata align=4

CaptureBinaryFunctionAbi_unwind:
    db 01h
    db CaptureBinaryFunctionAbi_prolog_end - CaptureBinaryFunctionAbi
    db 30
    db 00h
    db CaptureBinaryFunctionAbi_save_xmm15 - CaptureBinaryFunctionAbi, 0F8h
    dw 0Bh
    db CaptureBinaryFunctionAbi_save_xmm14 - CaptureBinaryFunctionAbi, 0E8h
    dw 0Ah
    db CaptureBinaryFunctionAbi_save_xmm13 - CaptureBinaryFunctionAbi, 0D8h
    dw 09h
    db CaptureBinaryFunctionAbi_save_xmm12 - CaptureBinaryFunctionAbi, 0C8h
    dw 08h
    db CaptureBinaryFunctionAbi_save_xmm11 - CaptureBinaryFunctionAbi, 0B8h
    dw 07h
    db CaptureBinaryFunctionAbi_save_xmm10 - CaptureBinaryFunctionAbi, 0A8h
    dw 06h
    db CaptureBinaryFunctionAbi_save_xmm9 - CaptureBinaryFunctionAbi, 098h
    dw 05h
    db CaptureBinaryFunctionAbi_save_xmm8 - CaptureBinaryFunctionAbi, 088h
    dw 04h
    db CaptureBinaryFunctionAbi_save_xmm7 - CaptureBinaryFunctionAbi, 078h
    dw 03h
    db CaptureBinaryFunctionAbi_save_xmm6 - CaptureBinaryFunctionAbi, 068h
    dw 02h
    db CaptureBinaryFunctionAbi_alloc - CaptureBinaryFunctionAbi, 01h
    dw 019h
    db CaptureBinaryFunctionAbi_push_r15 - CaptureBinaryFunctionAbi, 0F0h
    db CaptureBinaryFunctionAbi_push_r14 - CaptureBinaryFunctionAbi, 0E0h
    db CaptureBinaryFunctionAbi_push_r13 - CaptureBinaryFunctionAbi, 0D0h
    db CaptureBinaryFunctionAbi_push_r12 - CaptureBinaryFunctionAbi, 0C0h
    db CaptureBinaryFunctionAbi_push_rdi - CaptureBinaryFunctionAbi, 070h
    db CaptureBinaryFunctionAbi_push_rsi - CaptureBinaryFunctionAbi, 060h
    db CaptureBinaryFunctionAbi_push_rbp - CaptureBinaryFunctionAbi, 050h
    db CaptureBinaryFunctionAbi_push_rbx - CaptureBinaryFunctionAbi, 030h

section .pdata rdata align=4

    dd CaptureBinaryFunctionAbi wrt ..imagebase
    dd CaptureBinaryFunctionAbi_end wrt ..imagebase
    dd CaptureBinaryFunctionAbi_unwind wrt ..imagebase
