BITS 64
DEFAULT REL

SECTION .text
GLOBAL vm_native_call_bridge
GLOBAL vm_instruction_bridge
GLOBAL vm_atomic_exchange
GLOBAL vm_atomic_bit_operation
GLOBAL vm_raise_divide_by_zero
GLOBAL vm_raise_divide_overflow

%define STATE_GPR_RAX      0
%define STATE_GPR_RCX      8
%define STATE_GPR_RDX      16
%define STATE_GPR_R8       64
%define STATE_GPR_R9       72
%define STATE_GPR_R10      80
%define STATE_GPR_R11      88
%define STATE_RFLAGS       128
%define STATE_STACK        136
%define STATE_TARGET       144
%define STATE_GUARD        152
%define STATE_STACK_BYTES  160
%define STATE_EXTENDED     176
%define STATE_EXT_FLAGS    184
%define STATE_HOST_EXT     192
%define STATE_HOST_STORAGE 200

%define IBRIDGE_TARGET         136
%define IBRIDGE_GUARD          144
%define IBRIDGE_HOST_EXT       160
%define IBRIDGE_EXT_FLAGS      240
%define IBRIDGE_HOST_STORAGE   248

vm_native_call_bridge:
    push rsi
    push rdi
    push r15
    mov r15, rcx
    sub rsp, 220h

    mov rsi, [r15 + STATE_STACK]
    add rsi, 20h
    lea rdi, [rsp + 20h]
    mov ecx, [r15 + STATE_STACK_BYTES]
    cld
    rep movsb

    lea r10, [r15 + STATE_HOST_STORAGE + 63]
    and r10, -64
    mov [r15 + STATE_HOST_EXT], r10
    cmp dword [r15 + STATE_EXT_FLAGS], 0
    je .save_host_fx
    mov eax, 7
    xor edx, edx
    xsave64 [r10]
    jmp .host_extended_saved
.save_host_fx:
    fxsave64 [r10]
.host_extended_saved:

    mov r10, [r15 + STATE_EXTENDED]
    cmp dword [r15 + STATE_EXT_FLAGS], 0
    je .restore_fx
    mov eax, 7
    xor edx, edx
    xrstor64 [r10]
    jmp .extended_restored
.restore_fx:
    fxrstor64 [r10]
.extended_restored:

    mov rcx, [r15 + STATE_GPR_RCX]
    mov rdx, [r15 + STATE_GPR_RDX]
    mov r8,  [r15 + STATE_GPR_R8]
    mov r9,  [r15 + STATE_GPR_R9]
    mov r10, [r15 + STATE_GPR_R10]
    mov r11, [r15 + STATE_GPR_R11]
    mov rax, [r15 + STATE_TARGET]
    cmp qword [r15 + STATE_GUARD], 0
    je .direct_call
    push qword [r15 + STATE_RFLAGS]
    popfq
    call qword [r15 + STATE_GUARD]
    jmp .call_complete
.direct_call:
    push qword [r15 + STATE_RFLAGS]
    popfq
    call qword [r15 + STATE_TARGET]
.call_complete:

    mov [r15 + STATE_GPR_RAX], rax
    mov [r15 + STATE_GPR_RCX], rcx
    mov [r15 + STATE_GPR_RDX], rdx
    mov [r15 + STATE_GPR_R8], r8
    mov [r15 + STATE_GPR_R9], r9
    mov [r15 + STATE_GPR_R10], r10
    mov [r15 + STATE_GPR_R11], r11
    pushfq
    pop qword [r15 + STATE_RFLAGS]
    mov r10, [r15 + STATE_EXTENDED]
    cmp dword [r15 + STATE_EXT_FLAGS], 0
    je .save_fx
    mov eax, 7
    xor edx, edx
    xsave64 [r10]
    jmp .extended_saved
.save_fx:
    fxsave64 [r10]
.extended_saved:

    mov r10, [r15 + STATE_HOST_EXT]
    cmp dword [r15 + STATE_EXT_FLAGS], 0
    je .restore_host_fx
    mov eax, 7
    xor edx, edx
    xrstor64 [r10]
    jmp .host_extended_restored
.restore_host_fx:
    fxrstor64 [r10]
.host_extended_restored:

    lea rsi, [rsp + 20h]
    mov rdi, [r15 + STATE_STACK]
    add rdi, 20h
    mov ecx, [r15 + STATE_STACK_BYTES]
    cld
    rep movsb

    add rsp, 220h
    pop r15
    pop rdi
    pop rsi
    xor eax, eax
    ret
vm_native_call_bridge_end:

vm_instruction_bridge:
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    lea r10, [rbx + IBRIDGE_HOST_STORAGE + 63]
    and r10, -64
    mov [rbx + IBRIDGE_HOST_EXT], r10
    cmp dword [rbx + IBRIDGE_EXT_FLAGS], 0
    je .instruction_save_fx
    mov eax, 7
    xor edx, edx
    xsave64 [r10]
    jmp .instruction_host_saved
.instruction_save_fx:
    fxsave64 [r10]
.instruction_host_saved:
    mov rcx, rbx
    mov rax, [rbx + IBRIDGE_TARGET]
    cmp qword [rbx + IBRIDGE_GUARD], 0
    je .instruction_direct_call
    call qword [rbx + IBRIDGE_GUARD]
    jmp .instruction_complete
.instruction_direct_call:
    call rax
.instruction_complete:
    cld
    mov r10, [rbx + IBRIDGE_HOST_EXT]
    cmp dword [rbx + IBRIDGE_EXT_FLAGS], 0
    je .instruction_restore_fx
    mov eax, 7
    xor edx, edx
    xrstor64 [r10]
    jmp .instruction_host_restored
.instruction_restore_fx:
    fxrstor64 [r10]
.instruction_host_restored:
    add rsp, 20h
    pop rbx
    xor eax, eax
    ret
vm_instruction_bridge_end:

vm_atomic_exchange:
    cmp r8d, 1
    je .exchange8
    cmp r8d, 2
    je .exchange16
    cmp r8d, 4
    je .exchange32
    cmp r8d, 8
    je .exchange64
    xor eax, eax
    ret
.exchange8:
    xchg byte [rcx], dl
    movzx eax, dl
    ret
.exchange16:
    xchg word [rcx], dx
    movzx eax, dx
    ret
.exchange32:
    xchg dword [rcx], edx
    mov eax, edx
    ret
.exchange64:
    xchg qword [rcx], rdx
    mov rax, rdx
    ret

vm_atomic_bit_operation:
    cmp r9d, 2
    je .bit16
    cmp r9d, 4
    je .bit32
    cmp r9d, 8
    je .bit64
    mov eax, 2
    ret
.bit16:
    cmp r8d, 1
    je .bts16
    lock btr word [rcx], dx
    jmp .bit_result
.bts16:
    lock bts word [rcx], dx
    jmp .bit_result
.bit32:
    cmp r8d, 1
    je .bts32
    lock btr dword [rcx], edx
    jmp .bit_result
.bts32:
    lock bts dword [rcx], edx
    jmp .bit_result
.bit64:
    cmp r8d, 1
    je .bts64
    lock btr qword [rcx], rdx
    jmp .bit_result
.bts64:
    lock bts qword [rcx], rdx
.bit_result:
    setc al
    movzx eax, al
    ret

vm_raise_divide_by_zero:
    xor edx, edx
    xor eax, eax
    div rax
    ud2

vm_raise_divide_overflow:
    mov rax, 8000000000000000h
    mov rdx, -1
    mov rcx, -1
    idiv rcx
    ud2

SECTION .xdata rdata align=4
vm_native_call_bridge_unwind:
    db 01h                    ; version 1, no handler flags
    db 0Eh                    ; prologue size
    db 05h                    ; unwind-code slots
    db 00h                    ; no frame register
    db 0Eh, 01h, 44h, 00h    ; sub rsp, 220h: UWOP_ALLOC_LARGE, size/8
    db 04h, 0F0h             ; push r15
    db 02h, 070h             ; push rdi
    db 01h, 060h             ; push rsi
    db 00h, 00h              ; even alignment padding

vm_instruction_bridge_unwind:
    db 01h                    ; version 1, no handler flags
    db 05h                    ; prologue size
    db 02h                    ; unwind-code slots
    db 00h                    ; no frame register
    db 05h, 032h              ; sub rsp, 20h: UWOP_ALLOC_SMALL
    db 01h, 030h              ; push rbx

SECTION .pdata rdata align=4
    dd vm_native_call_bridge wrt ..imagebase
    dd vm_native_call_bridge_end wrt ..imagebase
    dd vm_native_call_bridge_unwind wrt ..imagebase
    dd vm_instruction_bridge wrt ..imagebase
    dd vm_instruction_bridge_end wrt ..imagebase
    dd vm_instruction_bridge_unwind wrt ..imagebase
