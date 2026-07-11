BITS 32

SECTION .text
GLOBAL _vm_native_call_bridge
GLOBAL _vm_instruction_bridge
GLOBAL _vm_atomic_exchange
GLOBAL _vm_atomic_bit_operation
GLOBAL _vm_raise_divide_by_zero
GLOBAL _vm_raise_divide_overflow
GLOBAL __allmul
GLOBAL __allshl
GLOBAL __aullshr

%define STATE_GPR_EAX      0
%define STATE_GPR_ECX      8
%define STATE_GPR_EDX      16
%define STATE_RFLAGS       128
%define STATE_STACK        136
%define STATE_TARGET       144
%define STATE_GUARD        152
%define STATE_STACK_BYTES  160
%define STATE_ORIG_STACK   168
%define STATE_EXTENDED     176
%define STATE_EXT_FLAGS    184
%define STATE_HOST_EXT     192
%define STATE_HOST_STORAGE 200

%define IBRIDGE_TARGET         136
%define IBRIDGE_GUARD          144
%define IBRIDGE_HOST_EXT       160
%define IBRIDGE_EXT_FLAGS      240
%define IBRIDGE_HOST_STORAGE   248

_vm_native_call_bridge:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov ebx, [ebp + 8]
    sub esp, 200h

    lea esi, [ebx + STATE_HOST_STORAGE + 63]
    and esi, -64
    mov [ebx + STATE_HOST_EXT], esi
    cmp dword [ebx + STATE_EXT_FLAGS], 0
    je .save_host_fx
    mov eax, 7
    xor edx, edx
    xsave [esi]
    jmp .host_extended_saved
.save_host_fx:
    fxsave [esi]
.host_extended_saved:

    mov esi, [ebx + STATE_STACK]
    mov [ebx + STATE_ORIG_STACK], esi
    mov edi, esp
    mov ecx, [ebx + STATE_STACK_BYTES]
    cld
    rep movsb
    mov edi, esp

    mov esi, [ebx + STATE_EXTENDED]
    cmp dword [ebx + STATE_EXT_FLAGS], 0
    je .restore_fx
    mov eax, 7
    xor edx, edx
    xrstor [esi]
    jmp .extended_restored
.restore_fx:
    fxrstor [esi]
.extended_restored:
    mov esi, [ebx + STATE_TARGET]
    cmp dword [ebx + STATE_GUARD], 0
    je .guard_complete
    mov ecx, esi
    call dword [ebx + STATE_GUARD]
.guard_complete:
    mov ecx, [ebx + STATE_GPR_ECX]
    mov edx, [ebx + STATE_GPR_EDX]
    mov eax, [ebx + STATE_GPR_EAX]
    push dword [ebx + STATE_RFLAGS]
    popfd
    call esi

    mov [ebx + STATE_GPR_EAX], eax
    mov [ebx + STATE_GPR_ECX], ecx
    mov [ebx + STATE_GPR_EDX], edx
    mov ecx, esp
    sub ecx, edi
    add [ebx + STATE_STACK], ecx
    pushfd
    pop dword [ebx + STATE_RFLAGS]
    mov esi, [ebx + STATE_EXTENDED]
    cmp dword [ebx + STATE_EXT_FLAGS], 0
    je .save_fx
    mov eax, 7
    xor edx, edx
    xsave [esi]
    jmp .extended_saved
.save_fx:
    fxsave [esi]
.extended_saved:

    mov esi, [ebx + STATE_HOST_EXT]
    cmp dword [ebx + STATE_EXT_FLAGS], 0
    je .restore_host_fx
    mov eax, 7
    xor edx, edx
    xrstor [esi]
    jmp .host_extended_restored
.restore_host_fx:
    fxrstor [esi]
.host_extended_restored:

    mov esi, edi
    mov edi, [ebx + STATE_ORIG_STACK]
    mov ecx, [ebx + STATE_STACK_BYTES]
    cld
    rep movsb

    lea esp, [ebp - 0Ch]
    pop edi
    pop esi
    pop ebx
    pop ebp
    xor eax, eax
    ret

_vm_instruction_bridge:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    mov ebx, [ebp + 8]
    lea esi, [ebx + IBRIDGE_HOST_STORAGE + 63]
    and esi, -64
    mov [ebx + IBRIDGE_HOST_EXT], esi
    cmp dword [ebx + IBRIDGE_EXT_FLAGS], 0
    je .instruction_save_fx
    mov eax, 7
    xor edx, edx
    xsave [esi]
    jmp .instruction_host_saved
.instruction_save_fx:
    fxsave [esi]
.instruction_host_saved:
    cmp dword [ebx + IBRIDGE_GUARD], 0
    je .instruction_guard_complete
    mov ecx, [ebx + IBRIDGE_TARGET]
    call dword [ebx + IBRIDGE_GUARD]
.instruction_guard_complete:
    push ebx
    call dword [ebx + IBRIDGE_TARGET]
    add esp, 4
    cld
    mov esi, [ebx + IBRIDGE_HOST_EXT]
    cmp dword [ebx + IBRIDGE_EXT_FLAGS], 0
    je .instruction_restore_fx
    mov eax, 7
    xor edx, edx
    xrstor [esi]
    jmp .instruction_host_restored
.instruction_restore_fx:
    fxrstor [esi]
.instruction_host_restored:
    lea esp, [ebp - 8]
    pop esi
    pop ebx
    pop ebp
    xor eax, eax
    ret

_vm_atomic_exchange:
    mov ecx, [esp + 4]
    mov eax, [esp + 8]
    mov edx, [esp + 16]
    cmp edx, 1
    je .exchange8
    cmp edx, 2
    je .exchange16
    cmp edx, 4
    je .exchange32
    xor eax, eax
    xor edx, edx
    ret
.exchange8:
    xchg byte [ecx], al
    movzx eax, al
    xor edx, edx
    ret
.exchange16:
    xchg word [ecx], ax
    movzx eax, ax
    xor edx, edx
    ret
.exchange32:
    xchg dword [ecx], eax
    xor edx, edx
    ret

_vm_atomic_bit_operation:
    mov ecx, [esp + 4]
    mov edx, [esp + 8]
    mov eax, [esp + 16]
    cmp eax, 2
    je .bit16
    cmp eax, 4
    je .bit32
    mov eax, 2
    ret
.bit16:
    cmp dword [esp + 12], 1
    je .bts16
    lock btr word [ecx], dx
    jmp .bit_result
.bts16:
    lock bts word [ecx], dx
    jmp .bit_result
.bit32:
    cmp dword [esp + 12], 1
    je .bts32
    lock btr dword [ecx], edx
    jmp .bit_result
.bts32:
    lock bts dword [ecx], edx
.bit_result:
    setc al
    movzx eax, al
    ret

_vm_raise_divide_by_zero:
    xor edx, edx
    xor eax, eax
    div eax
    ud2

_vm_raise_divide_overflow:
    mov eax, 80000000h
    mov edx, -1
    mov ecx, -1
    idiv ecx
    ud2

__allmul:
    mov eax, [esp + 8]
    mov ecx, [esp + 16]
    or ecx, eax
    mov ecx, [esp + 12]
    jnz .full_multiply
    mov eax, [esp + 4]
    mul ecx
    ret 16
.full_multiply:
    push ebx
    mul ecx
    mov ebx, eax
    mov eax, [esp + 8]
    mul dword [esp + 20]
    add ebx, eax
    mov eax, [esp + 8]
    mul ecx
    add edx, ebx
    pop ebx
    ret 16

__allshl:
    cmp cl, 64
    jae .shl_zero
    cmp cl, 32
    jae .shl_high
    shld edx, eax, cl
    shl eax, cl
    ret
.shl_high:
    mov edx, eax
    xor eax, eax
    and cl, 31
    shl edx, cl
    ret
.shl_zero:
    xor eax, eax
    xor edx, edx
    ret

__aullshr:
    cmp cl, 64
    jae .shr_zero
    cmp cl, 32
    jae .shr_low
    shrd eax, edx, cl
    shr edx, cl
    ret
.shr_low:
    mov eax, edx
    xor edx, edx
    and cl, 31
    shr eax, cl
    ret
.shr_zero:
    xor eax, eax
    xor edx, edx
    ret
