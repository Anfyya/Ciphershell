;
; CipherShell native differential worker - x86 raw register trampoline.
;
; void __cdecl VMNativeExecTrampolineInvoke(VMNativeExecTrampolineState* state)
;   state+0    : gpr[16] as uint64_t slots (only families 0..7 / low dword
;                are meaningful on x86: eax,ecx,edx,ebx,esp,ebp,esi,edi)
;   state+128  : rflags (low dword = eflags)
;   state+136  : entryPoint (low dword = 32-bit code pointer)
;
; Same isolation model as the x64 trampoline: entryPoint is entered with a
; real CALL against esp taken from gpr[4] (corpus-controlled memory), so its
; own RET returns here, and a vectored exception handler redirects EIP to
; VMNativeExecTrampolineFaultRecoveryLabel on any fault without relying on
; frame-based unwinding of the (possibly garbage) stack pointer.
;
; 编译命令：nasm -f win32 vm_native_exec_trampoline_x86.asm -o vm_native_exec_trampoline_x86.obj

bits 32

section .data align=4

g_state_ptr:    dd 0
g_harness_esp:  dd 0
g_entry_point:  dd 0
g_faulted:      db 0
align 4
g_out_eax:      dd 0
g_out_ecx:      dd 0
g_out_edx:      dd 0
g_out_ebx:      dd 0
g_out_esp:      dd 0
g_out_ebp:      dd 0
g_out_esi:      dd 0
g_out_edi:      dd 0
g_out_eflags:   dd 0

section .text

global _VMNativeExecTrampolineInvoke
global _VMNativeExecTrampolineFaultRecoveryLabel
global _VMNativeExecTrampolineFaulted

_VMNativeExecTrampolineFaulted:
    movzx eax, byte [g_faulted]
    ret

_VMNativeExecTrampolineInvoke:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov ecx, [ebp+8]
    mov [g_state_ptr], ecx
    mov [g_harness_esp], esp
    mov byte [g_faulted], 0

    mov eax, [ecx + 136]
    mov [g_entry_point], eax

    mov eax, [ecx + 128]
    push eax
    popfd

    ; Load every GPR family (ecx is our own base pointer and is read last;
    ; `mov ecx, [ecx+8]` still uses the old ecx to compute the address).
    mov eax, [ecx + 0*8]
    mov edx, [ecx + 2*8]
    mov ebx, [ecx + 3*8]
    mov ebp, [ecx + 5*8]
    mov esi, [ecx + 6*8]
    mov edi, [ecx + 7*8]
    ; state.gpr[4] is the architectural ESP observed at function entry.
    ; CALL itself pushes a 4-byte return address, so invoke from S+4 to make
    ; the callee enter at exactly S (the same value used by the VM half).
    mov esp, [ecx + 4*8]
    lea esp, [esp+4]
    mov ecx, [ecx + 1*8]

    call dword [g_entry_point]

    mov [g_out_ecx], ecx
    mov [g_out_edx], edx
    mov [g_out_ebx], ebx
    mov [g_out_ebp], ebp
    mov [g_out_esi], esi
    mov [g_out_edi], edi
    mov [g_out_esp], esp
    mov [g_out_eax], eax
    ; RET imm16 may leave ESP above the argument window.  Capture flags on
    ; the harness stack so PUSHFD cannot overwrite a callee-clean argument.
    mov esp, [g_harness_esp]
    pushfd
    pop dword [g_out_eflags]
    ; The ABI requires DF=0 on entry/exit of every function, but the corpus
    ; deliberately randomizes DF for entryPoint's benefit (it must observe
    ; whatever the real function would).  Restore it before falling back
    ; into ordinary C++, or the very next compiler-emitted string/rep
    ; instruction (e.g. inside a heap allocator) silently walks memory
    ; backwards and corrupts the process.
    cld
    jmp _VMNativeExecTrampolineEpilogue

; A vectored exception handler redirects EIP here on any fault raised while
; entryPoint (or anything it reached) was executing.  esp is untrusted at
; this point, so nothing below may push/pop or dereference it before the
; mov that restores the harness's own saved real stack.
_VMNativeExecTrampolineFaultRecoveryLabel:
    cld
    mov byte [g_faulted], 1

_VMNativeExecTrampolineEpilogue:
    mov ecx, [g_state_ptr]
    mov esp, [g_harness_esp]

    cmp byte [g_faulted], 0
    jne .skip_capture
    mov eax, [g_out_eax]
    mov [ecx + 0*8], eax
    mov dword [ecx + 0*8 + 4], 0
    mov eax, [g_out_ecx]
    mov [ecx + 1*8], eax
    mov dword [ecx + 1*8 + 4], 0
    mov eax, [g_out_edx]
    mov [ecx + 2*8], eax
    mov dword [ecx + 2*8 + 4], 0
    mov eax, [g_out_ebx]
    mov [ecx + 3*8], eax
    mov dword [ecx + 3*8 + 4], 0
    mov eax, [g_out_esp]
    mov [ecx + 4*8], eax
    mov dword [ecx + 4*8 + 4], 0
    mov eax, [g_out_ebp]
    mov [ecx + 5*8], eax
    mov dword [ecx + 5*8 + 4], 0
    mov eax, [g_out_esi]
    mov [ecx + 6*8], eax
    mov dword [ecx + 6*8 + 4], 0
    mov eax, [g_out_edi]
    mov [ecx + 7*8], eax
    mov dword [ecx + 7*8 + 4], 0
    mov eax, [g_out_eflags]
    mov [ecx + 128], eax
    mov dword [ecx + 128 + 4], 0
.skip_capture:

    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
