;
; CipherShell native differential worker - x64 raw register trampoline.
;
; VMNativeExecTrampolineInvoke(VMNativeExecTrampolineState* state)
;   state+0    : gpr[16]      (rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15)
;   state+128  : rflags
;   state+136  : entryPoint
;
; The callee is entered with a genuine CALL against a stack pointer taken
; from gpr[4] (corpus-controlled memory, not this thread's real stack), so
; its own RET returns control here.  A fault deep inside it cannot rely on
; frame-based unwinding (rsp may not describe any real call chain), so
; recovery is handled by a vectored exception handler in the C++ layer that
; simply redirects RIP to VMNativeExecTrampolineFaultRecoveryLabel -- which
; never touches rsp before restoring the harness's own saved real stack.
;
; 编译命令：nasm -f win64 vm_native_exec_trampoline_x64.asm -o vm_native_exec_trampoline_x64.obj

bits 64
default rel

section .data align=8

g_state_ptr:    dq 0
g_harness_rsp:  dq 0
g_entry_point:  dq 0
g_faulted:      db 0
align 8
g_out_rax:      dq 0
g_out_rcx:      dq 0
g_out_rdx:      dq 0
g_out_rbx:      dq 0
g_out_rsp:      dq 0
g_out_rbp:      dq 0
g_out_rsi:      dq 0
g_out_rdi:      dq 0
g_out_r8:       dq 0
g_out_r9:       dq 0
g_out_r10:      dq 0
g_out_r11:      dq 0
g_out_r12:      dq 0
g_out_r13:      dq 0
g_out_r14:      dq 0
g_out_r15:      dq 0
g_out_rflags:   dq 0

section .text

global VMNativeExecTrampolineInvoke
global VMNativeExecTrampolineFaultRecoveryLabel
global VMNativeExecTrampolineFaulted

; uint8_t VMNativeExecTrampolineFaulted(void)
VMNativeExecTrampolineFaulted:
    movzx eax, byte [g_faulted]
    ret

; void VMNativeExecTrampolineInvoke(VMNativeExecTrampolineState* state)  ; rcx = state
VMNativeExecTrampolineInvoke:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov [g_state_ptr], rcx
    mov [g_harness_rsp], rsp
    mov byte [g_faulted], 0

    mov rax, [rcx + 136]
    mov [g_entry_point], rax

    mov rax, [rcx + 128]
    push rax
    popfq

    ; Load every GPR from the request.  rcx is our own base pointer and must
    ; be read last -- `mov rcx, [rcx+8]` still uses the old rcx to compute
    ; the address before overwriting it, so this is safe.
    mov rax, [rcx + 0*8]
    mov rdx, [rcx + 2*8]
    mov rbx, [rcx + 3*8]
    mov rbp, [rcx + 5*8]
    mov rsi, [rcx + 6*8]
    mov rdi, [rcx + 7*8]
    mov r8,  [rcx + 8*8]
    mov r9,  [rcx + 9*8]
    mov r10, [rcx + 10*8]
    mov r11, [rcx + 11*8]
    mov r12, [rcx + 12*8]
    mov r13, [rcx + 13*8]
    mov r14, [rcx + 14*8]
    mov r15, [rcx + 15*8]
    mov rsp, [rcx + 4*8]
    mov rcx, [rcx + 1*8]

    call qword [g_entry_point]

    ; Normal return: capture every register before any of them are reused.
    mov [g_out_rcx], rcx
    mov [g_out_rdx], rdx
    mov [g_out_rbx], rbx
    mov [g_out_rbp], rbp
    mov [g_out_rsi], rsi
    mov [g_out_rdi], rdi
    mov [g_out_r8],  r8
    mov [g_out_r9],  r9
    mov [g_out_r10], r10
    mov [g_out_r11], r11
    mov [g_out_r12], r12
    mov [g_out_r13], r13
    mov [g_out_r14], r14
    mov [g_out_r15], r15
    mov [g_out_rsp], rsp
    pushfq
    mov [g_out_rax], rax
    pop rax
    mov [g_out_rflags], rax
    ; The Win64 ABI requires DF=0 on entry/exit of every function, but the
    ; corpus deliberately randomizes DF for entryPoint's benefit (it must
    ; observe whatever the real function would).  Restore it before falling
    ; back into ordinary C++, or the very next compiler-emitted string/rep
    ; instruction (e.g. inside a heap allocator) silently walks memory
    ; backwards and corrupts the process.
    cld
    jmp VMNativeExecTrampolineEpilogue

; A vectored exception handler redirects RIP here on any fault raised while
; entryPoint (or anything it reached) was executing.  rsp is untrusted at
; this point, so nothing below may push/pop or dereference it before the
; mov that restores the harness's own saved real stack.
VMNativeExecTrampolineFaultRecoveryLabel:
    cld
    mov byte [g_faulted], 1

VMNativeExecTrampolineEpilogue:
    mov rcx, [g_state_ptr]
    mov rsp, [g_harness_rsp]

    cmp byte [g_faulted], 0
    jne .skip_capture
    mov rax, [g_out_rax]
    mov [rcx + 0*8], rax
    mov rax, [g_out_rcx]
    mov [rcx + 1*8], rax
    mov rax, [g_out_rdx]
    mov [rcx + 2*8], rax
    mov rax, [g_out_rbx]
    mov [rcx + 3*8], rax
    mov rax, [g_out_rsp]
    mov [rcx + 4*8], rax
    mov rax, [g_out_rbp]
    mov [rcx + 5*8], rax
    mov rax, [g_out_rsi]
    mov [rcx + 6*8], rax
    mov rax, [g_out_rdi]
    mov [rcx + 7*8], rax
    mov rax, [g_out_r8]
    mov [rcx + 8*8], rax
    mov rax, [g_out_r9]
    mov [rcx + 9*8], rax
    mov rax, [g_out_r10]
    mov [rcx + 10*8], rax
    mov rax, [g_out_r11]
    mov [rcx + 11*8], rax
    mov rax, [g_out_r12]
    mov [rcx + 12*8], rax
    mov rax, [g_out_r13]
    mov [rcx + 13*8], rax
    mov rax, [g_out_r14]
    mov [rcx + 14*8], rax
    mov rax, [g_out_r15]
    mov [rcx + 15*8], rax
    mov rax, [g_out_rflags]
    mov [rcx + 128], rax
.skip_capture:

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
