#ifndef CS_VM_NATIVE_EXEC_TRAMPOLINE_H
#define CS_VM_NATIVE_EXEC_TRAMPOLINE_H

#include <array>
#include <cstdint>

namespace CipherShell {

/*
 * Raw-register invocation state shared with the NASM trampolines.  The
 * trampoline loads gpr[0..15] (x86 register-family numbering: 0=A,1=C,2=D,
 * 3=B,4=SP,5=BP,6=SI,7=DI,8-15=R8-R15) and rflags into the real CPU, jumps
 * into entryPoint via a genuine CALL (so the callee's own RET returns here),
 * and writes the post-execution register state back into the same fields.
 *
 * entryPoint runs on a stack pointer taken from gpr[4], which points into
 * corpus-controlled memory rather than this thread's real stack -- so a
 * fault deep inside it cannot be safely unwound frame-by-frame.  Recovery
 * uses a vectored exception handler that redirects RIP/EIP straight to
 * FaultRecoveryLabel, which never touches the (possibly garbage) stack
 * pointer before restoring the trampoline's own saved real stack.
 */
#pragma pack(push, 8)
struct VMNativeExecTrampolineState {
    std::array<uint64_t, 16> gpr{};
    uint64_t rflags = 0;
    uint64_t entryPoint = 0;
};
#pragma pack(pop)

extern "C" {
void VMNativeExecTrampolineInvoke(VMNativeExecTrampolineState* state);
void VMNativeExecTrampolineFaultRecoveryLabel();
uint8_t VMNativeExecTrampolineFaulted();
}

} // namespace CipherShell

#endif // CS_VM_NATIVE_EXEC_TRAMPOLINE_H
