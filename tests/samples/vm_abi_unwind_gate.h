#pragma once

#include <cstdint>

#if defined(_M_IX86)
using VmProtectedSubFunction = int (__stdcall*)(int, int);
#else
using VmProtectedSubFunction = int (*)(int, int);
#endif

// Executes the real exported function through its ordinary CALL ABI.  The
// assembly probe seeds every ABI nonvolatile register before CALL, snapshots
// the machine state immediately after the callee returns, and restores the
// probe's own caller state only after the snapshot is complete.
bool VerifyVmProtectedAbi(
    VmProtectedSubFunction function,
    bool expectPacked,
    int left,
    int right);

// Win64 only: resolves the final OS-loaded VM metadata record for `function`,
// binds it to the actual entry jump, and asks the system unwinder to unwind
// the trampoline at body/LEA/POP/RET control points.  On Win32 this validates
// the metadata-bound stdcall RET imm16 contract instead.
bool VerifyVmPackedUnwindOrStdcall(
    VmProtectedSubFunction function,
    bool expectPacked);
