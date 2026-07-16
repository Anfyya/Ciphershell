#ifndef CS_VM_NATIVE_DIFFERENTIAL_WORKER_HARNESS_H
#define CS_VM_NATIVE_DIFFERENTIAL_WORKER_HARNESS_H

#include "vm_native_differential_protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

/*
 * Worker-process-only execution of one differential case.  Both halves run
 * inside the same isolated worker (never inside the packer process itself):
 * the VM half loads the already-synthesized per-build handler image exactly
 * like a real trampoline-entered function would and drives it through the
 * direct-threaded context entry; the native half runs the target function's
 * own original machine code straight on the CPU.  Every fault is caught with
 * structured exception handling and reported, never allowed to propagate.
 */
struct VMNativeDifferentialWorkerOutcome {
    bool nativeExecuted = false;
    bool nativeFaulted = false;
    uint32_t nativeExceptionCode = 0;
    uint64_t nativeFaultOffset = 0;
    std::array<uint64_t, 16> nativeFinalGpr{};
    uint64_t nativeFinalRflags = 0;
    std::array<uint64_t, 16> nativeFaultGpr{};
    uint64_t nativeFaultRflags = 0;
    std::vector<uint8_t> nativeFinalMemory;

    bool vmExecuted = false;
    bool vmFaulted = false;
    uint32_t vmExceptionCode = 0;
    uint32_t vmRuntimeError = 0;
    uint64_t vmFaultOffset = 0;
    uint8_t vmCurrentSemantic = 0;
    uint8_t vmCurrentVariant = 0;
    uint64_t vmVipOffset = 0;
    std::array<uint64_t, 16> vmFinalGpr{};
    uint64_t vmFinalRflags = 0;
    std::array<uint64_t, 16> vmFaultGpr{};
    uint64_t vmFaultRflags = 0;
    std::vector<uint8_t> vmFinalMemory;
};

bool RunNativeDifferentialWorkerCase(
    const VMNativeDifferentialRequestHeader& header,
    const uint8_t* nativeCode,
    const VMNativeDifferentialCodeFixup* nativeCodeFixups,
    const uint8_t* corpusMemory,
    const uint8_t* vmBytecode,
    const uint8_t* handlerImage,
    const VMNativeDifferentialRelocation* handlerRelocations,
    const VMNativeDifferentialUnwindEntry* handlerUnwindEntries,
    VMNativeDifferentialWorkerOutcome& outcome,
    std::string& error);

} // namespace CipherShell

#endif // CS_VM_NATIVE_DIFFERENTIAL_WORKER_HARNESS_H
