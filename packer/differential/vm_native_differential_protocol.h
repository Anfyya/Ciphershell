#ifndef CS_VM_NATIVE_DIFFERENTIAL_PROTOCOL_H
#define CS_VM_NATIVE_DIFFERENTIAL_PROTOCOL_H

#include "../../runtime/common/vm_isa.h"
#include "../../runtime/common/vm_metadata.h"

#include <array>
#include <cstdint>

namespace CipherShell {

/*
 * On-disk request/response layout shared between the packer-process
 * evidence provider and the isolated vm_native_differential_worker process.
 * Both sides are always built from this header in the same repository, so a
 * flat versioned binary dump (fixed header + trailing blob region) is the
 * whole IPC contract: no general-purpose serialization dependency for a
 * single-writer, single-reader handoff that only ever runs on one machine.
 *
 * File layout:
 *   [VMNativeDifferentialRequestHeader]
 *   [native code bytes]                    nativeCodeSize
 *   [corpus memory, pre-execution]         memorySize
 *   [vm bytecode, with forced trailing
 *    FLAGS_MATERIALIZE before RET/EXIT]    vmBytecodeSize
 *   [synthesized handler image]            handlerImageSize
 *   [handler relocations]                  handlerRelocationsCount * sizeof(VMNativeDifferentialRelocation)
 *   [handler x64 unwind entries]           handlerUnwindCount * sizeof(VMNativeDifferentialUnwindEntry)
 *
 * Response file layout:
 *   [VMNativeDifferentialResponseBody]
 *   [native final memory]                  memorySize (echoed from request by the worker)
 *   [vm final memory]                      memorySize
 */

constexpr uint32_t VM_NATIVE_DIFFERENTIAL_REQUEST_MAGIC = 0x43534E44u;  /* "CSND" */
constexpr uint32_t VM_NATIVE_DIFFERENTIAL_RESPONSE_MAGIC = 0x43534E52u; /* "CSNR" */
constexpr uint32_t VM_NATIVE_DIFFERENTIAL_PROTOCOL_VERSION = 1u;

#pragma pack(push, 1)

struct VMNativeDifferentialRequestHeader {
    uint32_t magic = VM_NATIVE_DIFFERENTIAL_REQUEST_MAGIC;
    uint32_t version = VM_NATIVE_DIFFERENTIAL_PROTOCOL_VERSION;
    uint32_t architectureIsX64 = 0;
    uint32_t timeoutMilliseconds = 0;
    uint64_t memoryBase = 0;
    uint32_t memorySize = 0;
    uint32_t registerCount = 0;
    std::array<uint64_t, 16> initialGpr{};
    uint64_t initialRflags = 0;
    std::array<uint8_t, 16> familyToVregSlot{};
    std::array<uint8_t, 256> reverseOpcodeMap{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSemanticToSlot{};
    VM_OPERAND_CODEC operandCodec{};
    uint32_t contextEntryOffset = 0;

    uint32_t nativeCodeOffset = 0;
    uint32_t nativeCodeSize = 0;
    uint32_t corpusMemoryOffset = 0;
    uint32_t vmBytecodeOffset = 0;
    uint32_t vmBytecodeSize = 0;
    uint32_t handlerImageOffset = 0;
    uint32_t handlerImageSize = 0;
    uint32_t handlerRelocationsOffset = 0;
    uint32_t handlerRelocationsCount = 0;
    uint32_t handlerUnwindOffset = 0;
    uint32_t handlerUnwindCount = 0;
    uint64_t totalFileSize = 0;
};

struct VMNativeDifferentialRelocation {
    uint32_t offset = 0;
    uint16_t type = 0;
    uint16_t reserved = 0;
};

struct VMNativeDifferentialUnwindEntry {
    uint32_t beginOffset = 0;
    uint32_t endOffset = 0;
    uint32_t unwindOffset = 0;
};

struct VMNativeDifferentialResponseBody {
    uint32_t magic = VM_NATIVE_DIFFERENTIAL_RESPONSE_MAGIC;
    uint32_t version = VM_NATIVE_DIFFERENTIAL_PROTOCOL_VERSION;

    uint8_t nativeExecuted = 0;
    uint8_t nativeFaulted = 0;
    uint8_t vmExecuted = 0;
    uint8_t vmFaulted = 0;
    uint32_t nativeExceptionCode = 0;
    uint32_t vmExceptionCode = 0;
    uint32_t vmRuntimeError = 0;
    uint32_t reserved = 0;
    // Faulting address relative to the native code buffer / handler image
    // base, respectively; 0 when there was no fault.  Diagnostic only.
    uint64_t nativeFaultOffset = 0;
    uint64_t vmFaultOffset = 0;
    uint8_t vmCurrentSemantic = 0;
    uint8_t vmCurrentVariant = 0;
    uint64_t vmVipOffset = 0;

    std::array<uint64_t, 16> nativeFinalGpr{};
    uint64_t nativeFinalRflags = 0;
    std::array<uint64_t, 16> vmFinalGpr{};
    uint64_t vmFinalRflags = 0;
    uint32_t memorySize = 0;
};

#pragma pack(pop)

} // namespace CipherShell

#endif // CS_VM_NATIVE_DIFFERENTIAL_PROTOCOL_H
