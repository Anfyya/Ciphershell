#ifndef CS_VM_HANDLER_SEMANTIC_CODEGEN_H
#define CS_VM_HANDLER_SEMANTIC_CODEGEN_H

#include "../../runtime/common/vm_micro_runtime_abi.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

/*
 * A semantic kernel starts after the shared operand decoder has populated
 * decodedOperands/currentSemantic/currentVariant and advanced context->vip.
 * It contains the executable, per-variant semantic data path and mutation
 * envelope but not
 * the encrypted-storage envelope or direct-threaded dispatch tail;
 * vm_handler_synthesizer owns those two outer layers.
 *
 * Entry ABI:
 *   x64: R15 = VM_MICRO_EXECUTION_CONTEXT*
 *   x86: EDI = VM_MICRO_EXECUTION_CONTEXT*
 */
struct VMHandlerSemanticCodegenConfig {
    uint32_t architecture = VM_ARCH_X64;
    std::array<uint8_t, 32> buildSeed{};
    VM_MICRO_OPCODE semantic = VM_UOP_TRAP;
    uint8_t variant = 0;
};

enum class VMHandlerSemanticUnwindKind : uint8_t {
    StackAllocation = 1,
    PushNonvolatile = 2
};

/*
 * x64 handler-body funclet whose RSP/nonvolatile state differs from the
 * surrounding direct-threaded leaf code.  Offsets are relative to code.
 * vm_handler_synthesizer translates these ranges to physical handler RVAs
 * and owns the canonical UNWIND_INFO emission.
 */
struct VMHandlerSemanticStackFunclet {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t stackBytes = 0;
    VMHandlerSemanticUnwindKind kind =
        VMHandlerSemanticUnwindKind::StackAllocation;
    uint8_t prologSize = 0;
    uint8_t nonvolatileRegister = 0;
};

/*
 * CALL_HOST is the one semantic whose native-call frame, host extended-state
 * save and Windows unwind cleanup are inseparable.  Keep the complete fixed
 * layout here so semantic instruction emission, the x64 UNWIND_INFO builder
 * and the Win32 registration/cleanup path consume one typed source instead
 * of maintaining matching magic numbers in separate translation units.
 *
 * Per-build mutation is deliberately excluded from both layouts.  The
 * seed-selected target resolver runs before either frame is established.
 */
struct VMHandlerX64CallHostFramePlan {
    uint32_t stackBytes = 0;
    uint8_t prologSize = 0;
    uint8_t stackAllocationCodeOffset = 0;
    uint8_t unwindFlags = 0;
    uint32_t argumentBase = 0;
    uint32_t targetSpill = 0;
    uint32_t guestStackSpill = 0;
    uint32_t hostExtendedSpill = 0;
    uint32_t flagsSpill = 0;
    std::array<uint32_t, 7> volatileGprSpills{};
    uint32_t guardSpill = 0;
    uint32_t hostExtendedBase = 0;
    uint32_t hostExtendedModeSpill = 0;
    uint32_t hostExtendedPhaseSpill = 0;
};

struct VMHandlerX86CallHostFramePlan {
    uint32_t stackBytes = 0;
    uint32_t argumentBase = 0;
    uint32_t targetSpill = 0;
    uint32_t guestStackSpill = 0;
    uint32_t hostExtendedSpill = 0;
    uint32_t flagsSpill = 0;
    std::array<uint32_t, 3> volatileGprSpills{};
    uint32_t cleanupSpill = 0;
    uint32_t guardSpill = 0;
    std::array<uint32_t, 4> originalNonvolatileSpills{};
    uint32_t statusSpill = 0;
    uint32_t hostExtendedBase = 0;
    uint32_t hostExtendedModeSpill = 0;
    uint32_t hostExtendedPhaseSpill = 0;
    uint32_t sehRecordSpill = 0;
};

inline constexpr VMHandlerX64CallHostFramePlan
    kVMHandlerX64CallHostFramePlan = {
        0x608u, 18u, 7u, 2u, 0x20u,
        0x220u, 0x228u, 0x230u, 0x238u,
        {0x240u, 0x248u, 0x250u, 0x258u, 0x260u, 0x268u, 0x270u},
        0x278u, 0x280u, 0x600u, 0x604u};

inline constexpr VMHandlerX86CallHostFramePlan
    kVMHandlerX86CallHostFramePlan = {
        0x5D0u, 0u,
        0x200u, 0x204u, 0x208u, 0x20Cu,
        {0x210u, 0x214u, 0x218u},
        0x21Cu, 0x220u,
        {0x224u, 0x228u, 0x22Cu, 0x230u},
        0x234u, 0x240u, 0x5C0u, 0x5C4u, 0x5C8u};

static_assert(kVMHandlerX64CallHostFramePlan.hostExtendedBase +
        VM_XSAVE_AREA_SIZE + 64u <=
            kVMHandlerX64CallHostFramePlan.hostExtendedModeSpill &&
        kVMHandlerX64CallHostFramePlan.hostExtendedPhaseSpill + 4u <=
            kVMHandlerX64CallHostFramePlan.stackBytes,
    "x64 CALL_HOST host-state cleanup slots overlap its XSAVE image");
static_assert(kVMHandlerX86CallHostFramePlan.hostExtendedBase +
        VM_XSAVE_AREA_SIZE + 64u <=
            kVMHandlerX86CallHostFramePlan.hostExtendedModeSpill &&
        kVMHandlerX86CallHostFramePlan.sehRecordSpill + 8u <=
            kVMHandlerX86CallHostFramePlan.stackBytes,
    "x86 CALL_HOST SEH cleanup slots overlap its XSAVE image");

struct VMHandlerSemanticCodeRange {
    uint32_t offset = 0;
    uint32_t size = 0;
};

struct VMHandlerSemanticCodegenResult {
    bool success = false;
    bool semanticComplete = false;
    uint8_t operandCount = 0;
    int8_t stackPops = 0;
    int8_t stackPushes = 0;
    /* Operands are already decoded, so this is a count rather than byte size. */
    uint32_t decodedOperandCount = 0;
    std::array<uint8_t, 4> registerAssignment{};
    /*
     * These offsets delimit executable variant machinery.  They are verified
     * against the emitted instruction bytes before the synthesizer accepts a
     * handler; they are not readiness flags or descriptive-only metadata.
     */
    uint32_t variantPrefixOffset = 0;
    uint32_t variantPrefixSize = 0;
    uint32_t semanticBodyOffset = 0;
    uint32_t semanticBodySize = 0;
    /*
     * The input/result paths operate on real semantic operands/state, not on
     * mutationScratch.  The core-variant range identifies the selected
     * business instruction/MBA where that semantic has an equivalent native
     * lowering.  Validation treats all of these ranges as executable evidence
     * and requires them to be contained by semanticBody.
     */
    uint32_t semanticInputPathOffset = 0;
    uint32_t semanticInputPathSize = 0;
    uint32_t semanticCoreOffset = 0;
    uint32_t semanticCoreSize = 0;
    uint32_t semanticCoreVariantOffset = 0;
    uint32_t semanticCoreVariantSize = 0;
    uint32_t semanticResultPathOffset = 0;
    uint32_t semanticResultPathSize = 0;
    uint8_t semanticInputStrategy = 0;
    uint8_t semanticCoreStrategy = 0;
    uint8_t semanticResultStrategy = 0;
    // Every range is a mandatory encode/decode stage for the persistent
    // build-seed-specific VM value-stack representation.  Ranges are kept
    // separate from the business-core range so the quantitative gate cannot
    // let one segment dilute or hide reuse in the other.
    std::vector<VMHandlerSemanticCodeRange> valueCodecRanges;
    // x86 CALL_HOST only: body-relative address of the inline registration
    // handler that must be merged into an existing SafeSEH table by the final
    // PE emitter.  Zero with hasCallHostSehHandler=false on every other path.
    uint32_t callHostSehHandlerOffset = 0;
    bool hasCallHostSehHandler = false;
    uint32_t variantSuffixOffset = 0;
    uint32_t variantSuffixSize = 0;
    uint32_t opaquePredicateOffset = 0;
    uint32_t opaquePredicateSize = 0;
    std::array<uint32_t, 5> failureBlockOffsets{};
    std::vector<VMHandlerSemanticStackFunclet> stackFunclets;
    std::vector<uint8_t> code;
    std::string error;
};

VMHandlerSemanticCodegenResult GenerateVMHandlerSemanticKernel(
    const VMHandlerSemanticCodegenConfig& config);

bool ValidateVMHandlerSemanticVariantKernel(
    const VMHandlerSemanticCodegenConfig& config,
    const VMHandlerSemanticCodegenResult& result,
    std::string& error);

// x64 UNW_FLAG_UHANDLER target shared by every CALL_HOST funclet.  It restores
// an armed host FXSAVE/XSAVE image during phase-two unwind and updates the
// legacy floating-point portion of the dispatcher CONTEXT before continuing
// the search.  Encoder failure is reported fail-closed.
bool GenerateVMHandlerX64CallHostUnwindHandler(
    std::vector<uint8_t>& code,
    std::string& error);

} // namespace CipherShell

#endif // CS_VM_HANDLER_SEMANTIC_CODEGEN_H
