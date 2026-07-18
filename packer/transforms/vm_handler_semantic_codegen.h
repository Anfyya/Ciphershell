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

} // namespace CipherShell

#endif // CS_VM_HANDLER_SEMANTIC_CODEGEN_H
