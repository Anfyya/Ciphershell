#ifndef CS_VM_RUNTIME_BUILDER_H
#define CS_VM_RUNTIME_BUILDER_H

#include "vm_section_emitter.h"
#include "vm_handler_synthesizer.h"
#include "../pe_parser/pe_parser.h"
#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

struct VMRuntimeFunctionEntry {
    uint32_t beginRVA = 0;
    uint32_t endRVA = 0;
    uint32_t unwindRVA = 0;
};

constexpr uint32_t VM_RUNTIME_INTEGRITY_EXPECTATION_VERSION = 2;

struct VMRuntimeContentRange {
    // Relative to VMRuntimeBuildResult::sectionRVA.
    uint32_t offset = 0;
    uint32_t size = 0;
    uint64_t digest = 0;
};

struct VMRuntimeIntegrityExpectation {
    uint32_t version = 0;
    uint32_t sectionContentSize = 0;
    uint64_t sectionDigest = 0;
    uint64_t dispatchDigestDomain = 0;
    uint64_t opcodeMapDigest = 0;
    uint64_t handlerBodyDigest = 0;
    uint64_t dispatchKeyDigest = 0;
    uint64_t variantSelectorDigest = 0;
    VMDispatchTableCodec dispatchTableCodec{};
    VMRuntimeContentRange synthesizedImage;
    VMRuntimeContentRange encryptedHandlers;
    VMRuntimeContentRange dispatchTable;
    // Exact post-relocation bytes for the complete file-backed runtime section,
    // including deterministic raw padding and appended trampolines.
    std::vector<uint8_t> expectedSectionBytes;
};

struct VMHandlerPlaintextEvidence {
    uint8_t semantic = VM_HANDLER_INVALID;
    uint8_t slot = VM_HANDLER_INVALID;
    uint8_t variant = 0;
    uint32_t handlerBodySize = 0;
    uint32_t semanticCoreOffset = 0;
    uint32_t semanticCoreVariantOffset = 0;
    uint32_t semanticCoreVariantSize = 0;
    // Exact plaintext bytes from the synthesizer-published production core.
    // valueCodecRanges are handler-relative and identify the mandatory
    // cross-handler representation stages inside this same byte range.
    std::vector<uint8_t> core;
    std::vector<VMSynthesizedCodeRange> valueCodecRanges;
};

struct VMHandlerBytecodeReference {
    // Relative to the owning VM function record's plaintext bytecode range.
    uint32_t bytecodeOffset = 0;
    uint32_t encodedSize = 0;
    uint8_t semantic = VM_HANDLER_INVALID;
    uint8_t variant = 0;
};

struct VMRecordHandlerReferences {
    uint32_t functionRVA = 0;
    uint32_t bytecodeOffset = 0;
    uint32_t bytecodeSize = 0;
    uint64_t bytecodeDigest = 0;
    // Exact pack-time plaintext stream. The opt-in evidence sidecar uses it to
    // independently bind offsets/references; the protected PE still stores
    // only its authenticated encrypted form.
    std::vector<uint8_t> bytecode;
    // Kept in decoded instruction order so a runtime trace bytecode offset can
    // be mapped back to the exact semantic/K-variant handler selected there.
    std::vector<VMHandlerBytecodeReference> references;
};

struct VMRuntimeTraceBinding {
    uint32_t traceRVA = 0;
    uint32_t capacity = 0;
    uint32_t groupId = 0;
    uint32_t architecture = 0;
    std::array<uint8_t, 16> buildId{};
};

struct VMRuntimeBuildResult {
    bool success = false;
    bool executionReady = false;
    bool unwindVerified = false;
    bool cfgVerified = false;
    bool keySharePatched = false;
    bool relocationsVerified = false;
    bool handlerSynthesisVerified = false;
    bool directThreadedVerified = false;
    bool handlerEncryptionVerified = false;
    bool runtimeContentVerified = false;
    bool referenceRuntimeBlobFreeVerified = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    uint32_t runtimeEntryRVA = 0;
    uint32_t runtimeImageSize = 0;
    uint32_t architecture = 0;
    uint64_t opcodeMapDigest = 0;
    uint64_t handlerBodyDigest = 0;
    uint64_t semanticPlaintextEvidenceDigest = 0;
    uint64_t dispatchKeyDigest = 0;
    uint64_t variantSelectorDigest = 0;
    VMRuntimeTraceBinding traceBinding{};
    // Exact non-junk semantic-body ranges synthesized for this runtime, keyed
    // by semantic and K-variant. They are never emitted into the protected PE;
    // the opt-in CLI evidence writer quantifies the actual pack run without
    // letting unreachable storage islands, junk handlers, or encryption make
    // similarity look lower.
    std::vector<VMHandlerPlaintextEvidence> plaintextHandlers;
    std::vector<VMRecordHandlerReferences> handlerReferences;
    VMRuntimeIntegrityExpectation integrityExpectation;
    std::vector<VMTrampolineRecord> trampolines;
    std::vector<VMRuntimeFunctionEntry> unwindEntries;
    // x64 only: final image RVA of the CALL_HOST phase-two UNW_FLAG_UHANDLER
    // cleanup thunk, after the placeholder offset embedded by the synthesizer
    // has been rebased by this runtime's actual section RVA.  Zero on x86.
    uint32_t callHostUnwindHandlerRVA = 0;
    // x86 only: final image RVAs (already rebased) of every CALL_HOST inline
    // SEH registration handler in this runtime.  Empty on x64.  Merged into
    // the target PE's SafeSEH table (if any) via
    // PEEmitter::RebuildSafeSEHHandlerTable.
    std::vector<uint32_t> safeSehHandlerRVAs;
    bool safeSehMerged = false;
    std::string error;
};

class VMRuntimeBuilder {
public:
    VMRuntimeBuildResult Build(
        CS_PE_IMAGE* image,
        const std::vector<VMFunctionRecord>& records,
        const std::vector<uint8_t>& plaintextBytecode,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        uint32_t metadataRVA,
        const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
        const VMHandlerSynthesisConfig& synthesisConfig,
        const char sectionName[8],
        const char unwindSectionName[8],
        const char relocationSectionName[8],
        const char safeSehSectionName[8],
        const VMRuntimeTraceBinding* traceBinding = nullptr);

    // Re-read the currently parsed PE and bind the emitted runtime bytes to the
    // pack-time expectation.  This function never mutates the PE or the result.
    static bool VerifyRuntimeContents(
        const CS_PE_IMAGE* image,
        const VMRuntimeBuildResult& result,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_VM_RUNTIME_BUILDER_H
