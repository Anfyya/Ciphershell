#ifndef CS_VM_RUNTIME_BUILDER_H
#define CS_VM_RUNTIME_BUILDER_H

#include "vm_section_emitter.h"
#include "vm_handler_synthesizer.h"
#include "../pe_parser/pe_parser.h"
#include <array>
#include <cstdint>
#include <string>
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
    uint64_t dispatchKeyDigest = 0;
    uint64_t variantSelectorDigest = 0;
    VMRuntimeIntegrityExpectation integrityExpectation;
    std::vector<VMTrampolineRecord> trampolines;
    std::vector<VMRuntimeFunctionEntry> unwindEntries;
    std::string error;
};

class VMRuntimeBuilder {
public:
    VMRuntimeBuildResult Build(
        CS_PE_IMAGE* image,
        const std::vector<VMFunctionRecord>& records,
        uint32_t metadataRVA,
        const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
        const VMHandlerSynthesisConfig& synthesisConfig,
        const char sectionName[8],
        const char unwindSectionName[8],
        const char relocationSectionName[8]);

    // Re-read the currently parsed PE and bind the emitted runtime bytes to the
    // pack-time expectation.  This function never mutates the PE or the result.
    static bool VerifyRuntimeContents(
        const CS_PE_IMAGE* image,
        const VMRuntimeBuildResult& result,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_VM_RUNTIME_BUILDER_H
