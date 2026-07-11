#ifndef CS_VM_RUNTIME_BUILDER_H
#define CS_VM_RUNTIME_BUILDER_H

#include "vm_section_emitter.h"
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

struct VMRuntimeBuildResult {
    bool success = false;
    bool executionReady = false;
    bool unwindVerified = false;
    bool cfgVerified = false;
    bool keySharePatched = false;
    bool relocationsVerified = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    uint32_t runtimeEntryRVA = 0;
    uint32_t runtimeImageSize = 0;
    uint32_t architecture = 0;
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
        const char sectionName[8],
        const char unwindSectionName[8],
        const char relocationSectionName[8]);
};

} // namespace CipherShell

#endif // CS_VM_RUNTIME_BUILDER_H
