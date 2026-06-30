#ifndef CS_VM_RUNTIME_BUILDER_H
#define CS_VM_RUNTIME_BUILDER_H

#include "vm_section_emitter.h"
#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct VMTrampolineRecord {
    uint32_t functionRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t trampolineSize = 0;
};

struct VMRuntimeBuildResult {
    bool success = false;
    bool executionReady = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    uint32_t runtimeEntryRVA = 0;
    std::vector<VMTrampolineRecord> trampolines;
    std::string error;
};

class VMRuntimeBuilder {
public:
    VMRuntimeBuildResult Build(
        CS_PE_IMAGE* image,
        const std::vector<VMFunctionRecord>& records,
        uint32_t metadataRVA,
        const char sectionName[8]);

private:
    static void Emit8(std::vector<uint8_t>& out, uint8_t value);
    static void Emit32(std::vector<uint8_t>& out, uint32_t value);
    static size_t Emit32Placeholder(std::vector<uint8_t>& out);
    static void Patch32(std::vector<uint8_t>& out, size_t pos, uint32_t value);
    static void PatchRel32(std::vector<uint8_t>& out, size_t immPos, size_t target);
    static std::vector<uint8_t> BuildX64RuntimeInterpreter(uint32_t metadataRVA);
    static std::vector<uint8_t> BuildX64Trampoline(uint32_t functionRVA, uint32_t metadataRVA);
};

} // namespace CipherShell

#endif // CS_VM_RUNTIME_BUILDER_H
