#ifndef CS_VM_INSTRUCTION_BRIDGE_BUILDER_H
#define CS_VM_INSTRUCTION_BRIDGE_BUILDER_H

#include "translator.h"
#include "../pe_parser/pe_emitter.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct VMInstructionBridgeLink {
    uint32_t functionRVA = 0;
    uint32_t instructionRVA = 0;
    uint32_t thunkRVA = 0;
    uint32_t thunkSize = 0;
    uint32_t nativeInstructionRVA = 0;
    uint32_t nativeInstructionSize = 0;
    uint32_t unwindBeginRVA = 0;
    uint8_t hiddenNativeRegister = 0xFF;
    bool usesAvx = false;
    bool usesX87 = false;
};

struct VMInstructionBridgeBuildResult {
    bool success = false;
    bool cfgTableVerified = false;
    bool unwindVerified = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    std::vector<VMInstructionBridgeLink> links;
    std::vector<CS_RUNTIME_FUNCTION> unwindEntries;
    std::string error;
};

class VMInstructionBridgeBuilder {
public:
    VMInstructionBridgeBuildResult Build(
        CS_PE_IMAGE* image,
        const std::vector<Function>& functions,
        std::vector<TranslationResult>& translations,
        const char sectionName[8],
        const char unwindSectionName[8],
        const char guardSectionName[8]);
};

} // namespace CipherShell

#endif // CS_VM_INSTRUCTION_BRIDGE_BUILDER_H
