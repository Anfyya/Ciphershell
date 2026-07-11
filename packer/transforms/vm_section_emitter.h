#ifndef CS_VM_SECTION_EMITTER_H
#define CS_VM_SECTION_EMITTER_H

#include "../pe_parser/pe_parser.h"
#include "../../runtime/common/vm_metadata.h"
#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

using VMFunctionRecord = VM_FUNCTION_RECORD;

struct VMTrampolineRecord {
    uint32_t functionRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t trampolineSize = 0;
};

struct VMEmitResult {
    bool success = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    uint32_t metadataRVA = 0;
    uint32_t metadataSize = 0;
    uint32_t bytecodeRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t architecture = 0;
    uint32_t schemaVersion = 0;
    std::array<uint8_t, 16> buildId{};
    std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> runtimeKeyShare{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSemanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSlotToSemantic{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerVariants{};
    uint32_t junkHandlerCount = 0;
    bool handlerMutationEnabled = false;
    bool junkHandlersEnabled = false;
    std::vector<VMFunctionRecord> records;
    std::string error;
};

class VMSectionEmitter {
public:
    VMEmitResult Emit(
        CS_PE_IMAGE* image,
        const std::vector<uint8_t>& bytecode,
        const std::vector<VMFunctionRecord>& records,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSemanticToSlot,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSlotToSemantic,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerVariants,
        uint32_t junkHandlerCount,
        bool handlerMutationEnabled,
        bool junkHandlersEnabled,
        uint32_t runtimeEntryRVA = 0,
        const char sectionName[8] = nullptr);

    bool PatchLinkage(
        CS_PE_IMAGE* image,
        uint32_t metadataRVA,
        uint32_t runtimeBaseRVA,
        uint32_t runtimeEntryRVA,
        uint32_t runtimeSize,
        const std::vector<VMTrampolineRecord>& trampolines,
        const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
        uint32_t verifiedFlags,
        std::string* error = nullptr);

    static bool VerifyMetadata(
        const uint8_t* metadata,
        size_t availableSize,
        const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
        std::string& error);

private:
    static uint32_t AlignUp(uint32_t value, uint32_t alignment);
};

} // namespace CipherShell

#endif // CS_VM_SECTION_EMITTER_H
