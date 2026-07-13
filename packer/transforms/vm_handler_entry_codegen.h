#ifndef CS_VM_HANDLER_ENTRY_CODEGEN_H
#define CS_VM_HANDLER_ENTRY_CODEGEN_H

#include "../../runtime/common/vm_micro_runtime_abi.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

/*
 * All offsets in this interface are offsets from the beginning of the
 * synthesized runtime image.  The orchestrator is therefore free to append
 * the image at any PE RVA without teaching the entry generator a preferred
 * image base.
 */
struct VMHandlerEntryLayout {
    uint32_t publicEntryOffset = 0;
    uint32_t validationEntryOffset = 0;
    uint32_t decryptorOffset = 0;
    uint32_t operandDecoderOffset = 0;
    uint32_t flagMaterializerOffset = 0;
    uint32_t decryptionStateOffset = 0;
    uint32_t keyMarkerOffset = 0;
    uint32_t decodePlanTableOffset = 0;
    uint32_t decodePlanTableSize = 0;
    uint32_t dispatchTableOffset = 0;
    uint32_t encryptedHandlerOffset = 0;
    uint32_t encryptedHandlerSize = 0;
};

struct VMHandlerEntryCipher {
    uint64_t initialState = 0;
    uint64_t multiplier = 0;
    uint64_t addend = 0;
    uint8_t addByte = 0;
    uint8_t rotate = 1;
    uint8_t shiftLeftA = 13;
    uint8_t shiftRightB = 7;
    uint8_t shiftLeftC = 17;
    uint8_t instructionVariant = 0;
};

struct VMHandlerEntryCodegenConfig {
    uint32_t architecture = VM_ARCH_X64;
    std::array<uint8_t, 32> buildSeed{};
    uint32_t variantCount = VM_HANDLER_VARIANT_COUNT;
    VMHandlerEntryLayout layout{};
    VMHandlerEntryCipher cipher{};
    uint32_t virtualProtectIatRVA = 0;
    uint32_t flushInstructionCacheIatRVA = 0;
    uint32_t functionPlanCount = 0;
    bool emitCetLandingPads = true;
};

struct VMHandlerEntryRelocation {
    uint32_t offset = 0;
    uint16_t type = 0;
    uint16_t reserved = 0;
};

/*
 * unwindInfo is the packed Windows UNWIND_INFO byte sequence.  The caller
 * places it in .xdata and emits a RUNTIME_FUNCTION using beginOffset/endOffset.
 */
struct VMHandlerEntryUnwindRecord {
    uint32_t beginOffset = 0;
    uint32_t endOffset = 0;
    std::vector<uint8_t> unwindInfo;
};

struct VMHandlerEntryCodegenResult {
    bool success = false;
    bool publicEntryReady = false;
    bool validationEntryReady = false;
    uint64_t preferredBase = 0;
    std::vector<uint8_t> entryCode;
    std::vector<uint8_t> validationEntryCode;
    std::vector<uint8_t> decryptorCode;
    /* Routine-relative range of the executed rolling/decryption loop. */
    uint32_t decryptorLoopOffset = 0;
    uint32_t decryptorLoopSize = 0;
    std::vector<uint8_t> operandDecoderCode;
    std::vector<uint8_t> flagMaterializerCode;
    std::vector<VMHandlerEntryRelocation> relocations;
    std::vector<VMHandlerEntryUnwindRecord> unwindRecords;
    std::string error;
};

class VMHandlerEntryCodegen {
public:
    VMHandlerEntryCodegenResult Generate(
        const VMHandlerEntryCodegenConfig& config) const;

    static bool Validate(
        const VMHandlerEntryCodegenConfig& config,
        const VMHandlerEntryCodegenResult& result,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_VM_HANDLER_ENTRY_CODEGEN_H
