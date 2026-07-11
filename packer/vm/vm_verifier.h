#ifndef CS_VM_VERIFIER_H
#define CS_VM_VERIFIER_H

#include "vm_schema.h"
#include "../transforms/vm_section_emitter.h"
#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

struct VMRecordVerification {
    bool success = false;
    uint32_t instructionCount = 0;
    uint32_t maxGuestStackUsage = 0;
    std::string error;
};

class VMBytecodeVerifier {
public:
    static VMRecordVerification VerifyPlainRecord(
        const VMFunctionRecord& record,
        const std::vector<uint8_t>& bytecode,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        uint32_t registerCount,
        bool is64Bit);

    static bool VerifyEmittedMetadataAndBytecode(
        CS_PE_IMAGE* image,
        uint32_t metadataRVA,
        const std::vector<VMFunctionRecord>& expectedRecords,
        const std::vector<uint8_t>& expectedPlaintext,
        const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_VM_VERIFIER_H
