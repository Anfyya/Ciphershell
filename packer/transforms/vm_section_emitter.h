#ifndef CS_VM_SECTION_EMITTER_H
#define CS_VM_SECTION_EMITTER_H

#include "../pe_parser/pe_parser.h"
#include "translator.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct VMFunctionRecord {
    uint32_t functionRVA;
    uint32_t functionSize;
    uint32_t bytecodeOffset;
    uint32_t bytecodeSize;
    uint32_t opcodeMapOffset;
    uint32_t registerMapOffset;
    uint32_t flags;
};

struct VMEmitResult {
    bool success;
    uint32_t sectionRVA;
    uint32_t sectionRawOffset;
    uint32_t metadataRVA;
    uint32_t bytecodeRVA;
    uint32_t trampolineRVA;
    std::string error;
};

class VMSectionEmitter {
public:
    VMEmitResult Emit(
        CS_PE_IMAGE* image,
        const std::vector<uint8_t>& bytecode,
        const std::vector<VMFunctionRecord>& records,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap);

private:
    static uint32_t AlignUp(uint32_t value, uint32_t alignment);
    static void AppendU32(std::vector<uint8_t>& out, uint32_t value);
    static bool AppendSection(
        CS_PE_IMAGE* image,
        const char name[8],
        const std::vector<uint8_t>& data,
        uint32_t characteristics,
        VMEmitResult& result);
};

} // namespace CipherShell

#endif // CS_VM_SECTION_EMITTER_H
