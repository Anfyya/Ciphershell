#include "vm_section_emitter.h"
#include "../pe_parser/pe_emitter.h"
#include <algorithm>
#include <cstring>
#include <ctime>

namespace CipherShell {

namespace {
uint8_t BytecodeMask(uint32_t cookie, uint32_t offset) {
    uint8_t cookieByte = static_cast<uint8_t>(cookie >> ((offset & 3u) * 8u));
    return static_cast<uint8_t>(cookieByte ^ static_cast<uint8_t>((offset * 131u) & 0xFFu));
}
uint32_t RotL32(uint32_t v, unsigned c) {
    c &= 31;
    return (v << c) | (v >> ((32 - c) & 31));
}
}

uint32_t VMSectionEmitter::AlignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void VMSectionEmitter::AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

VMEmitResult VMSectionEmitter::Emit(
    CS_PE_IMAGE* image,
    const std::vector<uint8_t>& bytecode,
    const std::vector<VMFunctionRecord>& records,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint32_t runtimeEntryRVA,
    const char sectionName[8])
{
    VMEmitResult result{};
    if (!image || !image->isValid) {
        result.error = "VM_EMIT: invalid PE image";
        return result;
    }
    if (bytecode.empty() || records.empty()) {
        result.error = "VM_EMIT: empty bytecode or function record table";
        return result;
    }

    uint32_t cookie = static_cast<uint32_t>(time(nullptr)) ^ static_cast<uint32_t>(bytecode.size() * 0x45D9F3Bu);
    cookie ^= static_cast<uint32_t>(records.size() * 0x9E3779B9u);
    cookie ^= runtimeEntryRVA * 0x85EBCA6Bu;
    if (cookie == 0) cookie = 0xA5C35A3Cu;

    std::vector<uint8_t> section;
    section.reserve(0x100 + records.size() * 32 + bytecode.size());

    const uint32_t headerSize = 40;
    const uint32_t recordOffset = headerSize;
    const uint32_t recordSize = 28;
    const uint32_t opcodeMapOffset = recordOffset + static_cast<uint32_t>(records.size() * recordSize);
    const uint32_t opcodeMapSize = 256;
    const uint32_t registerMapOffset = opcodeMapOffset + opcodeMapSize;
    const uint32_t registerMapSize = 32;
    const uint32_t bytecodeOffset = registerMapOffset + registerMapSize;

    std::vector<uint8_t> encodedBytecode = bytecode;
    for (const auto& record : records) {
        if (record.bytecodeOffset > encodedBytecode.size() ||
            record.bytecodeSize > encodedBytecode.size() - record.bytecodeOffset) {
            result.error = "VM_EMIT: function bytecode range is outside bytecode blob";
            return result;
        }
        for (uint32_t i = 0; i < record.bytecodeSize; i++) {
            uint32_t pos = record.bytecodeOffset + i;
            encodedBytecode[pos] ^= BytecodeMask(cookie, i);
        }
    }

    AppendU32(section, cookie);
    AppendU32(section, static_cast<uint32_t>(records.size()) ^ cookie);
    AppendU32(section, recordOffset ^ RotL32(cookie, 3));
    AppendU32(section, opcodeMapOffset ^ RotL32(cookie, 7));
    AppendU32(section, registerMapOffset ^ RotL32(cookie, 11));
    AppendU32(section, bytecodeOffset ^ RotL32(cookie, 17));
    AppendU32(section, static_cast<uint32_t>(bytecode.size()) ^ RotL32(cookie, 19));
    AppendU32(section, runtimeEntryRVA ^ RotL32(cookie, 23));
    AppendU32(section, 0u ^ RotL32(cookie, 5));
    AppendU32(section, 0u ^ RotL32(cookie, 13));

    for (const auto& record : records) {
        AppendU32(section, record.functionRVA ^ cookie);
        AppendU32(section, record.functionSize ^ RotL32(cookie, 1));
        AppendU32(section, record.bytecodeOffset ^ RotL32(cookie, 5));
        AppendU32(section, record.bytecodeSize ^ RotL32(cookie, 9));
        AppendU32(section, record.opcodeMapOffset ^ RotL32(cookie, 13));
        AppendU32(section, record.registerMapOffset ^ RotL32(cookie, 15));
        AppendU32(section, record.flags ^ RotL32(cookie, 21));
    }

    uint8_t reverseOpcode[256];
    for (uint32_t i = 0; i < 256; i++) reverseOpcode[i] = static_cast<uint8_t>(i);
    for (const auto& kv : opcodeMap) reverseOpcode[kv.second] = kv.first;
    section.insert(section.end(), reverseOpcode, reverseOpcode + 256);

    uint8_t regMap[32];
    for (uint32_t i = 0; i < 32; i++) regMap[i] = static_cast<uint8_t>(i);
    for (const auto& kv : registerMap) {
        if (kv.first < 32) regMap[kv.first] = kv.second;
    }
    section.insert(section.end(), regMap, regMap + 32);
    section.insert(section.end(), encodedBytecode.begin(), encodedBytecode.end());

    char name[8] = {'.','c','s','v','m',0,0,0};
    if (sectionName) memcpy(name, sectionName, 8);

    PEEmitter emitter(image);
    auto append = emitter.AppendSection(name, section, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!append.success) {
        result.error = "VM_EMIT: " + append.error;
        return result;
    }

    result.sectionRVA = append.rva;
    result.sectionRawOffset = append.rawOffset;
    result.metadataRVA = append.rva;
    result.bytecodeRVA = append.rva + bytecodeOffset;
    result.trampolineRVA = runtimeEntryRVA;
    result.success = true;
    return result;
}

bool VMSectionEmitter::PatchRuntimeEntry(CS_PE_IMAGE* image, uint32_t metadataRVA, uint32_t runtimeEntryRVA, std::string* error) {
    PEEmitter emitter(image);
    if (!emitter.IsValid()) {
        if (error) *error = "invalid PE image";
        return false;
    }
    uint32_t metadataOffset = emitter.RvaToOffset(metadataRVA);
    if (metadataOffset == 0 || metadataOffset + 32 > image->rawSize) {
        if (error) *error = "metadata RVA is outside file data";
        return false;
    }
    uint32_t cookie = *reinterpret_cast<uint32_t*>(image->rawData + metadataOffset);
    uint32_t encoded = runtimeEntryRVA ^ RotL32(cookie, 23);
    std::vector<uint8_t> patch;
    AppendU32(patch, encoded);
    return emitter.PatchBytes(metadataRVA + 28, patch, error);
}
} // namespace CipherShell
