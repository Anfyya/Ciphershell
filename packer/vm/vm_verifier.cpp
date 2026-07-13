#include "vm_verifier.h"

#include "../../runtime/common/vm_crypto.h"
#include "../pe_parser/pe_emitter.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_map>

namespace CipherShell {
namespace {

void DecodeMasterKey(
    const VM_METADATA_HEADER& header,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    uint8_t output[32]) {
    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t cookieByte = static_cast<uint8_t>(
            header.cookie >> ((i & 3u) * 8u));
        output[i] = header.encodedMasterKey[i] ^ runtimeKeyShare[i] ^
            header.buildId[i & 15u] ^ cookieByte ^ static_cast<uint8_t>(i * 0x5Bu);
    }
}

bool BuildReverseMap(
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint8_t reverse[VM_OPCODE_MAP_SIZE],
    std::string& error) {
    if (opcodeMap.size() != VM_OPCODE_MAP_SIZE) {
        error = "opcode map is not a complete 256-entry permutation";
        return false;
    }
    std::array<uint8_t, VM_OPCODE_MAP_SIZE> seen{};
    for (const auto& item : opcodeMap) {
        if (seen[item.second]) {
            error = "opcode map is not injective";
            return false;
        }
        seen[item.second] = 1;
        reverse[item.second] = item.first;
    }
    return true;
}

bool BuildMapsFromMetadata(
    const uint8_t* metadata,
    const VM_METADATA_HEADER& header,
    std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    std::unordered_map<uint8_t, uint8_t>& registerMap,
    std::string& error) {
    const uint8_t* reverse = metadata + header.reverseOpcodeMapOffset;
    std::array<uint8_t, VM_OPCODE_MAP_SIZE> semanticSeen{};
    for (uint32_t mapped = 0; mapped < VM_OPCODE_MAP_SIZE; ++mapped) {
        const uint8_t semantic = reverse[mapped];
        if (semanticSeen[semantic]) {
            error = "metadata reverse opcode map is not a permutation";
            return false;
        }
        semanticSeen[semantic] = 1;
        opcodeMap[semantic] = static_cast<uint8_t>(mapped);
    }
    const uint8_t* registers = metadata + header.registerMapOffset;
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerSeen{};
    for (uint8_t native = 0; native < 16; ++native) {
        if (registers[native] >= VM_REGISTER_MAP_SIZE ||
            registerSeen[registers[native]]) {
            error = "metadata register map is invalid";
            return false;
        }
        registerSeen[registers[native]] = 1;
        registerMap[native] = registers[native];
    }
    return true;
}

} // namespace

VMRecordVerification VMBytecodeVerifier::VerifyPlainRecord(
    const VMFunctionRecord& record,
    const std::vector<uint8_t>& bytecode,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint64_t operandCodecSeed,
    uint32_t registerCount,
    bool is64Bit) {
    VMRecordVerification result{};
    if (record.bytecodeOffset > bytecode.size() ||
        record.bytecodeSize > bytecode.size() - record.bytecodeOffset ||
        record.bytecodeSize == 0) {
        result.error = "record micro-bytecode range is invalid";
        return result;
    }
    if (operandCodecSeed == 0 || registerCount < 16 ||
        registerCount > VM_REGISTER_MAP_SIZE) {
        result.error = "operand codec seed or register count is invalid";
        return result;
    }
    if (record.guestStackSize < 0x4000u || record.guestStackSize > 0x70000u ||
        (record.guestStackSize & 0x0FFFu) != 0) {
        result.error = "record guest stack reserve is invalid";
        return result;
    }
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> mappedRegisters{};
    for (uint8_t native = 0; native < 16; ++native) {
        const auto found = registerMap.find(native);
        if (found == registerMap.end() || found->second >= registerCount ||
            mappedRegisters[found->second]) {
            result.error = "native register map is missing, out of range, or non-injective";
            return result;
        }
        mappedRegisters[found->second] = 1;
    }

    uint8_t reverse[VM_OPCODE_MAP_SIZE]{};
    if (!BuildReverseMap(opcodeMap, reverse, result.error)) return result;
    const VM_OPERAND_CODEC codec =
        VMSchema::DeriveOperandCodec(operandCodecSeed, record.functionRVA);
    VMStreamValidation validation = VMSchema::ValidateStream(
        bytecode.data() + record.bytecodeOffset,
        record.bytecodeSize,
        reverse,
        codec,
        registerCount);
    if (!validation.success) {
        result.error = "micro stream validation failed: " + validation.error;
        return result;
    }
    bool terminal = false;
    for (const auto& decoded : validation.decoded) {
        const auto* descriptor = VMSchema::Lookup(decoded.instruction.opcode);
        if (!descriptor ||
            (is64Bit ? !descriptor->runtimeSupportedX64 :
                       !descriptor->runtimeSupportedX86)) {
            result.error = "runtime has no handler for decoded micro operation";
            return result;
        }
        if (decoded.instruction.handlerVariant >= VM_HANDLER_VARIANT_COUNT) {
            result.error = "micro stream selects a handler variant outside metadata K";
            return result;
        }
        terminal = terminal || descriptor->terminal;
    }
    if (!terminal) {
        result.error = "micro stream has no terminal RET/EXIT";
        return result;
    }
    result.instructionCount = validation.microOpCount;
    result.maxGuestStackUsage = validation.maxOperandStackDepth * sizeof(uint64_t);
    if (result.maxGuestStackUsage > record.guestStackSize) {
        result.error = "micro operand stack exceeds guest stack reserve";
        return result;
    }
    result.success = true;
    return result;
}

bool VMBytecodeVerifier::VerifyEmittedMetadataAndBytecode(
    CS_PE_IMAGE* image,
    uint32_t metadataRVA,
    const std::vector<VMFunctionRecord>& expectedRecords,
    const std::vector<uint8_t>& expectedPlaintext,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedSemanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedSlotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedVariants,
    uint32_t expectedJunkHandlerCount,
    bool expectedHandlerMutation,
    bool expectedJunkHandlers,
    std::string& error) {
    PEEmitter emitter(image);
    if (!emitter.IsValid()) {
        error = "invalid PE image";
        return false;
    }
    const uint32_t fileOffset = emitter.RvaToOffset(metadataRVA);
    if (fileOffset == 0 ||
        fileOffset + sizeof(VM_METADATA_HEADER) > image->rawSize) {
        error = "metadata RVA is outside output image";
        return false;
    }
    VM_METADATA_HEADER header{};
    std::memcpy(&header, image->rawData + fileOffset, sizeof(header));
    if (header.totalSize > image->rawSize - fileOffset) {
        error = "metadata total size is outside output image";
        return false;
    }
    const uint8_t* metadata = image->rawData + fileOffset;
    if (!VMSectionEmitter::VerifyMetadata(
            metadata, header.totalSize, runtimeKeyShare, error)) {
        return false;
    }
    if (header.recordCount != expectedRecords.size() ||
        header.bytecodeSize != expectedPlaintext.size() ||
        header.operandCodecSeed == 0) {
        error = "emitted record, bytecode, or operand-codec graph differs";
        return false;
    }
    const uint32_t requiredFlags =
        VM_METADATA_FLAG_AUTHENTICATED |
        VM_METADATA_FLAG_BYTECODE_CHACHA20 |
        VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
        VM_METADATA_FLAG_CFG_VERIFIED |
        VM_METADATA_FLAG_MICRO_STREAM |
        VM_METADATA_FLAG_LAZY_FLAGS |
        VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
        VM_METADATA_FLAG_DIRECT_THREADED |
        VM_METADATA_FLAG_HANDLER_ENCRYPTED;
    if ((header.flags & requiredFlags) != requiredFlags ||
        (header.architecture == VM_ARCH_X64 &&
            !(header.flags & VM_METADATA_FLAG_UNWIND_VERIFIED)) ||
        header.runtimeBaseRVA == 0 ||
        header.runtimeEntryRVA < header.runtimeBaseRVA ||
        header.runtimeSize == 0 || header.imageSize == 0 ||
        header.runtimeBaseRVA >= header.imageSize ||
        header.runtimeSize > header.imageSize - header.runtimeBaseRVA ||
        header.runtimeEntryRVA - header.runtimeBaseRVA >= header.runtimeSize) {
        error = "emitted metadata runtime synthesis flags or linkage are incomplete";
        return false;
    }
    if ((header.flags & VM_METADATA_FLAG_CFG_ENABLED) &&
        ((header.architecture == VM_ARCH_X64 &&
          header.guardCFDispatchPointerRVA == 0) ||
         (header.architecture == VM_ARCH_X86 &&
          header.guardCFCheckPointerRVA == 0))) {
        error = "CFG-enabled metadata has no architecture-specific Guard pointer";
        return false;
    }
    if (header.handlerTableSize != VM_HANDLER_TABLE_SIZE ||
        header.handlerVariantCount != VM_HANDLER_VARIANT_COUNT ||
        header.junkHandlerCount != expectedJunkHandlerCount ||
        expectedJunkHandlerCount > VM_HANDLER_USABLE_SLOT_COUNT) {
        error = "emitted handler metadata differs from build graph";
        return false;
    }
    const auto rangeInside = [&](uint32_t offset, uint32_t size) {
        return offset <= header.totalSize && size <= header.totalSize - offset;
    };
    if (!rangeInside(header.handlerSemanticMapOffset, VM_HANDLER_TABLE_SIZE) ||
        !rangeInside(header.handlerDescriptorOffset, VM_HANDLER_TABLE_SIZE) ||
        !rangeInside(header.handlerVariantOffset, VM_HANDLER_TABLE_SIZE)) {
        error = "emitted handler tables are outside authenticated metadata";
        return false;
    }
    const uint8_t* semanticToSlot =
        metadata + header.handlerSemanticMapOffset;
    const uint8_t* slotToSemantic =
        metadata + header.handlerDescriptorOffset;
    const uint8_t* variants = metadata + header.handlerVariantOffset;
    if (!std::equal(expectedSemanticToSlot.begin(),
            expectedSemanticToSlot.end(), semanticToSlot) ||
        !std::equal(expectedSlotToSemantic.begin(),
            expectedSlotToSemantic.end(), slotToSemantic) ||
        !std::equal(expectedVariants.begin(),
            expectedVariants.end(), variants)) {
        error = "emitted handler tables differ from MutationEngine output";
        return false;
    }
    if (((header.flags & VM_METADATA_FLAG_HANDLER_MUTATED) != 0) !=
            expectedHandlerMutation ||
        ((header.flags & VM_METADATA_FLAG_JUNK_HANDLERS) != 0) !=
            expectedJunkHandlers ||
        expectedJunkHandlers != (expectedJunkHandlerCount != 0)) {
        error = "emitted handler flags differ from build graph";
        return false;
    }

    uint8_t masterKey[32]{};
    DecodeMasterKey(header, runtimeKeyShare, masterKey);
    const auto* records = reinterpret_cast<const VM_FUNCTION_RECORD*>(
        metadata + header.recordOffset);
    std::vector<uint8_t> recovered(expectedPlaintext.size(), 0);
    for (uint32_t i = 0; i < header.recordCount; ++i) {
        const VM_FUNCTION_RECORD& record = records[i];
        const auto expected = std::find_if(
            expectedRecords.begin(), expectedRecords.end(),
            [&](const VMFunctionRecord& value) {
                return value.functionRVA == record.functionRVA;
            });
        if (expected == expectedRecords.end() ||
            record.bytecodeOffset != expected->bytecodeOffset ||
            record.bytecodeSize != expected->bytecodeSize ||
            record.returnStackCleanup != expected->returnStackCleanup ||
            record.guestStackSize != expected->guestStackSize ||
            record.trampolineRVA == 0 || record.trampolineSize == 0 ||
            (record.flags & (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                             VM_RECORD_FLAG_CFG_VERIFIED)) !=
                (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                 VM_RECORD_FLAG_CFG_VERIFIED) ||
            (header.architecture == VM_ARCH_X64 &&
             !(record.flags & VM_RECORD_FLAG_UNWIND_VERIFIED))) {
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "emitted record linkage differs from build graph";
            return false;
        }
        uint8_t recordKey[32]{};
        vm_derive_record_key(
            masterKey, header.buildId, record.functionRVA, recordKey);
        const uint8_t* ciphertext =
            metadata + header.bytecodeOffset + record.bytecodeOffset;
        const uint64_t tag = vm_siphash24(
            ciphertext, record.bytecodeSize, recordKey + 16);
        if (!vm_constant_time_equal64(tag, record.bytecodeTag)) {
            std::memset(recordKey, 0, sizeof(recordKey));
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "emitted bytecode authentication tag mismatch";
            return false;
        }
        vm_chacha20_xor(
            ciphertext,
            recovered.data() + record.bytecodeOffset,
            record.bytecodeSize,
            recordKey,
            record.nonce,
            1,
            0);
        std::memset(recordKey, 0, sizeof(recordKey));
    }
    std::memset(masterKey, 0, sizeof(masterKey));
    if (recovered != expectedPlaintext) {
        error = "decrypted emitted bytecode differs from Translator output";
        return false;
    }

    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;
    if (!BuildMapsFromMetadata(
            metadata, header, opcodeMap, registerMap, error)) {
        return false;
    }
    for (const auto& record : expectedRecords) {
        const auto verification = VerifyPlainRecord(
            record,
            recovered,
            opcodeMap,
            registerMap,
            header.operandCodecSeed,
            VM_REGISTER_MAP_SIZE,
            header.architecture == VM_ARCH_X64);
        if (!verification.success) {
            error = "recovered micro stream verification failed: " +
                verification.error;
            return false;
        }
    }
    return true;
}

} // namespace CipherShell
