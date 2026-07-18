#include "vm_section_emitter.h"

#include "../pe_parser/pe_emitter.h"
#include "../vm/vm_schema.h"
#include "../../runtime/common/vm_crypto.h"
#include <algorithm>
#ifdef _WIN32
#include <bcrypt.h>
#else
#include <random>
#endif
#include <cstddef>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#pragma comment(lib, "bcrypt.lib")
#endif

namespace CipherShell {
namespace {

constexpr uint32_t kKnownHeaderFlags = VM_METADATA_FLAG_AUTHENTICATED |
    VM_METADATA_FLAG_BYTECODE_CHACHA20 |
    VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
    VM_METADATA_FLAG_CFG_VERIFIED |
    VM_METADATA_FLAG_UNWIND_VERIFIED |
    VM_METADATA_FLAG_CFG_ENABLED |
    VM_METADATA_FLAG_HANDLER_MUTATED |
    VM_METADATA_FLAG_JUNK_HANDLERS |
    VM_METADATA_FLAG_MICRO_STREAM |
    VM_METADATA_FLAG_LAZY_FLAGS |
    VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
    VM_METADATA_FLAG_DIRECT_THREADED |
    VM_METADATA_FLAG_HANDLER_ENCRYPTED |
    VM_METADATA_FLAG_RUNTIME_TRACE;
constexpr uint32_t kKnownRecordFlags = VM_RECORD_FLAG_X64 |
    VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
    VM_RECORD_FLAG_UNWIND_VERIFIED |
    VM_RECORD_FLAG_CFG_VERIFIED |
    VM_RECORD_FLAG_USES_SIMD |
    VM_RECORD_FLAG_USES_AVX |
    VM_RECORD_FLAG_USES_X87;

bool SecureRandom(void* destination, size_t size) {
    if (!destination || size == 0) return false;
#ifdef _WIN32
    if (size > std::numeric_limits<ULONG>::max()) return false;
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(destination), static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
#else
    std::random_device source;
    auto* output = static_cast<uint8_t*>(destination);
    for (size_t i = 0; i < size; ++i) output[i] = static_cast<uint8_t>(source());
    return true;
#endif
}

void EncodeMasterKey(
    const uint8_t masterKey[32],
    const uint8_t runtimeKeyShare[VM_RUNTIME_KEY_SHARE_SIZE],
    const uint8_t buildId[16],
    uint32_t cookie,
    uint8_t encoded[32])
{
    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t cookieByte = static_cast<uint8_t>(cookie >> ((i & 3u) * 8u));
        encoded[i] = masterKey[i] ^ runtimeKeyShare[i] ^ buildId[i & 15u] ^
            cookieByte ^ static_cast<uint8_t>(i * 0x5Bu);
    }
}

void DecodeMasterKey(
    const VM_METADATA_HEADER& header,
    const uint8_t runtimeKeyShare[VM_RUNTIME_KEY_SHARE_SIZE],
    uint8_t masterKey[32]) {
    EncodeMasterKey(header.encodedMasterKey, runtimeKeyShare,
        header.buildId, header.cookie, masterKey);
}

uint32_t NextLayoutPadding(uint32_t& state, uint32_t minimum, uint32_t maximum) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return minimum + state % (maximum - minimum + 1u);
}

bool VaToImageRva(uint64_t imageBase, uint64_t va, uint32_t& rva) {
    if (va == 0) { rva = 0; return true; }
    if (va < imageBase || va - imageBase > std::numeric_limits<uint32_t>::max()) return false;
    rva = static_cast<uint32_t>(va - imageBase);
    return true;
}

uint64_t ComputeMetadataTag(
    const uint8_t* metadata,
    size_t authenticatedSize,
    const uint8_t masterKey[32])
{
    const size_t tagOffset = offsetof(VM_METADATA_HEADER, metadataTag);
    const uint64_t zero = 0;
    VM_SIPHASH24_CONTEXT context{};
    vm_siphash24_init(&context, masterKey);
    vm_siphash24_update(&context, metadata, tagOffset);
    vm_siphash24_update(&context, reinterpret_cast<const uint8_t*>(&zero), sizeof(zero));
    const size_t afterTag = tagOffset + sizeof(uint64_t);
    if (authenticatedSize > afterTag) {
        vm_siphash24_update(&context, metadata + afterTag, authenticatedSize - afterTag);
    }
    return vm_siphash24_final(&context);
}

bool BuildReverseOpcodeMap(
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint8_t reverse[VM_OPCODE_MAP_SIZE],
    std::string& error)
{
    if (opcodeMap.size() != VM_OPCODE_MAP_SIZE) {
        error = "VM_EMIT: opcode map must be a complete 256-entry permutation";
        return false;
    }
    std::array<uint8_t, VM_OPCODE_MAP_SIZE> seen{};
    for (const auto& item : opcodeMap) {
        if (seen[item.second]) {
            error = "VM_EMIT: opcode map is not injective";
            return false;
        }
        seen[item.second] = 1;
        reverse[item.second] = item.first;
    }
    return true;
}

bool BuildRegisterMap(
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint8_t output[VM_REGISTER_MAP_SIZE],
    std::string& error)
{
    for (uint32_t i = 0; i < VM_REGISTER_MAP_SIZE; ++i) output[i] = VM_REGISTER_INVALID;
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> seen{};
    for (uint8_t native = 0; native < 16; ++native) {
        auto mapped = registerMap.find(native);
        if (mapped == registerMap.end() || mapped->second >= VM_REGISTER_MAP_SIZE || seen[mapped->second]) {
            error = "VM_EMIT: register map is missing, out of range, or not injective";
            return false;
        }
        output[native] = mapped->second;
        seen[mapped->second] = 1;
    }
    return true;
}

bool ValidateHandlerLayout(
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& semanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& slotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& variants,
    uint32_t expectedJunkCount,
    bool is64Bit,
    std::string& error)
{
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> usedSlots{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> validSemantics{};
    uint32_t junkCount = 0;
    uint32_t validCount = 0;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        if (descriptor.opcode == VM_HANDLER_INVALID || descriptor.opcode == VM_HANDLER_JUNK) {
            error = "VM_EMIT: production opcode collides with a handler sentinel";
            return false;
        }
        const bool supported = is64Bit
            ? descriptor.runtimeSupportedX64
            : descriptor.runtimeSupportedX86;
        if (!supported) {
            if (semanticToSlot[descriptor.opcode] != VM_HANDLER_INVALID) {
                error = "VM_EMIT: runtime-unsupported semantic owns a handler slot";
                return false;
            }
            continue;
        }
        validSemantics[descriptor.opcode] = 1;
        ++validCount;
        const uint8_t slot = semanticToSlot[descriptor.opcode];
        if (slot == VM_HANDLER_INVALID || slot >= VM_HANDLER_USABLE_SLOT_COUNT ||
            usedSlots[slot] || slotToSemantic[slot] != descriptor.opcode) {
            error = "VM_EMIT: handler map is missing, duplicated, reserved, or not reversible";
            return false;
        }
        usedSlots[slot] = 1;
    }
    for (uint32_t semantic = 0; semantic < VM_HANDLER_TABLE_SIZE; ++semantic) {
        if (!validSemantics[semantic] && semanticToSlot[semantic] != VM_HANDLER_INVALID) {
            error = "VM_EMIT: unsupported semantic opcode owns a handler slot";
            return false;
        }
    }
    for (uint32_t slot = 0; slot < VM_HANDLER_TABLE_SIZE; ++slot) {
        if (variants[slot] >= VM_HANDLER_VARIANT_COUNT) {
            error = "VM_EMIT: handler variant is out of range";
            return false;
        }
        const uint8_t semantic = slotToSemantic[slot];
        if (slot >= VM_HANDLER_USABLE_SLOT_COUNT) {
            if (semantic != VM_HANDLER_INVALID || variants[slot] != 0) {
                error = "VM_EMIT: reserved handler slot 0xFF is not empty";
                return false;
            }
            continue;
        }
        if (semantic == VM_HANDLER_JUNK) {
            if (usedSlots[slot]) {
                error = "VM_EMIT: junk handler overlaps a real handler slot";
                return false;
            }
            ++junkCount;
            continue;
        }
        if (semantic == VM_HANDLER_INVALID) continue;
        if (!validSemantics[semantic] || semanticToSlot[semantic] != slot) {
            error = "VM_EMIT: handler slot descriptor is unsupported or not reversible";
            return false;
        }
    }
    if (junkCount != expectedJunkCount ||
        junkCount > VM_HANDLER_USABLE_SLOT_COUNT - validCount) {
        error = "VM_EMIT: junk handler count does not match the usable handler table";
        return false;
    }
    return true;
}


} // namespace

uint32_t VMSectionEmitter::AlignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1u) & ~(alignment - 1u);
}

VMEmitResult VMSectionEmitter::Emit(
    CS_PE_IMAGE* image,
    const std::vector<uint8_t>& bytecode,
    const std::vector<VMFunctionRecord>& inputRecords,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSemanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSlotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerVariants,
    uint32_t junkHandlerCount,
    bool handlerMutationEnabled,
    bool junkHandlersEnabled,
    uint64_t operandCodecSeed,
    uint32_t runtimeEntryRVA,
    const char sectionName[8])
{
    VMEmitResult result{};
    if (!image || !image->isValid || !image->rawData) {
        result.error = "VM_EMIT: invalid PE image";
        return result;
    }
    if (bytecode.empty() || inputRecords.empty() ||
        bytecode.size() > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: empty or oversized bytecode/record table";
        return result;
    }

    uint8_t reverseOpcode[VM_OPCODE_MAP_SIZE]{};
    uint8_t encodedRegisterMap[VM_REGISTER_MAP_SIZE]{};
    if (!BuildReverseOpcodeMap(opcodeMap, reverseOpcode, result.error) ||
        !BuildRegisterMap(registerMap, encodedRegisterMap, result.error) ||
        !ValidateHandlerLayout(handlerSemanticToSlot, handlerSlotToSemantic,
            handlerVariants, junkHandlerCount, image->is64Bit != 0,
            result.error)) return result;

    VM_METADATA_HEADER header{};
    uint8_t masterKey[32]{};
    std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> runtimeKeyShare{};
    if (!SecureRandom(&header.cookie, sizeof(header.cookie)) ||
        !SecureRandom(header.buildId, sizeof(header.buildId)) ||
        !SecureRandom(masterKey, sizeof(masterKey)) ||
        !SecureRandom(runtimeKeyShare.data(), runtimeKeyShare.size()) ||
        !SecureRandom(&header.layoutSeed, sizeof(header.layoutSeed))) {
        result.error = "VM_EMIT: BCryptGenRandom failed";
        return result;
    }
    if (header.cookie == 0) header.cookie = 1;
    if (operandCodecSeed == 0) {
        result.error = "VM_EMIT: operand codec seed is zero";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.operandCodecSeed = operandCodecSeed;

    header.headerSize = sizeof(VM_METADATA_HEADER);
    header.metadataVersion = VM_METADATA_VERSION;
    header.schemaVersion = VMSchema::Version();
    header.runtimeVersion = VM_RUNTIME_VERSION;
    header.keyEncodingVersion = VM_KEY_ENCODING_VERSION;
    header.architecture = image->is64Bit ? VM_ARCH_X64 : VM_ARCH_X86;
    header.flags = VM_METADATA_FLAG_AUTHENTICATED |
        VM_METADATA_FLAG_BYTECODE_CHACHA20 |
        VM_METADATA_FLAG_MICRO_STREAM |
        VM_METADATA_FLAG_LAZY_FLAGS;
    if (image->loadConfig.hasCFG) header.flags |= VM_METADATA_FLAG_CFG_ENABLED;
    if (handlerMutationEnabled) header.flags |= VM_METADATA_FLAG_HANDLER_MUTATED;
    if (junkHandlersEnabled) header.flags |= VM_METADATA_FLAG_JUNK_HANDLERS;
    header.recordCount = static_cast<uint32_t>(inputRecords.size());
    header.recordSize = sizeof(VM_FUNCTION_RECORD);
    header.opcodeMapSize = VM_OPCODE_MAP_SIZE;
    header.registerMapSize = VM_REGISTER_MAP_SIZE;
    header.handlerTableSize = VM_HANDLER_TABLE_SIZE;
    header.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
    header.junkHandlerCount = junkHandlerCount;
    header.imageSize = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SizeOfImage
        : image->ntHeaders32->OptionalHeader.SizeOfImage;
    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
    if (!VaToImageRva(imageBase, image->loadConfig.guardCFCheckFunctionPointer,
            header.guardCFCheckPointerRVA) ||
        !VaToImageRva(imageBase, image->loadConfig.guardCFDispatchFunctionPointer,
            header.guardCFDispatchPointerRVA)) {
        result.error = "VM_EMIT: CFG check/dispatch pointer is outside the image";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    if (image->loadConfig.hasCFG &&
        ((image->is64Bit && header.guardCFDispatchPointerRVA == 0) ||
         (!image->is64Bit && header.guardCFCheckPointerRVA == 0))) {
        result.error = "VM_EMIT: CFG image has no architecture-specific Guard call target";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }

    uint32_t layoutState = header.layoutSeed ? header.layoutSeed : 0xC51F3A79u;
    const uint64_t recordsSize = static_cast<uint64_t>(inputRecords.size()) * sizeof(VM_FUNCTION_RECORD);
    header.recordOffset = AlignUp(header.headerSize +
        NextLayoutPadding(layoutState, 16, 127), 16);
    if (recordsSize > std::numeric_limits<uint32_t>::max() ||
        recordsSize > std::numeric_limits<uint32_t>::max() - header.recordOffset) {
        result.error = "VM_EMIT: record table exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    const uint64_t reverseOffset = static_cast<uint64_t>(header.recordOffset) + recordsSize +
        NextLayoutPadding(layoutState, 16, 127);
    if (reverseOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: opcode map offset exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.reverseOpcodeMapOffset = AlignUp(static_cast<uint32_t>(reverseOffset), 16);
    const uint64_t registerOffset = static_cast<uint64_t>(header.reverseOpcodeMapOffset) +
        VM_OPCODE_MAP_SIZE + NextLayoutPadding(layoutState, 16, 127);
    if (registerOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: register map offset exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.registerMapOffset = AlignUp(static_cast<uint32_t>(registerOffset), 16);
    const uint64_t semanticMapOffset = static_cast<uint64_t>(header.registerMapOffset) +
        VM_REGISTER_MAP_SIZE + NextLayoutPadding(layoutState, 16, 127);
    if (semanticMapOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: handler semantic map offset exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.handlerSemanticMapOffset = AlignUp(static_cast<uint32_t>(semanticMapOffset), 16);
    const uint64_t descriptorOffset = static_cast<uint64_t>(header.handlerSemanticMapOffset) +
        VM_HANDLER_TABLE_SIZE + NextLayoutPadding(layoutState, 16, 127);
    if (descriptorOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: handler descriptor offset exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.handlerDescriptorOffset = AlignUp(static_cast<uint32_t>(descriptorOffset), 16);
    const uint64_t variantOffset = static_cast<uint64_t>(header.handlerDescriptorOffset) +
        VM_HANDLER_TABLE_SIZE + NextLayoutPadding(layoutState, 16, 127);
    if (variantOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: handler variant offset exceeds uint32 metadata range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.handlerVariantOffset = AlignUp(static_cast<uint32_t>(variantOffset), 16);
    const uint64_t bytecodeOffset = static_cast<uint64_t>(header.handlerVariantOffset) +
        VM_HANDLER_TABLE_SIZE + NextLayoutPadding(layoutState, 16, 127);
    if (bytecodeOffset > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: randomized metadata layout exceeds uint32 RVA range";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.bytecodeOffset = AlignUp(static_cast<uint32_t>(bytecodeOffset), 64);
    header.bytecodeSize = static_cast<uint32_t>(bytecode.size());
    const uint64_t totalSize = static_cast<uint64_t>(header.bytecodeOffset) +
        header.bytecodeSize + NextLayoutPadding(layoutState, 16, 127);
    if (totalSize > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_EMIT: randomized metadata section exceeds uint32 size";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    header.totalSize = static_cast<uint32_t>(totalSize);
    header.runtimeEntryRVA = runtimeEntryRVA;
    EncodeMasterKey(masterKey, runtimeKeyShare.data(), header.buildId,
        header.cookie, header.encodedMasterKey);

    result.records = inputRecords;
    std::vector<uint8_t> encryptedBytecode = bytecode;
    std::unordered_set<uint32_t> functionRVAs;
    for (auto& record : result.records) {
        if (!functionRVAs.insert(record.functionRVA).second) {
            result.error = "VM_EMIT: duplicate function RVA";
            std::memset(masterKey, 0, sizeof(masterKey));
            return result;
        }
        if (record.bytecodeOffset > encryptedBytecode.size() ||
            record.bytecodeSize > encryptedBytecode.size() - record.bytecodeOffset ||
            record.bytecodeSize == 0) {
            result.error = "VM_EMIT: function micro-bytecode range is invalid";
            std::memset(masterKey, 0, sizeof(masterKey));
            return result;
        }
        record.opcodeMapOffset = header.reverseOpcodeMapOffset;
        record.registerMapOffset = header.registerMapOffset;
        if (!SecureRandom(record.nonce, sizeof(record.nonce))) {
            result.error = "VM_EMIT: record nonce generation failed";
            std::memset(masterKey, 0, sizeof(masterKey));
            return result;
        }
        uint8_t recordKey[32]{};
        vm_derive_record_key(masterKey, header.buildId, record.functionRVA, recordKey);
        vm_chacha20_xor(
            bytecode.data() + record.bytecodeOffset,
            encryptedBytecode.data() + record.bytecodeOffset,
            record.bytecodeSize,
            recordKey,
            record.nonce,
            1,
            0);
        record.bytecodeTag = vm_siphash24(
            encryptedBytecode.data() + record.bytecodeOffset,
            record.bytecodeSize,
            recordKey + 16);
        std::memset(recordKey, 0, sizeof(recordKey));
    }

    std::vector<uint8_t> section(header.totalSize, 0);
    if (!SecureRandom(section.data(), section.size())) {
        result.error = "VM_EMIT: randomized metadata padding generation failed";
        std::memset(masterKey, 0, sizeof(masterKey));
        return result;
    }
    std::memcpy(section.data(), &header, sizeof(header));
    std::memcpy(section.data() + header.recordOffset, result.records.data(),
        result.records.size() * sizeof(VM_FUNCTION_RECORD));
    std::memcpy(section.data() + header.reverseOpcodeMapOffset, reverseOpcode, sizeof(reverseOpcode));
    std::memcpy(section.data() + header.registerMapOffset, encodedRegisterMap, sizeof(encodedRegisterMap));
    std::memcpy(section.data() + header.handlerSemanticMapOffset,
        handlerSemanticToSlot.data(), handlerSemanticToSlot.size());
    std::memcpy(section.data() + header.handlerDescriptorOffset,
        handlerSlotToSemantic.data(), handlerSlotToSemantic.size());
    std::memcpy(section.data() + header.handlerVariantOffset,
        handlerVariants.data(), handlerVariants.size());
    std::memcpy(section.data() + header.bytecodeOffset, encryptedBytecode.data(), encryptedBytecode.size());

    header.metadataTag = ComputeMetadataTag(section.data(), header.totalSize, masterKey);
    std::memcpy(section.data(), &header, sizeof(header));
    std::memset(masterKey, 0, sizeof(masterKey));

    char name[8] = {'.', 'c', 's', 'v', 'm', 0, 0, 0};
    if (sectionName) std::memcpy(name, sectionName, sizeof(name));
    PEEmitter emitter(image);
    auto appended = emitter.AppendSection(
        name, section, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        result.error = "VM_EMIT: " + appended.error;
        return result;
    }

    result.success = true;
    result.sectionRVA = appended.rva;
    result.sectionRawOffset = appended.rawOffset;
    result.sectionSize = appended.rawSize;
    result.metadataRVA = appended.rva;
    result.metadataSize = header.totalSize;
    result.bytecodeRVA = appended.rva + header.bytecodeOffset;
    result.trampolineRVA = runtimeEntryRVA;
    result.architecture = header.architecture;
    result.schemaVersion = header.schemaVersion;
    result.operandCodecSeed = header.operandCodecSeed;
    std::copy(std::begin(header.buildId), std::end(header.buildId), result.buildId.begin());
    result.runtimeKeyShare = runtimeKeyShare;
    result.handlerSemanticToSlot = handlerSemanticToSlot;
    result.handlerSlotToSemantic = handlerSlotToSemantic;
    result.handlerVariants = handlerVariants;
    result.junkHandlerCount = junkHandlerCount;
    result.handlerMutationEnabled = handlerMutationEnabled;
    result.junkHandlersEnabled = junkHandlersEnabled;
    return result;
}

VMTraceEmitResult VMSectionEmitter::EmitTrace(
    CS_PE_IMAGE* image,
    const std::array<uint8_t, 16>& buildId,
    uint32_t architecture,
    uint32_t groupId,
    uint32_t capacity,
    const char sectionName[8])
{
    VMTraceEmitResult result{};
    if (!image || !image->isValid || !image->rawData ||
        (architecture != VM_ARCH_X86 && architecture != VM_ARCH_X64) ||
        groupId >= 64u || capacity == 0 || capacity > VM_TRACE_MAX_CAPACITY) {
        result.error = "VM_TRACE: invalid image or trace binding";
        return result;
    }
    const uint64_t byteCount = sizeof(VM_TRACE_HEADER) +
        static_cast<uint64_t>(capacity) * sizeof(VM_TRACE_EVENT);
    if (byteCount > (std::numeric_limits<uint32_t>::max)()) {
        result.error = "VM_TRACE: trace section exceeds uint32 range";
        return result;
    }
    std::vector<uint8_t> section(static_cast<size_t>(byteCount), 0);
    VM_TRACE_HEADER header{};
    header.magic = VM_TRACE_MAGIC;
    header.version = VM_TRACE_VERSION;
    header.headerSize = sizeof(VM_TRACE_HEADER);
    header.eventSize = sizeof(VM_TRACE_EVENT);
    header.capacity = capacity;
    header.architecture = architecture;
    header.groupId = groupId;
    std::copy(buildId.begin(), buildId.end(), std::begin(header.buildId));
    std::memcpy(section.data(), &header, sizeof(header));

    char name[8] = {'.', 'c', 's', 't', 'r', 'c', 0, 0};
    if (sectionName) std::memcpy(name, sectionName, sizeof(name));
    PEEmitter emitter(image);
    auto appended = emitter.AppendSection(name, section,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_WRITE);
    if (!appended.success) {
        result.error = "VM_TRACE: " + appended.error;
        return result;
    }
    result.success = true;
    result.sectionRVA = appended.rva;
    result.sectionRawOffset = appended.rawOffset;
    result.sectionSize = static_cast<uint32_t>(byteCount);
    result.capacity = capacity;
    result.groupId = groupId;
    result.architecture = architecture;
    result.buildId = buildId;
    return result;
}

bool VMSectionEmitter::VerifyMetadata(
    const uint8_t* metadata,
    size_t availableSize,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    std::string& error)
{
    if (!metadata || availableSize < sizeof(VM_METADATA_HEADER)) {
        error = "metadata header is truncated";
        return false;
    }
    VM_METADATA_HEADER header{};
    std::memcpy(&header, metadata, sizeof(header));
    if (header.headerSize != sizeof(VM_METADATA_HEADER) ||
        header.recordSize != sizeof(VM_FUNCTION_RECORD) ||
        header.metadataVersion != VM_METADATA_VERSION ||
        header.schemaVersion != VMSchema::Version() ||
        header.runtimeVersion != VM_RUNTIME_VERSION ||
        header.keyEncodingVersion != VM_KEY_ENCODING_VERSION ||
        (header.architecture != VM_ARCH_X86 && header.architecture != VM_ARCH_X64) ||
        (header.flags & ~kKnownHeaderFlags) != 0 ||
        (header.flags & (VM_METADATA_FLAG_AUTHENTICATED |
                         VM_METADATA_FLAG_BYTECODE_CHACHA20 |
                         VM_METADATA_FLAG_MICRO_STREAM |
                         VM_METADATA_FLAG_LAZY_FLAGS)) !=
            (VM_METADATA_FLAG_AUTHENTICATED |
             VM_METADATA_FLAG_BYTECODE_CHACHA20 |
             VM_METADATA_FLAG_MICRO_STREAM |
             VM_METADATA_FLAG_LAZY_FLAGS) ||
        header.opcodeMapSize != VM_OPCODE_MAP_SIZE ||
        header.registerMapSize != VM_REGISTER_MAP_SIZE ||
        header.handlerTableSize != VM_HANDLER_TABLE_SIZE ||
        header.handlerVariantCount != VM_HANDLER_VARIANT_COUNT) {
        error = "metadata version or fixed structure size mismatch";
        return false;
    }
    if (header.totalSize > availableSize || header.totalSize < header.bytecodeOffset ||
        header.bytecodeOffset > header.totalSize ||
        header.bytecodeSize > header.totalSize - header.bytecodeOffset ||
        header.recordCount == 0 ||
        header.recordOffset < header.headerSize ||
        header.recordOffset > header.reverseOpcodeMapOffset ||
        header.recordCount > (header.reverseOpcodeMapOffset - header.recordOffset) / header.recordSize ||
        header.reverseOpcodeMapOffset > header.registerMapOffset ||
        VM_OPCODE_MAP_SIZE > header.registerMapOffset - header.reverseOpcodeMapOffset ||
        header.registerMapOffset > header.handlerSemanticMapOffset ||
        VM_REGISTER_MAP_SIZE > header.handlerSemanticMapOffset - header.registerMapOffset ||
        header.handlerSemanticMapOffset > header.handlerDescriptorOffset ||
        VM_HANDLER_TABLE_SIZE > header.handlerDescriptorOffset - header.handlerSemanticMapOffset ||
        header.handlerDescriptorOffset > header.handlerVariantOffset ||
        VM_HANDLER_TABLE_SIZE > header.handlerVariantOffset - header.handlerDescriptorOffset ||
        header.handlerVariantOffset > header.bytecodeOffset ||
        VM_HANDLER_TABLE_SIZE > header.bytecodeOffset - header.handlerVariantOffset ||
        header.junkHandlerCount > VM_HANDLER_USABLE_SLOT_COUNT ||
        header.layoutSeed == 0 || header.operandCodecSeed == 0 || header.imageSize == 0 ||
        ((header.runtimeBaseRVA == 0 || header.runtimeEntryRVA == 0 || header.runtimeSize == 0) &&
            (header.runtimeBaseRVA != 0 || header.runtimeEntryRVA != 0 || header.runtimeSize != 0)) ||
        (header.runtimeBaseRVA != 0 &&
            (header.runtimeBaseRVA >= header.imageSize ||
             header.runtimeSize > header.imageSize - header.runtimeBaseRVA ||
             header.runtimeEntryRVA < header.runtimeBaseRVA ||
             header.runtimeEntryRVA - header.runtimeBaseRVA >= header.runtimeSize)) ||
        (((header.flags & VM_METADATA_FLAG_RUNTIME_TRACE) == 0) &&
            (header.traceRVA != 0 || header.traceCapacity != 0 ||
             header.traceGroup != 0)) ||
        (((header.flags & VM_METADATA_FLAG_RUNTIME_TRACE) != 0) &&
            (header.traceRVA == 0 || header.traceRVA >= header.imageSize ||
             header.traceCapacity == 0 ||
             header.traceCapacity > VM_TRACE_MAX_CAPACITY ||
             header.traceGroup >= 64u ||
             sizeof(VM_TRACE_HEADER) +
                 static_cast<uint64_t>(header.traceCapacity) *
                     sizeof(VM_TRACE_EVENT) >
                 static_cast<uint64_t>(header.imageSize - header.traceRVA)))) {
        error = "metadata range validation failed";
        return false;
    }
    uint8_t masterKey[32]{};
    DecodeMasterKey(header, runtimeKeyShare.data(), masterKey);
    const uint64_t expected = ComputeMetadataTag(metadata, header.totalSize, masterKey);
    if (!vm_constant_time_equal64(expected, header.metadataTag)) {
        std::memset(masterKey, 0, sizeof(masterKey));
        error = "metadata authentication failed";
        return false;
    }
    const auto* records = reinterpret_cast<const VM_FUNCTION_RECORD*>(
        metadata + header.recordOffset);
    std::unordered_set<uint32_t> functionRVAs;
    for (uint32_t i = 0; i < header.recordCount; ++i) {
        const auto& record = records[i];
        if (!functionRVAs.insert(record.functionRVA).second ||
            record.functionRVA == 0 || record.functionSize < 5 ||
            record.bytecodeSize == 0 ||
            record.bytecodeOffset > header.bytecodeSize ||
            record.bytecodeSize > header.bytecodeSize - record.bytecodeOffset ||
            record.opcodeMapOffset != header.reverseOpcodeMapOffset ||
            record.registerMapOffset != header.registerMapOffset ||
            (record.flags & ~kKnownRecordFlags) != 0 ||
            record.guestStackSize < 0x4000u || record.guestStackSize > 0x70000u ||
            (record.guestStackSize & 0x0FFFu) != 0 ||
            ((header.architecture == VM_ARCH_X64) !=
                ((record.flags & VM_RECORD_FLAG_X64) != 0)) ||
            (header.architecture == VM_ARCH_X64 && record.returnStackCleanup != 0) ||
            record.returnStackCleanup > 0xFFFFu ||
            ((record.flags & VM_RECORD_FLAG_USES_AVX) != 0 &&
                (record.flags & VM_RECORD_FLAG_USES_SIMD) == 0) ||
            ((record.trampolineRVA == 0) != (record.trampolineSize == 0)) ||
            (header.runtimeBaseRVA != 0 &&
                (record.trampolineRVA == 0 || record.trampolineSize == 0))) {
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "metadata function record contract failed";
            return false;
        }
        uint8_t recordKey[32]{};
        vm_derive_record_key(masterKey, header.buildId, record.functionRVA, recordKey);
        const uint8_t* ciphertext = metadata + header.bytecodeOffset + record.bytecodeOffset;
        const uint64_t bytecodeTag = vm_siphash24(
            ciphertext, record.bytecodeSize, recordKey + 16);
        std::memset(recordKey, 0, sizeof(recordKey));
        if (!vm_constant_time_equal64(bytecodeTag, record.bytecodeTag)) {
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "metadata record bytecode authentication failed";
            return false;
        }
    }
    std::memset(masterKey, 0, sizeof(masterKey));
    std::array<uint8_t, VM_OPCODE_MAP_SIZE> opcodeSeen{};
    const uint8_t* reverse = metadata + header.reverseOpcodeMapOffset;
    for (uint32_t i = 0; i < VM_OPCODE_MAP_SIZE; ++i) {
        if (opcodeSeen[reverse[i]]) {
            error = "reverse opcode map is not a permutation";
            return false;
        }
        opcodeSeen[reverse[i]] = 1;
    }
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerSeen{};
    const uint8_t* registers = metadata + header.registerMapOffset;
    for (uint32_t i = 0; i < 16; ++i) {
        if (registers[i] >= VM_REGISTER_MAP_SIZE || registerSeen[registers[i]]) {
            error = "native register map is out of range or not injective";
            return false;
        }
        registerSeen[registers[i]] = 1;
    }
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> semanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> slotToSemantic{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> variants{};
    std::memcpy(semanticToSlot.data(), metadata + header.handlerSemanticMapOffset,
        semanticToSlot.size());
    std::memcpy(slotToSemantic.data(), metadata + header.handlerDescriptorOffset,
        slotToSemantic.size());
    std::memcpy(variants.data(), metadata + header.handlerVariantOffset, variants.size());
    if (!ValidateHandlerLayout(semanticToSlot, slotToSemantic, variants,
            header.junkHandlerCount, header.architecture == VM_ARCH_X64,
            error)) return false;
    if (((header.flags & VM_METADATA_FLAG_HANDLER_MUTATED) != 0) ==
            std::all_of(VMSchema::Opcodes().begin(), VMSchema::Opcodes().end(),
                [&](const VMOpcodeDescriptor& descriptor) {
                    const bool supported = header.architecture == VM_ARCH_X64
                        ? descriptor.runtimeSupportedX64
                        : descriptor.runtimeSupportedX86;
                    if (!supported) {
                        return semanticToSlot[descriptor.opcode] ==
                            VM_HANDLER_INVALID;
                    }
                    return semanticToSlot[descriptor.opcode] == descriptor.opcode;
                })) {
        error = "handler mutation flag does not match the emitted handler entry layout";
        return false;
    }
    if (((header.flags & VM_METADATA_FLAG_JUNK_HANDLERS) != 0) !=
            (header.junkHandlerCount != 0)) {
        error = "junk handler flag does not match the emitted handler table";
        return false;
    }
    return true;
}

bool VMSectionEmitter::PatchLinkage(
    CS_PE_IMAGE* image,
    uint32_t metadataRVA,
    uint32_t runtimeBaseRVA,
    uint32_t runtimeEntryRVA,
    uint32_t runtimeSize,
    const std::vector<VMTrampolineRecord>& trampolines,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    uint32_t verifiedFlags,
    std::string* error,
    uint32_t traceRVA,
    uint32_t traceCapacity,
    uint32_t traceGroup)
{
    PEEmitter emitter(image);
    if (!emitter.IsValid()) {
        if (error) *error = "invalid PE image";
        return false;
    }
    const uint32_t imageSize = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SizeOfImage
        : image->ntHeaders32->OptionalHeader.SizeOfImage;
    if (runtimeBaseRVA == 0 || runtimeEntryRVA < runtimeBaseRVA || runtimeSize == 0 ||
        runtimeBaseRVA >= imageSize || runtimeSize > imageSize - runtimeBaseRVA ||
        runtimeEntryRVA - runtimeBaseRVA >= runtimeSize) {
        if (error) *error = "runtime base/entry/size linkage is outside the final image";
        return false;
    }
    const uint32_t metadataOffset = emitter.RvaToOffset(metadataRVA);
    if (metadataOffset == 0 || metadataOffset + sizeof(VM_METADATA_HEADER) > image->rawSize) {
        if (error) *error = "metadata RVA is outside file data";
        return false;
    }
    const uint8_t* rawMetadata = image->rawData + metadataOffset;
    VM_METADATA_HEADER header{};
    std::memcpy(&header, rawMetadata, sizeof(header));
    if (header.totalSize > image->rawSize - metadataOffset || header.bytecodeOffset > header.totalSize) {
        if (error) *error = "metadata linkage range is invalid";
        return false;
    }
    std::string initialVerificationError;
    if (!VerifyMetadata(rawMetadata, header.totalSize,
            runtimeKeyShare, initialVerificationError)) {
        if (error) *error = "metadata is invalid before linkage patch: " + initialVerificationError;
        return false;
    }
    std::vector<uint8_t> updated(rawMetadata, rawMetadata + header.totalSize);
    auto* mutableHeader = reinterpret_cast<VM_METADATA_HEADER*>(updated.data());
    mutableHeader->runtimeBaseRVA = runtimeBaseRVA;
    mutableHeader->runtimeEntryRVA = runtimeEntryRVA;
    mutableHeader->runtimeSize = runtimeSize;
    mutableHeader->imageSize = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SizeOfImage
        : image->ntHeaders32->OptionalHeader.SizeOfImage;
    mutableHeader->flags |= verifiedFlags;
    if (traceRVA != 0 || traceCapacity != 0 || traceGroup != 0) {
        if (traceRVA == 0 || traceCapacity == 0 ||
            traceCapacity > VM_TRACE_MAX_CAPACITY || traceGroup >= 64u ||
            traceRVA >= mutableHeader->imageSize ||
            sizeof(VM_TRACE_HEADER) +
                static_cast<uint64_t>(traceCapacity) * sizeof(VM_TRACE_EVENT) >
                static_cast<uint64_t>(mutableHeader->imageSize - traceRVA)) {
            if (error) *error = "trace linkage is outside the final image";
            return false;
        }
        const uint64_t traceBytes = sizeof(VM_TRACE_HEADER) +
            static_cast<uint64_t>(traceCapacity) * sizeof(VM_TRACE_EVENT);
        const IMAGE_SECTION_HEADER* traceSection = nullptr;
        for (uint16_t index = 0; index < image->numSections; ++index) {
            const auto& candidate = image->sections[index];
            if (candidate.VirtualAddress == traceRVA) {
                if (traceSection != nullptr) {
                    if (error) *error = "trace RVA aliases multiple sections";
                    return false;
                }
                traceSection = &candidate;
            }
        }
        constexpr uint32_t forbiddenTraceCharacteristics =
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_DISCARDABLE;
        if (traceSection == nullptr ||
            traceSection->Misc.VirtualSize != traceBytes ||
            traceSection->SizeOfRawData < traceBytes ||
            traceSection->PointerToRawData == 0 ||
            traceSection->PointerToRawData > image->rawSize ||
            traceBytes > image->rawSize - traceSection->PointerToRawData ||
            (traceSection->Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
            (traceSection->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
            (traceSection->Characteristics & forbiddenTraceCharacteristics) != 0) {
            if (error) *error =
                "trace storage is not one independent file-backed RW/NX section";
            return false;
        }
        const uint32_t traceOffset = emitter.RvaToOffset(traceRVA);
        if (traceOffset != traceSection->PointerToRawData ||
            image->rawSize < sizeof(VM_TRACE_HEADER) ||
            traceOffset > image->rawSize - sizeof(VM_TRACE_HEADER)) {
            if (error) *error = "trace header RVA/raw mapping is invalid";
            return false;
        }
        VM_TRACE_HEADER trace{};
        std::memcpy(&trace, image->rawData + traceOffset, sizeof(trace));
        if (trace.magic != VM_TRACE_MAGIC ||
            trace.version != VM_TRACE_VERSION ||
            trace.headerSize != sizeof(VM_TRACE_HEADER) ||
            trace.eventSize != sizeof(VM_TRACE_EVENT) ||
            trace.capacity != traceCapacity || trace.nextSequence != 0 ||
            trace.committedCount != 0 || trace.overflow != 0 ||
            trace.architecture != mutableHeader->architecture ||
            trace.groupId != traceGroup || trace.reserved[0] != 0 ||
            trace.reserved[1] != 0 ||
            std::memcmp(trace.buildId, mutableHeader->buildId,
                sizeof(trace.buildId)) != 0) {
            if (error) *error = "trace header does not match authenticated metadata";
            return false;
        }
        mutableHeader->traceRVA = traceRVA;
        mutableHeader->traceCapacity = traceCapacity;
        mutableHeader->traceGroup = traceGroup;
        mutableHeader->flags |= VM_METADATA_FLAG_RUNTIME_TRACE;
    } else {
        mutableHeader->traceRVA = 0;
        mutableHeader->traceCapacity = 0;
        mutableHeader->traceGroup = 0;
        mutableHeader->flags &= ~VM_METADATA_FLAG_RUNTIME_TRACE;
    }

    std::unordered_map<uint32_t, VMTrampolineRecord> byFunction;
    for (const auto& trampoline : trampolines) byFunction[trampoline.functionRVA] = trampoline;
    auto* records = reinterpret_cast<VM_FUNCTION_RECORD*>(updated.data() + mutableHeader->recordOffset);
    for (uint32_t i = 0; i < mutableHeader->recordCount; ++i) {
        auto found = byFunction.find(records[i].functionRVA);
        if (!trampolines.empty() && found == byFunction.end()) {
            if (error) *error = "metadata record has no matching trampoline";
            return false;
        }
        if (found != byFunction.end()) {
            records[i].trampolineRVA = found->second.trampolineRVA;
            records[i].trampolineSize = found->second.trampolineSize;
        }
        if (verifiedFlags & VM_METADATA_FLAG_NATIVE_BODY_DESTROYED)
            records[i].flags |= VM_RECORD_FLAG_NATIVE_BODY_DESTROYED;
        if (verifiedFlags & VM_METADATA_FLAG_UNWIND_VERIFIED)
            records[i].flags |= VM_RECORD_FLAG_UNWIND_VERIFIED;
        if (verifiedFlags & VM_METADATA_FLAG_CFG_VERIFIED)
            records[i].flags |= VM_RECORD_FLAG_CFG_VERIFIED;
    }

    uint8_t masterKey[32]{};
    DecodeMasterKey(*mutableHeader, runtimeKeyShare.data(), masterKey);
    mutableHeader->metadataTag = 0;
    mutableHeader->metadataTag = ComputeMetadataTag(updated.data(), updated.size(), masterKey);
    std::memset(masterKey, 0, sizeof(masterKey));
    if (!emitter.PatchBytes(metadataRVA, updated, error)) return false;

    std::string verificationError;
    if (!VerifyMetadata(image->rawData + metadataOffset, header.totalSize,
            runtimeKeyShare, verificationError)) {
        if (error) *error = verificationError;
        return false;
    }
    return true;
}

} // namespace CipherShell
