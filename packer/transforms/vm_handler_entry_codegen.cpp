#include "vm_handler_entry_codegen.h"

#include "../vm/vm_schema.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <set>

namespace CipherShell {
namespace {

constexpr uint16_t kRelocationHighLow = 3;
constexpr uint16_t kRelocationDir64 = 10;
constexpr uint32_t kPageSize = 0x1000u;
constexpr uint32_t kPageReadWrite = 0x04u;
constexpr uint32_t kPageExecuteRead = 0x20u;
constexpr uint32_t kRequiredMetadataFlags =
    VM_METADATA_FLAG_AUTHENTICATED |
    VM_METADATA_FLAG_BYTECODE_CHACHA20 |
    VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
    VM_METADATA_FLAG_CFG_VERIFIED |
    VM_METADATA_FLAG_MICRO_STREAM |
    VM_METADATA_FLAG_LAZY_FLAGS |
    VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
    VM_METADATA_FLAG_DIRECT_THREADED |
    VM_METADATA_FLAG_HANDLER_ENCRYPTED;
constexpr uint32_t kKnownMetadataFlags = kRequiredMetadataFlags |
    VM_METADATA_FLAG_UNWIND_VERIFIED |
    VM_METADATA_FLAG_CFG_ENABLED |
    VM_METADATA_FLAG_HANDLER_MUTATED |
    VM_METADATA_FLAG_JUNK_HANDLERS;
constexpr uint32_t kKnownRecordFlags =
    VM_RECORD_FLAG_X64 |
    VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
    VM_RECORD_FLAG_UNWIND_VERIFIED |
    VM_RECORD_FLAG_CFG_VERIFIED |
    VM_RECORD_FLAG_USES_SIMD |
    VM_RECORD_FLAG_USES_AVX |
    VM_RECORD_FLAG_USES_X87;

constexpr uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    return alignment == 0 ? value :
        (value + alignment - 1u) & ~(alignment - 1u);
}

constexpr uint32_t kRuntimeKeyOffset =
    AlignUp(static_cast<uint32_t>(sizeof(VM_MICRO_EXECUTION_CONTEXT)), 16u);
constexpr uint32_t kRuntimeScratchSize = kRuntimeKeyOffset + 64u;

#pragma pack(push, 1)
struct RuntimeFunctionDecodeTable {
    uint32_t functionRVA;
    VM_OPERAND_CODEC codec;
    VM_RUNTIME_DECODE_PLAN plans[VM_UOP_COUNT];
};
#pragma pack(pop)

static_assert(sizeof(RuntimeFunctionDecodeTable) ==
    sizeof(uint32_t) + sizeof(VM_OPERAND_CODEC) +
        sizeof(VM_RUNTIME_DECODE_PLAN) * VM_UOP_COUNT,
    "runtime decode table layout mismatch");

constexpr uint32_t CtxValues =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, values));
constexpr uint32_t CtxVregs =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vregs));
constexpr uint32_t CtxTemps =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, temps));
constexpr uint32_t CtxCallStack =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, callStack));
constexpr uint32_t CtxValueDepth =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, valueDepth));
constexpr uint32_t CtxCallDepth =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, callDepth));
constexpr uint32_t CtxVip =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vip));
constexpr uint32_t CtxBytecodeBegin =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, bytecodeBegin));
constexpr uint32_t CtxBytecodeEnd =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, bytecodeEnd));
constexpr uint32_t CtxDispatchTable =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, dispatchTable));
constexpr uint32_t CtxReverseOpcodeMap =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, reverseOpcodeMap));
constexpr uint32_t CtxRegisterMap =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, registerMap));
constexpr uint32_t CtxSemanticToSlot =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, handlerSemanticToSlot));
constexpr uint32_t CtxDecodePlans =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, decodePlans));
constexpr uint32_t CtxDecodeOperands =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, decodeOperands));
constexpr uint32_t CtxFlagMaterializer =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, flagMaterializer));
constexpr uint32_t CtxImageBase =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, imageBase));
constexpr uint32_t CtxMetadata =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, metadata));
constexpr uint32_t CtxRecord =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, record));
constexpr uint32_t CtxNativeFrame =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, nativeFrame));
constexpr uint32_t CtxExtendedState =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, extendedState));
constexpr uint32_t CtxVirtualProtect =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, virtualProtect));
constexpr uint32_t CtxFlushInstructionCache =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, flushInstructionCache));
constexpr uint32_t CtxRollingKey =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, rollingKey));
constexpr uint32_t CtxOperandCodec =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, operandCodec));
constexpr uint32_t CtxDecodedOperands =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, decodedOperands));
constexpr uint32_t CtxDecodedOperandCount =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, decodedOperandCount));
constexpr uint32_t CtxCurrentSemantic =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, currentSemantic));
constexpr uint32_t CtxCurrentVariant =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, currentVariant));
constexpr uint32_t CtxVirtualFlags =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, virtualFlags));
constexpr uint32_t CtxPendingFlags =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, pendingFlags));
constexpr uint32_t CtxArchitecture =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, architecture));
constexpr uint32_t CtxReturnStackCleanup =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, returnStackCleanup));
constexpr uint32_t CtxError =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, error));
constexpr uint32_t CtxHalted =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, halted));

constexpr uint32_t MetaCookie =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, cookie));
constexpr uint32_t MetaHeaderSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, headerSize));
constexpr uint32_t MetaTotalSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, totalSize));
constexpr uint32_t MetaMetadataVersion =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, metadataVersion));
constexpr uint32_t MetaSchemaVersion =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, schemaVersion));
constexpr uint32_t MetaRuntimeVersion =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, runtimeVersion));
constexpr uint32_t MetaArchitecture =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, architecture));
constexpr uint32_t MetaFlags =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, flags));
constexpr uint32_t MetaRecordCount =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, recordCount));
constexpr uint32_t MetaRecordSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, recordSize));
constexpr uint32_t MetaRecordOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, recordOffset));
constexpr uint32_t MetaReverseOpcodeMapOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, reverseOpcodeMapOffset));
constexpr uint32_t MetaRegisterMapOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, registerMapOffset));
constexpr uint32_t MetaBytecodeOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, bytecodeOffset));
constexpr uint32_t MetaBytecodeSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, bytecodeSize));
constexpr uint32_t MetaRuntimeEntryRVA =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, runtimeEntryRVA));
constexpr uint32_t MetaRuntimeSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, runtimeSize));
constexpr uint32_t MetaImageSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, imageSize));
constexpr uint32_t MetaOperandCodecSeed =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, operandCodecSeed));
constexpr uint32_t MetaKeyEncodingVersion =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, keyEncodingVersion));
constexpr uint32_t MetaOpcodeMapSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, opcodeMapSize));
constexpr uint32_t MetaRegisterMapSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, registerMapSize));
constexpr uint32_t MetaSemanticMapOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, handlerSemanticMapOffset));
constexpr uint32_t MetaHandlerDescriptorOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, handlerDescriptorOffset));
constexpr uint32_t MetaHandlerVariantOffset =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, handlerVariantOffset));
constexpr uint32_t MetaHandlerTableSize =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, handlerTableSize));
constexpr uint32_t MetaHandlerVariantCount =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, handlerVariantCount));
constexpr uint32_t MetaBuildId =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, buildId));
constexpr uint32_t MetaEncodedMasterKey =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, encodedMasterKey));
constexpr uint32_t MetaMetadataTag =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, metadataTag));
constexpr uint32_t MetaRuntimeBaseRVA =
    static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, runtimeBaseRVA));

constexpr uint32_t RecordFunctionRVA =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, functionRVA));
constexpr uint32_t RecordFunctionSize =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, functionSize));
constexpr uint32_t RecordBytecodeOffset =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, bytecodeOffset));
constexpr uint32_t RecordBytecodeSize =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, bytecodeSize));
constexpr uint32_t RecordTrampolineRVA =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, trampolineRVA));
constexpr uint32_t RecordTrampolineSize =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, trampolineSize));
constexpr uint32_t RecordFlags =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, flags));
constexpr uint32_t RecordReturnStackCleanup =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, returnStackCleanup));
constexpr uint32_t RecordOpcodeMapOffset =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, opcodeMapOffset));
constexpr uint32_t RecordRegisterMapOffset =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, registerMapOffset));
constexpr uint32_t RecordNonce =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, nonce));
constexpr uint32_t RecordBytecodeTag =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, bytecodeTag));
constexpr uint32_t RecordGuestStackSize =
    static_cast<uint32_t>(offsetof(VM_FUNCTION_RECORD, guestStackSize));

class SeedStream {
public:
    SeedStream(const std::array<uint8_t, 32>& seed, uint64_t domain) {
        m_s0 = 0xA0761D6478BD642FULL ^ domain;
        m_s1 = 0xE7037ED1A0B428DBULL ^ (domain << 1u);
        for (size_t i = 0; i < seed.size(); ++i) {
            m_s0 ^= static_cast<uint64_t>(seed[i]) << ((i & 7u) * 8u);
            m_s0 *= 0x9E3779B185EBCA87ULL;
            m_s1 ^= (m_s0 >> 23u) + seed[i] + i;
            m_s1 *= 0xD6E8FEB86659FD93ULL;
        }
        if ((m_s0 | m_s1) == 0) m_s1 = 1;
        for (unsigned i = 0; i < 16; ++i) Next64();
    }

    uint64_t Next64() {
        uint64_t s1 = m_s0;
        const uint64_t s0 = m_s1;
        m_s0 = s0;
        s1 ^= s1 << 23u;
        m_s1 = s1 ^ s0 ^ (s1 >> 17u) ^ (s0 >> 26u);
        return m_s1 + s0;
    }

    uint32_t Next32() { return static_cast<uint32_t>(Next64()); }
    uint8_t Next8() { return static_cast<uint8_t>(Next64()); }

private:
    uint64_t m_s0 = 0;
    uint64_t m_s1 = 0;
};

class CodeBuffer {
public:
    explicit CodeBuffer(uint32_t imageOffset) : m_imageOffset(imageOffset) {}

    std::vector<uint8_t> bytes;

    size_t Offset() const { return bytes.size(); }
    uint32_t ImageOffset() const { return m_imageOffset; }
    uint32_t CurrentImageOffset() const {
        return m_imageOffset + static_cast<uint32_t>(bytes.size());
    }
    void U8(uint8_t value) { bytes.push_back(value); }
    void U16(uint16_t value) {
        U8(static_cast<uint8_t>(value));
        U8(static_cast<uint8_t>(value >> 8u));
    }
    void U32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void U64(uint64_t value) {
        for (unsigned i = 0; i < 8; ++i)
            U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void Raw(std::initializer_list<uint8_t> values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    void Patch32(size_t offset, uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8u));
    }

    size_t NewLabel() {
        m_labels.push_back((std::numeric_limits<size_t>::max)());
        return m_labels.size() - 1u;
    }
    void Bind(size_t label) { m_labels[label] = Offset(); }
    void Jmp32(size_t label) {
        U8(0xE9);
        m_fixups.push_back({Offset(), label});
        U32(0);
    }
    void Jcc32(uint8_t conditionOpcode, size_t label) {
        Raw({0x0F, conditionOpcode});
        m_fixups.push_back({Offset(), label});
        U32(0);
    }
    void CallLabel(size_t label) {
        U8(0xE8);
        m_fixups.push_back({Offset(), label});
        U32(0);
    }
    bool Rel32(uint32_t targetImageOffset, std::string& error) {
        const int64_t relative = static_cast<int64_t>(targetImageOffset) -
            static_cast<int64_t>(CurrentImageOffset() + 4u);
        if (relative < (std::numeric_limits<int32_t>::min)() ||
            relative > (std::numeric_limits<int32_t>::max)()) {
            error = "entry code relative target is outside rel32 range";
            U32(0);
            return false;
        }
        U32(static_cast<uint32_t>(static_cast<int32_t>(relative)));
        return true;
    }
    bool Call(uint32_t targetImageOffset, std::string& error) {
        U8(0xE8);
        return Rel32(targetImageOffset, error);
    }
    bool RipDisp32(
        uint32_t targetImageOffset,
        std::string& error,
        uint32_t trailingInstructionBytes = 0)
    {
        const int64_t relative = static_cast<int64_t>(targetImageOffset) -
            static_cast<int64_t>(CurrentImageOffset() + 4u +
                trailingInstructionBytes);
        if (relative < (std::numeric_limits<int32_t>::min)() ||
            relative > (std::numeric_limits<int32_t>::max)()) {
            error = "entry code RIP-relative target is outside disp32 range";
            U32(0);
            return false;
        }
        U32(static_cast<uint32_t>(static_cast<int32_t>(relative)));
        return true;
    }
    bool Resolve(std::string& error) {
        for (const auto& fixup : m_fixups) {
            if (fixup.label >= m_labels.size() ||
                m_labels[fixup.label] == (std::numeric_limits<size_t>::max)()) {
                error = "entry code contains an unbound branch label";
                return false;
            }
            const int64_t relative = static_cast<int64_t>(m_labels[fixup.label]) -
                static_cast<int64_t>(fixup.offset + 4u);
            if (relative < (std::numeric_limits<int32_t>::min)() ||
                relative > (std::numeric_limits<int32_t>::max)()) {
                error = "entry code local branch is outside rel32 range";
                return false;
            }
            Patch32(fixup.offset,
                static_cast<uint32_t>(static_cast<int32_t>(relative)));
        }
        return true;
    }

private:
    struct Fixup { size_t offset; size_t label; };
    uint32_t m_imageOffset;
    std::vector<size_t> m_labels;
    std::vector<Fixup> m_fixups;
};

void EmitCet(CodeBuffer& code, bool x64, bool enabled) {
    if (!enabled) return;
    code.Raw(x64 ? std::initializer_list<uint8_t>{0xF3,0x0F,0x1E,0xFA}
                 : std::initializer_list<uint8_t>{0xF3,0x0F,0x1E,0xFB});
}

void EmitSeedIsland(CodeBuffer& code, SeedStream& random, uint32_t minimum) {
    const uint32_t size = minimum + (random.Next32() & 31u);
    code.U8(0xE9);
    code.U32(size);
    for (uint32_t i = 0; i < size; ++i) code.U8(random.Next8());
}

std::vector<uint8_t> BuildUnwindInfo(
    uint8_t prologSize,
    uint32_t stackAllocation,
    const std::vector<std::pair<uint8_t, uint8_t>>& pushes)
{
    struct Slot { uint8_t offset; uint8_t op; uint16_t extra; bool hasExtra; };
    std::vector<Slot> slots;
    if (stackAllocation != 0) {
        slots.push_back({prologSize, 0x01,
            static_cast<uint16_t>(stackAllocation / 8u), true});
    }
    for (auto it = pushes.rbegin(); it != pushes.rend(); ++it) {
        slots.push_back({it->first,
            static_cast<uint8_t>((it->second << 4u) | 0x00u), 0, false});
    }
    uint32_t codeCount = 0;
    for (const auto& slot : slots) codeCount += slot.hasExtra ? 2u : 1u;
    std::vector<uint8_t> output;
    output.reserve(4u + codeCount * 2u + 2u);
    output.push_back(0x01);
    output.push_back(prologSize);
    output.push_back(static_cast<uint8_t>(codeCount));
    output.push_back(0x00);
    for (const auto& slot : slots) {
        output.push_back(slot.offset);
        output.push_back(slot.op);
        if (slot.hasExtra) {
            output.push_back(static_cast<uint8_t>(slot.extra));
            output.push_back(static_cast<uint8_t>(slot.extra >> 8u));
        }
    }
    while ((output.size() & 3u) != 0) output.push_back(0);
    return output;
}

void AddX64Unwind(
    std::vector<VMHandlerEntryUnwindRecord>& records,
    uint32_t begin,
    uint32_t end,
    uint8_t prologSize,
    uint32_t stackAllocation,
    const std::vector<std::pair<uint8_t, uint8_t>>& pushes)
{
    VMHandlerEntryUnwindRecord record{};
    record.beginOffset = begin;
    record.endOffset = end;
    record.unwindInfo = BuildUnwindInfo(
        prologSize, stackAllocation, pushes);
    records.push_back(std::move(record));
}

bool RangeEnd(uint32_t offset, uint32_t size, uint32_t& end) {
    if (size > (std::numeric_limits<uint32_t>::max)() - offset) return false;
    end = offset + size;
    return true;
}

bool ConfigValid(const VMHandlerEntryCodegenConfig& config, std::string& error) {
    if (config.architecture != VM_ARCH_X86 && config.architecture != VM_ARCH_X64) {
        error = "entry codegen architecture is invalid";
        return false;
    }
    if (std::all_of(config.buildSeed.begin(), config.buildSeed.end(),
            [](uint8_t byte) { return byte == 0; })) {
        error = "entry codegen build seed is all zero";
        return false;
    }
    if (config.variantCount == 0 || config.variantCount > VM_MICRO_MAX_HANDLER_VARIANTS ||
        (config.variantCount & (config.variantCount - 1u)) != 0) {
        error = "entry codegen variant count must be a power of two in [1,16]";
        return false;
    }
    if ((config.cipher.multiplier & 1u) == 0 || config.cipher.rotate == 0 ||
        config.cipher.rotate > 7 || config.cipher.addByte == 0 ||
        config.cipher.shiftLeftA == 0 || config.cipher.shiftLeftA >= 32 ||
        config.cipher.shiftRightB == 0 || config.cipher.shiftRightB >= 32 ||
        config.cipher.shiftLeftC == 0 || config.cipher.shiftLeftC >= 32) {
        error = "entry codegen handler cipher contract is invalid";
        return false;
    }
    if (config.virtualProtectIatRVA == 0 ||
        config.flushInstructionCacheIatRVA == 0) {
        error = "entry codegen requires VirtualProtect and FlushInstructionCache IAT RVAs";
        return false;
    }
    if (config.functionPlanCount == 0) {
        error = "entry codegen has no per-function runtime decode plan";
        return false;
    }
    const uint64_t expectedPlanBytes =
        static_cast<uint64_t>(config.functionPlanCount) *
        sizeof(RuntimeFunctionDecodeTable);
    if (expectedPlanBytes != config.layout.decodePlanTableSize) {
        error = "entry codegen decode-plan table size does not match function count";
        return false;
    }
    if (config.layout.encryptedHandlerSize == 0 ||
        (config.layout.encryptedHandlerOffset & (kPageSize - 1u)) != 0) {
        error = "entry codegen encrypted handler range is empty or not page aligned";
        return false;
    }
    if ((config.layout.decryptionStateOffset & (kPageSize - 1u)) != 0) {
        error = "entry decryption state must begin on a non-executable data page";
        return false;
    }
    uint32_t handlerEnd = 0;
    if (!RangeEnd(config.layout.encryptedHandlerOffset,
            config.layout.encryptedHandlerSize, handlerEnd)) {
        error = "entry codegen encrypted handler range overflows uint32";
        return false;
    }
    const uint32_t decryptorPage = config.layout.decryptorOffset & ~(kPageSize - 1u);
    const uint32_t handlerFirstPage =
        config.layout.encryptedHandlerOffset & ~(kPageSize - 1u);
    const uint32_t handlerLastPage = (handlerEnd - 1u) & ~(kPageSize - 1u);
    if (decryptorPage >= handlerFirstPage && decryptorPage <= handlerLastPage) {
        error = "entry decryptor must not share a page with encrypted handlers";
        return false;
    }
    const std::array<uint32_t, 10> codeOffsets = {
        config.layout.publicEntryOffset,
        config.layout.validationEntryOffset,
        config.layout.decryptorOffset,
        config.layout.operandDecoderOffset,
        config.layout.flagMaterializerOffset,
        config.layout.decryptionStateOffset,
        config.layout.keyMarkerOffset,
        config.layout.decodePlanTableOffset,
        config.layout.dispatchTableOffset,
        config.layout.encryptedHandlerOffset
    };
    std::set<uint32_t> unique(codeOffsets.begin(), codeOffsets.end());
    if (unique.size() != codeOffsets.size()) {
        error = "entry codegen layout aliases code, key, plan, or dispatch offsets";
        return false;
    }
    return true;
}

/* Forward declarations for the independently placed generated routines. */
bool BuildPublicEntry(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result);
bool BuildValidationEntry(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result);
bool BuildDecryptor(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result);
bool BuildOperandDecoder(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result);
bool BuildFlagMaterializer(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result);

} // namespace

VMHandlerEntryCodegenResult VMHandlerEntryCodegen::Generate(
    const VMHandlerEntryCodegenConfig& config) const
{
    VMHandlerEntryCodegenResult result{};
    if (!ConfigValid(config, result.error)) return result;
    result.preferredBase = 0;
    if (!BuildPublicEntry(config, result) ||
        !BuildValidationEntry(config, result) ||
        !BuildDecryptor(config, result) ||
        !BuildOperandDecoder(config, result) ||
        !BuildFlagMaterializer(config, result)) {
        result.publicEntryReady = false;
        result.validationEntryReady = false;
        return result;
    }
    std::string validationError;
    result.publicEntryReady = true;
    result.validationEntryReady = true;
    result.success = true;
    if (!Validate(config, result, validationError)) {
        result.success = false;
        result.publicEntryReady = false;
        result.validationEntryReady = false;
        result.error = validationError;
    }
    return result;
}

bool VMHandlerEntryCodegen::Validate(
    const VMHandlerEntryCodegenConfig& config,
    const VMHandlerEntryCodegenResult& result,
    std::string& error)
{
    if (!ConfigValid(config, error)) return false;
    if (!result.success || !result.publicEntryReady ||
        !result.validationEntryReady || result.preferredBase != 0) {
        error = "entry codegen result is not marked as a preferred-base-zero ready image";
        return false;
    }
    if (result.entryCode.empty() || result.validationEntryCode.empty() ||
        result.decryptorCode.empty() || result.operandDecoderCode.empty() ||
        result.flagMaterializerCode.empty()) {
        error = "entry codegen omitted a required runtime routine";
        return false;
    }
    if (result.decryptorLoopOffset > result.decryptorCode.size() ||
        result.decryptorLoopSize == 0 ||
        result.decryptorLoopSize >
            result.decryptorCode.size() - result.decryptorLoopOffset) {
        error = "entry decryptor active-loop range is missing or invalid";
        return false;
    }
    if (config.architecture == VM_ARCH_X64 && result.unwindRecords.size() < 5) {
        error = "x64 entry codegen omitted unwind coverage for generated routines";
        return false;
    }
    if (config.architecture == VM_ARCH_X86 && !result.unwindRecords.empty()) {
        error = "x86 entry codegen unexpectedly emitted x64 unwind records";
        return false;
    }
    struct Segment { uint32_t offset; uint32_t size; const char* name; };
    const uint32_t pointerSize = config.architecture == VM_ARCH_X64 ? 8u : 4u;
    const uint64_t dispatchBytes64 = static_cast<uint64_t>(VM_HANDLER_TABLE_SIZE) *
        config.variantCount * pointerSize;
    if (dispatchBytes64 > (std::numeric_limits<uint32_t>::max)()) {
        error = "entry dispatch table size overflows uint32";
        return false;
    }
    std::vector<Segment> segments = {
        {config.layout.publicEntryOffset,
            static_cast<uint32_t>(result.entryCode.size()), "public entry"},
        {config.layout.validationEntryOffset,
            static_cast<uint32_t>(result.validationEntryCode.size()), "validation entry"},
        {config.layout.decryptorOffset,
            static_cast<uint32_t>(result.decryptorCode.size()), "decryptor"},
        {config.layout.operandDecoderOffset,
            static_cast<uint32_t>(result.operandDecoderCode.size()), "operand decoder"},
        {config.layout.flagMaterializerOffset,
            static_cast<uint32_t>(result.flagMaterializerCode.size()), "flag materializer"},
        {config.layout.decryptionStateOffset, 1u, "decryption state"},
        {config.layout.keyMarkerOffset, VM_RUNTIME_KEY_SHARE_SIZE, "runtime key share"},
        {config.layout.decodePlanTableOffset,
            config.layout.decodePlanTableSize, "decode plan table"},
        {config.layout.dispatchTableOffset,
            static_cast<uint32_t>(dispatchBytes64), "dispatch table"},
        {config.layout.encryptedHandlerOffset,
            config.layout.encryptedHandlerSize, "encrypted handlers"}
    };
    std::sort(segments.begin(), segments.end(),
        [](const Segment& lhs, const Segment& rhs) { return lhs.offset < rhs.offset; });
    for (size_t i = 0; i < segments.size(); ++i) {
        uint32_t end = 0;
        if (segments[i].size == 0 || !RangeEnd(segments[i].offset,segments[i].size,end)) {
            error = std::string("entry layout has an invalid segment: ") + segments[i].name;
            return false;
        }
        if (i + 1u < segments.size() && end > segments[i + 1u].offset) {
            error = std::string("entry layout overlaps ") + segments[i].name +
                " with " + segments[i + 1u].name;
            return false;
        }
    }
    const uint16_t relocationType = config.architecture == VM_ARCH_X64
        ? kRelocationDir64 : kRelocationHighLow;
    for (const auto& relocation : result.relocations) {
        if (relocation.type != relocationType) {
            error = "entry codegen emitted an architecture-incompatible relocation";
            return false;
        }
    }
    for (const auto& unwind : result.unwindRecords) {
        if (unwind.beginOffset >= unwind.endOffset || unwind.unwindInfo.size() < 4u ||
            (unwind.unwindInfo.size() & 3u) != 0 ||
            (unwind.unwindInfo[0] & 7u) != 1u) {
            error = "entry codegen emitted malformed x64 unwind metadata";
            return false;
        }
    }
    return true;
}

namespace {

bool BuildDecryptor(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    CodeBuffer code(config.layout.decryptorOffset);
    SeedStream random(config.buildSeed, 0x454E545259444543ULL);
    EmitCet(code, x64, config.emitCetLandingPads);
    const uint32_t functionBegin = code.ImageOffset();

    if (x64) {
        std::vector<std::pair<uint8_t, uint8_t>> pushes;
        const auto push = [&](uint8_t opcode, uint8_t unwindReg) {
            code.U8(opcode);
            pushes.push_back({static_cast<uint8_t>(code.Offset()), unwindReg});
        };
        push(0x53, 3);                         // rbx
        push(0x56, 6);                         // rsi
        push(0x57, 7);                         // rdi
        code.Raw({0x41,0x54}); pushes.push_back({static_cast<uint8_t>(code.Offset()), static_cast<uint8_t>(12)});
        code.Raw({0x41,0x55}); pushes.push_back({static_cast<uint8_t>(code.Offset()), static_cast<uint8_t>(13)});
        code.Raw({0x41,0x56}); pushes.push_back({static_cast<uint8_t>(code.Offset()), static_cast<uint8_t>(14)});
        code.Raw({0x41,0x57}); pushes.push_back({static_cast<uint8_t>(code.Offset()), static_cast<uint8_t>(15)});
        // Entry RSP is 8 mod 16. Seven nonvolatile pushes make it aligned;
        // keep the outgoing call frame a multiple of 16.
        constexpr uint32_t stackSize = 0x40u;
        code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stackSize)});
        const uint8_t prologSize = static_cast<uint8_t>(code.Offset());
        code.Raw({0x49,0x89,0xCF});             // r15 = context

        const size_t retry = code.NewLabel();
        const size_t owner = code.NewLabel();
        const size_t wait = code.NewLabel();
        const size_t ready = code.NewLabel();
        const size_t fail = code.NewLabel();
        const size_t failOwned = code.NewLabel();
        const size_t loop = code.NewLabel();
        const size_t restoreFail = code.NewLabel();
        const size_t restoreAttemptDone = code.NewLabel();
        const size_t epilog = code.NewLabel();

        code.Bind(retry);
        code.Raw({0x31,0xC0,0xB2,0x01,0xF0,0x0F,0xB0,0x15});
        if (!code.RipDisp32(config.layout.decryptionStateOffset,
                result.error)) return false;
        code.Jcc32(0x84, owner);                // je owner (old state zero)
        code.Raw({0x3C,0x02});
        code.Jcc32(0x84, ready);
        code.Raw({0x84,0xC0});
        code.Jcc32(0x84, retry);
        code.Raw({0x3C,0x01});
        code.Jcc32(0x85, fail);
        code.U8(0xBF); code.U32(0x00100000u);
        code.Bind(wait);
        code.Raw({0xF3,0x90,0x0F,0xB6,0x05});
        if (!code.RipDisp32(config.layout.decryptionStateOffset,
                result.error)) return false;
        code.Raw({0x3C,0x02});
        code.Jcc32(0x84, ready);
        code.Raw({0x84,0xC0});
        code.Jcc32(0x84, retry);
        code.Raw({0x3C,0x01});
        code.Jcc32(0x85, fail);
        code.Raw({0xFF,0xCF});
        code.Jcc32(0x84, fail);
        code.Jmp32(wait);

        code.Bind(owner);
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x48,0x85,0xC0});
        code.Jcc32(0x84, failOwned);
        code.Raw({0x48,0x8D,0x35});
        if (!code.RipDisp32(config.layout.encryptedHandlerOffset, result.error)) return false;
        code.Raw({0x48,0x89,0xF1,0xBA}); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x41,0xB8}); code.U32(kPageReadWrite);
        code.Raw({0x4C,0x8D,0x4C,0x24,0x30,0xFF,0xD0,0x85,0xC0});
        code.Jcc32(0x84, failOwned);

        code.Raw({0x49,0xBC}); code.U64(config.cipher.initialState); // r12 state
        code.Raw({0x49,0xBD}); code.U64(config.cipher.multiplier);
        code.Raw({0x49,0xBE}); code.U64(config.cipher.addend);
        code.U8(0xBF); code.U32(config.layout.encryptedHandlerSize);
        code.Bind(loop);
        result.decryptorLoopOffset = static_cast<uint32_t>(code.Offset());
        code.Raw({0x4C,0x89,0xE0,0x48,0xC1,0xE0});
        code.U8(config.cipher.shiftLeftA);
        code.Raw({0x49,0x31,0xC4,0x4C,0x89,0xE0,0x48,0xC1,0xE8});
        code.U8(config.cipher.shiftRightB);
        code.Raw({0x49,0x31,0xC4,0x4C,0x89,0xE0,0x48,0xC1,0xE0});
        code.U8(config.cipher.shiftLeftC);
        code.Raw({0x49,0x31,0xC4,0x4D,0x0F,0xAF,0xE5,0x4D,0x01,0xF4,
                  0x8A,0x06});
        if ((config.cipher.instructionVariant & 1u) != 0) {
            code.Raw({0xC0,0xC8}); code.U8(config.cipher.rotate);
        } else {
            code.Raw({0xC0,0xC0});
            code.U8(static_cast<uint8_t>(8u - config.cipher.rotate));
        }
        if ((config.cipher.instructionVariant & 2u) != 0) {
            code.U8(0x2C); code.U8(config.cipher.addByte);
        } else {
            code.U8(0x04);
            code.U8(static_cast<uint8_t>(0u - config.cipher.addByte));
        }
        if ((config.cipher.instructionVariant & 4u) != 0) {
            code.Raw({0x44,0x30,0xE0});
        } else {
            code.Raw({0x44,0x89,0xE2,0x30,0xD0});
        }
        code.Raw({0x88,0x06});
        switch ((config.cipher.instructionVariant >> 3u) % 3u) {
            case 0: code.Raw({0x48,0xFF,0xC6}); break;
            case 1: code.Raw({0x48,0x83,0xC6,0x01}); break;
            default: code.Raw({0x48,0x8D,0x76,0x01}); break;
        }
        if ((config.cipher.instructionVariant & 0x20u) != 0)
            code.Raw({0xFF,0xCF});
        else
            code.Raw({0x83,0xEF,0x01});
        code.Jcc32(0x85, loop);
        result.decryptorLoopSize = static_cast<uint32_t>(code.Offset()) -
            result.decryptorLoopOffset;

        code.Raw({0x49,0x8B,0x87}); code.U32(CtxFlushInstructionCache);
        code.Raw({0x48,0x85,0xC0});
        code.Jcc32(0x84, restoreFail);
        code.Raw({0x48,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF,
                  0x48,0x8D,0x15});
        if (!code.RipDisp32(config.layout.encryptedHandlerOffset, result.error)) return false;
        code.Raw({0x41,0xB8}); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0xFF,0xD0,0x85,0xC0});
        code.Jcc32(0x84, restoreFail);

        code.Raw({0x49,0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x48,0x8D,0x0D});
        if (!code.RipDisp32(config.layout.encryptedHandlerOffset, result.error)) return false;
        code.U8(0xBA); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x41,0xB8}); code.U32(kPageExecuteRead);
        code.Raw({0x4C,0x8D,0x4C,0x24,0x30,0xFF,0xD0,0x85,0xC0});
        code.Jcc32(0x84, restoreFail);
        code.Raw({0xC6,0x05});
        if (!code.RipDisp32(config.layout.decryptionStateOffset,
                result.error, 1u)) return false;
        code.U8(2);
        code.Jmp32(ready);

        code.Bind(restoreFail);
        // Best-effort W^X restoration still precedes the fail-closed return.
        code.Raw({0xC6,0x05});
        if (!code.RipDisp32(config.layout.decryptionStateOffset,
                result.error, 1u)) return false;
        code.U8(3);
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x48,0x85,0xC0});
        code.Jcc32(0x84, restoreAttemptDone);
        code.Raw({0x48,0x8D,0x0D});
        if (!code.RipDisp32(config.layout.encryptedHandlerOffset, result.error)) return false;
        code.U8(0xBA); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x41,0xB8}); code.U32(kPageExecuteRead);
        code.Raw({0x4C,0x8D,0x4C,0x24,0x30,0xFF,0xD0});
        code.Bind(restoreAttemptDone);
        code.Jmp32(fail);

        code.Bind(failOwned);
        code.Raw({0xC6,0x05});
        if (!code.RipDisp32(config.layout.decryptionStateOffset,
                result.error, 1u)) return false;
        code.U8(0);
        code.Bind(fail);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Jmp32(epilog);

        code.Bind(ready);
        code.Raw({0x31,0xC0});
        code.Bind(epilog);
        code.Raw({0x48,0x83,0xC4,static_cast<uint8_t>(stackSize),
                  0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
                  0x5F,0x5E,0x5B,0xC3});
        if (!code.Resolve(result.error)) return false;
        AddX64Unwind(result.unwindRecords, functionBegin,
            code.CurrentImageOffset(), prologSize, stackSize, pushes);
    } else {
        const size_t retry = code.NewLabel();
        const size_t owner = code.NewLabel();
        const size_t wait = code.NewLabel();
        const size_t ready = code.NewLabel();
        const size_t failOwned = code.NewLabel();
        const size_t loop = code.NewLabel();
        const size_t restoreFail = code.NewLabel();
        const size_t restoreAttemptDone = code.NewLabel();
        const size_t epilog = code.NewLabel();

        code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x81,0xEC}); code.U32(0x30);
        code.Raw({0x8B,0x7D,0x08,0xE8,0x00,0x00,0x00,0x00,0x5B});
        // call $+5 pushes the address of the following POP byte, not the
        // address after POP.
        const uint32_t popImageOffset = code.CurrentImageOffset() - 1u;
        const int32_t stateDisp = static_cast<int32_t>(
            config.layout.decryptionStateOffset - popImageOffset);
        const int32_t handlerDisp = static_cast<int32_t>(
            config.layout.encryptedHandlerOffset - popImageOffset);

        code.Bind(retry);
        code.Raw({0x31,0xC0,0xB2,0x01,0xF0,0x0F,0xB0,0x93}); code.U32(stateDisp);
        code.Jcc32(0x84, owner);
        code.Raw({0x3C,0x02}); code.Jcc32(0x84, ready);
        code.Raw({0x84,0xC0}); code.Jcc32(0x84, retry);
        code.Raw({0x3C,0x01}); code.Jcc32(0x85, restoreAttemptDone);
        code.Raw({0xC7,0x45,0xC8}); code.U32(0x00100000u);
        code.Bind(wait);
        code.Raw({0xF3,0x90,0x0F,0xB6,0x83}); code.U32(stateDisp);
        code.Raw({0x3C,0x02}); code.Jcc32(0x84, ready);
        code.Raw({0x84,0xC0}); code.Jcc32(0x84, retry);
        code.Raw({0x3C,0x01}); code.Jcc32(0x85, restoreAttemptDone);
        code.Raw({0xFF,0x4D,0xC8});
        code.Jcc32(0x84, restoreAttemptDone);
        code.Jmp32(wait);

        code.Bind(owner);
        code.Raw({0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x85,0xC0}); code.Jcc32(0x84, failOwned);
        code.Raw({0x8D,0xB3}); code.U32(handlerDisp);
        code.Raw({0x8D,0x4D,0xC4,0x51,0x68}); code.U32(kPageReadWrite);
        code.U8(0x68); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x56,0xFF,0xD0,0x85,0xC0}); code.Jcc32(0x84, failOwned);

        // Saved EBX/ESI/EDI occupy [ebp-4..ebp-12]. Cipher locals therefore
        // start below them; overwriting those save slots corrupts the caller's
        // context register after the decryptor returns.
        // -14 state.lo, -18 state.hi, -1c count, -20 mul.lo,
        // -24 mul.hi, -28 add.lo, -2c add.hi, -30 temporary low,
        // -34 context, -38 wait counter, -3c old protection.
        code.Raw({0xC7,0x45,0xEC}); code.U32(static_cast<uint32_t>(config.cipher.initialState));
        code.Raw({0xC7,0x45,0xE8}); code.U32(static_cast<uint32_t>(config.cipher.initialState >> 32u));
        code.Raw({0xC7,0x45,0xE4}); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0xC7,0x45,0xE0}); code.U32(static_cast<uint32_t>(config.cipher.multiplier));
        code.Raw({0xC7,0x45,0xDC}); code.U32(static_cast<uint32_t>(config.cipher.multiplier >> 32u));
        code.Raw({0xC7,0x45,0xD8}); code.U32(static_cast<uint32_t>(config.cipher.addend));
        code.Raw({0xC7,0x45,0xD4}); code.U32(static_cast<uint32_t>(config.cipher.addend >> 32u));
        code.Raw({0x89,0x7D,0xCC});             // preserve context while EDI is scratch
        code.Bind(loop);
        result.decryptorLoopOffset = static_cast<uint32_t>(code.Offset());
        // First seed-selected left-xorshift over the 64-bit state pair.
        code.Raw({0x8B,0x45,0xEC,0x8B,0x55,0xE8,0x89,0xC1,0xC1,0xE1});
        code.U8(config.cipher.shiftLeftA);
        code.Raw({0x89,0xD7,0xC1,0xE7}); code.U8(config.cipher.shiftLeftA);
        code.Raw({0xC1,0xE8});
        code.U8(static_cast<uint8_t>(32u - config.cipher.shiftLeftA));
        code.Raw({0x09,0xC7,
                  0x31,0x4D,0xEC,0x31,0x7D,0xE8});
        // Seed-selected right-xorshift over the 64-bit state pair.
        code.Raw({0x8B,0x45,0xEC,0x8B,0x55,0xE8,0x89,0xD1,0xC1,0xE9});
        code.U8(config.cipher.shiftRightB);
        code.Raw({0x89,0xC7,0xC1,0xEF}); code.U8(config.cipher.shiftRightB);
        code.Raw({0xC1,0xE2});
        code.U8(static_cast<uint8_t>(32u - config.cipher.shiftRightB));
        code.Raw({0x09,0xD7,
                  0x31,0x7D,0xEC,0x31,0x4D,0xE8});
        // Second seed-selected left-xorshift over the 64-bit state pair.
        code.Raw({0x8B,0x45,0xEC,0x8B,0x55,0xE8,0x89,0xC1,0xC1,0xE1});
        code.U8(config.cipher.shiftLeftC);
        code.Raw({0x89,0xD7,0xC1,0xE7}); code.U8(config.cipher.shiftLeftC);
        code.Raw({0xC1,0xE8});
        code.U8(static_cast<uint8_t>(32u - config.cipher.shiftLeftC));
        code.Raw({0x09,0xC7,
                  0x31,0x4D,0xEC,0x31,0x7D,0xE8});
        // 64-bit state = state * multiplier + addend (mod 2^64).
        code.Raw({0x8B,0x45,0xEC,0xF7,0x65,0xE0,0x89,0x45,0xD0,
                  0x89,0xD1,0x8B,0x45,0xEC,0x0F,0xAF,0x45,0xDC,0x01,0xC1,
                  0x8B,0x45,0xE8,0x0F,0xAF,0x45,0xE0,0x01,0xC1,
                  0x8B,0x45,0xD0,0x03,0x45,0xD8,0x13,0x4D,0xD4,
                  0x89,0x45,0xEC,0x89,0x4D,0xE8});
        code.Raw({0x8A,0x06});
        if ((config.cipher.instructionVariant & 1u) != 0) {
            code.Raw({0xC0,0xC8}); code.U8(config.cipher.rotate);
        } else {
            code.Raw({0xC0,0xC0});
            code.U8(static_cast<uint8_t>(8u - config.cipher.rotate));
        }
        if ((config.cipher.instructionVariant & 2u) != 0) {
            code.U8(0x2C); code.U8(config.cipher.addByte);
        } else {
            code.U8(0x04);
            code.U8(static_cast<uint8_t>(0u - config.cipher.addByte));
        }
        if ((config.cipher.instructionVariant & 4u) != 0)
            code.Raw({0x32,0x45,0xEC});
        else
            code.Raw({0x8A,0x55,0xEC,0x30,0xD0});
        code.Raw({0x88,0x06});
        switch ((config.cipher.instructionVariant >> 3u) % 3u) {
            case 0: code.U8(0x46); break;
            case 1: code.Raw({0x83,0xC6,0x01}); break;
            default: code.Raw({0x8D,0x76,0x01}); break;
        }
        if ((config.cipher.instructionVariant & 0x20u) != 0)
            code.Raw({0xFF,0x4D,0xE4});
        else
            code.Raw({0x83,0x6D,0xE4,0x01});
        code.Jcc32(0x85, loop);
        result.decryptorLoopSize = static_cast<uint32_t>(code.Offset()) -
            result.decryptorLoopOffset;
        code.Raw({0x8B,0x7D,0xCC});
        // The decrypt loop advances ESI to the byte after the region.  W^X
        // restore and instruction-cache flush both require the original base.
        code.Raw({0x81,0xEE}); code.U32(config.layout.encryptedHandlerSize);

        code.Raw({0x8B,0x87}); code.U32(CtxFlushInstructionCache);
        code.Raw({0x85,0xC0}); code.Jcc32(0x84, restoreFail);
        code.U8(0x68); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x56,0x6A,0xFF,0xFF,0xD0,0x85,0xC0});
        code.Jcc32(0x84, restoreFail);
        code.Raw({0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x8D,0x4D,0xC4,0x51,0x68}); code.U32(kPageExecuteRead);
        code.U8(0x68); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x56,0xFF,0xD0,0x85,0xC0}); code.Jcc32(0x84, restoreFail);
        code.Raw({0xC6,0x83}); code.U32(stateDisp); code.U8(2);
        code.Jmp32(ready);

        code.Bind(restoreFail);
        code.Raw({0xC6,0x83}); code.U32(stateDisp); code.U8(3);
        code.Raw({0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x85,0xC0}); code.Jcc32(0x84, restoreAttemptDone);
        code.Raw({0x8D,0x4D,0xC4,0x51,0x68}); code.U32(kPageExecuteRead);
        code.U8(0x68); code.U32(config.layout.encryptedHandlerSize);
        code.Raw({0x56,0xFF,0xD0});
        code.Bind(restoreAttemptDone);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Jmp32(epilog);
        code.Bind(failOwned);
        code.Raw({0xC6,0x83}); code.U32(stateDisp); code.U8(0);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_HANDLER_CIPHER);
        code.Jmp32(epilog);
        code.Bind(ready);
        code.Raw({0x31,0xC0});
        code.Bind(epilog);
        code.Raw({0x8D,0x65,0xF4,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
        if (!code.Resolve(result.error)) return false;
    }

    EmitSeedIsland(code, random, 48);
    result.decryptorCode = std::move(code.bytes);
    return true;
}

void EmitX64SetVirtualFlag(
    CodeBuffer& code,
    uint32_t flag,
    uint8_t localOffset)
{
    const size_t next = code.NewLabel();
    code.Raw({0x41,0xF7,0xC6}); code.U32(flag); // test r14d,flag
    code.Jcc32(0x84, next);
    code.Raw({0x49,0x81,0xE4}); code.U32(~flag); // and r12,~flag
    code.Raw({0x80,0x7C,0x24,localOffset,0x00});
    code.Jcc32(0x84, next);
    code.Raw({0x49,0x81,0xCC}); code.U32(flag); // or r12,flag
    code.Bind(next);
}

void EmitX86SetVirtualFlag(
    CodeBuffer& code,
    uint32_t flag,
    uint8_t localOffset)
{
    const size_t next = code.NewLabel();
    code.Raw({0xF7,0x45,0xD0}); code.U32(flag); // test requested,flag
    code.Jcc32(0x84, next);
    code.Raw({0x81,0x65,0xCC}); code.U32(~flag); // flags &= ~flag
    code.Raw({0x80,0x7D,localOffset,0x00});
    code.Jcc32(0x84, next);
    code.Raw({0x81,0x4D,0xCC}); code.U32(flag);
    code.Bind(next);
}

bool BuildFlagMaterializer(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    CodeBuffer code(config.layout.flagMaterializerOffset);
    SeedStream random(config.buildSeed, 0x454E545259464C47ULL);
    EmitCet(code, x64, config.emitCetLandingPads);
    const uint32_t functionBegin = code.ImageOffset();
    constexpr uint32_t pfA = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, a));
    constexpr uint32_t pfB = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, b));
    constexpr uint32_t pfResult = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, result));
    constexpr uint32_t pfAux = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, auxiliary));
    constexpr uint32_t pfDefined = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, definedMask));
    constexpr uint32_t pfOperation = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, operation));
    constexpr uint32_t pfWidth = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, width));
    constexpr uint32_t pfValid = CtxPendingFlags +
        static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, valid));

    if (x64) {
        std::vector<std::pair<uint8_t, uint8_t>> pushes;
        const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
            code.Raw(bytes);
            pushes.push_back({static_cast<uint8_t>(code.Offset()), reg});
        };
        push({0x53}, 3); push({0x55}, 5); push({0x56}, 6); push({0x57}, 7);
        push({0x41,0x54}, 12); push({0x41,0x55}, 13);
        push({0x41,0x56}, 14); push({0x41,0x57}, 15);
        constexpr uint32_t stackSize = 0x28u;
        code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stackSize)});
        const uint8_t prologSize = static_cast<uint8_t>(code.Offset());
        code.Raw({0x49,0x89,0xCF,0x41,0x89,0xD6}); // ctx, requested
        code.Raw({0x4D,0x8B,0xA7}); code.U32(CtxVirtualFlags);

        const size_t done = code.NewLabel();
        const size_t invalid = code.NewLabel();
        const size_t maskReady = code.NewLabel();
        const size_t add = code.NewLabel();
        const size_t adc = code.NewLabel();
        const size_t sub = code.NewLabel();
        const size_t inc = code.NewLabel();
        const size_t sbb = code.NewLabel();
        const size_t logic = code.NewLabel();
        const size_t neg = code.NewLabel();
        const size_t shl = code.NewLabel();
        const size_t shr = code.NewLabel();
        const size_t sar = code.NewLabel();
        const size_t rol = code.NewLabel();
        const size_t ror = code.NewLabel();
        const size_t mul = code.NewLabel();
        const size_t imul = code.NewLabel();
        const size_t bit = code.NewLabel();
        const size_t updateFlags = code.NewLabel();
        const size_t consume = code.NewLabel();

        code.Raw({0x41,0x80,0xBF}); code.U32(pfValid); code.U8(0);
        code.Jcc32(0x84, done);
        code.Raw({0x45,0x23,0xB7}); code.U32(pfDefined);
        code.Jcc32(0x84, done);
        code.Raw({0x41,0x0F,0xB6,0xBF}); code.U32(pfWidth);
        code.Raw({0x83,0xFF,0x01}); code.Jcc32(0x84, maskReady);
        code.Raw({0x83,0xFF,0x02}); code.Jcc32(0x84, maskReady);
        code.Raw({0x83,0xFF,0x04}); code.Jcc32(0x84, maskReady);
        code.Raw({0x83,0xFF,0x08}); code.Jcc32(0x85, invalid);
        code.Bind(maskReady);
        code.Raw({0x49,0xC7,0xC3,0xFF,0xFF,0xFF,0xFF}); // r11=-1
        const size_t fullMask = code.NewLabel();
        code.Raw({0x83,0xFF,0x08}); code.Jcc32(0x84, fullMask);
        code.Raw({0x89,0xF9,0xC1,0xE1,0x03,0x49,0xC7,0xC3,0x01,0x00,0x00,0x00,
                  0x49,0xD3,0xE3,0x49,0xFF,0xCB});
        code.Bind(fullMask);
        code.Raw({0x89,0xFD,0xC1,0xE5,0x03,0xFF,0xCD,
                  0x48,0xC7,0xC3,0x01,0x00,0x00,0x00,0x89,0xE9,0x48,0xD3,0xE3});
        code.Raw({0x4D,0x8B,0x87}); code.U32(pfA);
        code.Raw({0x4D,0x8B,0x8F}); code.U32(pfB);
        code.Raw({0x4D,0x8B,0x97}); code.U32(pfResult);
        code.Raw({0x4D,0x8B,0xAF}); code.U32(pfAux);
        code.Raw({0x4D,0x21,0xD8,0x4D,0x21,0xD9,0x4D,0x21,0xDA});
        // [rsp+20]=CF, +21=OF, +22=AF, +23=result flags, +24=no-change.
        code.Raw({0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                  0xC6,0x44,0x24,0x24,0x00});
        code.Raw({0x41,0x0F,0xB6,0xB7}); code.U32(pfOperation);

        const auto cmpOp = [&](uint8_t op, size_t target) {
            code.Raw({0x83,0xFE,op}); code.Jcc32(0x84, target);
        };
        cmpOp(VM_LAZY_ADD, add); cmpOp(VM_LAZY_ADC, adc);
        cmpOp(VM_LAZY_SUB, sub); cmpOp(VM_LAZY_DEC, sub);
        cmpOp(VM_LAZY_INC, inc); cmpOp(VM_LAZY_SBB, sbb);
        cmpOp(VM_LAZY_LOGIC, logic); cmpOp(VM_LAZY_NEG, neg);
        cmpOp(VM_LAZY_SHL, shl); cmpOp(VM_LAZY_SHR, shr);
        cmpOp(VM_LAZY_SAR, sar); cmpOp(VM_LAZY_ROL, rol);
        cmpOp(VM_LAZY_ROR, ror); cmpOp(VM_LAZY_MUL, mul);
        cmpOp(VM_LAZY_IMUL, imul); cmpOp(VM_LAZY_BIT_TEST, bit);
        code.Jmp32(invalid);

        const auto emitCommonArithmetic = [&](bool subtract) {
            // OF and AF are pure bit formulas; no native flags are imported.
            code.Raw({0x4C,0x89,0xC0,0x4C,0x31,0xC8});
            if (!subtract) code.Raw({0x48,0xF7,0xD0});
            code.Raw({0x4C,0x89,0xD2,0x4C,0x31,0xC2,0x48,0x21,0xD0,
                      0x48,0x85,0xD8,0x0F,0x95,0x44,0x24,0x21});
            code.Raw({0x4C,0x89,0xC0,0x4C,0x31,0xC8,0x4C,0x31,0xD0,
                      0xA8,0x10,0x0F,0x95,0x44,0x24,0x22,
                      0xC6,0x44,0x24,0x23,0x01});
            code.Jmp32(updateFlags);
        };
        code.Bind(add);
        code.Raw({0x4D,0x39,0xC2,0x0F,0x92,0x44,0x24,0x20});
        emitCommonArithmetic(false);
        code.Bind(adc);
        code.Raw({0x4D,0x39,0xC2,0x0F,0x92,0xC0,0x4D,0x85,0xED,
                  0x0F,0x95,0xC2,0x4D,0x39,0xC2,0x0F,0x94,0xC1,
                  0x20,0xCA,0x08,0xD0,0x88,0x44,0x24,0x20});
        emitCommonArithmetic(false);
        code.Bind(sub);
        code.Raw({0x4D,0x39,0xC8,0x0F,0x92,0x44,0x24,0x20});
        emitCommonArithmetic(true);
        code.Bind(inc);
        code.Raw({0x4D,0x39,0xC2,0x0F,0x92,0x44,0x24,0x20});
        emitCommonArithmetic(false);
        code.Bind(sbb);
        code.Raw({0x4D,0x39,0xC8,0x0F,0x92,0xC0,0x4D,0x85,0xED,
                  0x0F,0x95,0xC2,0x4D,0x39,0xC8,0x0F,0x94,0xC1,
                  0x20,0xCA,0x08,0xD0,0x88,0x44,0x24,0x20});
        emitCommonArithmetic(true);
        code.Bind(logic);
        code.Raw({0xC6,0x44,0x24,0x23,0x01}); code.Jmp32(updateFlags);
        code.Bind(neg);
        code.Raw({0x4D,0x85,0xC0,0x0F,0x95,0x44,0x24,0x20,
                  0x49,0x39,0xD8,0x0F,0x94,0x44,0x24,0x21,
                  0x4C,0x89,0xC0,0x4C,0x31,0xD0,0xA8,0x10,
                  0x0F,0x95,0x44,0x24,0x22,0xC6,0x44,0x24,0x23,0x01});
        code.Jmp32(updateFlags);

        const auto emitShift = [&](uint8_t kind) {
            const size_t nonzero = code.NewLabel();
            const size_t countInRange = code.NewLabel();
            const size_t afterCf = code.NewLabel();
            code.Raw({0x44,0x89,0xC9,0x83,0xE1}); code.U8(kind == VM_LAZY_SHL ||
                kind == VM_LAZY_SHR || kind == VM_LAZY_SAR ? 0x3F : 0x3F);
            // x86 masks non-64 widths by 31, matching architectural counts.
            const size_t width64 = code.NewLabel();
            code.Raw({0x83,0xFF,0x08}); code.Jcc32(0x84, width64);
            code.Raw({0x83,0xE1,0x1F});
            code.Bind(width64);
            code.Raw({0x85,0xC9}); code.Jcc32(0x85, nonzero);
            code.Raw({0xC6,0x44,0x24,0x24,0x01}); code.Jmp32(consume);
            code.Bind(nonzero);
            code.Raw({0x89,0xFA,0xC1,0xE2,0x03,0x39,0xD1});
            code.Jcc32(0x86, countInRange);
            code.Raw({0xC6,0x44,0x24,0x20,0x00}); code.Jmp32(afterCf);
            code.Bind(countInRange);
            if (kind == VM_LAZY_SHL) {
                code.Raw({0x29,0xCA,0x89,0xD1,0x4C,0x89,0xC0,0x48,0xD3,0xE8});
            } else {
                code.Raw({0xFF,0xC9,0x4C,0x89,0xC0,0x48,0xD3,0xE8});
            }
            code.Raw({0x24,0x01,0x88,0x44,0x24,0x20});
            code.Bind(afterCf);
            // OF is defined by x86 only for a one-bit count.
            const size_t notOne = code.NewLabel();
            code.Raw({0x41,0x83,0xE1}); code.U8(kind == VM_LAZY_SHL ||
                kind == VM_LAZY_SHR || kind == VM_LAZY_SAR ? 0x3F : 0x3F);
            code.Raw({0x41,0x83,0xF9,0x01}); code.Jcc32(0x85, notOne);
            if (kind == VM_LAZY_SHL) {
                code.Raw({0x4C,0x89,0xD0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                          0x0F,0x95,0xC0,0x32,0x44,0x24,0x20,
                          0x88,0x44,0x24,0x21});
            } else if (kind == VM_LAZY_SHR) {
                code.Raw({0x4C,0x89,0xC0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                          0x0F,0x95,0x44,0x24,0x21});
            }
            code.Bind(notOne);
            code.Raw({0xC6,0x44,0x24,0x23,0x01});
            code.Jmp32(updateFlags);
        };
        code.Bind(shl); emitShift(VM_LAZY_SHL);
        code.Bind(shr); emitShift(VM_LAZY_SHR);
        code.Bind(sar); emitShift(VM_LAZY_SAR);

        const auto emitRotate = [&](bool left) {
            const size_t nonzero = code.NewLabel();
            const size_t notOne = code.NewLabel();
            code.Raw({0x89,0xF9,0xC1,0xE1,0x03,0xFF,0xC9,
                      0x44,0x21,0xC9,0x85,0xC9});
            code.Jcc32(0x85, nonzero);
            code.Raw({0xC6,0x44,0x24,0x24,0x01}); code.Jmp32(consume);
            code.Bind(nonzero);
            if (left) {
                code.Raw({0x44,0x88,0xD0,0x24,0x01,0x88,0x44,0x24,0x20});
            } else {
                code.Raw({0x4C,0x89,0xD0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                          0x0F,0x95,0x44,0x24,0x20});
            }
            code.Raw({0x83,0xF9,0x01}); code.Jcc32(0x85, notOne);
            if (left) {
                code.Raw({0x4C,0x89,0xD0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                          0x0F,0x95,0xC0,0x32,0x44,0x24,0x20,
                          0x88,0x44,0x24,0x21});
            } else {
                code.Raw({0x4C,0x89,0xD0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                          0x0F,0x95,0xC0,0x48,0xD1,0xEB,0x4C,0x89,0xD2,
                          0x48,0x21,0xDA,0x48,0x85,0xD2,0x0F,0x95,0xC2,
                          0x30,0xD0,0x88,0x44,0x24,0x21});
            }
            code.Bind(notOne);
            code.Jmp32(updateFlags);
        };
        code.Bind(rol); emitRotate(true);
        code.Bind(ror); emitRotate(false);
        code.Bind(mul);
        code.Raw({0x4D,0x85,0xED,0x0F,0x95,0xC0,0x88,0x44,0x24,0x20,
                  0x88,0x44,0x24,0x21}); code.Jmp32(updateFlags);
        code.Bind(imul);
        code.Raw({0x31,0xC0,0x4C,0x85,0xD3,0x49,0x0F,0x45,0xC3,
                  0x49,0x39,0xC5,0x0F,0x95,0xC0,
                  0x88,0x44,0x24,0x20,0x88,0x44,0x24,0x21});
        code.Jmp32(updateFlags);
        code.Bind(bit);
        code.Raw({0x44,0x88,0xE8,0x24,0x01,0x88,0x44,0x24,0x20});
        code.Jmp32(updateFlags);

        code.Bind(updateFlags);
        EmitX64SetVirtualFlag(code, VM_FLAG_CF, 0x20);
        EmitX64SetVirtualFlag(code, VM_FLAG_OF, 0x21);
        EmitX64SetVirtualFlag(code, VM_FLAG_AF, 0x22);
        const size_t skipResult = code.NewLabel();
        code.Raw({0x80,0x7C,0x24,0x23,0x00}); code.Jcc32(0x84, skipResult);
        // ZF.
        code.Raw({0x4D,0x85,0xD2,0x0F,0x94,0x44,0x24,0x25});
        EmitX64SetVirtualFlag(code, VM_FLAG_ZF, 0x25);
        // SF.
        code.Raw({0x4C,0x89,0xD0,0x48,0x21,0xD8,0x48,0x85,0xC0,
                  0x0F,0x95,0x44,0x24,0x25});
        EmitX64SetVirtualFlag(code, VM_FLAG_SF, 0x25);
        // PF uses only result byte and never reads a native arithmetic flag
        // across the VM boundary.
        code.Raw({0x45,0x84,0xD2,0x0F,0x9A,0x44,0x24,0x25});
        EmitX64SetVirtualFlag(code, VM_FLAG_PF, 0x25);
        code.Bind(skipResult);
        code.Bind(consume);
        code.Raw({0x4D,0x89,0xA7}); code.U32(CtxVirtualFlags);
        code.Raw({0x44,0x89,0xF0,0xF7,0xD0,0x41,0x21,0x87}); code.U32(pfDefined);
        const size_t pendingRemains = code.NewLabel();
        code.Raw({0x41,0x83,0xBF}); code.U32(pfDefined); code.U8(0);
        code.Jcc32(0x85, pendingRemains);
        code.Raw({0x41,0xC6,0x87}); code.U32(pfValid); code.U8(0);
        code.Bind(pendingRemains);
        code.Jmp32(done);

        code.Bind(invalid);
        code.Raw({0x41,0xC6,0x87}); code.U32(pfValid); code.U8(0);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_FLAGS_STATE);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Bind(done);
        code.Raw({0x4C,0x89,0xE0,0x48,0x83,0xC4,static_cast<uint8_t>(stackSize),
                  0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
                  0x5F,0x5E,0x5D,0x5B,0xC3});
        if (!code.Resolve(result.error)) return false;
        AddX64Unwind(result.unwindRecords, functionBegin,
            code.CurrentImageOffset(), prologSize, stackSize, pushes);
    } else {
        const size_t done = code.NewLabel();
        const size_t invalid = code.NewLabel();
        const size_t add = code.NewLabel();
        const size_t adc = code.NewLabel();
        const size_t sub = code.NewLabel();
        const size_t inc = code.NewLabel();
        const size_t sbb = code.NewLabel();
        const size_t logic = code.NewLabel();
        const size_t neg = code.NewLabel();
        const size_t shl = code.NewLabel();
        const size_t shr = code.NewLabel();
        const size_t sar = code.NewLabel();
        const size_t rol = code.NewLabel();
        const size_t ror = code.NewLabel();
        const size_t mul = code.NewLabel();
        const size_t imul = code.NewLabel();
        const size_t bit = code.NewLabel();
        const size_t updateFlags = code.NewLabel();
        const size_t consume = code.NewLabel();

        code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x83,0xEC,0x38,
                  0x8B,0x7D,0x08,0x8B,0x45,0x0C,0x89,0x45,0xD0,
                  0x8B,0x87}); code.U32(CtxVirtualFlags); code.Raw({0x89,0x45,0xCC});
        code.Raw({0x80,0xBF}); code.U32(pfValid); code.U8(0); code.Jcc32(0x84, done);
        code.Raw({0x8B,0x87}); code.U32(pfDefined); code.Raw({0x21,0x45,0xD0});
        code.Jcc32(0x84, done);
        code.Raw({0x0F,0xB6,0x87}); code.U32(pfWidth); code.Raw({0x89,0x45,0xC8});
        code.Raw({0x83,0xF8,0x01}); const size_t widthOk = code.NewLabel(); code.Jcc32(0x84, widthOk);
        code.Raw({0x83,0xF8,0x02}); code.Jcc32(0x84, widthOk);
        code.Raw({0x83,0xF8,0x04}); code.Jcc32(0x85, invalid);
        code.Bind(widthOk);
        code.Raw({0xB9,0xFF,0xFF,0xFF,0xFF,0x83,0xF8,0x04});
        const size_t fullWidthMask = code.NewLabel();
        const size_t masksReady = code.NewLabel();
        code.Jcc32(0x84, fullWidthMask);
        code.Raw({0xC1,0xE0,0x03,0xBA,0x01,0x00,0x00,0x00,0x89,0xC1,
                  0xD3,0xE2,0x4A,0x89,0xD1,
                  0x8D,0x51,0x01,0xD1,0xEA});
        code.Jmp32(masksReady);
        code.Bind(fullWidthMask);
        code.Raw({0xBA,0x00,0x00,0x00,0x80});
        code.Bind(masksReady);
        code.Raw({0x89,0x4D,0xC4,0x89,0x55,0xC0});
        code.Raw({0x8B,0x87}); code.U32(pfA); code.Raw({0x21,0xC8,0x89,0x45,0xBC});
        code.Raw({0x8B,0x87}); code.U32(pfB); code.Raw({0x21,0xC8,0x89,0x45,0xB8});
        code.Raw({0x8B,0x87}); code.U32(pfResult); code.Raw({0x21,0xC8,0x89,0x45,0xB4});
        code.Raw({0x8B,0x87}); code.U32(pfAux); code.Raw({0x89,0x45,0xB0});
        code.Raw({0xC7,0x45,0xD4,0x00,0x00,0x00,0x00,
                  0xC6,0x45,0xD8,0x00});
        code.Raw({0x0F,0xB6,0x87}); code.U32(pfOperation); code.Raw({0x89,0x45,0xAC});
        const auto cmpOp = [&](uint8_t op, size_t target) {
            code.Raw({0x83,0xF8,op}); code.Jcc32(0x84, target);
        };
        cmpOp(VM_LAZY_ADD, add); cmpOp(VM_LAZY_ADC, adc);
        cmpOp(VM_LAZY_SUB, sub); cmpOp(VM_LAZY_DEC, sub);
        cmpOp(VM_LAZY_INC, inc); cmpOp(VM_LAZY_SBB, sbb);
        cmpOp(VM_LAZY_LOGIC, logic); cmpOp(VM_LAZY_NEG, neg);
        cmpOp(VM_LAZY_SHL, shl); cmpOp(VM_LAZY_SHR, shr);
        cmpOp(VM_LAZY_SAR, sar); cmpOp(VM_LAZY_ROL, rol);
        cmpOp(VM_LAZY_ROR, ror); cmpOp(VM_LAZY_MUL, mul);
        cmpOp(VM_LAZY_IMUL, imul); cmpOp(VM_LAZY_BIT_TEST, bit);
        code.Jmp32(invalid);

        const auto common = [&](bool subtract) {
            code.Raw({0x8B,0x45,0xBC,0x33,0x45,0xB8});
            if (!subtract) code.Raw({0xF7,0xD0});
            code.Raw({0x8B,0x55,0xBC,0x33,0x55,0xB4,0x21,0xD0,
                      0x23,0x45,0xC0,0x0F,0x95,0x45,0xD5,
                      0x8B,0x45,0xBC,0x33,0x45,0xB8,0x33,0x45,0xB4,
                      0xA8,0x10,0x0F,0x95,0x45,0xD6,
                      0xC6,0x45,0xD7,0x01});
            code.Jmp32(updateFlags);
        };
        code.Bind(add);
        code.Raw({0x8B,0x45,0xB4,0x3B,0x45,0xBC,0x0F,0x92,0x45,0xD4}); common(false);
        code.Bind(adc);
        code.Raw({0x8B,0x45,0xB4,0x3B,0x45,0xBC,0x0F,0x92,0xC1,
                  0x83,0x7D,0xB0,0x00,0x0F,0x95,0xC2,
                  0x3B,0x45,0xBC,0x0F,0x94,0xC0,0x20,0xC2,0x08,0xD1,
                  0x88,0x4D,0xD4}); common(false);
        code.Bind(sub);
        code.Raw({0x8B,0x45,0xBC,0x3B,0x45,0xB8,0x0F,0x92,0x45,0xD4}); common(true);
        code.Bind(inc);
        code.Raw({0x8B,0x45,0xB4,0x3B,0x45,0xBC,0x0F,0x92,0x45,0xD4}); common(false);
        code.Bind(sbb);
        code.Raw({0x8B,0x45,0xBC,0x3B,0x45,0xB8,0x0F,0x92,0xC1,
                  0x83,0x7D,0xB0,0x00,0x0F,0x95,0xC2,
                  0x3B,0x45,0xB8,0x0F,0x94,0xC0,0x20,0xC2,0x08,0xD1,
                  0x88,0x4D,0xD4}); common(true);
        code.Bind(logic); code.Raw({0xC6,0x45,0xD7,0x01}); code.Jmp32(updateFlags);
        code.Bind(neg);
        code.Raw({0x83,0x7D,0xBC,0x00,0x0F,0x95,0x45,0xD4,
                  0x8B,0x45,0xBC,0x3B,0x45,0xC0,0x0F,0x94,0x45,0xD5,
                  0x33,0x45,0xB4,0xA8,0x10,0x0F,0x95,0x45,0xD6,
                  0xC6,0x45,0xD7,0x01}); code.Jmp32(updateFlags);

        const auto shift = [&](uint8_t kind) {
            const size_t nonzero = code.NewLabel();
            const size_t inRange = code.NewLabel();
            const size_t afterCf = code.NewLabel();
            const size_t notOne = code.NewLabel();
            code.Raw({0x8B,0x4D,0xB8,0x83,0xE1,0x1F,0x85,0xC9});
            code.Jcc32(0x85, nonzero); code.Raw({0xC6,0x45,0xD8,0x01}); code.Jmp32(consume);
            code.Bind(nonzero);
            code.Raw({0x8B,0x55,0xC8,0xC1,0xE2,0x03,0x3B,0xCA});
            code.Jcc32(0x86, inRange); code.Raw({0xC6,0x45,0xD4,0x00}); code.Jmp32(afterCf);
            code.Bind(inRange);
            if (kind == VM_LAZY_SHL) {
                code.Raw({0x2B,0xD1,0x8B,0x4D,0xBC,0x87,0xCA,0xD3,0xEA,0x89,0xD0});
            } else {
                code.Raw({0x49,0x8B,0x45,0xBC,0xD3,0xE8});
            }
            code.Raw({0x24,0x01,0x88,0x45,0xD4});
            code.Bind(afterCf);
            // OF is defined when the architectural (masked) count is one,
            // not only when the raw encoded count literally equals one.
            code.Raw({0x8B,0x45,0xB8,0x83,0xE0,0x1F,0x83,0xF8,0x01});
            code.Jcc32(0x85, notOne);
            if (kind == VM_LAZY_SHL) {
                code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x95,0xC0,
                          0x32,0x45,0xD4,0x88,0x45,0xD5});
            } else if (kind == VM_LAZY_SHR) {
                code.Raw({0x8B,0x45,0xBC,0x23,0x45,0xC0,0x0F,0x95,0x45,0xD5});
            }
            code.Bind(notOne);
            code.Raw({0xC6,0x45,0xD7,0x01}); code.Jmp32(updateFlags);
        };
        code.Bind(shl); shift(VM_LAZY_SHL);
        code.Bind(shr); shift(VM_LAZY_SHR);
        code.Bind(sar); shift(VM_LAZY_SAR);
        const auto rotate = [&](bool left) {
            const size_t nonzero = code.NewLabel();
            const size_t notOne = code.NewLabel();
            code.Raw({0x8B,0x4D,0xC8,0xC1,0xE1,0x03,0x49,
                      0x23,0x4D,0xB8,0x85,0xC9});
            code.Jcc32(0x85, nonzero); code.Raw({0xC6,0x45,0xD8,0x01}); code.Jmp32(consume);
            code.Bind(nonzero);
            if (left) code.Raw({0x8A,0x45,0xB4,0x24,0x01,0x88,0x45,0xD4});
            else code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x95,0x45,0xD4});
            code.Raw({0x83,0xF9,0x01}); code.Jcc32(0x85, notOne);
            if (left) {
                code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x95,0xC0,
                          0x32,0x45,0xD4,0x88,0x45,0xD5});
            } else {
                code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x95,0xC0,
                          0x8B,0x55,0xC0,0xD1,0xEA,0x23,0x55,0xB4,
                          0x0F,0x95,0xC2,0x30,0xD0,0x88,0x45,0xD5});
            }
            code.Bind(notOne); code.Jmp32(updateFlags);
        };
        code.Bind(rol); rotate(true); code.Bind(ror); rotate(false);
        code.Bind(mul);
        code.Raw({0x83,0x7D,0xB0,0x00,0x0F,0x95,0xC0,
                  0x88,0x45,0xD4,0x88,0x45,0xD5}); code.Jmp32(updateFlags);
        code.Bind(imul);
        code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x45,0x45,0xC4,
                  0x3B,0x45,0xB0,0x0F,0x95,0xC0,
                  0x88,0x45,0xD4,0x88,0x45,0xD5}); code.Jmp32(updateFlags);
        code.Bind(bit);
        code.Raw({0x8A,0x45,0xB0,0x24,0x01,0x88,0x45,0xD4}); code.Jmp32(updateFlags);

        code.Bind(updateFlags);
        EmitX86SetVirtualFlag(code, VM_FLAG_CF, 0xD4);
        EmitX86SetVirtualFlag(code, VM_FLAG_OF, 0xD5);
        EmitX86SetVirtualFlag(code, VM_FLAG_AF, 0xD6);
        const size_t noResult = code.NewLabel();
        code.Raw({0x80,0x7D,0xD7,0x00}); code.Jcc32(0x84, noResult);
        code.Raw({0x83,0x7D,0xB4,0x00,0x0F,0x94,0x45,0xD9});
        EmitX86SetVirtualFlag(code, VM_FLAG_ZF, 0xD9);
        code.Raw({0x8B,0x45,0xB4,0x23,0x45,0xC0,0x0F,0x95,0x45,0xD9});
        EmitX86SetVirtualFlag(code, VM_FLAG_SF, 0xD9);
        // SF left EAX sign-masked.  PF must use the unmodified result byte.
        code.Raw({0x8A,0x45,0xB4,0x84,0xC0,0x0F,0x9A,0x45,0xD9});
        EmitX86SetVirtualFlag(code, VM_FLAG_PF, 0xD9);
        code.Bind(noResult);
        code.Bind(consume);
        code.Raw({0x8B,0x45,0xCC,0x89,0x87}); code.U32(CtxVirtualFlags);
        code.Raw({0x8B,0x45,0xD0,0xF7,0xD0,0x21,0x87}); code.U32(pfDefined);
        const size_t remains = code.NewLabel();
        code.Raw({0x83,0xBF}); code.U32(pfDefined); code.U8(0); code.Jcc32(0x85, remains);
        code.Raw({0xC6,0x87}); code.U32(pfValid); code.U8(0);
        code.Bind(remains); code.Jmp32(done);
        code.Bind(invalid);
        code.Raw({0xC6,0x87}); code.U32(pfValid); code.U8(0);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_FLAGS_STATE);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Bind(done);
        code.Raw({0x8B,0x87}); code.U32(CtxVirtualFlags);
        code.Raw({0x8B,0x97}); code.U32(CtxVirtualFlags + 4u);
        code.Raw({0x8D,0x65,0xF4,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
        if (!code.Resolve(result.error)) return false;
    }
    EmitSeedIsland(code, random, 48);
    result.flagMaterializerCode = std::move(code.bytes);
    return true;
}

void EmitX64DwordLoad(CodeBuffer& code, uint8_t reg, uint8_t displacement) {
    code.Raw({0x8B, static_cast<uint8_t>(0x44u | ((reg & 7u) << 3u)),
              0x24, displacement});
}

void EmitX64DwordStore(CodeBuffer& code, uint8_t reg, uint8_t displacement) {
    code.Raw({0x89, static_cast<uint8_t>(0x44u | ((reg & 7u) << 3u)),
              0x24, displacement});
}

void EmitX64QuarterRound(
    CodeBuffer& code,
    uint8_t a,
    uint8_t b,
    uint8_t c,
    uint8_t d)
{
    // EAX/EDX are the only scratch registers.  Every value is explicitly
    // stored after each step, so native status flags never become VM state.
    EmitX64DwordLoad(code, 0, a);
    code.Raw({0x03,0x44,0x24,b});
    EmitX64DwordStore(code, 0, a);
    EmitX64DwordLoad(code, 2, d);
    code.Raw({0x31,0xC2,0xC1,0xC2,0x10});
    EmitX64DwordStore(code, 2, d);
    EmitX64DwordLoad(code, 0, c);
    code.Raw({0x03,0x44,0x24,d});
    EmitX64DwordStore(code, 0, c);
    EmitX64DwordLoad(code, 2, b);
    code.Raw({0x31,0xC2,0xC1,0xC2,0x0C});
    EmitX64DwordStore(code, 2, b);
    EmitX64DwordLoad(code, 0, a);
    code.Raw({0x03,0x44,0x24,b});
    EmitX64DwordStore(code, 0, a);
    EmitX64DwordLoad(code, 2, d);
    code.Raw({0x31,0xC2,0xC1,0xC2,0x08});
    EmitX64DwordStore(code, 2, d);
    EmitX64DwordLoad(code, 0, c);
    code.Raw({0x03,0x44,0x24,d});
    EmitX64DwordStore(code, 0, c);
    EmitX64DwordLoad(code, 2, b);
    code.Raw({0x31,0xC2,0xC1,0xC2,0x07});
    EmitX64DwordStore(code, 2, b);
}

void EmitX86QuarterRound(
    CodeBuffer& code,
    uint8_t a,
    uint8_t b,
    uint8_t c,
    uint8_t d)
{
    // ESI points at the 16-word working state.
    code.Raw({0x8B,0x46,a,0x03,0x46,b,0x89,0x46,a,
              0x8B,0x56,d,0x31,0xC2,0xC1,0xC2,0x10,0x89,0x56,d,
              0x8B,0x46,c,0x03,0x46,d,0x89,0x46,c,
              0x8B,0x56,b,0x31,0xC2,0xC1,0xC2,0x0C,0x89,0x56,b,
              0x8B,0x46,a,0x03,0x46,b,0x89,0x46,a,
              0x8B,0x56,d,0x31,0xC2,0xC1,0xC2,0x08,0x89,0x56,d,
              0x8B,0x46,c,0x03,0x46,d,0x89,0x46,c,
              0x8B,0x56,b,0x31,0xC2,0xC1,0xC2,0x07,0x89,0x56,b});
}

void EmitChaChaDoubleRoundX64(CodeBuffer& code, uint8_t state) {
    const auto o = [state](uint8_t word) {
        return static_cast<uint8_t>(state + word * 4u);
    };
    EmitX64QuarterRound(code, o(0), o(4), o(8), o(12));
    EmitX64QuarterRound(code, o(1), o(5), o(9), o(13));
    EmitX64QuarterRound(code, o(2), o(6), o(10), o(14));
    EmitX64QuarterRound(code, o(3), o(7), o(11), o(15));
    EmitX64QuarterRound(code, o(0), o(5), o(10), o(15));
    EmitX64QuarterRound(code, o(1), o(6), o(11), o(12));
    EmitX64QuarterRound(code, o(2), o(7), o(8), o(13));
    EmitX64QuarterRound(code, o(3), o(4), o(9), o(14));
}

void EmitChaChaDoubleRoundX86(CodeBuffer& code) {
    const auto o = [](uint8_t word) { return static_cast<uint8_t>(word * 4u); };
    EmitX86QuarterRound(code, o(0), o(4), o(8), o(12));
    EmitX86QuarterRound(code, o(1), o(5), o(9), o(13));
    EmitX86QuarterRound(code, o(2), o(6), o(10), o(14));
    EmitX86QuarterRound(code, o(3), o(7), o(11), o(15));
    EmitX86QuarterRound(code, o(0), o(5), o(10), o(15));
    EmitX86QuarterRound(code, o(1), o(6), o(11), o(12));
    EmitX86QuarterRound(code, o(2), o(7), o(8), o(13));
    EmitX86QuarterRound(code, o(3), o(4), o(9), o(14));
}

bool BuildOperandDecoder(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    CodeBuffer code(config.layout.operandDecoderOffset);
    SeedStream random(config.buildSeed, 0x454E545259444543ULL ^ 0x4F504552ULL);
    EmitCet(code, x64, config.emitCetLandingPads);
    const uint32_t decoderBegin = code.ImageOffset();
    const size_t readByte = code.NewLabel();
    constexpr uint32_t planVariant =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_DECODE_PLAN, variant));
    constexpr uint32_t planOperands =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_DECODE_PLAN, operands));
    constexpr uint32_t operandKind =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, kind));
    constexpr uint32_t operandCanonical =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, canonicalIndex));
    constexpr uint32_t operandFixedWidth =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, fixedWidth));
    constexpr uint32_t operandBias =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, u8Bias));
    constexpr uint32_t operandXor =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, u8Xor));
    constexpr uint32_t operandRotate =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, u8Rotate));
    constexpr uint32_t operandByteOrder =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, byteOrder));
    constexpr uint32_t operandByteXor =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, byteXor));
    constexpr uint32_t operandVarintXor =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, varintXor));
    constexpr uint32_t operandVarintRotate =
        static_cast<uint32_t>(offsetof(VM_RUNTIME_OPERAND_DECODE_PLAN, varintRotate));
    constexpr uint32_t codecInverse = CtxOperandCodec +
        static_cast<uint32_t>(offsetof(VM_OPERAND_CODEC, affineInverse));

    if (x64) {
        std::vector<std::pair<uint8_t, uint8_t>> pushes;
        const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
            code.Raw(bytes);
            pushes.push_back({static_cast<uint8_t>(code.Offset()), reg});
        };
        push({0x53},3); push({0x55},5); push({0x56},6); push({0x57},7);
        push({0x41,0x54},12); push({0x41,0x57},15);
        constexpr uint32_t decoderStack = 0x28u;
        code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(decoderStack)});
        const uint8_t decoderProlog = static_cast<uint8_t>(code.Offset());
        code.Raw({0x49,0x89,0xCF});             // r15=context

        const size_t fail = code.NewLabel();
        const size_t unsupported = code.NewLabel();
        const size_t fields = code.NewLabel();
        const size_t oneByte = code.NewLabel();
        const size_t fixedWidth = code.NewLabel();
        const size_t fixedLoop = code.NewLabel();
        const size_t varint = code.NewLabel();
        const size_t varintLoop = code.NewLabel();
        const size_t store = code.NewLabel();
        const size_t decoded = code.NewLabel();
        const size_t epilog = code.NewLabel();

        code.Raw({0x4C,0x89,0xF9}); code.CallLabel(readByte);
        code.Raw({0x85,0xC0}); code.Jcc32(0x88, fail);
        code.Raw({0x49,0x8B,0x8F}); code.U32(CtxReverseOpcodeMap);
        code.Raw({0x0F,0xB6,0x04,0x01,0x3D}); code.U32(VM_UOP_COUNT);
        code.Jcc32(0x83, unsupported);
        code.Raw({0x41,0x88,0x87}); code.U32(CtxCurrentSemantic);
        code.Raw({0x49,0x8B,0x9F}); code.U32(CtxDecodePlans);
        code.Raw({0x69,0xC0}); code.U32(sizeof(VM_RUNTIME_DECODE_PLAN));
        code.Raw({0x48,0x01,0xC3});             // rbx=plan

        code.Raw({0x4C,0x89,0xF9}); code.CallLabel(readByte);
        code.Raw({0x85,0xC0}); code.Jcc32(0x88, fail);
        code.Raw({0x8A,0x8B}); code.U32(planVariant + operandRotate);
        code.Raw({0xD2,0xC8});
        code.Raw({0x32,0x83}); code.U32(planVariant + operandXor);
        code.Raw({0x2A,0x83}); code.U32(planVariant + operandBias);
        code.Raw({0x41,0x0F,0xB6,0x8F}); code.U32(codecInverse);
        code.Raw({0x0F,0xAF,0xC1,0x25}); code.U32(config.variantCount - 1u);
        code.Raw({0x41,0x88,0x87}); code.U32(CtxCurrentVariant);
        // Keep the encoded-field cursor separate from r12, which is the
        // decoded 64-bit value accumulator.  Reusing r12 for both made the
        // second field index depend on the first decoded operand.
        code.Raw({0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00});

        code.Bind(fields);
        code.Raw({0x8A,0x44,0x24,0x20,0x3A,0x43,0x02});
        code.Jcc32(0x83, decoded);
        code.Raw({0x0F,0xB6,0x4C,0x24,0x20,
                  0x0F,0xB6,0x6C,0x0B,0x03}); // ebp=canonical
        code.Raw({0x6B,0xED,static_cast<uint8_t>(sizeof(VM_RUNTIME_OPERAND_DECODE_PLAN))});
        code.Raw({0x48,0x8D,0xAC,0x2B}); code.U32(planOperands);
        code.Raw({0x0F,0xB6,0x7D,static_cast<uint8_t>(operandFixedWidth)});
        code.Raw({0x83,0xFF,0x01}); code.Jcc32(0x84, oneByte);
        code.Raw({0x85,0xFF}); code.Jcc32(0x84, varint);
        code.Raw({0x83,0xFF,0x08}); code.Jcc32(0x87, fail);
        code.Jmp32(fixedWidth);

        code.Bind(oneByte);
        code.Raw({0x4C,0x89,0xF9}); code.CallLabel(readByte);
        code.Raw({0x85,0xC0}); code.Jcc32(0x88, fail);
        code.Raw({0x8A,0x4D,static_cast<uint8_t>(operandRotate),0xD2,0xC8,
                  0x32,0x45,static_cast<uint8_t>(operandXor),
                  0x2A,0x45,static_cast<uint8_t>(operandBias)});
        code.Raw({0x41,0x0F,0xB6,0x8F}); code.U32(codecInverse);
        code.Raw({0x0F,0xAF,0xC1,0x44,0x0F,0xB6,0xE0});
        code.Jmp32(store);

        code.Bind(fixedWidth);
        code.Raw({0x45,0x31,0xE4,0x31,0xF6}); // value r12, j esi
        code.Bind(fixedLoop);
        code.Raw({0x39,0xFE}); code.Jcc32(0x83, store);
        code.Raw({0x4C,0x89,0xF9}); code.CallLabel(readByte);
        code.Raw({0x85,0xC0}); code.Jcc32(0x88, fail);
        code.Raw({0x32,0x44,0x35,static_cast<uint8_t>(operandByteXor)});
        code.Raw({0x0F,0xB6,0x4C,0x35,static_cast<uint8_t>(operandByteOrder),
                  0xC1,0xE1,0x03,0x48,0xD3,0xE0,0x49,0x09,0xC4,0xFF,0xC6});
        code.Jmp32(fixedLoop);

        code.Bind(varint);
        code.Raw({0x45,0x31,0xE4,0x31,0xF6,0x31,0xFF}); // value,chunk,shift
        code.Bind(varintLoop);
        code.Raw({0x83,0xFE,0x0A}); code.Jcc32(0x83, fail);
        code.Raw({0x4C,0x89,0xF9}); code.CallLabel(readByte);
        code.Raw({0x85,0xC0}); code.Jcc32(0x88, fail);
        code.Raw({0x89,0xC2,0x83,0xE0,0x7F});
        code.Raw({0x0F,0xB6,0x4C,0x35,static_cast<uint8_t>(operandVarintRotate)});
        // Rotate-right in a seven-bit lane.
        code.Raw({0x41,0x89,0xC0,0x41,0xD3,0xE8,
                  0x41,0xB9,0x07,0x00,0x00,0x00,0x41,0x29,0xC9,
                  0x44,0x89,0xC9,0xD3,0xE0,0x44,0x09,0xC0,0x83,0xE0,0x7F});
        code.Raw({0x32,0x44,0x35,static_cast<uint8_t>(operandVarintXor)});
        const size_t canonicalVarint = code.NewLabel();
        code.Raw({0xF6,0xC2,0x80}); code.Jcc32(0x85, canonicalVarint);
        code.Raw({0x85,0xF6}); code.Jcc32(0x84, canonicalVarint);
        code.Raw({0x85,0xC0}); code.Jcc32(0x84, fail);
        code.Bind(canonicalVarint);
        const size_t shiftNot63 = code.NewLabel();
        code.Raw({0x83,0xFF,0x3F}); code.Jcc32(0x85, shiftNot63);
        code.Raw({0x83,0xF8,0x01}); code.Jcc32(0x87, fail);
        code.Bind(shiftNot63);
        code.Raw({0x89,0xF9,0x48,0xD3,0xE0,0x49,0x09,0xC4,
                  0xFF,0xC6,0x83,0xC7,0x07,0xF6,0xC2,0x80});
        code.Jcc32(0x85, varintLoop);
        code.Raw({0x80,0x7D,static_cast<uint8_t>(operandKind),VM_MICRO_OPERAND_VAR_SINT});
        const size_t unsignedValue = code.NewLabel(); code.Jcc32(0x85, unsignedValue);
        code.Raw({0x4C,0x89,0xE0,0x48,0xD1,0xE8,0x49,0x83,0xE4,0x01,
                  0x49,0xF7,0xDC,0x49,0x31,0xC4});
        code.Bind(unsignedValue);

        code.Bind(store);
        code.Raw({0x0F,0xB6,0x45,static_cast<uint8_t>(operandCanonical)});
        code.Raw({0x4D,0x89,0xA4,0xC7}); code.U32(CtxDecodedOperands);
        code.Raw({0xFF,0x44,0x24,0x20});
        code.Jmp32(fields);

        code.Bind(decoded);
        code.Raw({0x8A,0x44,0x24,0x20,0x41,0x88,0x87});
        code.U32(CtxDecodedOperandCount);
        code.Raw({0x4D,0x8B,0xAF}); code.U32(CtxVip); // VM ABI VIP
        code.Raw({0x41,0x0F,0xB6,0x87}); code.U32(CtxCurrentSemantic);
        code.Raw({0x49,0x8B,0x8F}); code.U32(CtxSemanticToSlot);
        code.Raw({0x0F,0xB6,0x0C,0x01,0x80,0xF9,VM_HANDLER_INVALID});
        code.Jcc32(0x84, unsupported);
        code.Raw({0x6B,0xC9,static_cast<uint8_t>(config.variantCount)});
        code.Raw({0x41,0x0F,0xB6,0x97}); code.U32(CtxCurrentVariant);
        code.Raw({0x01,0xD1,0x49,0x8B,0x04,0xCE,0x48,0x85,0xC0});
        code.Jcc32(0x84, unsupported);
        code.Jmp32(epilog);

        code.Bind(unsupported);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_OPCODE_UNSUPPORTED);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0x31,0xC0}); code.Jmp32(epilog);
        code.Bind(fail);
        const size_t hasError = code.NewLabel();
        code.Raw({0x41,0x83,0xBF}); code.U32(CtxError); code.U8(0);
        code.Jcc32(0x85, hasError);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_BYTECODE_RANGE);
        code.Bind(hasError);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0x31,0xC0});
        code.Bind(epilog);
        code.Raw({0x48,0x83,0xC4,static_cast<uint8_t>(decoderStack),
                  0x41,0x5F,0x41,0x5C,0x5F,0x5E,0x5D,0x5B,0xC3});
        const uint32_t decoderEnd = code.CurrentImageOffset();
        AddX64Unwind(result.unwindRecords, decoderBegin, decoderEnd,
            decoderProlog, decoderStack, pushes);

        // read_decoded_byte(context): authenticated ChaCha20 is applied on
        // demand. rollingKey==0 is reserved for verifier/tests that provide a
        // pre-decrypted context; the public entry always supplies a record key.
        code.Bind(readByte);
        const uint32_t readerBegin = code.CurrentImageOffset();
        EmitCet(code, true, config.emitCetLandingPads);
        std::vector<std::pair<uint8_t, uint8_t>> readerPushes;
        const auto rpush = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
            code.Raw(bytes);
            readerPushes.push_back({static_cast<uint8_t>(code.CurrentImageOffset() - readerBegin), reg});
        };
        rpush({0x53},3); rpush({0x55},5); rpush({0x56},6); rpush({0x57},7);
        rpush({0x41,0x54},12); rpush({0x41,0x55},13);
        rpush({0x41,0x56},14); rpush({0x41,0x57},15);
        constexpr uint32_t readerStack = 0xA8u;
        code.Raw({0x48,0x81,0xEC}); code.U32(readerStack);
        const uint8_t readerProlog = static_cast<uint8_t>(code.CurrentImageOffset() - readerBegin);
        code.Raw({0x49,0x89,0xCF});
        const size_t readerFail = code.NewLabel();
        const size_t readerPlain = code.NewLabel();
        const size_t readerRounds = code.NewLabel();
        const size_t readerDone = code.NewLabel();
        code.Raw({0x4D,0x8B,0xAF}); code.U32(CtxVip);
        code.Raw({0x4D,0x3B,0xAF}); code.U32(CtxBytecodeEnd);
        code.Jcc32(0x83, readerFail);
        code.Raw({0x4D,0x8B,0xA7}); code.U32(CtxRollingKey);
        code.Raw({0x4D,0x85,0xE4}); code.Jcc32(0x84, readerPlain);
        code.Raw({0x4D,0x89,0xEE,0x4D,0x2B,0xB7}); code.U32(CtxBytecodeBegin);
        code.Raw({0x4C,0x89,0xF0,0x48,0xC1,0xE8,0x06,
                  0x48,0x3D,0xFE,0xFF,0xFF,0xFF});
        code.Jcc32(0x87, readerFail);
        // Keep r13 as the ciphertext/VIP pointer.  The prior encoding put the
        // ChaCha counter in r13d, zero-extending and destroying that pointer.
        code.Raw({0x44,0x8D,0x58,0x01});       // counter in r11d
        // Initial state at rsp+60, working state at rsp+20.
        const auto put = [&](uint8_t off, uint32_t value) {
            code.Raw({0xC7,0x44,0x24,off}); code.U32(value);
        };
        put(0x60,0x61707865u); put(0x64,0x3320646Eu);
        put(0x68,0x79622D32u); put(0x6C,0x6B206574u);
        for (uint8_t i = 0; i < 8; ++i) {
            code.Raw({0x41,0x8B,static_cast<uint8_t>(0x44u | ((i & 0u) << 3u)),0x24,i * 4u});
            // The previous compact encoding is replaced by the canonical
            // mov eax,[r12+disp8] form.
            code.bytes.resize(code.bytes.size() - 5u);
            code.Raw({0x41,0x8B,0x44,0x24,static_cast<uint8_t>(i * 4u)});
            EmitX64DwordStore(code, 0, static_cast<uint8_t>(0x70u + i * 4u));
        }
        code.Raw({0x44,0x89,0x5C,0x24,0x90}); // counter (r11d)
        code.Raw({0x49,0x8B,0x9F}); code.U32(CtxRecord);
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 0u); EmitX64DwordStore(code,0,0x94);
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 4u); EmitX64DwordStore(code,0,0x98);
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 8u); EmitX64DwordStore(code,0,0x9C);
        code.Raw({0xF3,0x0F,0x6F,0x44,0x24,0x60,0xF3,0x0F,0x7F,0x44,0x24,0x20,
                  0xF3,0x0F,0x6F,0x44,0x24,0x70,0xF3,0x0F,0x7F,0x44,0x24,0x30,
                  0xF3,0x0F,0x6F,0x44,0x24,0x80,0xF3,0x0F,0x7F,0x44,0x24,0x40,
                  0xF3,0x0F,0x6F,0x44,0x24,0x90,0xF3,0x0F,0x7F,0x44,0x24,0x50});
        code.U8(0xBF); code.U32(10);
        code.Bind(readerRounds);
        EmitChaChaDoubleRoundX64(code, 0x20);
        code.Raw({0xFF,0xCF}); code.Jcc32(0x85, readerRounds);
        code.Raw({0x44,0x89,0xF3,0x83,0xE3,0x3F,0x89,0xD9,0xC1,0xE9,0x02,
                  0x8B,0x44,0x8C,0x20,0x03,0x44,0x8C,0x60,
                  0x89,0xD9,0x83,0xE1,0x03,0xC1,0xE1,0x03,0xD3,0xE8,
                  0x41,0x0F,0xB6,0x55,0x00,0x31,0xD0,0x0F,0xB6,0xC0,
                  0x49,0xFF,0xC5,0x4D,0x89,0xAF}); code.U32(CtxVip);
        code.Jmp32(readerDone);
        code.Bind(readerPlain);
        code.Raw({0x41,0x0F,0xB6,0x45,0x00,0x49,0xFF,0xC5,
                  0x4D,0x89,0xAF}); code.U32(CtxVip);
        code.Jmp32(readerDone);
        code.Bind(readerFail);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_BYTECODE_RANGE);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0xB8,0xFF,0xFF,0xFF,0xFF});
        code.Bind(readerDone);
        code.Raw({0x48,0x81,0xC4}); code.U32(readerStack);
        code.Raw({0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
                  0x5F,0x5E,0x5D,0x5B,0xC3});
        const uint32_t readerEnd = code.CurrentImageOffset();
        AddX64Unwind(result.unwindRecords, readerBegin, readerEnd,
            readerProlog, readerStack, readerPushes);
        if (!code.Resolve(result.error)) return false;
    } else {
        // x86 decoder keeps EDI=context, EBX=dispatch and ESI=VIP across the
        // direct-threaded chain.  It uses the same precomputed plan ABI.
        // EBX/ESI intentionally leave this routine as the VM ABI dispatch/VIP
        // registers. The validation entry owns and restores the host values.
        code.Raw({0x55,0x8B,0xEC,0x57,0x83,0xEC,0x30,0x8B,0x7D,0x08});
        const size_t fail = code.NewLabel();
        const size_t unsupported = code.NewLabel();
        const size_t fields = code.NewLabel();
        const size_t oneByte = code.NewLabel();
        const size_t fixedWidth = code.NewLabel();
        const size_t fixedLoop = code.NewLabel();
        const size_t varint = code.NewLabel();
        const size_t varintLoop = code.NewLabel();
        const size_t store = code.NewLabel();
        const size_t decoded = code.NewLabel();
        const size_t epilog = code.NewLabel();
        code.Raw({0x57}); code.CallLabel(readByte); code.Raw({0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x88, fail);
        code.Raw({0x8B,0x8F}); code.U32(CtxReverseOpcodeMap);
        code.Raw({0x0F,0xB6,0x04,0x01,0x3D}); code.U32(VM_UOP_COUNT);
        code.Jcc32(0x83, unsupported);
        code.Raw({0x88,0x87}); code.U32(CtxCurrentSemantic);
        code.Raw({0x8B,0x9F}); code.U32(CtxDecodePlans);
        code.Raw({0x69,0xC0}); code.U32(sizeof(VM_RUNTIME_DECODE_PLAN)); code.Raw({0x01,0xC3});
        code.Raw({0x57}); code.CallLabel(readByte); code.Raw({0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x88, fail);
        code.Raw({0x8A,0x8B}); code.U32(planVariant + operandRotate);
        code.Raw({0xD2,0xC8,0x32,0x83}); code.U32(planVariant + operandXor);
        code.Raw({0x2A,0x83}); code.U32(planVariant + operandBias);
        code.Raw({0x0F,0xB6,0x8F}); code.U32(codecInverse);
        code.Raw({0x0F,0xAF,0xC1,0x25}); code.U32(config.variantCount - 1u);
        code.Raw({0x88,0x87}); code.U32(CtxCurrentVariant);
        code.Raw({0xC7,0x45,0xF0,0x00,0x00,0x00,0x00});
        code.Bind(fields);
        code.Raw({0x8B,0x45,0xF0,0x3A,0x43,0x02}); code.Jcc32(0x83, decoded);
        code.Raw({0x0F,0xB6,0x74,0x03,0x03,0x6B,0xF6,
                  static_cast<uint8_t>(sizeof(VM_RUNTIME_OPERAND_DECODE_PLAN)),
                  0x8D,0xB4,0x33}); code.U32(planOperands);
        code.Raw({0x0F,0xB6,0x56,static_cast<uint8_t>(operandFixedWidth),0x89,0x55,0xEC,
                  0x83,0xFA,0x01}); code.Jcc32(0x84, oneByte);
        code.Raw({0x85,0xD2}); code.Jcc32(0x84, varint);
        code.Raw({0x83,0xFA,0x08}); code.Jcc32(0x87, fail); code.Jmp32(fixedWidth);
        code.Bind(oneByte);
        code.Raw({0x57}); code.CallLabel(readByte); code.Raw({0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x88, fail);
        code.Raw({0x8A,0x4E,static_cast<uint8_t>(operandRotate),0xD2,0xC8,
                  0x32,0x46,static_cast<uint8_t>(operandXor),
                  0x2A,0x46,static_cast<uint8_t>(operandBias)});
        code.Raw({0x0F,0xB6,0x8F}); code.U32(codecInverse);
        // The affine inverse is modulo 256.  IMUL leaves the full product in
        // EAX; truncate through AL before publishing the canonical operand.
        code.Raw({0x0F,0xAF,0xC1,0x0F,0xB6,0xC0,
                  0x89,0x45,0xE8,0xC7,0x45,0xE4,0x00,0x00,0x00,0x00});
        code.Jmp32(store);
        code.Bind(fixedWidth);
        code.Raw({0xC7,0x45,0xE8,0x00,0x00,0x00,0x00,
                  0xC7,0x45,0xE4,0x00,0x00,0x00,0x00,
                  0xC7,0x45,0xE0,0x00,0x00,0x00,0x00});
        code.Bind(fixedLoop);
        code.Raw({0x8B,0x45,0xE0,0x3B,0x45,0xEC}); code.Jcc32(0x83, store);
        code.Raw({0x57}); code.CallLabel(readByte); code.Raw({0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x88, fail);
        code.Raw({0x8B,0x4D,0xE0,0x32,0x44,0x0E,static_cast<uint8_t>(operandByteXor),
                  0x0F,0xB6,0x4C,0x0E,static_cast<uint8_t>(operandByteOrder),
                  0x83,0xF9,0x08});
        code.Jcc32(0x83, fail);
        const size_t fixedHigh = code.NewLabel();
        const size_t fixedNext = code.NewLabel();
        code.Raw({0x83,0xF9,0x04}); code.Jcc32(0x83, fixedHigh);
        code.Raw({0xC1,0xE1,0x03,0xD3,0xE0,0x09,0x45,0xE8});
        code.Jmp32(fixedNext);
        code.Bind(fixedHigh);
        code.Raw({0x83,0xE9,0x04,0xC1,0xE1,0x03,0xD3,0xE0,
                  0x09,0x45,0xE4});
        code.Bind(fixedNext);
        code.Raw({0xFF,0x45,0xE0}); code.Jmp32(fixedLoop);
        code.Bind(varint);
        code.Raw({0xC7,0x45,0xE8,0x00,0x00,0x00,0x00,
                  0xC7,0x45,0xE4,0x00,0x00,0x00,0x00,
                  0xC7,0x45,0xE0,0x00,0x00,0x00,0x00,
                  0xC7,0x45,0xDC,0x00,0x00,0x00,0x00});
        code.Bind(varintLoop);
        code.Raw({0x83,0x7D,0xE0,0x0A}); code.Jcc32(0x83, fail);
        code.Raw({0x57}); code.CallLabel(readByte); code.Raw({0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x88, fail);
        code.Raw({0x89,0x45,0xD8,0x83,0xE0,0x7F,0x8B,0x4D,0xE0,
                  0x0F,0xB6,0x4C,0x0E,static_cast<uint8_t>(operandVarintRotate),
                  0x89,0xC2,0xD3,0xEA,0x89,0x4D,0xD0,
                  0xB9,0x07,0x00,0x00,0x00,0x2B,0x4D,0xD0,
                  0xD3,0xE0,0x09,0xD0,0x83,0xE0,0x7F,
                  0x8B,0x4D,0xE0,0x32,0x44,0x0E,static_cast<uint8_t>(operandVarintXor),
                  });
        code.Raw({0x89,0x45,0xD4});           // decoded seven-bit raw chunk
        const size_t xShiftInRange = code.NewLabel();
        code.Raw({0x83,0x7D,0xDC,0x3F}); code.Jcc32(0x85, xShiftInRange);
        code.Raw({0x83,0xF8,0x01}); code.Jcc32(0x87, fail);
        code.Bind(xShiftInRange);
        const size_t xCanonicalVarint = code.NewLabel();
        code.Raw({0xF6,0x45,0xD8,0x80}); code.Jcc32(0x85, xCanonicalVarint);
        code.Raw({0x83,0x7D,0xE0,0x00}); code.Jcc32(0x84, xCanonicalVarint);
        code.Raw({0x85,0xC0}); code.Jcc32(0x84, fail);
        code.Bind(xCanonicalVarint);
        const size_t xVarintHigh = code.NewLabel();
        const size_t xVarintAccumulated = code.NewLabel();
        code.Raw({0x8B,0x4D,0xDC,0x83,0xF9,0x20});
        code.Jcc32(0x83, xVarintHigh);
        code.Raw({0x8B,0x45,0xD4,0x31,0xD2,0x0F,0xA5,0xC2,0xD3,0xE0,
                  0x09,0x45,0xE8,0x09,0x55,0xE4});
        code.Jmp32(xVarintAccumulated);
        code.Bind(xVarintHigh);
        code.Raw({0x83,0xE9,0x20,0x8B,0x45,0xD4,0xD3,0xE0,
                  0x09,0x45,0xE4});
        code.Bind(xVarintAccumulated);
        code.Raw({0xFF,0x45,0xE0,0x83,0x45,0xDC,0x07,
                  0xF6,0x45,0xD8,0x80}); code.Jcc32(0x85, varintLoop);
        code.Raw({0x80,0x7E,static_cast<uint8_t>(operandKind),VM_MICRO_OPERAND_VAR_SINT});
        const size_t xu = code.NewLabel(); code.Jcc32(0x85, xu);
        code.Raw({0x8B,0x45,0xE8,0x8B,0x55,0xE4,0x89,0xC1,0x83,0xE1,0x01,
                  0x0F,0xAC,0xD0,0x01,0xD1,0xEA,0xF7,0xD9,
                  0x31,0xC8,0x31,0xCA,0x89,0x45,0xE8,0x89,0x55,0xE4});
        code.Bind(xu);
        code.Bind(store);
        code.Raw({0x0F,0xB6,0x46,static_cast<uint8_t>(operandCanonical),
                  0x8B,0x55,0xE8,0x89,0x94,0xC7}); code.U32(CtxDecodedOperands);
        code.Raw({0x8B,0x55,0xE4,0x89,0x94,0xC7}); code.U32(CtxDecodedOperands + 4u);
        code.Raw({0xFF,0x45,0xF0}); code.Jmp32(fields);
        code.Bind(decoded);
        code.Raw({0x8A,0x45,0xF0,0x88,0x87}); code.U32(CtxDecodedOperandCount);
        code.Raw({0x8B,0xB7}); code.U32(CtxVip);
        code.Raw({0x0F,0xB6,0x87}); code.U32(CtxCurrentSemantic);
        code.Raw({0x8B,0x8F}); code.U32(CtxSemanticToSlot);
        code.Raw({0x0F,0xB6,0x0C,0x01,0x80,0xF9,VM_HANDLER_INVALID});
        code.Jcc32(0x84, unsupported);
        code.Raw({0x6B,0xC9,static_cast<uint8_t>(config.variantCount)});
        code.Raw({0x0F,0xB6,0x97}); code.U32(CtxCurrentVariant);
        code.Raw({0x01,0xD1,0x8B,0x9F}); code.U32(CtxDispatchTable);
        code.Raw({0x8B,0x04,0x8B,0x85,0xC0}); code.Jcc32(0x84, unsupported);
        code.Jmp32(epilog);
        code.Bind(unsupported);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_OPCODE_UNSUPPORTED);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0x31,0xC0}); code.Jmp32(epilog);
        code.Bind(fail);
        const size_t xhas = code.NewLabel();
        code.Raw({0x83,0xBF}); code.U32(CtxError); code.U8(0); code.Jcc32(0x85, xhas);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_BYTECODE_RANGE);
        code.Bind(xhas); code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0x31,0xC0});
        code.Bind(epilog);
        code.Raw({0x83,0xC4,0x30,0x5F,0x8B,0xE5,0x5D,0xC3});

        code.Bind(readByte);
        EmitCet(code, false, config.emitCetLandingPads);
        code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x81,0xEC}); code.U32(0x98);
        code.Raw({0x8B,0x7D,0x08,0x8B,0xB7}); code.U32(CtxVip);
        const size_t xReaderFail = code.NewLabel();
        const size_t xReaderPlain = code.NewLabel();
        const size_t xRounds = code.NewLabel();
        const size_t xReaderDone = code.NewLabel();
        code.Raw({0x3B,0xB7}); code.U32(CtxBytecodeEnd); code.Jcc32(0x83, xReaderFail);
        code.Raw({0x8B,0x9F}); code.U32(CtxRollingKey);
        code.Raw({0x85,0xDB}); code.Jcc32(0x84, xReaderPlain);
        code.Raw({0x8B,0xC6,0x2B,0x87}); code.U32(CtxBytecodeBegin);
        code.Raw({0x89,0x45,0xF0,0xC1,0xE8,0x06,0x3D,0xFE,0xFF,0xFF,0xFF});
        code.Jcc32(0x87, xReaderFail);
        code.Raw({0x40,0x89,0x45,0xEC});
        // initial at esp+48, working at esp+08; saved ciphertext at esp+88.
        // disp8 is signed on x86.  These slots live above +0x7f, so use the
        // canonical SIB + disp32 forms instead of accidentally addressing the
        // caller's stack at esp-0x78/esp-0x80.
        code.Raw({0x89,0xB4,0x24,0x88,0x00,0x00,0x00});
        const auto xput = [&](uint8_t off, uint32_t value) {
            code.Raw({0xC7,0x44,0x24,off}); code.U32(value);
        };
        xput(0x48,0x61707865u); xput(0x4C,0x3320646Eu);
        xput(0x50,0x79622D32u); xput(0x54,0x6B206574u);
        for (uint8_t i = 0; i < 8; ++i) {
            code.Raw({0x8B,0x43,static_cast<uint8_t>(i * 4u),
                      0x89,0x44,0x24,static_cast<uint8_t>(0x58u + i * 4u)});
        }
        code.Raw({0x8B,0x45,0xEC,0x89,0x44,0x24,0x78,
                  0x8B,0x9F}); code.U32(CtxRecord);
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 0u); code.Raw({0x89,0x44,0x24,0x7C});
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 4u);
        code.Raw({0x89,0x84,0x24,0x80,0x00,0x00,0x00});
        code.Raw({0x8B,0x83}); code.U32(RecordNonce + 8u);
        code.Raw({0x89,0x84,0x24,0x84,0x00,0x00,0x00});
        code.Raw({0xF3,0x0F,0x6F,0x44,0x24,0x48,0xF3,0x0F,0x7F,0x44,0x24,0x08,
                  0xF3,0x0F,0x6F,0x44,0x24,0x58,0xF3,0x0F,0x7F,0x44,0x24,0x18,
                  0xF3,0x0F,0x6F,0x44,0x24,0x68,0xF3,0x0F,0x7F,0x44,0x24,0x28,
                  0xF3,0x0F,0x6F,0x44,0x24,0x78,0xF3,0x0F,0x7F,0x44,0x24,0x38,
                  0x8D,0x74,0x24,0x08,0xBB,0x0A,0x00,0x00,0x00});
        code.Bind(xRounds); EmitChaChaDoubleRoundX86(code);
        code.Raw({0x4B}); code.Jcc32(0x85, xRounds);
        code.Raw({0x8B,0x4D,0xF0,0x83,0xE1,0x3F,0x89,0xCA,0xC1,0xEA,0x02,
                  0x8B,0x44,0x94,0x08,0x03,0x44,0x94,0x48,
                  0x83,0xE1,0x03,0xC1,0xE1,0x03,0xD3,0xE8,
                  0x8B,0xB4,0x24,0x88,0x00,0x00,0x00,
                  0x0F,0xB6,0x16,0x31,0xD0,0x0F,0xB6,0xC0,
                  0x46,0x89,0xB7}); code.U32(CtxVip); code.Jmp32(xReaderDone);
        code.Bind(xReaderPlain);
        code.Raw({0x0F,0xB6,0x06,0x46,0x89,0xB7}); code.U32(CtxVip); code.Jmp32(xReaderDone);
        code.Bind(xReaderFail);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_BYTECODE_RANGE);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.Raw({0xB8,0xFF,0xFF,0xFF,0xFF});
        code.Bind(xReaderDone);
        code.Raw({0x81,0xC4}); code.U32(0x98);
        code.Raw({0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
        if (!code.Resolve(result.error)) return false;
    }
    EmitSeedIsland(code, random, 96);
    result.operandDecoderCode = std::move(code.bytes);
    return true;
}

void EmitSipRoundX64(CodeBuffer& code) {
    // v0=r8, v1=r9, v2=r10, v3=r11.
    code.Raw({0x4D,0x01,0xC8,0x49,0xC1,0xC1,0x0D,0x4D,0x31,0xC1,
              0x49,0xC1,0xC0,0x20,
              0x4D,0x01,0xDA,0x49,0xC1,0xC3,0x10,0x4D,0x31,0xD3,
              0x4D,0x01,0xD8,0x49,0xC1,0xC3,0x15,0x4D,0x31,0xC3,
              0x4D,0x01,0xCA,0x49,0xC1,0xC1,0x11,0x4D,0x31,0xD1,
              0x49,0xC1,0xC2,0x20});
}

void EmitXmmRol64(CodeBuffer& code, uint8_t reg, uint8_t temporary, uint8_t count) {
    code.Raw({0x66,0x0F,0x6F,
              static_cast<uint8_t>(0xC0u | (temporary << 3u) | reg)});
    code.Raw({0x66,0x0F,0x73,static_cast<uint8_t>(0xF0u | reg),count});
    code.Raw({0x66,0x0F,0x73,static_cast<uint8_t>(0xD0u | temporary),
              static_cast<uint8_t>(64u - count)});
    code.Raw({0x66,0x0F,0xEB,
              static_cast<uint8_t>(0xC0u | (reg << 3u) | temporary)});
}

void EmitSipRoundX86(CodeBuffer& code) {
    // v0=xmm0, v1=xmm1, v2=xmm2, v3=xmm3; xmm4/xmm5 scratch.
    code.Raw({0x66,0x0F,0xD4,0xC1}); EmitXmmRol64(code,1,4,13);
    code.Raw({0x66,0x0F,0xEF,0xC8}); EmitXmmRol64(code,0,4,32);
    code.Raw({0x66,0x0F,0xD4,0xD3}); EmitXmmRol64(code,3,4,16);
    code.Raw({0x66,0x0F,0xEF,0xDA});
    code.Raw({0x66,0x0F,0xD4,0xC3}); EmitXmmRol64(code,3,4,21);
    code.Raw({0x66,0x0F,0xEF,0xD8});
    code.Raw({0x66,0x0F,0xD4,0xD1}); EmitXmmRol64(code,1,4,17);
    code.Raw({0x66,0x0F,0xEF,0xCA}); EmitXmmRol64(code,2,4,32);
}

bool EmitSipHashHelperX64(
    CodeBuffer& code,
    size_t helperLabel,
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    code.Bind(helperLabel);
    const uint32_t begin = code.CurrentImageOffset();
    EmitCet(code, true, config.emitCetLandingPads);
    std::vector<std::pair<uint8_t, uint8_t>> pushes;
    const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
        code.Raw(bytes);
        pushes.push_back({static_cast<uint8_t>(code.CurrentImageOffset() - begin), reg});
    };
    push({0x53},3); push({0x56},6); push({0x57},7);
    push({0x41,0x54},12); push({0x41,0x55},13);
    push({0x41,0x56},14); push({0x41,0x57},15);
    constexpr uint32_t stack = 0x20u;
    code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stack)});
    const uint8_t prolog = static_cast<uint8_t>(code.CurrentImageOffset() - begin);
    code.Raw({0x48,0x89,0xCE,0x48,0x89,0xD7,0x4C,0x89,0xC3,
              0x45,0x89,0xCC});
    code.Raw({0x48,0x8B,0x03,0x48,0x8B,0x53,0x08,
              0x49,0xB8}); code.U64(0x736F6D6570736575ULL);
    code.Raw({0x49,0x31,0xC0,0x49,0xB9}); code.U64(0x646F72616E646F6DULL);
    code.Raw({0x49,0x31,0xD1,0x49,0xBA}); code.U64(0x6C7967656E657261ULL);
    code.Raw({0x49,0x31,0xC2,0x49,0xBB}); code.U64(0x7465646279746573ULL);
    code.Raw({0x49,0x31,0xD3,0x45,0x31,0xED,0x45,0x31,0xF6,0x45,0x31,0xFF});
    const size_t loop = code.NewLabel();
    const size_t nonzeroByte = code.NewLabel();
    const size_t append = code.NewLabel();
    const size_t next = code.NewLabel();
    const size_t finish = code.NewLabel();
    code.Bind(loop);
    code.Raw({0x49,0x39,0xFD}); code.Jcc32(0x83, finish);
    code.Raw({0x42,0x0F,0xB6,0x04,0x2E});
    code.Raw({0x41,0x83,0xFC,0xFF}); code.Jcc32(0x84, nonzeroByte);
    code.Raw({0x45,0x39,0xE5}); code.Jcc32(0x82, nonzeroByte);
    code.Raw({0x41,0x8D,0x54,0x24,0x08,0x41,0x39,0xD5});
    code.Jcc32(0x83, nonzeroByte);
    code.Raw({0x31,0xC0}); code.Jmp32(append);
    code.Bind(nonzeroByte);
    code.Bind(append);
    code.Raw({0x44,0x89,0xF9,0xC1,0xE1,0x03,
              0x48,0xD3,0xE0,0x49,0x09,0xC6,
              0x41,0xFF,0xC7,0x41,0x83,0xFF,0x08});
    code.Jcc32(0x85, next);
    code.Raw({0x4D,0x31,0xF3}); EmitSipRoundX64(code); EmitSipRoundX64(code);
    code.Raw({0x4D,0x31,0xF0,0x45,0x31,0xF6,0x45,0x31,0xFF});
    code.Bind(next);
    code.Raw({0x49,0xFF,0xC5}); code.Jmp32(loop);
    code.Bind(finish);
    code.Raw({0x48,0x89,0xF8,0x25,0xFF,0x00,0x00,0x00,
              0x48,0xC1,0xE0,0x38,0x49,0x09,0xC6,
              0x4D,0x31,0xF3});
    EmitSipRoundX64(code); EmitSipRoundX64(code);
    code.Raw({0x4D,0x31,0xF0,0x49,0x81,0xF2,0xFF,0x00,0x00,0x00});
    EmitSipRoundX64(code); EmitSipRoundX64(code);
    EmitSipRoundX64(code); EmitSipRoundX64(code);
    code.Raw({0x4C,0x89,0xC0,0x4C,0x31,0xC8,0x4C,0x31,0xD0,0x4C,0x31,0xD8,
              0x48,0x83,0xC4,static_cast<uint8_t>(stack),
              0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
              0x5F,0x5E,0x5B,0xC3});
    const uint32_t end = code.CurrentImageOffset();
    AddX64Unwind(result.unwindRecords, begin, end, prolog, stack, pushes);
    return true;
}

bool EmitHChaChaHelperX64(
    CodeBuffer& code,
    size_t helperLabel,
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    code.Bind(helperLabel);
    const uint32_t begin = code.CurrentImageOffset();
    EmitCet(code, true, config.emitCetLandingPads);
    std::vector<std::pair<uint8_t, uint8_t>> pushes;
    const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
        code.Raw(bytes);
        pushes.push_back({static_cast<uint8_t>(code.CurrentImageOffset() - begin), reg});
    };
    push({0x53},3); push({0x56},6); push({0x57},7);
    push({0x41,0x54},12); push({0x41,0x55},13);
    constexpr uint32_t stack = 0x68u;
    code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stack)});
    const uint8_t prolog = static_cast<uint8_t>(code.CurrentImageOffset() - begin);
    code.Raw({0x48,0x89,0xCB,0x48,0x89,0xD6,0x45,0x89,0xC4,0x4C,0x89,0xCF});
    const auto put = [&](uint8_t off, uint32_t value) {
        code.Raw({0xC7,0x44,0x24,off}); code.U32(value);
    };
    put(0x20,0x61707865u); put(0x24,0x3320646Eu);
    put(0x28,0x79622D32u); put(0x2C,0x6B206574u);
    for (uint8_t i = 0; i < 8; ++i) {
        code.Raw({0x8B,0x43,static_cast<uint8_t>(i * 4u)});
        EmitX64DwordStore(code,0,static_cast<uint8_t>(0x30u + i * 4u));
    }
    for (uint8_t i = 0; i < 4; ++i) {
        code.Raw({0x8B,0x46,static_cast<uint8_t>(i * 4u)});
        if (i == 3) code.Raw({0x44,0x31,0xE0});
        EmitX64DwordStore(code,0,static_cast<uint8_t>(0x50u + i * 4u));
    }
    code.U8(0xBE); code.U32(10);
    const size_t rounds = code.NewLabel(); code.Bind(rounds);
    EmitChaChaDoubleRoundX64(code,0x20);
    code.Raw({0xFF,0xCE}); code.Jcc32(0x85, rounds);
    const uint8_t outputWords[] = {0,1,2,3,12,13,14,15};
    for (uint8_t i = 0; i < 8; ++i) {
        EmitX64DwordLoad(code,0,static_cast<uint8_t>(0x20u + outputWords[i] * 4u));
        code.Raw({0x89,0x47,static_cast<uint8_t>(i * 4u)});
    }
    code.Raw({0x48,0x83,0xC4,static_cast<uint8_t>(stack),
              0x41,0x5D,0x41,0x5C,0x5F,0x5E,0x5B,0xC3});
    const uint32_t end = code.CurrentImageOffset();
    AddX64Unwind(result.unwindRecords, begin, end, prolog, stack, pushes);
    return true;
}

bool BuildPublicEntryX64(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result,
    CodeBuffer& code,
    size_t sipHash,
    size_t hChaCha)
{
    const uint32_t begin = code.ImageOffset();
    EmitCet(code, true, config.emitCetLandingPads);
    std::vector<std::pair<uint8_t, uint8_t>> pushes;
    const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
        code.Raw(bytes);
        pushes.push_back({static_cast<uint8_t>(code.Offset()), reg});
    };
    push({0x53},3); push({0x55},5); push({0x56},6); push({0x57},7);
    push({0x41,0x54},12); push({0x41,0x55},13);
    push({0x41,0x56},14); push({0x41,0x57},15);
    constexpr uint32_t stack = 0x78u;
    code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stack)});
    const uint8_t prolog = static_cast<uint8_t>(code.Offset());
    code.Raw({0x48,0x89,0xCB,0x41,0x89,0xD4,0x4C,0x89,0xC6,0x4C,0x89,0xCF,
              0x4C,0x8B,0xAC,0x24}); code.U32(stack + 8u * 8u + 0x28u);
    code.Raw({0x48,0x89,0x7C,0x24,0x50}); // preserve image base across rep stosb
    code.Raw({0x45,0x31,0xF6,0x45,0x31,0xFF}); // ctx/record null

    const size_t failMetadata = code.NewLabel();
    const size_t failRecord = code.NewLabel();
    const size_t failRecordInvalid = code.NewLabel();
    const size_t failAuth = code.NewLabel();
    const size_t failRegister = code.NewLabel();
    const size_t failStack = code.NewLabel();
    const size_t failRuntime = code.NewLabel();
    const size_t cleanup = code.NewLabel();
    const size_t wipe = code.NewLabel();
    const size_t recordLoop = code.NewLabel();
    const size_t recordFound = code.NewLabel();
    const size_t keyLoop = code.NewLabel();
    const size_t keyDone = code.NewLabel();

    code.Raw({0x48,0x85,0xDB}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x48,0x85,0xF6}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x48,0x85,0xFF}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x4D,0x85,0xED}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x41,0xF6,0xC5,0x3F}); code.Jcc32(0x85, failMetadata);
    // PE header and SizeOfImage validation.
    code.Raw({0x66,0x81,0x3F,0x4D,0x5A}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x8B,0x47,0x3C,0x3D,0x40,0x00,0x00,0x00}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3D,0x00,0x00,0x10,0x00}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0x3C,0x07,0x50,0x45,0x00,0x00}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x66,0x81,0x7C,0x07,0x18,0x0B,0x02}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x8B,0x6C,0x07,0x50,0x85,0xED}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x48,0x89,0xF0,0x48,0x29,0xF8,0x48,0x39,0xE8});
    code.Jcc32(0x83, failMetadata);
    code.Raw({0x89,0xEA,0x29,0xC2,0x81,0xFA});
    code.U32(sizeof(VM_METADATA_HEADER));
    code.Jcc32(0x82, failMetadata);

    const auto cmpMeta32 = [&](uint32_t offset, uint32_t expected) {
        code.Raw({0x81,0xBE}); code.U32(offset); code.U32(expected);
        code.Jcc32(0x85, failMetadata);
    };
    cmpMeta32(MetaHeaderSize,sizeof(VM_METADATA_HEADER));
    cmpMeta32(MetaMetadataVersion,VM_METADATA_VERSION);
    cmpMeta32(MetaSchemaVersion,VM_SCHEMA_VERSION);
    cmpMeta32(MetaRuntimeVersion,VM_RUNTIME_VERSION);
    cmpMeta32(MetaArchitecture,VM_ARCH_X64);
    cmpMeta32(MetaRecordSize,sizeof(VM_FUNCTION_RECORD));
    cmpMeta32(MetaKeyEncodingVersion,VM_KEY_ENCODING_VERSION);
    cmpMeta32(MetaOpcodeMapSize,VM_OPCODE_MAP_SIZE);
    cmpMeta32(MetaRegisterMapSize,VM_REGISTER_MAP_SIZE);
    cmpMeta32(MetaHandlerTableSize,VM_HANDLER_TABLE_SIZE);
    cmpMeta32(MetaHandlerVariantCount,config.variantCount);
    code.Raw({0x8B,0x86}); code.U32(MetaFlags);
    code.Raw({0x89,0xC1,0x81,0xE1}); code.U32(~kKnownMetadataFlags);
    code.Jcc32(0x85, failMetadata);
    code.Raw({0x25}); code.U32(kRequiredMetadataFlags);
    code.Raw({0x3D}); code.U32(kRequiredMetadataFlags); code.Jcc32(0x85, failMetadata);
    code.Raw({0xF7,0x86}); code.U32(MetaFlags); code.U32(VM_METADATA_FLAG_UNWIND_VERIFIED);
    code.Jcc32(0x84, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaTotalSize);
    code.Raw({0x3D}); code.U32(sizeof(VM_METADATA_HEADER)); code.Jcc32(0x82, failMetadata);
    code.Raw({0x48,0x89,0xF2,0x48,0x29,0xFA,0x39,0xEA});
    code.Jcc32(0x83, failMetadata);
    code.Raw({0x89,0xE9,0x29,0xD1,0x39,0xC8});
    code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaImageSize); code.Raw({0x39,0xE8});
    code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeBaseRVA);
    code.Raw({0x85,0xC0}); code.Jcc32(0x84, failRuntime);
    code.Raw({0x8B,0x96}); code.U32(MetaRuntimeSize);
    code.Raw({0x8B,0x8E}); code.U32(MetaImageSize);
    code.Raw({0x39,0xC8}); code.Jcc32(0x83, failRuntime);
    code.Raw({0x29,0xC1,0x39,0xCA}); code.Jcc32(0x87, failRuntime);
    code.Raw({0x81,0xFA}); code.U32(config.layout.encryptedHandlerOffset +
        config.layout.encryptedHandlerSize); code.Jcc32(0x82, failRuntime);
    code.Raw({0x81,0xFA}); code.U32(config.layout.keyMarkerOffset +
        VM_RUNTIME_KEY_SHARE_SIZE); code.Jcc32(0x82, failRuntime);
    code.Raw({0x8B,0x8E}); code.U32(MetaRuntimeEntryRVA);
    code.Raw({0x05}); code.U32(config.layout.publicEntryOffset);
    code.Jcc32(0x82, failRuntime);
    code.Raw({0x39,0xC1}); code.Jcc32(0x85, failRuntime);
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeBaseRVA);
    code.Raw({0x05}); code.U32(config.layout.keyMarkerOffset);
    code.Jcc32(0x82, failRuntime);
    code.Raw({0x83,0xC0,VM_RUNTIME_KEY_SHARE_SIZE});
    code.Jcc32(0x82, failRuntime);
    code.Raw({0x39,0xE8}); code.Jcc32(0x87, failRuntime);

    // Recover the master key into a private stack slot.
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeBaseRVA);
    code.Raw({0x05}); code.U32(config.layout.keyMarkerOffset);
    code.Raw({0x4C,0x8D,0x1C,0x07,0x45,0x31,0xC0});
    code.Bind(keyLoop);
    code.Raw({0x41,0x83,0xF8,0x20}); code.Jcc32(0x83, keyDone);
    code.Raw({0x42,0x0F,0xB6,0x84,0x06}); code.U32(MetaEncodedMasterKey);
    code.Raw({0x43,0x32,0x04,0x03});
    code.Raw({0x45,0x89,0xC1,0x41,0x83,0xE1,0x0F,
              0x42,0x32,0x84,0x0E}); code.U32(MetaBuildId);
    code.Raw({0x44,0x89,0xC1,0x83,0xE1,0x03,0xC1,0xE1,0x03,
              0x8B,0x96}); code.U32(MetaCookie);
    code.Raw({0xD3,0xEA,0x30,0xD0,
              0x45,0x6B,0xC8,0x5B,0x44,0x30,0xC8,
              0x42,0x88,0x44,0x04,0x30,0x41,0xFF,0xC0});
    code.Jmp32(keyLoop);
    code.Bind(keyDone);

    code.Raw({0x48,0x89,0xF1,0x8B,0x96}); code.U32(MetaTotalSize);
    code.Raw({0x4C,0x8D,0x44,0x24,0x30,0x41,0xB9}); code.U32(MetaMetadataTag);
    code.CallLabel(sipHash);
    code.Raw({0x48,0x33,0x86}); code.U32(MetaMetadataTag);
    code.Jcc32(0x85, failAuth);

    // Authenticated layout/order checks.
    code.Raw({0x8B,0x86}); code.U32(MetaRecordCount);
    code.Raw({0x85,0xC0}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x3D,0x00,0x00,0x10,0x00}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x8E}); code.U32(MetaRecordOffset);
    code.Raw({0x81,0xF9}); code.U32(sizeof(VM_METADATA_HEADER)); code.Jcc32(0x82, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaReverseOpcodeMapOffset);
    code.Raw({0x39,0xD1}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x6B,0xC0,static_cast<uint8_t>(sizeof(VM_FUNCTION_RECORD)),0x01,0xC8});
    code.Jcc32(0x82, failMetadata);
    code.Raw({0x39,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaRegisterMapOffset);
    code.Raw({0x39,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_OPCODE_MAP_SIZE);
    code.Jcc32(0x82, failMetadata);
    code.Raw({0x39,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaSemanticMapOffset);
    code.Raw({0x39,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x83,0xC0,VM_REGISTER_MAP_SIZE}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x39,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaHandlerDescriptorOffset);
    code.Raw({0x39,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_HANDLER_TABLE_SIZE);
    code.Jcc32(0x82, failMetadata);
    code.Raw({0x39,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaHandlerVariantOffset);
    code.Raw({0x39,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x05}); code.U32(VM_HANDLER_TABLE_SIZE); code.Jcc32(0x82, failMetadata);
    code.Raw({0x39,0xD0});
    code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x39,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_HANDLER_TABLE_SIZE);
    code.Jcc32(0x82, failMetadata); code.Raw({0x39,0xC2});
    code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaBytecodeSize);
    code.Raw({0x01,0xD0}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0x86}); code.U32(MetaTotalSize);
    code.Jcc32(0x87, failMetadata);

    // Locate the requested authenticated record.
    code.Raw({0x8B,0x86}); code.U32(MetaRecordOffset);
    code.Raw({0x4C,0x8D,0x3C,0x06,0x31,0xC9});
    code.Bind(recordLoop);
    code.Raw({0x3B,0x8E}); code.U32(MetaRecordCount); code.Jcc32(0x83, failRecord);
    code.Raw({0x45,0x39,0x27}); code.Jcc32(0x84, recordFound);
    code.Raw({0x49,0x83,0xC7,static_cast<uint8_t>(sizeof(VM_FUNCTION_RECORD)),0xFF,0xC1});
    code.Jmp32(recordLoop);
    code.Bind(recordFound);
    code.Raw({0x41,0x8B,0x47,static_cast<uint8_t>(RecordBytecodeSize),0x85,0xC0});
    code.Jcc32(0x84, failRecordInvalid);
    code.Raw({0x41,0x8B,0x4F,static_cast<uint8_t>(RecordBytecodeOffset),
              0x3B,0x8E}); code.U32(MetaBytecodeSize); code.Jcc32(0x87, failRecordInvalid);
    code.Raw({0x01,0xC1,0x3B,0x8E}); code.U32(MetaBytecodeSize); code.Jcc32(0x87, failRecordInvalid);
    code.Raw({0x41,0x8B,0x4F,static_cast<uint8_t>(RecordFlags),0x89,0xCA,
              0x81,0xE2}); code.U32(~kKnownRecordFlags); code.Jcc32(0x85, failRecordInvalid);
    constexpr uint32_t requiredX64RecordFlags = VM_RECORD_FLAG_X64 |
        VM_RECORD_FLAG_NATIVE_BODY_DESTROYED | VM_RECORD_FLAG_UNWIND_VERIFIED |
        VM_RECORD_FLAG_CFG_VERIFIED;
    code.Raw({0x89,0xCA,0x81,0xE2}); code.U32(requiredX64RecordFlags);
    code.Raw({0x81,0xFA}); code.U32(requiredX64RecordFlags);
    code.Jcc32(0x85, failRecordInvalid);
    code.Raw({0x41,0x83,0x7F,static_cast<uint8_t>(RecordReturnStackCleanup),0x00});
    code.Jcc32(0x85, failRecordInvalid);
    code.Raw({0x41,0x8B,0x47,static_cast<uint8_t>(RecordGuestStackSize),
              0x3D,0x00,0x40,0x00,0x00}); code.Jcc32(0x82, failStack);
    code.Raw({0x3D,0x00,0x00,0x07,0x00}); code.Jcc32(0x87, failStack);
    code.Raw({0xA9,0xFF,0x0F,0x00,0x00}); code.Jcc32(0x85, failStack);
    code.Raw({0x3D}); code.U32(kRuntimeScratchSize); code.Jcc32(0x82, failStack);
    code.Raw({0x4C,0x8D,0xB3}); code.U32(VM_RUNTIME_X64_FRAME_TO_SCRATCH);
    // Zero private per-call runtime scratch only after guest-range validation.
    code.Raw({0x4C,0x89,0xF7,0x31,0xC0,0xB9}); code.U32(kRuntimeScratchSize);
    code.Raw({0xF3,0xAA});
    code.Raw({0x48,0x8B,0x7C,0x24,0x50});
    // Derive record key into ctx tail.
    code.Raw({0x48,0x8D,0x4C,0x24,0x30,0x48,0x8D,0x96}); code.U32(MetaBuildId);
    code.Raw({0x45,0x89,0xE0,0x4D,0x8D,0x8E}); code.U32(kRuntimeKeyOffset);
    code.CallLabel(hChaCha);
    // Authenticate ciphertext before exposing it to the decoder.
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x41,0x03,0x47,static_cast<uint8_t>(RecordBytecodeOffset),
              0x48,0x8D,0x0C,0x06,
              0x41,0x8B,0x57,static_cast<uint8_t>(RecordBytecodeSize),
              0x4D,0x8D,0x86}); code.U32(kRuntimeKeyOffset + 16u);
    code.Raw({0x41,0xB9,0xFF,0xFF,0xFF,0xFF}); code.CallLabel(sipHash);
    code.Raw({0x49,0x33,0x47,static_cast<uint8_t>(RecordBytecodeTag)});
    code.Jcc32(0x85, failAuth);

    // Initialize the only runtime context consumed by synthesized handlers.
    code.Raw({0x4D,0x89,0xBE}); code.U32(CtxRecord);
    code.Raw({0x49,0x89,0xB6}); code.U32(CtxMetadata);
    code.Raw({0x49,0x89,0xBE}); code.U32(CtxImageBase);
    code.Raw({0x49,0x89,0x9E}); code.U32(CtxNativeFrame);
    code.Raw({0x4D,0x89,0xAE}); code.U32(CtxExtendedState);
    code.Raw({0x41,0xC7,0x86}); code.U32(CtxArchitecture); code.U32(VM_ARCH_X64);
    code.Raw({0x49,0x8D,0x86}); code.U32(kRuntimeKeyOffset);
    code.Raw({0x49,0x89,0x86}); code.U32(CtxRollingKey);
    code.Raw({0x8B,0x86}); code.U32(MetaReverseOpcodeMapOffset);
    code.Raw({0x48,0x8D,0x0C,0x06,0x49,0x89,0x8E}); code.U32(CtxReverseOpcodeMap);
    code.Raw({0x8B,0x86}); code.U32(MetaRegisterMapOffset);
    code.Raw({0x48,0x8D,0x0C,0x06,0x49,0x89,0x8E}); code.U32(CtxRegisterMap);
    code.Raw({0x8B,0x86}); code.U32(MetaSemanticMapOffset);
    code.Raw({0x48,0x8D,0x0C,0x06,0x49,0x89,0x8E}); code.U32(CtxSemanticToSlot);
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x41,0x03,0x47,static_cast<uint8_t>(RecordBytecodeOffset),
              0x48,0x8D,0x0C,0x06,0x49,0x89,0x8E}); code.U32(CtxBytecodeBegin);
    code.Raw({0x41,0x03,0x47,static_cast<uint8_t>(RecordBytecodeSize),
              0x48,0x8D,0x0C,0x06,0x49,0x89,0x8E}); code.U32(CtxBytecodeEnd);
    code.Raw({0x49,0x8B,0x86}); code.U32(CtxBytecodeBegin);
    code.Raw({0x49,0x89,0x86}); code.U32(CtxVip);
    code.Raw({0x48,0x8B,0x83}); code.U32(offsetof(VM_NATIVE_FRAME_X64,rflags));
    code.Raw({0x49,0x89,0x86}); code.U32(CtxVirtualFlags);
    // Authenticated register map drives native-family -> vreg mapping.
    const uint32_t nativeOffsets[16] = {
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rax)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rcx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rdx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rbx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,originalRsp)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rbp)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rsi)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,rdi)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r8)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r9)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r10)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r11)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r12)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r13)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r14)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X64,r15))
    };
    for (uint8_t family = 0; family < 16; ++family) {
        code.Raw({0x49,0x8B,0x8E}); code.U32(CtxRegisterMap);
        code.Raw({0x0F,0xB6,0x49,family,0x83,0xF9,0x20}); code.Jcc32(0x83, failRegister);
        code.Raw({0x48,0x8B,0x83}); code.U32(nativeOffsets[family]);
        code.Raw({0x49,0x89,0x84,0xCE}); code.U32(CtxVregs);
    }
    code.Raw({0x4C,0x89,0xF1});
    if (!code.Call(config.layout.validationEntryOffset, result.error)) return false;
    code.Raw({0x85,0xC0}); code.Jcc32(0x85, cleanup);
    code.Raw({0x41,0x83,0xBE}); code.U32(CtxCallDepth); code.U8(0);
    code.Jcc32(0x85, failStack);
    code.Raw({0x41,0x83,0xBE}); code.U32(CtxHalted); code.U8(1);
    code.Jcc32(0x85, failRuntime);
    code.Raw({0x41,0x8B,0x87}); code.U32(RecordReturnStackCleanup);
    code.Raw({0x41,0x39,0x86}); code.U32(CtxReturnStackCleanup);
    code.Jcc32(0x85, failStack);
    // Write back all GPRs except architectural SP.
    for (uint8_t family = 0; family < 16; ++family) {
        if (family == 4) continue;
        code.Raw({0x49,0x8B,0x8E}); code.U32(CtxRegisterMap);
        code.Raw({0x0F,0xB6,0x49,family,0x49,0x8B,0x84,0xCE}); code.U32(CtxVregs);
        code.Raw({0x48,0x89,0x83}); code.U32(nativeOffsets[family]);
    }
    code.Raw({0x49,0x8B,0x86}); code.U32(CtxVirtualFlags);
    code.Raw({0x48,0x89,0x83}); code.U32(offsetof(VM_NATIVE_FRAME_X64,rflags));
    code.Raw({0x31,0xC0}); code.Jmp32(cleanup);

    code.Bind(failMetadata); code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID); code.Jmp32(cleanup);
    code.Bind(failRecord); code.U8(0xB8); code.U32(VM_MICRO_ERR_RECORD_NOT_FOUND); code.Jmp32(cleanup);
    code.Bind(failRecordInvalid); code.U8(0xB8); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH); code.Jmp32(cleanup);
    code.Bind(failAuth); code.U8(0xB8); code.U32(VM_MICRO_ERR_BYTECODE_AUTH); code.Jmp32(cleanup);
    code.Bind(failRegister); code.U8(0xB8); code.U32(VM_MICRO_ERR_REGISTER_MAP_INVALID); code.Jmp32(cleanup);
    code.Bind(failStack); code.U8(0xB8); code.U32(VM_MICRO_ERR_STACK_ALIGNMENT); code.Jmp32(cleanup);
    code.Bind(failRuntime); code.U8(0xB8); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH);
    code.Bind(cleanup);
    code.Raw({0x89,0x44,0x24,0x20});
    code.Raw({0x4D,0x85,0xF6}); code.Jcc32(0x84, wipe);
    code.Raw({0x41,0x83,0xBE}); code.U32(CtxError); code.U8(0);
    const size_t ctxHasError = code.NewLabel(); code.Jcc32(0x85, ctxHasError);
    code.Raw({0x8B,0x44,0x24,0x20,0x41,0x89,0x86}); code.U32(CtxError);
    code.Bind(ctxHasError);
    code.Raw({0x4C,0x89,0xF7,0x31,0xC0,0xB9}); code.U32(kRuntimeScratchSize);
    code.Raw({0xF3,0xAA});
    code.Bind(wipe);
    code.Raw({0x48,0x8D,0x7C,0x24,0x30,0x31,0xC0,0xB9,0x20,0x00,0x00,0x00,
              0xF3,0xAA,0x8B,0x44,0x24,0x20,
              0x48,0x83,0xC4,static_cast<uint8_t>(stack),
              0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
              0x5F,0x5E,0x5D,0x5B,0xC3});
    const uint32_t publicEnd = code.CurrentImageOffset();
    AddX64Unwind(result.unwindRecords, begin, publicEnd,
        prolog, stack, pushes);
    return true;
}

bool BuildValidationEntry(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    CodeBuffer code(config.layout.validationEntryOffset);
    SeedStream random(config.buildSeed, 0x56414C4944415445ULL);
    EmitCet(code, x64, config.emitCetLandingPads);
    const uint32_t begin = code.ImageOffset();
    if (x64) {
        std::vector<std::pair<uint8_t, uint8_t>> pushes;
        const auto push = [&](std::initializer_list<uint8_t> bytes, uint8_t reg) {
            code.Raw(bytes); pushes.push_back({static_cast<uint8_t>(code.Offset()), reg});
        };
        push({0x53},3); push({0x55},5); push({0x56},6); push({0x57},7);
        push({0x41,0x54},12); push({0x41,0x55},13);
        push({0x41,0x56},14); push({0x41,0x57},15);
        constexpr uint32_t stack = 0x28u;
        code.Raw({0x48,0x83,0xEC,static_cast<uint8_t>(stack)});
        const uint8_t prolog = static_cast<uint8_t>(code.Offset());
        code.Raw({0x49,0x89,0xCF});
        const size_t failMetadata = code.NewLabel();
        const size_t failNoContext = code.NewLabel();
        const size_t failPlan = code.NewLabel();
        const size_t planLoop = code.NewLabel();
        const size_t planFound = code.NewLabel();
        const size_t recordPresent = code.NewLabel();
        const size_t functionReady = code.NewLabel();
        const size_t afterDecrypt = code.NewLabel();
        const size_t afterDispatch = code.NewLabel();
        const size_t epilog = code.NewLabel();
        code.Raw({0x4D,0x85,0xFF}); code.Jcc32(0x84, failNoContext);
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxImageBase);
        code.Raw({0x48,0x85,0xC0}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x49,0x8B,0x9F}); code.U32(CtxMetadata);
        code.Raw({0x48,0x85,0xDB}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x8B,0x8B}); code.U32(MetaImageSize);
        code.Raw({0x81,0xF9}); code.U32(config.virtualProtectIatRVA + 8u);
        code.Jcc32(0x82, failMetadata);
        code.Raw({0x81,0xF9}); code.U32(config.flushInstructionCacheIatRVA + 8u);
        code.Jcc32(0x82, failMetadata);
        code.Raw({0x48,0x8B,0x88}); code.U32(config.virtualProtectIatRVA);
        code.Raw({0x48,0x85,0xC9}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x49,0x89,0x8F}); code.U32(CtxVirtualProtect);
        code.Raw({0x48,0x8B,0x88}); code.U32(config.flushInstructionCacheIatRVA);
        code.Raw({0x48,0x85,0xC9}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x49,0x89,0x8F}); code.U32(CtxFlushInstructionCache);
        code.Raw({0x48,0x8D,0x05});
        if (!code.RipDisp32(config.layout.operandDecoderOffset, result.error)) return false;
        code.Raw({0x49,0x89,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0x48,0x8D,0x05});
        if (!code.RipDisp32(config.layout.flagMaterializerOffset, result.error)) return false;
        code.Raw({0x49,0x89,0x87}); code.U32(CtxFlagMaterializer);
        code.Raw({0x4C,0x8D,0x35});
        if (!code.RipDisp32(config.layout.dispatchTableOffset, result.error)) return false;
        code.Raw({0x4D,0x89,0xB7}); code.U32(CtxDispatchTable);
        code.Raw({0x48,0x8D,0x35});
        if (!code.RipDisp32(config.layout.decodePlanTableOffset, result.error)) return false;
        code.Raw({0x45,0x31,0xE4});
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxRecord);
        code.Raw({0x48,0x85,0xC0}); code.Jcc32(0x85, recordPresent);
        code.Raw({0x41,0x8B,0x87}); code.U32(CtxOperandCodec +
            static_cast<uint32_t>(offsetof(VM_OPERAND_CODEC,functionRva)));
        code.Jmp32(functionReady);
        code.Bind(recordPresent);
        code.Raw({0x8B,0x00});
        code.Bind(functionReady);
        code.Bind(planLoop);
        code.Raw({0x41,0x81,0xFC}); code.U32(config.functionPlanCount);
        code.Jcc32(0x83, failPlan);
        code.Raw({0x39,0x06}); code.Jcc32(0x84, planFound);
        code.Raw({0x48,0x81,0xC6}); code.U32(sizeof(RuntimeFunctionDecodeTable));
        code.Raw({0x41,0xFF,0xC4}); code.Jmp32(planLoop);
        code.Bind(planFound);
        code.Raw({0xF3,0x0F,0x6F,0x46,0x04,
                  0xF3,0x41,0x0F,0x7F,0x87}); code.U32(CtxOperandCodec);
        code.Raw({0xF3,0x0F,0x6F,0x46,0x10,
                  0xF3,0x41,0x0F,0x7F,0x87}); code.U32(CtxOperandCodec + 12u);
        code.Raw({0x48,0x8D,0x46}); code.U8(static_cast<uint8_t>(
            offsetof(RuntimeFunctionDecodeTable, plans)));
        code.Raw({0x49,0x89,0x87}); code.U32(CtxDecodePlans);
        // The state/plan/dispatch page is data-only.  The runtime section is
        // initially RX, so make this page RW before the first atomic owner
        // election.  It intentionally remains non-executable and writable:
        // later entrants still execute a locked cmpxchg even when state==2.
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxVirtualProtect);
        code.Raw({0x48,0x8D,0x0D});
        if (!code.RipDisp32(config.layout.decryptionStateOffset, result.error)) return false;
        code.U8(0xBA); code.U32(kPageSize);
        code.Raw({0x41,0xB8}); code.U32(kPageReadWrite);
        code.Raw({0x4C,0x8D,0x4C,0x24,0x20,0xFF,0xD0,0x85,0xC0});
        code.Jcc32(0x84, failMetadata);
        code.Raw({0x4C,0x89,0xF9});
        if (!code.Call(config.layout.decryptorOffset, result.error)) return false;
        code.Raw({0x85,0xC0}); code.Jcc32(0x85, epilog);
        code.Bind(afterDecrypt);
        code.Raw({0x4D,0x8B,0xAF}); code.U32(CtxVip);
        code.Raw({0x4C,0x89,0xF9,0x49,0x8B,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0xFF,0xD0,0x48,0x85,0xC0}); code.Jcc32(0x84, afterDispatch);
        code.Raw({0xFF,0xD0});
        code.Bind(afterDispatch);
        code.Raw({0x41,0x8B,0x87}); code.U32(CtxError);
        code.Raw({0x85,0xC0}); code.Jcc32(0x85, epilog);
        code.Raw({0x4C,0x89,0xF9,0xBA}); code.U32(VM_FLAG_ARCHITECTURAL_MASK);
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxFlagMaterializer);
        code.Raw({0xFF,0xD0,0x41,0x8B,0x87}); code.U32(CtxError);
        code.Jmp32(epilog);
        code.Bind(failPlan);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH); code.Jmp32(epilog);
        code.Bind(failMetadata);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Jmp32(epilog);
        code.Bind(failNoContext);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Bind(epilog);
        code.Raw({0x48,0x83,0xC4,static_cast<uint8_t>(stack),
                  0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
                  0x5F,0x5E,0x5D,0x5B,0xC3});
        if (!code.Resolve(result.error)) return false;
        AddX64Unwind(result.unwindRecords, begin, code.CurrentImageOffset(),
            prolog, stack, pushes);
    } else {
        code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x83,0xEC,0x10,
                  0x8B,0x7D,0x08});
        const size_t failMetadata = code.NewLabel();
        const size_t failNoContext = code.NewLabel();
        const size_t failPlan = code.NewLabel();
        const size_t planLoop = code.NewLabel();
        const size_t planFound = code.NewLabel();
        const size_t recordPresent = code.NewLabel();
        const size_t functionReady = code.NewLabel();
        const size_t afterDispatch = code.NewLabel();
        const size_t epilog = code.NewLabel();
        code.Raw({0x85,0xFF}); code.Jcc32(0x84, failNoContext);
        code.Raw({0x8B,0x87}); code.U32(CtxImageBase); code.Raw({0x85,0xC0});
        code.Jcc32(0x84, failMetadata);
        code.Raw({0x8B,0x9F}); code.U32(CtxMetadata); code.Raw({0x85,0xDB});
        code.Jcc32(0x84, failMetadata);
        code.Raw({0x8B,0x8B}); code.U32(MetaImageSize);
        code.Raw({0x81,0xF9}); code.U32(config.virtualProtectIatRVA + 4u);
        code.Jcc32(0x82, failMetadata);
        code.Raw({0x81,0xF9}); code.U32(config.flushInstructionCacheIatRVA + 4u);
        code.Jcc32(0x82, failMetadata);
        code.Raw({0x8B,0x88}); code.U32(config.virtualProtectIatRVA);
        code.Raw({0x85,0xC9}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x89,0x8F}); code.U32(CtxVirtualProtect);
        code.Raw({0x8B,0x88}); code.U32(config.flushInstructionCacheIatRVA);
        code.Raw({0x85,0xC9}); code.Jcc32(0x84, failMetadata);
        code.Raw({0x89,0x8F}); code.U32(CtxFlushInstructionCache);
        code.Raw({0xE8,0x00,0x00,0x00,0x00,0x5E});
        const uint32_t pop = code.CurrentImageOffset() - 1u;
        code.Raw({0x8D,0x86}); code.U32(config.layout.operandDecoderOffset - pop);
        code.Raw({0x89,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0x8D,0x86}); code.U32(config.layout.flagMaterializerOffset - pop);
        code.Raw({0x89,0x87}); code.U32(CtxFlagMaterializer);
        code.Raw({0x8D,0x9E}); code.U32(config.layout.dispatchTableOffset - pop);
        code.Raw({0x89,0x9F}); code.U32(CtxDispatchTable);
        code.Raw({0x8D,0xB6}); code.U32(config.layout.decodePlanTableOffset - pop);
        code.Raw({0xC7,0x45,0xF0,0x00,0x00,0x00,0x00});
        code.Raw({0x8B,0x87}); code.U32(CtxRecord); code.Raw({0x85,0xC0});
        code.Jcc32(0x85, recordPresent);
        code.Raw({0x8B,0x87}); code.U32(CtxOperandCodec +
            static_cast<uint32_t>(offsetof(VM_OPERAND_CODEC,functionRva)));
        code.Jmp32(functionReady);
        code.Bind(recordPresent); code.Raw({0x8B,0x00});
        code.Bind(functionReady);
        code.Bind(planLoop);
        code.Raw({0x81,0x7D,0xF0}); code.U32(config.functionPlanCount);
        code.Jcc32(0x83, failPlan);
        code.Raw({0x39,0x06}); code.Jcc32(0x84, planFound);
        code.Raw({0x81,0xC6}); code.U32(sizeof(RuntimeFunctionDecodeTable));
        code.Raw({0xFF,0x45,0xF0}); code.Jmp32(planLoop);
        code.Bind(planFound);
        code.Raw({0x8D,0x9F}); code.U32(CtxOperandCodec);
        code.Raw({0x8D,0x4E,0x04,0xBA}); code.U32(sizeof(VM_OPERAND_CODEC));
        const size_t copyCodec = code.NewLabel(); code.Bind(copyCodec);
        code.Raw({0x8A,0x01,0x88,0x03,0x41,0x43,0x4A}); code.Jcc32(0x85, copyCodec);
        code.Raw({0x8D,0x46}); code.U8(static_cast<uint8_t>(
            offsetof(RuntimeFunctionDecodeTable,plans)));
        code.Raw({0x89,0x87}); code.U32(CtxDecodePlans);
        code.Raw({0x8B,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0x05}); code.U32(config.layout.decryptionStateOffset -
            config.layout.operandDecoderOffset);
        code.Raw({0x8D,0x55,0xEC,0x52,0x68}); code.U32(kPageReadWrite);
        code.Raw({0x68}); code.U32(kPageSize);
        code.Raw({0x50,0x8B,0x8F}); code.U32(CtxVirtualProtect);
        // VirtualProtect is WINAPI/stdcall on x86 and cleans its four args.
        code.Raw({0xFF,0xD1,0x85,0xC0});
        code.Jcc32(0x84, failMetadata);
        code.Raw({0x57});
        if (!code.Call(config.layout.decryptorOffset, result.error)) return false;
        code.Raw({0x83,0xC4,0x04,0x85,0xC0}); code.Jcc32(0x85, epilog);
        code.Raw({0x8B,0xB7}); code.U32(CtxVip);
        code.Raw({0x8B,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0x57,0xFF,0xD0,0x83,0xC4,0x04,0x85,0xC0});
        code.Jcc32(0x84, afterDispatch); code.Raw({0xFF,0xD0});
        code.Bind(afterDispatch);
        code.Raw({0x8B,0x87}); code.U32(CtxError); code.Raw({0x85,0xC0});
        code.Jcc32(0x85, epilog);
        code.Raw({0x68}); code.U32(VM_FLAG_ARCHITECTURAL_MASK);
        code.Raw({0x57,0x8B,0x87}); code.U32(CtxFlagMaterializer);
        code.Raw({0xFF,0xD0,0x83,0xC4,0x08,0x8B,0x87}); code.U32(CtxError);
        code.Jmp32(epilog);
        code.Bind(failPlan);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH); code.Jmp32(epilog);
        code.Bind(failMetadata);
        code.Raw({0xC7,0x87}); code.U32(CtxError); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Jmp32(epilog);
        code.Bind(failNoContext);
        code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID);
        code.Bind(epilog);
        code.Raw({0x83,0xC4,0x10,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
        if (!code.Resolve(result.error)) return false;
    }
    EmitSeedIsland(code, random, 64);
    result.validationEntryCode = std::move(code.bytes);
    return true;
}

bool EmitSipHashHelperX86(
    CodeBuffer& code,
    size_t helperLabel,
    const VMHandlerEntryCodegenConfig& config)
{
    code.Bind(helperLabel);
    EmitCet(code, false, config.emitCetLandingPads);
    code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x83,0xEC,0x40,
              0x8B,0x75,0x08,0x8B,0x7D,0x0C,0x8B,0x5D,0x14});
    // Locals -40..-1 hold constants/tail/message; initialize state in XMM0-3.
    const auto local64 = [&](uint8_t disp, uint64_t value) {
        code.Raw({0xC7,0x45,disp}); code.U32(static_cast<uint32_t>(value));
        code.Raw({0xC7,0x45,static_cast<uint8_t>(disp + 4u)});
        code.U32(static_cast<uint32_t>(value >> 32u));
    };
    local64(0xC0,0x736F6D6570736575ULL);
    local64(0xC8,0x646F72616E646F6DULL);
    local64(0xD0,0x6C7967656E657261ULL);
    local64(0xD8,0x7465646279746573ULL);
    code.Raw({0xF3,0x0F,0x7E,0x45,0xC0,0xF3,0x0F,0x7E,0x4D,0xC8,
              0xF3,0x0F,0x7E,0x55,0xD0,0xF3,0x0F,0x7E,0x5D,0xD8,
              0x8B,0x45,0x10,0xF3,0x0F,0x7E,0x30,
              0xF3,0x0F,0x7E,0x78,0x08,
              0x66,0x0F,0xEF,0xC6,0x66,0x0F,0xEF,0xCF,
              0x66,0x0F,0xEF,0xD6,0x66,0x0F,0xEF,0xDF,
              0xC7,0x45,0xE0,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xE4,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xE8,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xEC,0x00,0x00,0x00,0x00});
    const size_t loop = code.NewLabel();
    const size_t nonzero = code.NewLabel();
    const size_t append = code.NewLabel();
    const size_t highTail = code.NewLabel();
    const size_t appended = code.NewLabel();
    const size_t next = code.NewLabel();
    const size_t finish = code.NewLabel();
    code.Bind(loop);
    code.Raw({0x8B,0x45,0xE8,0x3B,0xC7}); code.Jcc32(0x83, finish);
    code.Raw({0x0F,0xB6,0x14,0x06,0x83,0xFB,0xFF}); code.Jcc32(0x84, nonzero);
    code.Raw({0x3B,0xC3}); code.Jcc32(0x82, nonzero);
    code.Raw({0x8D,0x4B,0x08,0x3B,0xC1}); code.Jcc32(0x83, nonzero);
    code.Raw({0x31,0xD2}); code.Jmp32(append);
    code.Bind(nonzero);
    code.Bind(append);
    code.Raw({0x8B,0x4D,0xEC,0x83,0xF9,0x04}); code.Jcc32(0x83, highTail);
    code.Raw({0xC1,0xE1,0x03,0xD3,0xE2,0x09,0x55,0xE0}); code.Jmp32(appended);
    code.Bind(highTail);
    code.Raw({0x83,0xE9,0x04,0xC1,0xE1,0x03,0xD3,0xE2,0x09,0x55,0xE4});
    code.Bind(appended);
    code.Raw({0xFF,0x45,0xEC,0x83,0x7D,0xEC,0x08}); code.Jcc32(0x85, next);
    code.Raw({0xF3,0x0F,0x7E,0x75,0xE0,0x66,0x0F,0xEF,0xDE});
    EmitSipRoundX86(code); EmitSipRoundX86(code);
    code.Raw({0x66,0x0F,0xEF,0xC6,
              0xC7,0x45,0xE0,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xE4,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xEC,0x00,0x00,0x00,0x00});
    code.Bind(next); code.Raw({0xFF,0x45,0xE8}); code.Jmp32(loop);
    code.Bind(finish);
    code.Raw({0x8B,0xC7,0x25,0xFF,0x00,0x00,0x00,0xC1,0xE0,0x18,
              0x09,0x45,0xE4,0xF3,0x0F,0x7E,0x75,0xE0,
              0x66,0x0F,0xEF,0xDE});
    EmitSipRoundX86(code); EmitSipRoundX86(code);
    code.Raw({0x66,0x0F,0xEF,0xC6,
              0xC7,0x45,0xE0,0xFF,0x00,0x00,0x00,
              0xC7,0x45,0xE4,0x00,0x00,0x00,0x00,
              0xF3,0x0F,0x7E,0x75,0xE0,0x66,0x0F,0xEF,0xD6});
    EmitSipRoundX86(code); EmitSipRoundX86(code);
    EmitSipRoundX86(code); EmitSipRoundX86(code);
    code.Raw({0x66,0x0F,0xEF,0xC1,0x66,0x0F,0xEF,0xC2,
              0x66,0x0F,0xEF,0xC3,0x66,0x0F,0xD6,0x45,0xE0,
              0x8B,0x45,0xE0,0x8B,0x55,0xE4,
              0x8D,0x65,0xF4,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
    return true;
}

bool EmitHChaChaHelperX86(
    CodeBuffer& code,
    size_t helperLabel,
    const VMHandlerEntryCodegenConfig& config)
{
    code.Bind(helperLabel);
    EmitCet(code, false, config.emitCetLandingPads);
    code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x83,0xEC,0x44,
              0x8B,0x5D,0x08,0x8B,0x7D,0x0C,0x8B,0x4D,0x10,
              0x8B,0x55,0x14,0x89,0x55,0xF0,0x8D,0x34,0x24});
    const auto put = [&](uint8_t off, uint32_t value) {
        code.Raw({0xC7,0x46,off}); code.U32(value);
    };
    put(0x00,0x61707865u); put(0x04,0x3320646Eu);
    put(0x08,0x79622D32u); put(0x0C,0x6B206574u);
    for (uint8_t i = 0; i < 8; ++i)
        code.Raw({0x8B,0x43,static_cast<uint8_t>(i * 4u),0x89,0x46,
                  static_cast<uint8_t>(0x10u + i * 4u)});
    for (uint8_t i = 0; i < 4; ++i) {
        code.Raw({0x8B,0x47,static_cast<uint8_t>(i * 4u)});
        if (i == 3) code.Raw({0x31,0xC8});
        code.Raw({0x89,0x46,static_cast<uint8_t>(0x30u + i * 4u)});
    }
    code.U8(0xBF); code.U32(10);
    const size_t rounds = code.NewLabel(); code.Bind(rounds);
    EmitChaChaDoubleRoundX86(code);
    code.Raw({0x4F}); code.Jcc32(0x85, rounds);
    // [ebp-4] is the saved EBX slot.  Keep the output pointer in the real
    // local area at [ebp-16] so the helper honours the x86 callee-save ABI.
    code.Raw({0x8B,0x7D,0xF0});
    const uint8_t words[] = {0,1,2,3,12,13,14,15};
    for (uint8_t i = 0; i < 8; ++i)
        code.Raw({0x8B,0x46,static_cast<uint8_t>(words[i] * 4u),
                  0x89,0x47,static_cast<uint8_t>(i * 4u)});
    code.Raw({0x8D,0x65,0xF4,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
    return true;
}

bool BuildPublicEntryX86(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result,
    CodeBuffer& code,
    size_t sipHash,
    size_t hChaCha)
{
    EmitCet(code, false, config.emitCetLandingPads);
    code.Raw({0x55,0x8B,0xEC,0x53,0x56,0x57,0x81,0xEC}); code.U32(0x70);
    code.Raw({0x8B,0x5D,0x08,0x8B,0x75,0x10,
              0xC7,0x45,0xF0,0x00,0x00,0x00,0x00,
              0xC7,0x45,0xEC,0x00,0x00,0x00,0x00});
    const size_t failMetadata = code.NewLabel();
    const size_t failRecord = code.NewLabel();
    const size_t failAuth = code.NewLabel();
    const size_t failRegister = code.NewLabel();
    const size_t failStack = code.NewLabel();
    const size_t failRuntime = code.NewLabel();
    const size_t cleanup = code.NewLabel();
    const size_t wipe = code.NewLabel();
    const size_t keyLoop = code.NewLabel();
    const size_t keyDone = code.NewLabel();
    const size_t recordLoop = code.NewLabel();
    const size_t recordFound = code.NewLabel();
    code.Raw({0x85,0xDB}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x85,0xF6}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x8B,0x7D,0x14,0x85,0xFF}); code.Jcc32(0x84, failMetadata);
    code.Raw({0x8B,0x45,0x18,0x85,0xC0}); code.Jcc32(0x84, failMetadata);
    code.Raw({0xA8,0x3F}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x66,0x81,0x3F,0x4D,0x5A}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x8B,0x47,0x3C,0x3D,0x40,0x00,0x00,0x00}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3D,0x00,0x00,0x10,0x00}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0x3C,0x07,0x50,0x45,0x00,0x00}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x66,0x81,0x7C,0x07,0x18,0x0B,0x01}); code.Jcc32(0x85, failMetadata);
    code.Raw({0x8B,0x4C,0x07,0x50,0x89,0x4D,0xE8,0x85,0xC9});
    code.Jcc32(0x84, failMetadata);
    code.Raw({0x8B,0xC6,0x2B,0xC7,0x3B,0xC1}); code.Jcc32(0x83, failMetadata);
    code.Raw({0x8B,0xD1,0x2B,0xD0,0x81,0xFA});
    code.U32(sizeof(VM_METADATA_HEADER));
    code.Jcc32(0x82, failMetadata);
    const auto cmpMeta32 = [&](uint32_t offset, uint32_t expected) {
        code.Raw({0x81,0xBE}); code.U32(offset); code.U32(expected);
        code.Jcc32(0x85, failMetadata);
    };
    cmpMeta32(MetaHeaderSize,sizeof(VM_METADATA_HEADER));
    cmpMeta32(MetaMetadataVersion,VM_METADATA_VERSION);
    cmpMeta32(MetaSchemaVersion,VM_SCHEMA_VERSION);
    cmpMeta32(MetaRuntimeVersion,VM_RUNTIME_VERSION);
    cmpMeta32(MetaArchitecture,VM_ARCH_X86);
    cmpMeta32(MetaRecordSize,sizeof(VM_FUNCTION_RECORD));
    cmpMeta32(MetaKeyEncodingVersion,VM_KEY_ENCODING_VERSION);
    cmpMeta32(MetaOpcodeMapSize,VM_OPCODE_MAP_SIZE);
    cmpMeta32(MetaRegisterMapSize,VM_REGISTER_MAP_SIZE);
    cmpMeta32(MetaHandlerTableSize,VM_HANDLER_TABLE_SIZE);
    cmpMeta32(MetaHandlerVariantCount,config.variantCount);
    code.Raw({0x8B,0x86}); code.U32(MetaFlags);
    code.Raw({0x89,0xC2,0x81,0xE2}); code.U32(~kKnownMetadataFlags);
    code.Jcc32(0x85, failMetadata);
    code.Raw({0x25}); code.U32(kRequiredMetadataFlags);
    code.Raw({0x3D}); code.U32(kRequiredMetadataFlags); code.Jcc32(0x85, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaTotalSize);
    code.Raw({0x3D}); code.U32(sizeof(VM_METADATA_HEADER)); code.Jcc32(0x82, failMetadata);
    code.Raw({0x8B,0xCE,0x2B,0xCF,0x8B,0x55,0xE8,0x2B,0xD1,0x3B,0xC2});
    code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaImageSize);
    code.Raw({0x3B,0x45,0xE8}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeBaseRVA);
    code.Raw({0x85,0xC0}); code.Jcc32(0x84, failRuntime);
    code.Raw({0x8B,0x96}); code.U32(MetaRuntimeSize);
    code.Raw({0x8B,0x8E}); code.U32(MetaImageSize);
    code.Raw({0x3B,0xC1}); code.Jcc32(0x83, failRuntime);
    code.Raw({0x2B,0xC8,0x3B,0xD1}); code.Jcc32(0x87, failRuntime);
    code.Raw({0x81,0xFA}); code.U32(config.layout.encryptedHandlerOffset +
        config.layout.encryptedHandlerSize); code.Jcc32(0x82, failRuntime);
    code.Raw({0x8B,0x8E}); code.U32(MetaRuntimeEntryRVA);
    code.Raw({0x05}); code.U32(config.layout.publicEntryOffset);
    code.Jcc32(0x82, failRuntime);
    code.Raw({0x3B,0xC8}); code.Jcc32(0x85, failRuntime);
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeSize);
    code.Raw({0x3D}); code.U32(config.layout.keyMarkerOffset +
        VM_RUNTIME_KEY_SHARE_SIZE);
    code.Jcc32(0x82, failRuntime);
    // Master key at ebp-60.
    code.Raw({0x8B,0x86}); code.U32(MetaRuntimeBaseRVA);
    code.Raw({0x05}); code.U32(config.layout.keyMarkerOffset);
    code.Raw({0x8D,0x0C,0x07,0x89,0x4D,0xDC,0x31,0xD2});
    code.Bind(keyLoop);
    code.Raw({0x83,0xFA,0x20}); code.Jcc32(0x83, keyDone);
    code.Raw({0x0F,0xB6,0x84,0x16}); code.U32(MetaEncodedMasterKey);
    code.Raw({0x8B,0x4D,0xDC,0x32,0x04,0x11,0x89,0xD7,0x83,0xE7,0x0F,
              0x32,0x84,0x3E}); code.U32(MetaBuildId);
    code.Raw({0x88,0x45,0xE4,0x89,0xD1,0x83,0xE1,0x03,0xC1,0xE1,0x03,
              0x8B,0x86}); code.U32(MetaCookie);
    code.Raw({0xD3,0xE8,0x30,0x45,0xE4,0x6B,0xC2,0x5B,
              0x30,0x45,0xE4,0x8A,0x45,0xE4,
              0x88,0x44,0x15,0xA0,0x42}); code.Jmp32(keyLoop);
    code.Bind(keyDone);
    code.Raw({0x68}); code.U32(MetaMetadataTag);
    code.Raw({0x8D,0x45,0xA0,0x50,0xFF,0xB6}); code.U32(MetaTotalSize);
    code.Raw({0x56}); code.CallLabel(sipHash); code.Raw({0x83,0xC4,0x10,
              0x33,0x86}); code.U32(MetaMetadataTag);
    code.Raw({0x33,0x96}); code.U32(MetaMetadataTag + 4u);
    code.Raw({0x09,0xD0}); code.Jcc32(0x85, failAuth);
    // Authenticated table order and record lookup.
    code.Raw({0x8B,0x86}); code.U32(MetaRecordCount); code.Raw({0x85,0xC0});
    code.Jcc32(0x84, failMetadata);
    code.Raw({0x3D,0x00,0x00,0x10,0x00}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x8E}); code.U32(MetaRecordOffset);
    code.Raw({0x81,0xF9}); code.U32(sizeof(VM_METADATA_HEADER)); code.Jcc32(0x82, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaReverseOpcodeMapOffset);
    code.Raw({0x3B,0xCA}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x6B,0xC0,static_cast<uint8_t>(sizeof(VM_FUNCTION_RECORD)),0x03,0xC1});
    code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaRegisterMapOffset);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_OPCODE_MAP_SIZE); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaSemanticMapOffset);
    code.Raw({0x3B,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x83,0xC0,VM_REGISTER_MAP_SIZE}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaHandlerDescriptorOffset);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_HANDLER_TABLE_SIZE); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaHandlerVariantOffset);
    code.Raw({0x3B,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x05}); code.U32(VM_HANDLER_TABLE_SIZE); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xC2}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x81,0xC2}); code.U32(VM_HANDLER_TABLE_SIZE); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0xD0}); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8B,0x96}); code.U32(MetaBytecodeSize);
    code.Raw({0x03,0xC2}); code.Jcc32(0x82, failMetadata);
    code.Raw({0x3B,0x86}); code.U32(MetaTotalSize); code.Jcc32(0x87, failMetadata);
    code.Raw({0x8D,0x3C,0x0E,0x31,0xC9});
    code.Bind(recordLoop);
    code.Raw({0x3B,0x8E}); code.U32(MetaRecordCount); code.Jcc32(0x83, failRecord);
    code.Raw({0x8B,0x45,0x0C,0x39,0x07}); code.Jcc32(0x84, recordFound);
    code.Raw({0x83,0xC7,static_cast<uint8_t>(sizeof(VM_FUNCTION_RECORD)),0x41});
    code.Jmp32(recordLoop);
    code.Bind(recordFound); code.Raw({0x89,0x7D,0xEC});
    code.Raw({0x8B,0x47,static_cast<uint8_t>(RecordBytecodeSize),0x85,0xC0});
    code.Jcc32(0x84, failRecord);
    code.Raw({0x8B,0x4F,static_cast<uint8_t>(RecordBytecodeOffset),
              0x3B,0x8E}); code.U32(MetaBytecodeSize); code.Jcc32(0x87, failRecord);
    code.Raw({0x03,0xC8,0x3B,0x8E}); code.U32(MetaBytecodeSize); code.Jcc32(0x87, failRecord);
    code.Raw({0x8B,0x4F,static_cast<uint8_t>(RecordFlags),0x89,0xCA,0x81,0xE2});
    code.U32(~kKnownRecordFlags); code.Jcc32(0x85, failRecord);
    code.Raw({0xF7,0xC1}); code.U32(VM_RECORD_FLAG_X64); code.Jcc32(0x85, failRecord);
    constexpr uint32_t requiredX86RecordFlags =
        VM_RECORD_FLAG_NATIVE_BODY_DESTROYED | VM_RECORD_FLAG_CFG_VERIFIED;
    code.Raw({0x89,0xCA,0x81,0xE2}); code.U32(requiredX86RecordFlags);
    code.Raw({0x81,0xFA}); code.U32(requiredX86RecordFlags);
    code.Jcc32(0x85, failRecord);
    code.Raw({0x8B,0x47,static_cast<uint8_t>(RecordGuestStackSize),
              0x3D,0x00,0x40,0x00,0x00}); code.Jcc32(0x82, failStack);
    code.Raw({0x3D,0x00,0x00,0x07,0x00}); code.Jcc32(0x87, failStack);
    code.Raw({0xA9,0xFF,0x0F,0x00,0x00}); code.Jcc32(0x85, failStack);
    code.Raw({0x3D}); code.U32(kRuntimeScratchSize); code.Jcc32(0x82, failStack);
    code.Raw({0x8D,0xBB}); code.U32(VM_RUNTIME_X86_FRAME_TO_SCRATCH);
    code.Raw({0x89,0x7D,0xF0,0x31,0xC0,0xB9});
    code.U32(kRuntimeScratchSize); code.Raw({0xF3,0xAA});
    // HChaCha(master, buildId, functionRva, ctxKey).
    code.Raw({0x8B,0x7D,0xF0,0x81,0xC7}); code.U32(kRuntimeKeyOffset);
    code.Raw({0x57,0xFF,0x75,0x0C,0x8D,0x86}); code.U32(MetaBuildId);
    code.Raw({0x50,0x8D,0x45,0xA0,0x50}); code.CallLabel(hChaCha);
    code.Raw({0x83,0xC4,0x10});
    // Record SipHash.
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x8B,0x7D,0xEC,0x03,0x47,static_cast<uint8_t>(RecordBytecodeOffset),
              0x03,0xC6,0x6A,0xFF,0x8B,0x4D,0xF0,0x81,0xC1});
    code.U32(kRuntimeKeyOffset + 16u);
    code.Raw({0x51,0xFF,0x77,static_cast<uint8_t>(RecordBytecodeSize),0x50});
    code.CallLabel(sipHash); code.Raw({0x83,0xC4,0x10,
              0x33,0x47,static_cast<uint8_t>(RecordBytecodeTag),
              0x33,0x57,static_cast<uint8_t>(RecordBytecodeTag + 4u),0x09,0xD0});
    code.Jcc32(0x85, failAuth);
    // Context initialization.
    code.Raw({0x8B,0x7D,0xF0,0x8B,0x45,0xEC,0x89,0x87}); code.U32(CtxRecord);
    code.Raw({0x89,0xB7}); code.U32(CtxMetadata);
    code.Raw({0x8B,0x45,0x14,0x89,0x87}); code.U32(CtxImageBase);
    code.Raw({0x89,0x9F}); code.U32(CtxNativeFrame);
    code.Raw({0x8B,0x45,0x18,0x89,0x87}); code.U32(CtxExtendedState);
    code.Raw({0xC7,0x87}); code.U32(CtxArchitecture); code.U32(VM_ARCH_X86);
    code.Raw({0x8D,0x87}); code.U32(kRuntimeKeyOffset); code.Raw({0x89,0x87}); code.U32(CtxRollingKey);
    const auto metaPointer = [&](uint32_t metaOffset, uint32_t ctxOffset) {
        code.Raw({0x8B,0x86}); code.U32(metaOffset);
        code.Raw({0x03,0xC6,0x89,0x87}); code.U32(ctxOffset);
    };
    metaPointer(MetaReverseOpcodeMapOffset,CtxReverseOpcodeMap);
    metaPointer(MetaRegisterMapOffset,CtxRegisterMap);
    metaPointer(MetaSemanticMapOffset,CtxSemanticToSlot);
    code.Raw({0x8B,0x86}); code.U32(MetaBytecodeOffset);
    code.Raw({0x8B,0x4D,0xEC,0x03,0x41,static_cast<uint8_t>(RecordBytecodeOffset),
              0x03,0xC6,0x89,0x87}); code.U32(CtxBytecodeBegin);
    code.Raw({0x03,0x41,static_cast<uint8_t>(RecordBytecodeSize),0x89,0x87}); code.U32(CtxBytecodeEnd);
    code.Raw({0x8B,0x87}); code.U32(CtxBytecodeBegin); code.Raw({0x89,0x87}); code.U32(CtxVip);
    code.Raw({0x8B,0x83}); code.U32(offsetof(VM_NATIVE_FRAME_X86,eflags));
    code.Raw({0x89,0x87}); code.U32(CtxVirtualFlags);
    const uint32_t nativeOffsets[8] = {
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,eax)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,ecx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,edx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,ebx)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,originalEsp)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,ebp)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,esi)),
        static_cast<uint32_t>(offsetof(VM_NATIVE_FRAME_X86,edi))
    };
    for (uint8_t family = 0; family < 8; ++family) {
        code.Raw({0x8B,0x8F}); code.U32(CtxRegisterMap);
        code.Raw({0x0F,0xB6,0x49,family,0x83,0xF9,0x20}); code.Jcc32(0x83, failRegister);
        code.Raw({0x8B,0x83}); code.U32(nativeOffsets[family]);
        if (family == 4) code.Raw({0x83,0xC0,0x04});
        code.Raw({0x89,0x84,0xCF}); code.U32(CtxVregs);
        code.Raw({0xC7,0x84,0xCF}); code.U32(CtxVregs + 4u); code.U32(0);
    }
    code.Raw({0x57});
    if (!code.Call(config.layout.validationEntryOffset, result.error)) return false;
    code.Raw({0x83,0xC4,0x04,0x85,0xC0}); code.Jcc32(0x85, cleanup);
    code.Raw({0x83,0xBF}); code.U32(CtxCallDepth); code.U8(0); code.Jcc32(0x85, failStack);
    code.Raw({0x83,0xBF}); code.U32(CtxHalted); code.U8(1); code.Jcc32(0x85, failRuntime);
    // The direct-threaded handler ABI owns the scratch GPR allocation.  Do
    // not carry the public-entry copy of EBX across the synthesized chain;
    // reload the authenticated frame pointer from the execution context for
    // write-back.
    code.Raw({0x8B,0x9F}); code.U32(CtxNativeFrame);
    code.Raw({0x85,0xDB}); code.Jcc32(0x84, failRuntime);
    for (uint8_t family = 0; family < 8; ++family) {
        if (family == 4) continue;
        code.Raw({0x8B,0x8F}); code.U32(CtxRegisterMap);
        code.Raw({0x0F,0xB6,0x49,family,0x8B,0x84,0xCF}); code.U32(CtxVregs);
        code.Raw({0x89,0x83}); code.U32(nativeOffsets[family]);
    }
    code.Raw({0x8B,0x87}); code.U32(CtxVirtualFlags);
    code.Raw({0x89,0x83}); code.U32(offsetof(VM_NATIVE_FRAME_X86,eflags));
    code.Raw({0x31,0xC0}); code.Jmp32(cleanup);
    code.Bind(failMetadata); code.U8(0xB8); code.U32(VM_MICRO_ERR_METADATA_INVALID); code.Jmp32(cleanup);
    code.Bind(failRecord); code.U8(0xB8); code.U32(VM_MICRO_ERR_RECORD_NOT_FOUND); code.Jmp32(cleanup);
    code.Bind(failAuth); code.U8(0xB8); code.U32(VM_MICRO_ERR_BYTECODE_AUTH); code.Jmp32(cleanup);
    code.Bind(failRegister); code.U8(0xB8); code.U32(VM_MICRO_ERR_REGISTER_MAP_INVALID); code.Jmp32(cleanup);
    code.Bind(failStack); code.U8(0xB8); code.U32(VM_MICRO_ERR_STACK_ALIGNMENT); code.Jmp32(cleanup);
    code.Bind(failRuntime); code.U8(0xB8); code.U32(VM_MICRO_ERR_SCHEMA_MISMATCH);
    code.Bind(cleanup);
    code.Raw({0x89,0x45,0xE4,0x83,0x7D,0xF0,0x00}); code.Jcc32(0x84, wipe);
    code.Raw({0x8B,0x7D,0xF0,0x31,0xC0,0xB9}); code.U32(kRuntimeScratchSize);
    code.Raw({0xF3,0xAA});
    code.Bind(wipe);
    code.Raw({0x8D,0x7D,0xA0,0x31,0xC0,0xB9,0x20,0x00,0x00,0x00,
              0xF3,0xAA,0x8B,0x45,0xE4,
              0x8D,0x65,0xF4,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3});
    return true;
}

bool BuildPublicEntry(
    const VMHandlerEntryCodegenConfig& config,
    VMHandlerEntryCodegenResult& result)
{
    CodeBuffer code(config.layout.publicEntryOffset);
    const size_t sipHash = code.NewLabel();
    const size_t hChaCha = code.NewLabel();
    if (config.architecture == VM_ARCH_X64) {
        if (!BuildPublicEntryX64(config,result,code,sipHash,hChaCha) ||
            !EmitSipHashHelperX64(code,sipHash,config,result) ||
            !EmitHChaChaHelperX64(code,hChaCha,config,result)) return false;
    } else {
        if (!BuildPublicEntryX86(config,result,code,sipHash,hChaCha) ||
            !EmitSipHashHelperX86(code,sipHash,config) ||
            !EmitHChaChaHelperX86(code,hChaCha,config)) return false;
    }
    if (!code.Resolve(result.error)) return false;
    result.entryCode = std::move(code.bytes);
    return true;
}

} // namespace
} // namespace CipherShell
