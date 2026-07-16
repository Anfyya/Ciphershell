#include "packer/mutation/mutation_engine.h"
#include "packer/transforms/vm_handler_synthesizer.h"
#include "packer/vm/vm_schema.h"
#include "runtime/common/vm_crypto.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using CipherShell::MicroInstruction;
using CipherShell::MutatedISA;
using CipherShell::MutationConfig;
using CipherShell::MutationEngine;
using CipherShell::VMHandlerArchitecture;
using CipherShell::VMHandlerFunctionDecodePlans;
using CipherShell::VMHandlerSynthesisConfig;
using CipherShell::VMHandlerSynthesisResult;
using CipherShell::VMHandlerSynthesizer;
using CipherShell::VMSchema;

constexpr uint32_t kVirtualProtectIatRVA = 0x400u;
constexpr uint32_t kFlushInstructionCacheIatRVA = 0x408u;
constexpr uint32_t kMetadataRVA = 0x1000u;
constexpr uint32_t kRuntimeRVA = 0x20000u;
constexpr uint32_t kFunctionRVA = 0x1234u;
#if defined(_M_X64)
constexpr uint64_t kExpectedRax = 0xD15EA5E5C0DEC0DEULL;
#else
constexpr uint64_t kExpectedRax = 0xC0DEC0DEu;
#endif

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

std::array<uint8_t, 32> MakeSeed() {
    std::array<uint8_t, 32> seed{};
    uint32_t state = 0xC51F3A79u;
    for (size_t i = 0; i < seed.size(); ++i) {
        state ^= state << 13u;
        state ^= state >> 17u;
        state ^= state << 5u;
        seed[i] = static_cast<uint8_t>(state >> ((i & 3u) * 8u));
    }
    return seed;
}

struct TestISA {
    VMHandlerSynthesisConfig config{};
    std::unordered_map<uint8_t, uint8_t> forward;
    std::array<uint8_t, VM_OPCODE_MAP_SIZE> reverse{};
    VM_OPERAND_CODEC codec{};
    uint64_t codecSeed = 0;
};

TestISA BuildISA() {
    TestISA output{};
    const auto seed = MakeSeed();
    MutationConfig mutation{};
    mutation.seed = seed;
    mutation.registerCount = 24;
    mutation.randomizeOpcodeMap = true;
    mutation.randomizeRegisterMap = true;
    mutation.mutateHandlers = true;
    mutation.embedJunkHandlers = true;
    mutation.requestedJunkHandlerCount = 8;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool supported =
#if defined(_M_X64)
            descriptor.runtimeSupportedX64;
#else
            descriptor.runtimeSupportedX86;
#endif
        if (supported) {
            mutation.validOpcodes.push_back(static_cast<uint8_t>(descriptor.opcode));
        }
    }
    MutationEngine engine;
    Require(engine.Initialize(mutation), "公开入口测试无法初始化 ISA 变异器");
    const MutatedISA isa = engine.GenerateMutatedISA();

#if defined(_M_X64)
    output.config.architecture = VMHandlerArchitecture::X64;
#else
    output.config.architecture = VMHandlerArchitecture::X86;
#endif
    output.config.buildSeed = seed;
    output.config.handlerSemanticToSlot = isa.handlerSemanticToSlot;
    output.config.handlerSlotToSemantic = isa.handlerSlotToSemantic;
    output.config.handlerVariants = isa.handlerVariants;
    output.config.variantCount = VM_HANDLER_VARIANT_COUNT;
    output.config.virtualProtectIatRVA = kVirtualProtectIatRVA;
    output.config.flushInstructionCacheIatRVA = kFlushInstructionCacheIatRVA;
    output.config.encryptHandlerBodies = true;
    output.config.emitCetLandingPads = true;
    std::memcpy(&output.codecSeed, seed.data(), sizeof(output.codecSeed));
    output.codec = VMSchema::DeriveOperandCodec(output.codecSeed, kFunctionRVA);
    VMHandlerFunctionDecodePlans plans{};
    plans.functionRVA = kFunctionRVA;
    plans.codec = output.codec;
    std::string planError;
    Require(VMSchema::BuildRuntimeDecodePlans(
            plans.codec, plans.plans.data(), planError),
        "公开入口测试无法生成 runtime decode plan: " + planError);
    output.config.functionDecodePlans.push_back(plans);
    output.forward = isa.opcodeMap;
    output.reverse.fill(VM_HANDLER_INVALID);
    for (const auto& pair : output.forward) output.reverse[pair.second] = pair.first;
    return output;
}

MicroInstruction Uop(
    VM_MICRO_OPCODE opcode,
    std::initializer_list<uint64_t> operands,
    uint8_t variant)
{
    const auto* descriptor = VMSchema::Lookup(opcode);
    Require(descriptor != nullptr && descriptor->operandCount == operands.size(),
        "公开入口测试微操作描述不合法");
    MicroInstruction instruction{};
    instruction.opcode = opcode;
    instruction.handlerVariant = variant;
    instruction.operandCount = descriptor->operandCount;
    size_t index = 0;
    for (uint64_t operand : operands) instruction.operands[index++] = operand;
    return instruction;
}

std::vector<uint8_t> BuildBytecode(const TestISA& isa) {
    std::vector<MicroInstruction> program;
    program.push_back(Uop(VM_UOP_PUSH_IMM, {kExpectedRax,
#if defined(_M_X64)
            8
#else
            4
#endif
        }, 1));
    program.push_back(Uop(VM_UOP_POP_VREG, {0,
#if defined(_M_X64)
            8
#else
            4
#endif
            , 0, 1}, 2));
    // Drive the authenticated reader well beyond the first 64-byte ChaCha block.
    // This also detects generated x64 stack references that encode +0x80..+0x9f
    // with a signed disp8 and silently write below the reader's allocated frame.
    for (uint32_t index = 0; index < 24u; ++index) {
        program.push_back(Uop(VM_UOP_PUSH_IMM,
            {0x1122334455660000ULL + index,
#if defined(_M_X64)
             8
#else
             4
#endif
            }, static_cast<uint8_t>(index & 3u)));
        program.push_back(Uop(VM_UOP_DROP, {},
            static_cast<uint8_t>((index + 1u) & 3u)));
    }
    program.push_back(Uop(VM_UOP_EXIT, {0}, 3));
    std::vector<uint8_t> bytecode;
    for (const auto& instruction : program) {
        std::string error;
        Require(VMSchema::Encode(
                instruction, isa.forward, isa.codec, bytecode, error),
            "公开入口测试字节码编码失败: " + error);
    }
    const auto validation = VMSchema::ValidateStream(
        bytecode.data(), bytecode.size(), isa.reverse.data(), isa.codec, 24);
    Require(validation.success, "公开入口测试字节码校验失败: " + validation.error);
    Require(bytecode.size() > 128u,
        "公开入口测试未跨过 ChaCha reader 的高位栈槽/多 block 边界");
    return bytecode;
}

void EncodeMasterKey(
    const uint8_t master[32],
    const uint8_t runtimeShare[32],
    const VM_METADATA_HEADER& header,
    uint8_t encoded[32])
{
    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t cookie = static_cast<uint8_t>(
            header.cookie >> ((i & 3u) * 8u));
        encoded[i] = master[i] ^ runtimeShare[i] ^ header.buildId[i & 15u] ^
            cookie ^ static_cast<uint8_t>(i * 0x5Bu);
    }
}

uint64_t MetadataTag(
    const uint8_t* metadata,
    size_t size,
    const uint8_t master[32])
{
    const size_t tagOffset = offsetof(VM_METADATA_HEADER, metadataTag);
    const uint64_t zero = 0;
    VM_SIPHASH24_CONTEXT context{};
    vm_siphash24_init(&context, master);
    vm_siphash24_update(&context, metadata, tagOffset);
    vm_siphash24_update(&context,
        reinterpret_cast<const uint8_t*>(&zero), sizeof(zero));
    const size_t after = tagOffset + sizeof(uint64_t);
    if (after < size) vm_siphash24_update(&context, metadata + after, size - after);
    return vm_siphash24_final(&context);
}

struct MetadataImage {
    std::vector<uint8_t> bytes;
    std::array<uint8_t, 32> master{};
    std::array<uint8_t, 32> runtimeShare{};
};

MetadataImage BuildMetadata(
    const TestISA& isa,
    const VMHandlerSynthesisResult& runtime,
    const std::vector<uint8_t>& plaintext,
    uint32_t imageSize)
{
    VM_METADATA_HEADER header{};
    header.cookie = 0xC0DEC51Fu;
    header.headerSize = sizeof(header);
    header.metadataVersion = VM_METADATA_VERSION;
    header.schemaVersion = VM_SCHEMA_VERSION;
    header.runtimeVersion = VM_RUNTIME_VERSION;
#if defined(_M_X64)
    header.architecture = VM_ARCH_X64;
#else
    header.architecture = VM_ARCH_X86;
#endif
    header.flags = VM_METADATA_FLAG_AUTHENTICATED |
        VM_METADATA_FLAG_BYTECODE_CHACHA20 |
        VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
        VM_METADATA_FLAG_CFG_VERIFIED |
        VM_METADATA_FLAG_HANDLER_MUTATED |
        VM_METADATA_FLAG_JUNK_HANDLERS |
        VM_METADATA_FLAG_MICRO_STREAM |
        VM_METADATA_FLAG_LAZY_FLAGS |
        VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
        VM_METADATA_FLAG_DIRECT_THREADED |
        VM_METADATA_FLAG_HANDLER_ENCRYPTED;
#if defined(_M_X64)
    header.flags |= VM_METADATA_FLAG_UNWIND_VERIFIED;
#endif
    header.recordCount = 1;
    header.recordSize = sizeof(VM_FUNCTION_RECORD);
    header.recordOffset = AlignUp(sizeof(header), 16u);
    header.reverseOpcodeMapOffset = header.recordOffset + sizeof(VM_FUNCTION_RECORD);
    header.registerMapOffset = header.reverseOpcodeMapOffset + VM_OPCODE_MAP_SIZE;
    header.handlerSemanticMapOffset = header.registerMapOffset + VM_REGISTER_MAP_SIZE;
    header.handlerDescriptorOffset = header.handlerSemanticMapOffset + VM_HANDLER_TABLE_SIZE;
    header.handlerVariantOffset = header.handlerDescriptorOffset + VM_HANDLER_TABLE_SIZE;
    header.bytecodeOffset = AlignUp(
        header.handlerVariantOffset + VM_HANDLER_TABLE_SIZE, 64u);
    header.bytecodeSize = static_cast<uint32_t>(plaintext.size());
    header.totalSize = AlignUp(header.bytecodeOffset + header.bytecodeSize, 16u);
    header.runtimeEntryRVA = kRuntimeRVA + runtime.entryOffset;
    header.runtimeSize = static_cast<uint32_t>(runtime.image.size());
    header.imageSize = imageSize;
    header.layoutSeed = 0xA17E5EEDu;
    header.operandCodecSeed = isa.codecSeed;
    header.keyEncodingVersion = VM_KEY_ENCODING_VERSION;
    header.opcodeMapSize = VM_OPCODE_MAP_SIZE;
    header.registerMapSize = VM_REGISTER_MAP_SIZE;
    header.handlerTableSize = VM_HANDLER_TABLE_SIZE;
    header.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
    header.runtimeBaseRVA = kRuntimeRVA;
    for (uint8_t i = 0; i < sizeof(header.buildId); ++i)
        header.buildId[i] = static_cast<uint8_t>(0x31u + i * 7u);

    MetadataImage output{};
    for (uint8_t i = 0; i < 32; ++i) {
        output.master[i] = static_cast<uint8_t>(0xA5u ^ (i * 13u));
        output.runtimeShare[i] = static_cast<uint8_t>(0x5Au ^ (i * 29u));
    }
    EncodeMasterKey(output.master.data(), output.runtimeShare.data(),
        header, header.encodedMasterKey);

    VM_FUNCTION_RECORD record{};
    record.functionRVA = kFunctionRVA;
    record.functionSize = 16;
    record.bytecodeOffset = 0;
    record.bytecodeSize = header.bytecodeSize;
    record.flags = VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
        VM_RECORD_FLAG_CFG_VERIFIED;
#if defined(_M_X64)
    record.flags |= VM_RECORD_FLAG_X64 | VM_RECORD_FLAG_UNWIND_VERIFIED;
#endif
    record.guestStackSize = 0x4000u;
    for (uint8_t i = 0; i < sizeof(record.nonce); ++i)
        record.nonce[i] = static_cast<uint8_t>(0xC3u + i * 5u);

    uint8_t recordKey[32]{};
    vm_derive_record_key(output.master.data(), header.buildId,
        record.functionRVA, recordKey);
    std::vector<uint8_t> ciphertext(plaintext.size());
    vm_chacha20_xor(plaintext.data(), ciphertext.data(), ciphertext.size(),
        recordKey, record.nonce, 1, 0);
    record.bytecodeTag = vm_siphash24(
        ciphertext.data(), ciphertext.size(), recordKey + 16);
    std::memset(recordKey, 0, sizeof(recordKey));

    output.bytes.assign(header.totalSize, 0xA7);
    std::memcpy(output.bytes.data(), &header, sizeof(header));
    std::memcpy(output.bytes.data() + header.recordOffset, &record, sizeof(record));
    std::memcpy(output.bytes.data() + header.reverseOpcodeMapOffset,
        isa.reverse.data(), isa.reverse.size());
    for (uint8_t i = 0; i < VM_REGISTER_MAP_SIZE; ++i)
        output.bytes[header.registerMapOffset + i] = i;
    std::memcpy(output.bytes.data() + header.handlerSemanticMapOffset,
        isa.config.handlerSemanticToSlot.data(), VM_HANDLER_TABLE_SIZE);
    std::memcpy(output.bytes.data() + header.handlerDescriptorOffset,
        isa.config.handlerSlotToSemantic.data(), VM_HANDLER_TABLE_SIZE);
    std::memcpy(output.bytes.data() + header.handlerVariantOffset,
        isa.config.handlerVariants.data(), VM_HANDLER_TABLE_SIZE);
    std::memcpy(output.bytes.data() + header.bytecodeOffset,
        ciphertext.data(), ciphertext.size());
    auto* mutableHeader = reinterpret_cast<VM_METADATA_HEADER*>(output.bytes.data());
    mutableHeader->metadataTag = MetadataTag(
        output.bytes.data(), output.bytes.size(), output.master.data());
    return output;
}

#if defined(_M_X64)
using PublicEntry = uint32_t (__fastcall*)(
    VM_NATIVE_FRAME_X64*, uint32_t, VM_METADATA_HEADER*,
    uint8_t*, VM_EXTENDED_STATE*);
using GeneratedSipHash = uint64_t (__fastcall*)(
    const uint8_t*, uint32_t, const uint8_t*, uint32_t);
using GeneratedHChaCha = void (__fastcall*)(
    const uint8_t*, const uint8_t*, uint32_t, uint8_t*);
using GeneratedReadByte = int32_t (__fastcall*)(VM_MICRO_EXECUTION_CONTEXT*);
using GeneratedDecodeThunk = uintptr_t (__fastcall*)(
    VM_MICRO_EXECUTION_CONTEXT*, void*, void*);
using GeneratedExecuteThunk = void (__fastcall*)(
    VM_MICRO_EXECUTION_CONTEXT*, void*, void*);

uint32_t InvokePublic(
    PublicEntry entry,
    VM_NATIVE_FRAME_X64* frame,
    VM_METADATA_HEADER* metadata,
    uint8_t* imageBase,
    VM_EXTENDED_STATE* extended,
    DWORD& exception)
{
    exception = 0;
    __try {
        return entry(frame, kFunctionRVA, metadata, imageBase, extended);
    } __except((exception = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)) {
        return VM_MICRO_ERR_HANDLER_BUG;
    }
}

DWORD InvokeDecodedChain(
    GeneratedExecuteThunk thunk,
    VM_MICRO_EXECUTION_CONTEXT* context,
    void* dispatch,
    void* handler)
{
    DWORD exception = 0;
    __try {
        thunk(context, dispatch, handler);
    } __except((exception = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)) {
    }
    return exception;
}

class LoadedProduct final {
public:
    ~LoadedProduct() {
        if (m_registered && !m_functions.empty())
            RtlDeleteFunctionTable(m_functions.data());
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
    }

    bool Load(
        const VMHandlerSynthesisResult& runtime,
        const MetadataImage& metadata,
        std::string& error)
    {
        m_size = AlignUp(kRuntimeRVA + static_cast<uint32_t>(runtime.image.size()),
            0x1000u) + 0x1000u;
        m_base = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m_base) { error = "VirtualAlloc 失败"; return false; }
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_base);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(m_base + dos->e_lfanew);
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt->OptionalHeader.SizeOfImage = m_size;
        const uintptr_t virtualProtect = reinterpret_cast<uintptr_t>(&::VirtualProtect);
        const uintptr_t flush = reinterpret_cast<uintptr_t>(&::FlushInstructionCache);
        std::memcpy(m_base + kVirtualProtectIatRVA,
            &virtualProtect, sizeof(virtualProtect));
        std::memcpy(m_base + kFlushInstructionCacheIatRVA,
            &flush, sizeof(flush));
        std::memcpy(m_base + kMetadataRVA,
            metadata.bytes.data(), metadata.bytes.size());
        std::memcpy(m_base + kRuntimeRVA,
            runtime.image.data(), runtime.image.size());
        std::memcpy(m_base + kRuntimeRVA + runtime.keyMarkerOffset,
            metadata.runtimeShare.data(), metadata.runtimeShare.size());
        const uintptr_t runtimeBase = reinterpret_cast<uintptr_t>(m_base + kRuntimeRVA);
        for (const auto& relocation : runtime.relocations) {
            uint8_t* target = m_base + kRuntimeRVA + relocation.offset;
            if (relocation.type != IMAGE_REL_BASED_DIR64) {
                error = "x64 公开入口测试出现非 DIR64 relocation";
                return false;
            }
            uint64_t value = 0;
            std::memcpy(&value, target, sizeof(value));
            value += runtimeBase;
            std::memcpy(target, &value, sizeof(value));
        }
        m_functions.reserve(runtime.unwindEntries.size());
        for (const auto& unwind : runtime.unwindEntries) {
            RUNTIME_FUNCTION function{};
            function.BeginAddress = kRuntimeRVA + unwind.beginOffset;
            function.EndAddress = kRuntimeRVA + unwind.endOffset;
            function.UnwindData = kRuntimeRVA + unwind.unwindOffset;
            m_functions.push_back(function);
        }
        std::sort(m_functions.begin(), m_functions.end(),
            [](const auto& left, const auto& right) {
                return left.BeginAddress < right.BeginAddress;
            });
        if (m_functions.empty() || !RtlAddFunctionTable(
                m_functions.data(), static_cast<DWORD>(m_functions.size()),
                reinterpret_cast<DWORD64>(m_base))) {
            error = "RtlAddFunctionTable 失败";
            return false;
        }
        m_registered = true;
        DWORD oldProtection = 0;
        if (!VirtualProtect(m_base + kRuntimeRVA,
                AlignUp(static_cast<uint32_t>(runtime.image.size()), 0x1000u),
                PAGE_EXECUTE_READ, &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(),
                m_base + kRuntimeRVA, runtime.image.size())) {
            error = "公开入口 runtime 无法切换为 RX";
            return false;
        }
        return true;
    }

    uint8_t* Base() const { return m_base; }
    VM_METADATA_HEADER* Metadata() const {
        return reinterpret_cast<VM_METADATA_HEADER*>(m_base + kMetadataRVA);
    }

private:
    uint8_t* m_base = nullptr;
    uint32_t m_size = 0;
    std::vector<RUNTIME_FUNCTION> m_functions;
    bool m_registered = false;
};

class NativeFrameRegion final {
public:
    NativeFrameRegion() {
        const size_t scratch = AlignUp(
            static_cast<uint32_t>(sizeof(VM_MICRO_EXECUTION_CONTEXT)), 16u) + 64u;
        m_size = VM_RUNTIME_X64_FRAME_TO_SCRATCH + scratch;
        m_bytes = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    ~NativeFrameRegion() {
        if (m_bytes) VirtualFree(m_bytes, 0, MEM_RELEASE);
    }
    VM_NATIVE_FRAME_X64* Frame() const {
        return reinterpret_cast<VM_NATIVE_FRAME_X64*>(m_bytes);
    }
    bool Valid() const { return m_bytes != nullptr; }

private:
    uint8_t* m_bytes = nullptr;
    size_t m_size = 0;
};

void TestPublicEntry() {
    TestISA isa = BuildISA();
    const std::vector<uint8_t> plaintext = BuildBytecode(isa);
    VMHandlerSynthesizer synthesizer;
    const VMHandlerSynthesisResult runtime = synthesizer.Synthesize(isa.config);
    Require(runtime.success, "公开入口 handler 合成失败: " + runtime.error);
    const uint32_t imageSize = AlignUp(
        kRuntimeRVA + static_cast<uint32_t>(runtime.image.size()), 0x1000u) + 0x1000u;
    MetadataImage metadata = BuildMetadata(isa, runtime, plaintext, imageSize);
    LoadedProduct product;
    std::string loadError;
    Require(product.Load(runtime, metadata, loadError),
        "公开入口测试产物装载失败: " + loadError);

    std::vector<uint32_t> publicRoutines;
    for (const auto& unwind : runtime.unwindEntries) {
        if (unwind.beginOffset < runtime.contextEntryOffset)
            publicRoutines.push_back(unwind.beginOffset);
    }
    std::sort(publicRoutines.begin(), publicRoutines.end());
    Require(publicRoutines.size() == 3,
        "公开入口没有独立 public/SipHash/HChaCha unwind 范围");
    const auto generatedSip = reinterpret_cast<GeneratedSipHash>(
        product.Base() + kRuntimeRVA + publicRoutines[1]);
    const uint64_t generatedMetadataTag = generatedSip(
        reinterpret_cast<const uint8_t*>(product.Metadata()),
        product.Metadata()->totalSize, metadata.master.data(),
        static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, metadataTag)));
    Require(generatedMetadataTag == product.Metadata()->metadataTag,
        "生成 SipHash 与 pack-time metadata tag 不一致: " +
        std::to_string(generatedMetadataTag) + "/" +
        std::to_string(product.Metadata()->metadataTag));
    const auto generatedHChaCha = reinterpret_cast<GeneratedHChaCha>(
        product.Base() + kRuntimeRVA + publicRoutines[2]);
    std::array<uint8_t, 32> generatedRecordKey{};
    std::array<uint8_t, 32> expectedRecordKey{};
    generatedHChaCha(metadata.master.data(), product.Metadata()->buildId,
        kFunctionRVA, generatedRecordKey.data());
    vm_derive_record_key(metadata.master.data(), product.Metadata()->buildId,
        kFunctionRVA, expectedRecordKey.data());
    Require(generatedRecordKey == expectedRecordKey,
        "生成 HChaCha 与 pack-time record key 不一致");
    std::cout << "[TRACE] public crypto helpers passed\n" << std::flush;
    std::vector<uint32_t> decoderRoutines;
    for (const auto& unwind : runtime.unwindEntries) {
        if (unwind.beginOffset >= runtime.operandDecoderOffset &&
            unwind.beginOffset < runtime.flagMaterializerOffset) {
            decoderRoutines.push_back(unwind.beginOffset);
        }
    }
    std::sort(decoderRoutines.begin(), decoderRoutines.end());
    Require(decoderRoutines.size() == 2,
        "operand decoder 没有独立 read-byte unwind 范围");
    const auto generatedReader = reinterpret_cast<GeneratedReadByte>(
        product.Base() + kRuntimeRVA + decoderRoutines[1]);
    auto* record = reinterpret_cast<VM_FUNCTION_RECORD*>(
        reinterpret_cast<uint8_t*>(product.Metadata()) +
        product.Metadata()->recordOffset);
    uint8_t* encrypted = reinterpret_cast<uint8_t*>(product.Metadata()) +
        product.Metadata()->bytecodeOffset + record->bytecodeOffset;
    VM_MICRO_EXECUTION_CONTEXT readerContext{};
    readerContext.vip = reinterpret_cast<uintptr_t>(encrypted);
    readerContext.bytecodeBegin = readerContext.vip;
    readerContext.bytecodeEnd = readerContext.vip + record->bytecodeSize;
    readerContext.record = reinterpret_cast<uintptr_t>(record);
    readerContext.rollingKey = reinterpret_cast<uintptr_t>(expectedRecordKey.data());
    for (uint8_t expected : plaintext) {
        const int32_t decoded = generatedReader(&readerContext);
        Require(decoded >= 0 && static_cast<uint8_t>(decoded) == expected,
            "生成 ChaCha read-byte 与 pack-time 密文不一致");
    }
    std::cout << "[TRACE] public ChaCha reader passed\n" << std::flush;
    const uint8_t thunkCode[] = {
        0xF3,0x0F,0x1E,0xFA,              // endbr64
        0x41,0x55,                         // push r13
        0x41,0x56,                         // push r14
        0x48,0x83,0xEC,0x28,              // shadow/alignment
        0x49,0x89,0xD6,                    // r14=dispatch table
        0x4C,0x89,0xC0,0xFF,0xD0,         // call r8 (decoder)
        0x48,0x83,0xC4,0x28,
        0x41,0x5E,0x41,0x5D,0xC3
    };
    uint8_t* thunkMemory = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 0x1000u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Require(thunkMemory != nullptr, "无法分配 decoder ABI thunk");
    std::memcpy(thunkMemory, thunkCode, sizeof(thunkCode));
    DWORD thunkOld = 0;
    Require(VirtualProtect(thunkMemory, 0x1000u, PAGE_EXECUTE_READ, &thunkOld),
        "无法启用 decoder ABI thunk");
    VM_MICRO_EXECUTION_CONTEXT decodeContext{};
    decodeContext.vip = reinterpret_cast<uintptr_t>(plaintext.data());
    decodeContext.bytecodeBegin = decodeContext.vip;
    decodeContext.bytecodeEnd = decodeContext.vip + plaintext.size();
    decodeContext.reverseOpcodeMap = reinterpret_cast<uintptr_t>(isa.reverse.data());
    decodeContext.handlerSemanticToSlot = reinterpret_cast<uintptr_t>(
        isa.config.handlerSemanticToSlot.data());
    decodeContext.decodePlans = reinterpret_cast<uintptr_t>(
        isa.config.functionDecodePlans[0].plans.data());
    decodeContext.dispatchTable = reinterpret_cast<uintptr_t>(
        product.Base() + kRuntimeRVA + runtime.dispatchTableOffset);
    decodeContext.operandCodec = isa.codec;
    const auto thunk = reinterpret_cast<GeneratedDecodeThunk>(thunkMemory);
    const uintptr_t decodedTarget = thunk(&decodeContext,
        reinterpret_cast<void*>(decodeContext.dispatchTable),
        product.Base() + kRuntimeRVA + decoderRoutines[0]);
    Require(decodedTarget != 0 && decodeContext.error == VM_MICRO_ERR_NONE,
        "生成 operand decoder 拒绝 pack-time 合法字节码: " +
        std::to_string(decodeContext.error));
    Require(decodeContext.currentSemantic == VM_UOP_PUSH_IMM,
        "生成 operand decoder 与 pack-time semantic 不一致: " +
        std::to_string(decodeContext.currentSemantic));
    Require(decodeContext.currentVariant == 1 &&
            decodeContext.decodedOperandCount == 2 &&
            decodeContext.decodedOperands[0] == kExpectedRax &&
            decodeContext.decodedOperands[1] == 8,
        "generated operand decoder produced the wrong variant/operands");
    const auto expectedHandler = std::find_if(runtime.handlers.begin(),
        runtime.handlers.end(), [](const auto& handler) {
            return handler.semantic == VM_UOP_PUSH_IMM && handler.variant == 1;
        });
    Require(expectedHandler != runtime.handlers.end() &&
            decodedTarget == reinterpret_cast<uintptr_t>(product.Base() +
                kRuntimeRVA + expectedHandler->storageOffset),
        "generated operand decoder selected the wrong dispatch cell");
    std::cout << "[TRACE] public operand decoder passed\n" << std::flush;

    NativeFrameRegion frameRegion;
    Require(frameRegion.Valid(), "无法分配 native-frame/guest-scratch 连续区");
    VM_NATIVE_FRAME_X64* frame = frameRegion.Frame();
    std::memset(frame, 0, sizeof(*frame));
    frame->rax = 0x0102030405060708ULL;
    frame->rflags = 0x202ULL;
    uint64_t guestStack[8]{};
    frame->originalRsp = reinterpret_cast<uintptr_t>(guestStack);
    alignas(64) VM_EXTENDED_STATE extended{};
    const auto entry = reinterpret_cast<PublicEntry>(
        product.Base() + kRuntimeRVA + runtime.entryOffset);
    DWORD exception = 0;
    const uint32_t status = InvokePublic(entry, frame, product.Metadata(),
        product.Base(), &extended, exception);
    std::cout << "[TRACE] public entry returned\n" << std::flush;
    Require(exception == 0, "公开五参数入口触发 native 异常: " +
        std::to_string(exception));
    MEMORY_BASIC_INFORMATION statusStatePage{};
    VirtualQuery(product.Base() + kRuntimeRVA +
        (runtime.keyMarkerOffset & ~0xFFFu), &statusStatePage,
        sizeof(statusStatePage));
    for (const auto& handler : runtime.handlers) {
        Require(std::memcmp(product.Base() + kRuntimeRVA + handler.storageOffset,
                handler.plaintextBody.data(), handler.plaintextBody.size()) == 0,
            "runtime handler 解密结果与 pack-time 明文不一致");
    }
    decodeContext.decodeOperands = reinterpret_cast<uintptr_t>(
        product.Base() + kRuntimeRVA + decoderRoutines[0]);
    const uint8_t executeThunkCode[] = {
        0xF3,0x0F,0x1E,0xFA,              // endbr64
        0x41,0x55,                         // push r13
        0x41,0x56,                         // push r14
        0x41,0x57,                         // push r15
        0x48,0x83,0xEC,0x20,              // shadow space
        0x49,0x89,0xCF,                    // r15=context
        0x49,0x89,0xD6,                    // r14=dispatch
        0x4C,0x8B,0xA9,                    // r13=[context.vip]
        static_cast<uint8_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vip)),
        static_cast<uint8_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vip) >> 8u),
        static_cast<uint8_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vip) >> 16u),
        static_cast<uint8_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, vip) >> 24u),
        0x4C,0x89,0xC0,0xFF,0xD0,         // call r8 (first handler)
        0x48,0x83,0xC4,0x20,
        0x41,0x5F,0x41,0x5E,0x41,0x5D,0xC3
    };
    uint8_t* executeThunkMemory = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 0x1000u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Require(executeThunkMemory != nullptr, "无法分配 handler ABI thunk");
    std::memcpy(executeThunkMemory, executeThunkCode, sizeof(executeThunkCode));
    DWORD executeThunkOld = 0;
    Require(VirtualProtect(executeThunkMemory, 0x1000u, PAGE_EXECUTE_READ,
            &executeThunkOld),
        "无法启用 handler ABI thunk");
    const DWORD chainException = InvokeDecodedChain(
        reinterpret_cast<GeneratedExecuteThunk>(executeThunkMemory),
        &decodeContext, reinterpret_cast<void*>(decodeContext.dispatchTable),
        reinterpret_cast<void*>(decodedTarget));
    Require(chainException == 0, "明文 direct-threaded handler 链触发 native 异常: " +
        std::to_string(chainException));
    Require(decodeContext.error == VM_MICRO_ERR_NONE &&
            decodeContext.halted == 1 && decodeContext.valueDepth == 0 &&
            decodeContext.vregs[0] == kExpectedRax,
        "明文 direct-threaded handler 链语义/栈状态不一致: error=" +
        std::to_string(decodeContext.error) + ", depth=" +
        std::to_string(decodeContext.valueDepth));

    // Re-run the exact chain through the authenticated ChaCha reader.  This
    // separates public-context initialization from decoder/handler semantics
    // and prevents a plaintext-only decoder gate from masking crypto drift.
    VM_MICRO_EXECUTION_CONTEXT encryptedContext{};
    encryptedContext.vip = reinterpret_cast<uintptr_t>(encrypted);
    encryptedContext.bytecodeBegin = encryptedContext.vip;
    encryptedContext.bytecodeEnd = encryptedContext.vip + record->bytecodeSize;
    encryptedContext.reverseOpcodeMap = reinterpret_cast<uintptr_t>(isa.reverse.data());
    encryptedContext.handlerSemanticToSlot = reinterpret_cast<uintptr_t>(
        isa.config.handlerSemanticToSlot.data());
    encryptedContext.decodePlans = reinterpret_cast<uintptr_t>(
        isa.config.functionDecodePlans[0].plans.data());
    encryptedContext.dispatchTable = reinterpret_cast<uintptr_t>(
        product.Base() + kRuntimeRVA + runtime.dispatchTableOffset);
    encryptedContext.decodeOperands = reinterpret_cast<uintptr_t>(
        product.Base() + kRuntimeRVA + decoderRoutines[0]);
    encryptedContext.record = reinterpret_cast<uintptr_t>(record);
    encryptedContext.rollingKey = reinterpret_cast<uintptr_t>(expectedRecordKey.data());
    encryptedContext.operandCodec = isa.codec;
    encryptedContext.virtualFlags = 0x202ULL;
    const uintptr_t encryptedTarget = thunk(&encryptedContext,
        reinterpret_cast<void*>(encryptedContext.dispatchTable),
        product.Base() + kRuntimeRVA + decoderRoutines[0]);
    Require(encryptedTarget != 0 && encryptedContext.error == VM_MICRO_ERR_NONE,
        "密文 operand decoder 拒绝合法首条微操作: " +
        std::to_string(encryptedContext.error));
    const DWORD encryptedChainException = InvokeDecodedChain(
        reinterpret_cast<GeneratedExecuteThunk>(executeThunkMemory),
        &encryptedContext,
        reinterpret_cast<void*>(encryptedContext.dispatchTable),
        reinterpret_cast<void*>(encryptedTarget));
    Require(encryptedChainException == 0 &&
            encryptedContext.error == VM_MICRO_ERR_NONE &&
            encryptedContext.halted == 1 && encryptedContext.valueDepth == 0 &&
            encryptedContext.vregs[0] == kExpectedRax,
        "密文 direct-threaded 链不等价: exception=" +
        std::to_string(encryptedChainException) + ", error=" +
        std::to_string(encryptedContext.error) + ", semantic=" +
        std::to_string(encryptedContext.currentSemantic) + ", operands=" +
        std::to_string(encryptedContext.decodedOperands[0]) + "," +
        std::to_string(encryptedContext.decodedOperands[1]));
    VirtualFree(executeThunkMemory, 0, MEM_RELEASE);
    VirtualFree(thunkMemory, 0, MEM_RELEASE);
    Require(status == VM_MICRO_ERR_NONE,
        "公开五参数入口返回错误: " + std::to_string(status) +
        ", stateProtect=" + std::to_string(statusStatePage.Protect));
    Require(frame->rax == kExpectedRax, "公开入口未按 VM 语义写回 RAX");
    Require(frame->rflags == 0x202ULL, "公开入口意外改变虚拟 flags");

    MEMORY_BASIC_INFORMATION statePage{};
    MEMORY_BASIC_INFORMATION handlerPage{};
    Require(VirtualQuery(product.Base() + kRuntimeRVA +
            (runtime.keyMarkerOffset & ~0xFFFu), &statePage,
            sizeof(statePage)) == sizeof(statePage),
        "无法查询 runtime 状态页权限");
    Require(VirtualQuery(product.Base() + kRuntimeRVA +
            runtime.encryptedHandlerOffset, &handlerPage,
            sizeof(handlerPage)) == sizeof(handlerPage),
        "无法查询 handler 页权限");
    Require((statePage.Protect & 0xFFu) == PAGE_READWRITE,
        "解密状态页没有保持 RW/NX");
    Require((handlerPage.Protect & 0xFFu) == PAGE_EXECUTE_READ,
        "handler 页没有在解密后恢复 RX");

    auto* header = product.Metadata();
    uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header) + header->bytecodeOffset;
    ciphertext[0] ^= 0x80u;
    header->metadataTag = MetadataTag(reinterpret_cast<uint8_t*>(header),
        header->totalSize, metadata.master.data());
    std::memset(frame, 0, sizeof(*frame));
    frame->rax = 0xABABABABABABABABULL;
    frame->rflags = 0x202ULL;
    frame->originalRsp = reinterpret_cast<uintptr_t>(guestStack);
    const VM_NATIVE_FRAME_X64 before = *frame;
    exception = 0;
    const uint32_t tamperedStatus = InvokePublic(entry, frame,
        header, product.Base(), &extended, exception);
    Require(exception == 0, "篡改密文导致公开入口 native 异常");
    Require(tamperedStatus == VM_MICRO_ERR_BYTECODE_AUTH,
        "篡改密文没有 fail-closed 到 BYTECODE_AUTH");
    Require(std::memcmp(frame, &before, sizeof(before)) == 0,
        "认证失败路径修改了 native frame");
}
#elif defined(_M_IX86)
using PublicEntryX86 = uint32_t (__cdecl*)(
    VM_NATIVE_FRAME_X86*, uint32_t, VM_METADATA_HEADER*,
    uint8_t*, VM_EXTENDED_STATE*);

uint32_t InvokePublicX86(
    PublicEntryX86 entry,
    VM_NATIVE_FRAME_X86* frame,
    VM_METADATA_HEADER* metadata,
    uint8_t* imageBase,
    VM_EXTENDED_STATE* extended,
    DWORD& exception)
{
    exception = 0;
    __try {
        return entry(frame, kFunctionRVA, metadata, imageBase, extended);
    } __except((exception = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)) {
        return VM_MICRO_ERR_HANDLER_BUG;
    }
}

class LoadedProductX86 final {
public:
    ~LoadedProductX86() {
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
    }

    bool Load(
        const VMHandlerSynthesisResult& runtime,
        const MetadataImage& metadata,
        std::string& error)
    {
        m_size = AlignUp(kRuntimeRVA + static_cast<uint32_t>(runtime.image.size()),
            0x1000u) + 0x1000u;
        m_base = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m_base) { error = "x86 VirtualAlloc 失败"; return false; }
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_base);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(m_base + dos->e_lfanew);
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        nt->OptionalHeader.SizeOfImage = m_size;
        const uint32_t virtualProtect = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(&::VirtualProtect));
        const uint32_t flush = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(&::FlushInstructionCache));
        std::memcpy(m_base + kVirtualProtectIatRVA,
            &virtualProtect, sizeof(virtualProtect));
        std::memcpy(m_base + kFlushInstructionCacheIatRVA,
            &flush, sizeof(flush));
        std::memcpy(m_base + kMetadataRVA,
            metadata.bytes.data(), metadata.bytes.size());
        std::memcpy(m_base + kRuntimeRVA,
            runtime.image.data(), runtime.image.size());
        std::memcpy(m_base + kRuntimeRVA + runtime.keyMarkerOffset,
            metadata.runtimeShare.data(), metadata.runtimeShare.size());
        const uint32_t runtimeBase = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(m_base + kRuntimeRVA));
        for (const auto& relocation : runtime.relocations) {
            if (relocation.type != IMAGE_REL_BASED_HIGHLOW) {
                error = "x86 公开入口出现非 HIGHLOW relocation";
                return false;
            }
            uint8_t* target = m_base + kRuntimeRVA + relocation.offset;
            uint32_t value = 0;
            std::memcpy(&value, target, sizeof(value));
            value += runtimeBase;
            std::memcpy(target, &value, sizeof(value));
        }
        DWORD oldProtection = 0;
        if (!VirtualProtect(m_base + kRuntimeRVA,
                AlignUp(static_cast<uint32_t>(runtime.image.size()), 0x1000u),
                PAGE_EXECUTE_READ, &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(),
                m_base + kRuntimeRVA, runtime.image.size())) {
            error = "x86 公开入口 runtime 无法切换为 RX";
            return false;
        }
        return true;
    }

    uint8_t* Base() const { return m_base; }
    VM_METADATA_HEADER* Metadata() const {
        return reinterpret_cast<VM_METADATA_HEADER*>(m_base + kMetadataRVA);
    }

private:
    uint8_t* m_base = nullptr;
    uint32_t m_size = 0;
};

class NativeFrameRegionX86 final {
public:
    NativeFrameRegionX86() {
        const size_t scratch = AlignUp(
            static_cast<uint32_t>(sizeof(VM_MICRO_EXECUTION_CONTEXT)), 16u) + 64u;
        m_size = VM_RUNTIME_X86_FRAME_TO_SCRATCH + scratch;
        m_bytes = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    ~NativeFrameRegionX86() {
        if (m_bytes) VirtualFree(m_bytes, 0, MEM_RELEASE);
    }
    VM_NATIVE_FRAME_X86* Frame() const {
        return reinterpret_cast<VM_NATIVE_FRAME_X86*>(m_bytes);
    }
    bool Valid() const { return m_bytes != nullptr; }

private:
    uint8_t* m_bytes = nullptr;
    size_t m_size = 0;
};

void TestPublicEntryX86() {
    TestISA isa = BuildISA();
    const std::vector<uint8_t> plaintext = BuildBytecode(isa);
    VMHandlerSynthesizer synthesizer;
    const VMHandlerSynthesisResult runtime = synthesizer.Synthesize(isa.config);
    Require(runtime.success, "x86 公开入口 handler 合成失败: " + runtime.error);
    Require(runtime.unwindEntries.empty(), "x86 runtime 不应携带 x64 unwind 表");
    const uint32_t imageSize = AlignUp(
        kRuntimeRVA + static_cast<uint32_t>(runtime.image.size()), 0x1000u) + 0x1000u;
    MetadataImage metadata = BuildMetadata(isa, runtime, plaintext, imageSize);
    LoadedProductX86 product;
    std::string loadError;
    Require(product.Load(runtime, metadata, loadError), loadError);

    NativeFrameRegionX86 frameRegion;
    Require(frameRegion.Valid(), "无法分配 x86 native-frame/guest-scratch 连续区");
    VM_NATIVE_FRAME_X86* frame = frameRegion.Frame();
    std::memset(frame, 0, sizeof(*frame));
    frame->eax = 0x01020304u;
    frame->eflags = 0x202u;
    uint32_t guestStack[8]{};
    frame->originalEsp = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(guestStack));
    alignas(64) VM_EXTENDED_STATE extended{};
    const auto entry = reinterpret_cast<PublicEntryX86>(
        product.Base() + kRuntimeRVA + runtime.entryOffset);
    DWORD exception = 0;
    const uint32_t status = InvokePublicX86(entry, frame, product.Metadata(),
        product.Base(), &extended, exception);
    Require(exception == 0, "x86 公开五参数入口触发 native 异常: " +
        std::to_string(exception));
    for (const auto& handler : runtime.handlers) {
        Require(std::memcmp(product.Base() + kRuntimeRVA + handler.storageOffset,
                handler.plaintextBody.data(), handler.plaintextBody.size()) == 0,
            "x86 runtime handler 解密结果与 pack-time 明文不一致");
    }
    Require(status == VM_MICRO_ERR_NONE,
        "x86 公开五参数入口返回错误: " + std::to_string(status));
    Require(frame->eax == static_cast<uint32_t>(kExpectedRax),
        "x86 公开入口未按 VM 语义写回 EAX");
    Require(frame->eflags == 0x202u, "x86 公开入口意外改变虚拟 flags");

    MEMORY_BASIC_INFORMATION statePage{};
    MEMORY_BASIC_INFORMATION handlerPage{};
    Require(VirtualQuery(product.Base() + kRuntimeRVA +
            (runtime.keyMarkerOffset & ~0xFFFu), &statePage,
            sizeof(statePage)) == sizeof(statePage),
        "无法查询 x86 runtime 状态页权限");
    Require(VirtualQuery(product.Base() + kRuntimeRVA +
            runtime.encryptedHandlerOffset, &handlerPage,
            sizeof(handlerPage)) == sizeof(handlerPage),
        "无法查询 x86 handler 页权限");
    Require((statePage.Protect & 0xFFu) == PAGE_READWRITE,
        "x86 解密状态页没有保持 RW/NX");
    Require((handlerPage.Protect & 0xFFu) == PAGE_EXECUTE_READ,
        "x86 handler 页没有在解密后恢复 RX");

    auto* header = product.Metadata();
    uint8_t* ciphertext = reinterpret_cast<uint8_t*>(header) + header->bytecodeOffset;
    ciphertext[0] ^= 0x80u;
    header->metadataTag = MetadataTag(reinterpret_cast<uint8_t*>(header),
        header->totalSize, metadata.master.data());
    std::memset(frame, 0, sizeof(*frame));
    frame->eax = 0xABABABABu;
    frame->eflags = 0x202u;
    frame->originalEsp = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(guestStack));
    const VM_NATIVE_FRAME_X86 before = *frame;
    exception = 0;
    const uint32_t tamperedStatus = InvokePublicX86(entry, frame,
        header, product.Base(), &extended, exception);
    Require(exception == 0, "x86 篡改密文导致公开入口 native 异常");
    Require(tamperedStatus == VM_MICRO_ERR_BYTECODE_AUTH,
        "x86 篡改密文没有 fail-closed 到 BYTECODE_AUTH");
    Require(std::memcmp(frame, &before, sizeof(before)) == 0,
        "x86 认证失败路径修改了 native frame");
}
#endif

} // namespace

int main() {
#if defined(_M_X64)
    try {
        TestPublicEntry();
        std::cout << "[PASS] x64 公开五参数入口 crypto/auth/ABI/W^X 闭环\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] x64 公开五参数入口: " << error.what() << '\n';
        return 1;
    }
#elif defined(_M_IX86)
    try {
        TestPublicEntryX86();
        std::cout << "[PASS] x86 公开五参数入口 crypto/auth/ABI/W^X 闭环\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] x86 公开五参数入口: " << error.what() << '\n';
        return 1;
    }
#else
#error test_vm_public_entry requires an x86 or x64 MSVC target
#endif
}
