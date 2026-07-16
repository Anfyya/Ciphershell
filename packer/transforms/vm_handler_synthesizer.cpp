#include "vm_handler_synthesizer.h"

#include "vm_handler_entry_codegen.h"
#include "vm_handler_semantic_codegen.h"
#include "../vm/vm_schema.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <unordered_set>

namespace CipherShell {
namespace {

constexpr std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> kRuntimeKeyMarker = {
    0x43,0x53,0x56,0x4D,0x4B,0x45,0x59,0x33,
    0x91,0x2D,0xE7,0x54,0xA8,0x6B,0xC0,0x1F,
    0x37,0xD2,0x4A,0xB9,0x65,0x0E,0x83,0xFC,
    0x18,0xA1,0x5D,0x72,0xCE,0x39,0xB4,0x06
};

constexpr uint32_t kPublicEntryReserve = 0x4000;
constexpr uint32_t kValidationEntryReserve = 0x1000;
constexpr uint32_t kDecryptorReserve = 0x1000;
constexpr uint32_t kOperandDecoderReserve = 0x2000;
constexpr uint32_t kFlagMaterializerReserve = 0x2000;
constexpr uint32_t kHandlerPageAlignment = 0x1000;
constexpr uint32_t kMaximumVariantCount = VM_MICRO_MAX_HANDLER_VARIANTS;
constexpr uint16_t kRelocationHighLow = 3;
constexpr uint16_t kRelocationDir64 = 10;
constexpr uint32_t kX64DirectTailStackSize = 0x28u;
constexpr uint8_t kX64DirectTailPrologSize = 4u;
static_assert(kX64DirectTailStackSize >= 8u &&
        kX64DirectTailStackSize <= 128u &&
        (kX64DirectTailStackSize % 8u) == 0u,
    "direct-tail stack allocation must fit UWOP_ALLOC_SMALL");
constexpr std::array<uint8_t, 8> kX64DirectTailUnwindInfo = {
    0x01,                               // version 1, no flags
    kX64DirectTailPrologSize,           // SUB RSP, 0x28 length
    0x01,                               // one unwind-code slot
    0x00,                               // no frame register
    kX64DirectTailPrologSize,
    static_cast<uint8_t>((((kX64DirectTailStackSize - 8u) / 8u) << 4u) |
        0x02u),                         // UWOP_ALLOC_SMALL, OpInfo=4 => 0x28
    0x00, 0x00                          // even-slot padding
};
constexpr uint32_t kX64BridgeStackSize =
    0x20u + sizeof(VM_INSTRUCTION_BRIDGE_STATE);
static_assert(kX64BridgeStackSize == 0x498u &&
        (kX64BridgeStackSize % 8u) == 0u,
    "extended bridge Win64 frame contract changed");
constexpr std::array<uint8_t, 8> kX64BridgeUnwindInfo = {
    0x01,                               // version 1, no flags
    0x07,                               // SUB RSP, imm32 length
    0x02,                               // UWOP_ALLOC_LARGE uses two slots
    0x00,
    0x07, 0x01,                         // UWOP_ALLOC_LARGE, OpInfo=0
    static_cast<uint8_t>(kX64BridgeStackSize / 8u),
    static_cast<uint8_t>(kX64BridgeStackSize / 8u >> 8u)
};
constexpr uint32_t kX64NativeCallStackSize = 0x608u;
static_assert((kX64NativeCallStackSize & 0xFu) == 8u &&
        kX64NativeCallStackSize / 8u <= 0xFFFFu,
    "native-call Win64 frame contract changed");
constexpr std::array<uint8_t, 8> kX64NativeCallUnwindInfo = {
    0x01,
    0x07,
    0x02,
    0x00,
    0x07, 0x01,
    static_cast<uint8_t>(kX64NativeCallStackSize / 8u),
    static_cast<uint8_t>(kX64NativeCallStackSize / 8u >> 8u)
};
constexpr std::array<uint8_t, 8> kX64CpuidUnwindInfo = {
    0x01,                               // version 1, no flags
    0x01,                               // PUSH RBX length
    0x01,                               // one unwind-code slot
    0x00,
    0x01, 0x30,                         // UWOP_PUSH_NONVOL, RBX=3
    0x00, 0x00
};
constexpr std::array<uint8_t, 22> kX64DirectTailStackCode = {
    0x48,0x83,0xEC,0x28,0xFF,0xD0,      // sub rsp, 0x28; call rax
    0x48,0x85,0xC0,                    // test rax, rax
    0x75,0x07,                          // jne have_target
    0x48,0x8D,0x05,0x09,0x00,0x00,0x00,
                                        // lea rax, [return_stub]
    0x48,0x83,0xC4,0x28                 // add rsp, 0x28
};
constexpr std::array<uint8_t, 6> kX64DirectTailLeafCode = {
    0x48,0x85,0xC0,                    // preserve the historical final TEST
    0xFF,0xE0,0xC3                     // jmp rax; return_stub: ret
};

bool ExpectedSemanticStackFunclet(
    uint8_t semantic,
    VMSynthesizedStackFunclet& expected)
{
    expected = {};
    switch (static_cast<VM_MICRO_OPCODE>(semantic)) {
        case VM_UOP_PUSH_FLAGS:
        case VM_UOP_FLAGS_LAZY:
        case VM_UOP_FLAGS_MATERIALIZE:
        case VM_UOP_FLAGS_WRITE:
        case VM_UOP_FLAGS_UPDATE:
        case VM_UOP_FLAGS_PACK_AH:
        case VM_UOP_FLAGS_UNPACK_AH:
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT:
        case VM_UOP_BRANCH_IF:
            expected.kind = VMSynthesizedUnwindKind::StackAllocation;
            expected.stackBytes = kX64DirectTailStackSize;
            expected.prologSize = kX64DirectTailPrologSize;
            return true;
        case VM_UOP_BRIDGE_EXTENDED:
            expected.kind = VMSynthesizedUnwindKind::StackAllocation;
            expected.stackBytes = kX64BridgeStackSize;
            expected.prologSize = 7u;
            return true;
        case VM_UOP_CALL_HOST:
            expected.kind = VMSynthesizedUnwindKind::StackAllocation;
            expected.stackBytes = kX64NativeCallStackSize;
            expected.prologSize = 7u;
            return true;
        case VM_UOP_CPUID:
            expected.kind = VMSynthesizedUnwindKind::PushNonvolatile;
            expected.prologSize = 1u;
            expected.nonvolatileRegister = 3u;
            return true;
        default:
            return false;
    }
}

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

constexpr uint32_t CtxDecodeOperands =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, decodeOperands));
constexpr uint32_t CtxError =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, error));
constexpr uint32_t CtxHalted =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, halted));
constexpr uint32_t CtxMutationScratch =
    static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, mutationScratch));

bool AlignUpChecked(uint32_t value, uint32_t alignment, uint32_t& output) {
    if (alignment == 0 || (alignment & (alignment - 1u)) != 0) return false;
    if (value > (std::numeric_limits<uint32_t>::max)() - (alignment - 1u)) return false;
    output = (value + alignment - 1u) & ~(alignment - 1u);
    return true;
}

uint8_t Rotl8(uint8_t value, unsigned count) {
    count &= 7u;
    return count == 0 ? value :
        static_cast<uint8_t>((value << count) | (value >> (8u - count)));
}

uint64_t HashBytes(const uint8_t* bytes, size_t size, uint64_t domain) {
    uint64_t hash = 1469598103934665603ULL ^ domain;
    for (size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
        hash ^= hash >> 29u;
    }
    return hash ? hash : (domain | 1ULL);
}

uint64_t HashBytes(const std::vector<uint8_t>& bytes, uint64_t domain) {
    return HashBytes(bytes.data(), bytes.size(), domain);
}

class SeedStream {
public:
    SeedStream(const std::array<uint8_t, 32>& seed, uint64_t domain) {
        m_s0 = HashBytes(seed.data(), 16, domain ^ 0xA0761D6478BD642FULL);
        m_s1 = HashBytes(seed.data() + 16, 16, domain ^ 0xE7037ED1A0B428DBULL);
        if ((m_s0 | m_s1) == 0) m_s1 = 1;
        for (unsigned round = 0; round < 16; ++round) Next64();
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
    uint32_t Below(uint32_t upper) { return upper == 0 ? 0 : Next32() % upper; }

private:
    uint64_t m_s0 = 0;
    uint64_t m_s1 = 0;
};

class CodeBuffer {
public:
    std::vector<uint8_t> bytes;

    void U8(uint8_t value) { bytes.push_back(value); }
    void U32(uint32_t value) {
        for (unsigned byte = 0; byte < 4; ++byte)
            U8(static_cast<uint8_t>(value >> (byte * 8u)));
    }
    void Raw(std::initializer_list<uint8_t> values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    template <size_t Size>
    void Raw(const std::array<uint8_t, Size>& values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    size_t Offset() const { return bytes.size(); }
};

bool SemanticRequired(const VMHandlerSynthesisConfig& config, uint8_t semantic) {
    const auto* descriptor = VMSchema::Lookup(semantic);
    if (!descriptor) return false;
    return config.architecture == VMHandlerArchitecture::X64
        ? descriptor->runtimeSupportedX64
        : descriptor->runtimeSupportedX86;
}

void EmitCetLandingPad(CodeBuffer& code, bool x64, bool enabled) {
    if (!enabled) return;
    code.Raw(x64 ? std::initializer_list<uint8_t>{0xF3,0x0F,0x1E,0xFA}
                 : std::initializer_list<uint8_t>{0xF3,0x0F,0x1E,0xFB});
}

void EmitOpaqueIsland(CodeBuffer& code, SeedStream& random, uint32_t minimumBytes) {
    const uint32_t size = minimumBytes + random.Below(97u);
    code.U8(0xE9);
    code.U32(size);
    for (uint32_t index = 0; index < size; ++index) code.U8(random.Next8());
}

void EmitMutationNoise(CodeBuffer& code, bool x64, SeedStream& random) {
    const uint32_t immediate = random.Next32() | 1u;
    if (x64) {
        code.Raw({0x4D,0x8B,0x9F}); code.U32(CtxMutationScratch);
        switch (random.Below(4u)) {
            case 0: code.Raw({0x49,0x81,0xF3}); code.U32(immediate); break;
            case 1: code.Raw({0x49,0x81,0xC3}); code.U32(immediate); break;
            case 2: code.Raw({0x49,0x81,0xEB}); code.U32(immediate); break;
            default:
                code.Raw({0x49,0xC1,0xC3,
                    static_cast<uint8_t>((immediate % 63u) + 1u)});
                break;
        }
        code.Raw({0x4D,0x89,0x9F}); code.U32(CtxMutationScratch);
    } else {
        code.Raw({0x8B,0x87}); code.U32(CtxMutationScratch);
        switch (random.Below(4u)) {
            case 0: code.U8(0x35); code.U32(immediate); break;
            case 1: code.U8(0x05); code.U32(immediate); break;
            case 2: code.U8(0x2D); code.U32(immediate); break;
            default:
                code.Raw({0xC1,0xC0,
                    static_cast<uint8_t>((immediate % 31u) + 1u)});
                break;
        }
        code.Raw({0x89,0x87}); code.U32(CtxMutationScratch);
    }
}

void EmitTrapKernel(CodeBuffer& code, bool x64) {
    if (x64) {
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxError);
        code.U32(VM_MICRO_ERR_OPCODE_UNSUPPORTED);
        code.Raw({0x41,0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
    } else {
        code.Raw({0xC7,0x87}); code.U32(CtxError);
        code.U32(VM_MICRO_ERR_OPCODE_UNSUPPORTED);
        code.Raw({0xC7,0x87}); code.U32(CtxHalted); code.U32(1);
    }
}

void EmitDirectTail(
    CodeBuffer& code,
    bool x64,
    VMSynthesizedHandler& handler)
{
    if (x64) {
        code.Raw({0x41,0x83,0xBF}); code.U32(CtxHalted);
        code.Raw({0x00,0x74,0x01,0xC3});
        code.Raw({0x4C,0x89,0xF9});
        code.Raw({0x49,0x8B,0x87}); code.U32(CtxDecodeOperands);
        // Handler entry is reached by CALL (RSP == 8 mod 16).  Reserve the
        // Win64 0x20-byte home area plus alignment before invoking the local
        // decoder ABI, then release it before direct-threading to the target.
        code.Raw({0x48,0x85,0xC0,0x74,0x1B});
        handler.dispatchUnwindOffset = static_cast<uint32_t>(code.Offset());
        code.Raw(kX64DirectTailStackCode);
        handler.dispatchUnwindSize = static_cast<uint32_t>(code.Offset()) -
            handler.dispatchUnwindOffset;
        // The final indirect jump and its null-target return stub are leaf
        // instructions reached only after RSP has been restored.
        code.Raw(kX64DirectTailLeafCode);
    } else {
        code.Raw({0x83,0xBF}); code.U32(CtxHalted);
        code.Raw({0x00,0x74,0x01,0xC3});
        code.Raw({0x8B,0x87}); code.U32(CtxDecodeOperands);
        code.Raw({0x85,0xC0,0x74,0x0C,0x57,0xFF,0xD0,0x83,0xC4,0x04,
                  0x85,0xC0,0x74,0x02,0xFF,0xE0,0xC3});
    }
}

bool BuildHandler(
    const VMHandlerSynthesisConfig& config,
    uint8_t semantic,
    uint8_t variant,
    uint8_t slot,
    VMSynthesizedHandler& handler,
    std::string& error)
{
    const bool x64 = config.architecture == VMHandlerArchitecture::X64;
    const uint64_t domain = 0x48414E444C455235ULL ^
        (static_cast<uint64_t>(semantic) << 24u) ^
        (static_cast<uint64_t>(variant) << 8u) ^
        static_cast<uint32_t>(config.architecture);
    SeedStream random(config.buildSeed, domain);
    CodeBuffer code;
    EmitCetLandingPad(code, x64, config.emitCetLandingPads);
    EmitOpaqueIsland(code, random,
        std::max<uint32_t>(24u, config.minimumJunkBytesPerHandler / 4u));
    EmitMutationNoise(code, x64, random);
    EmitOpaqueIsland(code, random,
        24u + static_cast<uint32_t>((semantic + variant) & 15u));

    handler = {};
    handler.semantic = semantic;
    handler.slot = slot;
    handler.variant = variant;

    if (semantic == VM_UOP_TRAP) {
        handler.semanticBodyOffset = static_cast<uint32_t>(code.Offset());
        EmitTrapKernel(code, x64);
        handler.semanticBodySize = static_cast<uint32_t>(code.Offset()) -
            handler.semanticBodyOffset;
        handler.semanticCoreOffset = handler.semanticBodyOffset;
        handler.semanticCoreSize = handler.semanticBodySize;
        handler.semanticCoreVariantOffset = handler.semanticBodyOffset;
        handler.semanticCoreVariantSize = handler.semanticBodySize;
        const std::array<uint8_t, 8> x64Registers = {0,2,8,10,11,9,1,3};
        const std::array<uint8_t, 6> x86Registers = {0,2,1,5,6,3};
        for (size_t index = 0; index < handler.registerAssignment.size(); ++index) {
            handler.registerAssignment[index] = x64
                ? x64Registers[(index + variant) % x64Registers.size()]
                : x86Registers[(index + variant) % x86Registers.size()];
        }
        handler.semanticComplete = true;
    } else {
        VMHandlerSemanticCodegenConfig semanticConfig{};
        semanticConfig.architecture = static_cast<uint32_t>(config.architecture);
        semanticConfig.buildSeed = config.buildSeed;
        semanticConfig.semantic = static_cast<VM_MICRO_OPCODE>(semantic);
        semanticConfig.variant = variant;
        VMHandlerSemanticCodegenResult generated =
            GenerateVMHandlerSemanticKernel(semanticConfig);
        if (!generated.success || !generated.semanticComplete || generated.code.empty()) {
            error = "semantic kernel generation failed for opcode " +
                std::to_string(semantic) + ": " + generated.error;
            return false;
        }
        std::string variantEvidenceError;
        if (!ValidateVMHandlerSemanticVariantKernel(
                semanticConfig, generated, variantEvidenceError)) {
            error = "semantic K-variant machine-code evidence failed for opcode " +
                std::to_string(semantic) + ": " + variantEvidenceError;
            return false;
        }
        const auto* descriptor = VMSchema::Lookup(semantic);
        if (!descriptor || generated.operandCount != descriptor->operandCount ||
            generated.stackPops != descriptor->stackPops ||
            generated.stackPushes != descriptor->stackPushes ||
            generated.decodedOperandCount != descriptor->operandCount) {
            error = "semantic kernel contract disagrees with schema for opcode " +
                std::to_string(semantic);
            return false;
        }
        if (code.Offset() > (std::numeric_limits<uint32_t>::max)()) {
            error = "semantic kernel base exceeds uint32 range";
            return false;
        }
        const uint32_t semanticKernelBase = static_cast<uint32_t>(code.Offset());
        if (generated.semanticBodySize == 0 ||
            generated.semanticBodyOffset > generated.code.size() ||
            generated.semanticBodySize >
                generated.code.size() - generated.semanticBodyOffset ||
            generated.semanticBodyOffset >
                (std::numeric_limits<uint32_t>::max)() - semanticKernelBase) {
            error = "semantic body evidence cannot be embedded";
            return false;
        }
        handler.semanticBodyOffset =
            semanticKernelBase + generated.semanticBodyOffset;
        handler.semanticBodySize = generated.semanticBodySize;
        handler.semanticCoreOffset =
            semanticKernelBase + generated.semanticCoreOffset;
        handler.semanticCoreSize = generated.semanticCoreSize;
        handler.semanticCoreVariantOffset = generated.semanticCoreVariantSize != 0
            ? semanticKernelBase + generated.semanticCoreVariantOffset : 0u;
        handler.semanticCoreVariantSize = generated.semanticCoreVariantSize;
        handler.valueCodecRanges.reserve(generated.valueCodecRanges.size());
        for (const auto& range : generated.valueCodecRanges) {
            if (range.size == 0 || range.offset > generated.code.size() ||
                range.size > generated.code.size() - range.offset ||
                range.offset > (std::numeric_limits<uint32_t>::max)() -
                    semanticKernelBase) {
                error = "value codec evidence range cannot be embedded";
                return false;
            }
            handler.valueCodecRanges.push_back({
                semanticKernelBase + range.offset, range.size});
        }
        for (const auto& funclet : generated.stackFunclets) {
            if (funclet.offset > generated.code.size() || funclet.size == 0 ||
                funclet.size > generated.code.size() - funclet.offset ||
                funclet.offset > (std::numeric_limits<uint32_t>::max)() -
                    semanticKernelBase ||
                funclet.size > (std::numeric_limits<uint32_t>::max)() -
                    (semanticKernelBase + funclet.offset)) {
                error = "semantic stack-funclet range cannot be embedded";
                return false;
            }
            VMSynthesizedStackFunclet embedded{};
            embedded.offset = semanticKernelBase + funclet.offset;
            embedded.size = funclet.size;
            embedded.stackBytes = funclet.stackBytes;
            embedded.prologSize = funclet.prologSize;
            embedded.nonvolatileRegister = funclet.nonvolatileRegister;
            switch (funclet.kind) {
                case VMHandlerSemanticUnwindKind::StackAllocation:
                    embedded.kind = VMSynthesizedUnwindKind::StackAllocation;
                    break;
                case VMHandlerSemanticUnwindKind::PushNonvolatile:
                    embedded.kind = VMSynthesizedUnwindKind::PushNonvolatile;
                    break;
                default:
                    error = "semantic stack-funclet kind cannot be embedded";
                    return false;
            }
            handler.semanticStackFunclets.push_back(embedded);
        }
        code.bytes.insert(code.bytes.end(), generated.code.begin(), generated.code.end());
        handler.registerAssignment = generated.registerAssignment;
        handler.operandBytesConsumed = generated.decodedOperandCount;
        handler.semanticComplete = true;
    }

    // Similarity resistance comes from the executed per-variant allocation,
    // MBA, junk and block layout in the semantic kernel.  Keep only a small
    // storage-envelope island here so unreachable bytes cannot dominate the
    // cross-build metric.
    EmitOpaqueIsland(code, random,
        std::max<uint32_t>(32u, config.minimumJunkBytesPerHandler / 2u));
    EmitMutationNoise(code, x64, random);
    handler.dispatchTailOffset = static_cast<uint32_t>(code.Offset());
    EmitDirectTail(code, x64, handler);
    handler.dispatchTailSize = static_cast<uint32_t>(code.Offset()) -
        handler.dispatchTailOffset;
    handler.plaintextBody = std::move(code.bytes);
    handler.bodyDigest = HashBytes(handler.plaintextBody,
        domain ^ 0xB0D1B0D1B0D1B0D1ULL);
    handler.dispatchTailDigest = HashBytes(
        handler.plaintextBody.data() + handler.dispatchTailOffset,
        handler.dispatchTailSize,
        domain ^ 0xD15FA7C4D15FA7C4ULL);
    return true;
}

bool BuildJunkHandler(
    const VMHandlerSynthesisConfig& config,
    uint8_t slot,
    uint8_t variant,
    VMSynthesizedHandler& handler)
{
    const bool x64 = config.architecture == VMHandlerArchitecture::X64;
    const uint64_t domain = 0x4A554E4B48444C35ULL ^
        (static_cast<uint64_t>(slot) << 16u) ^ variant;
    SeedStream random(config.buildSeed, domain);
    CodeBuffer code;
    EmitCetLandingPad(code, x64, config.emitCetLandingPads);
    EmitOpaqueIsland(code, random, 416u + random.Below(128u));
    EmitMutationNoise(code, x64, random);
    EmitOpaqueIsland(code, random, 416u + random.Below(128u));

    handler = {};
    handler.semantic = VM_HANDLER_JUNK;
    handler.slot = slot;
    handler.variant = variant;
    for (size_t index = 0; index < handler.registerAssignment.size(); ++index)
        handler.registerAssignment[index] =
            static_cast<uint8_t>((variant + index + slot) & (x64 ? 15u : 7u));
    handler.dispatchTailOffset = static_cast<uint32_t>(code.Offset());
    EmitDirectTail(code, x64, handler);
    handler.dispatchTailSize = static_cast<uint32_t>(code.Offset()) -
        handler.dispatchTailOffset;
    handler.semanticComplete = true;
    handler.plaintextBody = std::move(code.bytes);
    handler.bodyDigest = HashBytes(handler.plaintextBody,
        domain ^ 0x4A554E4B424F4459ULL);
    handler.dispatchTailDigest = HashBytes(
        handler.plaintextBody.data() + handler.dispatchTailOffset,
        handler.dispatchTailSize,
        domain ^ 0x4A554E4B5441494CULL);
    return true;
}

struct CipherParameters {
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

uint32_t PackCipherMutationPlan(const CipherParameters& parameters) {
    return static_cast<uint32_t>(parameters.shiftLeftA) |
        (static_cast<uint32_t>(parameters.shiftRightB) << 6u) |
        (static_cast<uint32_t>(parameters.shiftLeftC) << 12u) |
        (static_cast<uint32_t>(parameters.instructionVariant) << 24u);
}

CipherParameters DeriveCipher(const VMHandlerSynthesisConfig& config) {
    SeedStream random(config.buildSeed, 0x4349504845527634ULL);
    CipherParameters parameters{};
    parameters.initialState = random.Next64();
    parameters.multiplier =
        static_cast<uint64_t>((random.Next32() & 0x7FFFFFFFu) | 1u);
    parameters.addend = static_cast<uint64_t>(random.Next32() & 0x7FFFFFFFu);
    parameters.addByte = static_cast<uint8_t>(random.Next8() | 1u);
    parameters.rotate = static_cast<uint8_t>((random.Next8() % 7u) + 1u);
    const auto& shiftPlan = VM_DECRYPTOR_SHIFT_PLANS[
        random.Next8() % VM_DECRYPTOR_SHIFT_PLANS.size()];
    parameters.shiftLeftA = shiftPlan[0];
    parameters.shiftRightB = shiftPlan[1];
    parameters.shiftLeftC = shiftPlan[2];
    parameters.instructionVariant = static_cast<uint8_t>(
        random.Next8() % VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT);
    return parameters;
}

void EncryptHandlerRegion(
    std::vector<uint8_t>& image,
    uint32_t offset,
    uint32_t size,
    const CipherParameters& parameters)
{
    uint64_t state = parameters.initialState;
    for (uint32_t index = 0; index < size; ++index) {
        // Both target decoders implement the same modulo-2^64 state machine.
        // Keeping a 32-bit pack-time branch for x86 produced ciphertext that
        // the generated 64-bit-pair x86 decryptor could never invert.
        state ^= state << parameters.shiftLeftA;
        state ^= state >> parameters.shiftRightB;
        state ^= state << parameters.shiftLeftC;
        state = state * parameters.multiplier + parameters.addend;
        image[offset + index] = Rotl8(static_cast<uint8_t>(
            (image[offset + index] ^ static_cast<uint8_t>(state)) +
                parameters.addByte),
            parameters.rotate);
    }
}

void WritePointer(
    std::vector<uint8_t>& image,
    uint32_t offset,
    uint32_t pointerSize,
    uint64_t value)
{
    for (uint32_t byte = 0; byte < pointerSize; ++byte)
        image[offset + byte] = static_cast<uint8_t>(value >> (byte * 8u));
}

uint64_t DispatchPointerMask(uint32_t pointerSize) {
    return pointerSize == 8u ? (std::numeric_limits<uint64_t>::max)()
                             : 0xFFFFFFFFULL;
}

uint64_t RotateDispatchLeft(
    uint64_t value,
    uint8_t rotate,
    uint32_t pointerSize)
{
    const uint32_t bits = pointerSize * 8u;
    const uint32_t count = static_cast<uint32_t>(rotate) & (bits - 1u);
    const uint64_t mask = DispatchPointerMask(pointerSize);
    value &= mask;
    return count == 0u ? value :
        ((value << count) | (value >> (bits - count))) & mask;
}

uint64_t RotateDispatchRight(
    uint64_t value,
    uint8_t rotate,
    uint32_t pointerSize)
{
    const uint32_t bits = pointerSize * 8u;
    const uint32_t count = static_cast<uint32_t>(rotate) & (bits - 1u);
    const uint64_t mask = DispatchPointerMask(pointerSize);
    value &= mask;
    return count == 0u ? value :
        ((value >> count) | (value << (bits - count))) & mask;
}

uint64_t EncodeDispatchTableTarget(
    uint64_t targetOffset,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec)
{
    const uint64_t mask = DispatchPointerMask(pointerSize);
    if (codec.encoding == VMDispatchTableEncoding::XorKeyedTable)
        return (targetOffset ^ codec.key) & mask;
    return RotateDispatchLeft(
        (targetOffset + codec.key) & mask, codec.rotate, pointerSize);
}

uint64_t DecodeDispatchTableTarget(
    uint64_t encodedTarget,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec)
{
    const uint64_t mask = DispatchPointerMask(pointerSize);
    if (codec.encoding == VMDispatchTableEncoding::XorKeyedTable)
        return (encodedTarget ^ codec.key) & mask;
    return (RotateDispatchRight(
        encodedTarget, codec.rotate, pointerSize) - codec.key) & mask;
}

bool CopyRoutine(
    std::vector<uint8_t>& image,
    uint32_t offset,
    uint32_t reserve,
    const std::vector<uint8_t>& code,
    const char* name,
    std::string& error)
{
    if (code.empty()) {
        error = std::string(name) + " is empty";
        return false;
    }
    if (code.size() > reserve || offset > image.size() ||
        code.size() > image.size() - offset) {
        error = std::string(name) + " exceeds its reserved image range";
        return false;
    }
    std::copy(code.begin(), code.end(), image.begin() + offset);
    return true;
}

bool BuildFunctionPlans(
    const VMHandlerSynthesisConfig& config,
    std::vector<VMHandlerFunctionDecodePlans>& plans,
    std::string& error)
{
    plans = config.functionDecodePlans;
    if (!plans.empty()) return true;
    uint64_t seed64 = 0;
    std::memcpy(&seed64, config.buildSeed.data(), sizeof(seed64));
    VMHandlerFunctionDecodePlans generated{};
    generated.functionRVA = 0;
    generated.codec = VMSchema::DeriveOperandCodec(seed64, generated.functionRVA);
    if (!VMSchema::BuildRuntimeDecodePlans(
            generated.codec, generated.plans.data(), error)) {
        error = "handler runtime decode plan generation failed: " + error;
        return false;
    }
    plans.push_back(std::move(generated));
    return true;
}

bool ConfigValid(const VMHandlerSynthesisConfig& config, std::string& error) {
    if (config.architecture != VMHandlerArchitecture::X86 &&
        config.architecture != VMHandlerArchitecture::X64) {
        error = "handler target architecture is invalid";
        return false;
    }
    if (std::all_of(config.buildSeed.begin(), config.buildSeed.end(),
            [](uint8_t value) { return value == 0; })) {
        error = "handler build seed is all zero";
        return false;
    }
    if (config.variantCount == 0 || config.variantCount > kMaximumVariantCount ||
        (config.variantCount & (config.variantCount - 1u)) != 0) {
        error = "handler variant count must be a power of two in [1,16]";
        return false;
    }
    if (config.operandCodec.version != VM_OPERAND_CODEC_VERSION ||
        config.operandCodec.domain != VM_OPERAND_CODEC_DOMAIN ||
        config.operandCodec.opcodeRotate == 0 || config.operandCodec.opcodeRotate > 7) {
        error = "handler operand codec contract is invalid";
        return false;
    }
    if (!config.encryptHandlerBodies) {
        error = "plaintext handler storage is forbidden";
        return false;
    }
    if (config.virtualProtectIatRVA == 0 ||
        config.flushInstructionCacheIatRVA == 0) {
        error = "handler synthesis requires VirtualProtect and FlushInstructionCache IAT RVAs";
        return false;
    }

    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> seen{};
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        const uint8_t slot = config.handlerSemanticToSlot[semantic];
        if (!SemanticRequired(config, static_cast<uint8_t>(semantic))) {
            if (slot != VM_HANDLER_INVALID) {
                error = "unsupported micro semantic unexpectedly has a handler slot";
                return false;
            }
            continue;
        }
        if (slot >= VM_HANDLER_USABLE_SLOT_COUNT || seen[slot] ||
            config.handlerSlotToSemantic[slot] != semantic) {
            error = "micro semantic/slot map is incomplete or non-bijective";
            return false;
        }
        seen[slot] = 1;
        if (config.handlerVariants[slot] >= config.variantCount) {
            error = "handler variant seed is outside K";
            return false;
        }
    }

    for (uint32_t slot = 0; slot < VM_HANDLER_USABLE_SLOT_COUNT; ++slot) {
        const uint8_t semantic = config.handlerSlotToSemantic[slot];
        if (semantic == VM_HANDLER_INVALID || semantic == VM_HANDLER_JUNK) continue;
        if (semantic >= VM_UOP_COUNT || !SemanticRequired(config, semantic) ||
            config.handlerSemanticToSlot[semantic] != slot) {
            error = "handler slot maps to an unsupported or mismatched semantic";
            return false;
        }
    }

    std::unordered_set<uint32_t> functionRVAs;
    for (const auto& function : config.functionDecodePlans) {
        if (!functionRVAs.insert(function.functionRVA).second ||
            function.codec.functionRva != function.functionRVA) {
            error = "function decode plan table is duplicated or mismatched";
            return false;
        }
        for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
            if (!SemanticRequired(config, static_cast<uint8_t>(semantic))) continue;
            // TRAP is intentionally not a serializable bytecode semantic;
            // BuildRuntimeDecodePlans leaves it incomplete while the physical
            // trap slot remains synthesized for fail-closed dispatch.
            if (semantic == static_cast<uint32_t>(VM_UOP_TRAP)) continue;
            if (function.plans[semantic].semantic != semantic ||
                function.plans[semantic].semanticComplete == 0) {
                error = "function decode plan has an incomplete semantic";
                return false;
            }
        }
    }
    return true;
}

} // namespace

VMDispatchTableCodec DeriveVMDispatchTableCodec(
    const std::array<uint8_t, 32>& buildSeed)
{
    constexpr uint64_t kDispatchCodecDomain = 0x44535054424C454EULL;
    const uint64_t material = HashBytes(
        buildSeed.data(), buildSeed.size(), kDispatchCodecDomain);
    VMDispatchTableCodec codec{};
    codec.encoding = (material & 1u) == 0u
        ? VMDispatchTableEncoding::XorKeyedTable
        : VMDispatchTableEncoding::AddRotateKeyedTable;
    codec.key = static_cast<uint32_t>(
        (material >> 1u) & 0x7FFFFFFFULL) | 1u;
    codec.rotate = static_cast<uint8_t>(
        ((material >> 33u) % 31u) + 1u);
    return codec;
}

uint64_t EncodeVMDispatchTableTarget(
    uint64_t targetOffset,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec)
{
    return EncodeDispatchTableTarget(targetOffset, pointerSize, codec);
}

uint64_t DecodeVMDispatchTableTarget(
    uint64_t encodedTarget,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec)
{
    return DecodeDispatchTableTarget(encodedTarget, pointerSize, codec);
}

VMHandlerSynthesisResult VMHandlerSynthesizer::Synthesize(
    const VMHandlerSynthesisConfig& config) const
{
    VMHandlerSynthesisResult result{};
    if (!ConfigValid(config, result.error)) return result;

    result.architecture = static_cast<uint32_t>(config.architecture);
    result.directThreaded = true;
    result.handlerBodiesEncrypted = true;
    result.fixedRuntimeBlobUsed = false;
    result.dispatchTableCodec = DeriveVMDispatchTableCodec(config.buildSeed);
    result.entryOffset = 0;
    result.contextEntryOffset = kPublicEntryReserve;
    result.validationEntryOffset = result.contextEntryOffset;
    result.contextEntryABI = config.architecture == VMHandlerArchitecture::X64
        ? VMHandlerEntryABI::X64FastcallContext
        : VMHandlerEntryABI::X86CdeclContext;

    std::vector<VMHandlerFunctionDecodePlans> functionPlans;
    if (!BuildFunctionPlans(config, functionPlans, result.error)) return result;

    result.handlers.reserve(static_cast<size_t>(VM_UOP_COUNT) * config.variantCount);
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        if (!SemanticRequired(config, static_cast<uint8_t>(semantic))) continue;
        const uint8_t slot = config.handlerSemanticToSlot[semantic];
        for (uint32_t variant = 0; variant < config.variantCount; ++variant) {
            VMSynthesizedHandler handler{};
            if (!BuildHandler(config, static_cast<uint8_t>(semantic),
                    static_cast<uint8_t>(variant), slot, handler, result.error)) {
                return result;
            }
            result.handlers.push_back(std::move(handler));
        }
    }
    for (uint32_t slot = 0; slot < VM_HANDLER_USABLE_SLOT_COUNT; ++slot) {
        if (config.handlerSlotToSemantic[slot] != VM_HANDLER_JUNK) continue;
        for (uint32_t variant = 0; variant < config.variantCount; ++variant) {
            VMSynthesizedHandler handler{};
            BuildJunkHandler(config, static_cast<uint8_t>(slot),
                static_cast<uint8_t>(variant), handler);
            result.junkHandlers.push_back(std::move(handler));
        }
    }

    const uint32_t pointerSize = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    result.decryptorOffset = result.contextEntryOffset + kValidationEntryReserve;
    result.operandDecoderOffset = result.decryptorOffset + kDecryptorReserve;
    result.flagMaterializerOffset = result.operandDecoderOffset + kOperandDecoderReserve;
    const uint32_t stateOffset = result.flagMaterializerOffset + kFlagMaterializerReserve;
    if (!AlignUpChecked(stateOffset + 1u, 16u, result.keyMarkerOffset) ||
        !AlignUpChecked(result.keyMarkerOffset + VM_RUNTIME_KEY_SHARE_SIZE,
            16u, result.decodePlanTableOffset)) {
        result.error = "synthesized runtime fixed layout overflows";
        return result;
    }
    const uint64_t decodePlanBytes = static_cast<uint64_t>(functionPlans.size()) *
        sizeof(RuntimeFunctionDecodeTable);
    if (decodePlanBytes > (std::numeric_limits<uint32_t>::max)()) {
        result.error = "runtime decode plan table exceeds uint32 range";
        return result;
    }
    result.decodePlanTableSize = static_cast<uint32_t>(decodePlanBytes);
    if (result.decodePlanTableOffset > (std::numeric_limits<uint32_t>::max)() -
            result.decodePlanTableSize ||
        !AlignUpChecked(result.decodePlanTableOffset + result.decodePlanTableSize,
            pointerSize, result.dispatchTableOffset)) {
        result.error = "runtime decode plan/dispatch layout overflows";
        return result;
    }
    const uint64_t dispatchBytes = static_cast<uint64_t>(VM_HANDLER_TABLE_SIZE) *
        config.variantCount * pointerSize;
    if (dispatchBytes > (std::numeric_limits<uint32_t>::max)()) {
        result.error = "runtime dispatch table exceeds uint32 range";
        return result;
    }
    result.dispatchTableSize = static_cast<uint32_t>(dispatchBytes);
    if (result.dispatchTableOffset > (std::numeric_limits<uint32_t>::max)() -
            result.dispatchTableSize ||
        !AlignUpChecked(result.dispatchTableOffset + result.dispatchTableSize,
            kHandlerPageAlignment, result.encryptedHandlerOffset)) {
        result.error = "runtime handler layout overflows";
        return result;
    }

    uint64_t totalHandlerBytes = 0;
    for (const auto& handler : result.handlers)
        totalHandlerBytes += handler.plaintextBody.size();
    for (const auto& handler : result.junkHandlers)
        totalHandlerBytes += handler.plaintextBody.size();
    if (totalHandlerBytes == 0 ||
        totalHandlerBytes > (std::numeric_limits<uint32_t>::max)() -
            result.encryptedHandlerOffset) {
        result.error = "synthesized handler region is empty or exceeds uint32 range";
        return result;
    }
    result.encryptedHandlerSize = static_cast<uint32_t>(totalHandlerBytes);
    result.image.assign(result.encryptedHandlerOffset + result.encryptedHandlerSize, 0);
    std::copy(kRuntimeKeyMarker.begin(), kRuntimeKeyMarker.end(),
        result.image.begin() + result.keyMarkerOffset);

    for (size_t index = 0; index < functionPlans.size(); ++index) {
        RuntimeFunctionDecodeTable table{};
        table.functionRVA = functionPlans[index].functionRVA;
        table.codec = functionPlans[index].codec;
        std::copy(functionPlans[index].plans.begin(), functionPlans[index].plans.end(),
            std::begin(table.plans));
        std::memcpy(result.image.data() + result.decodePlanTableOffset +
            index * sizeof(RuntimeFunctionDecodeTable), &table, sizeof(table));
    }

    uint32_t cursor = result.encryptedHandlerOffset;
    for (auto& handler : result.handlers) {
        handler.storageOffset = cursor;
        handler.storageSize = static_cast<uint32_t>(handler.plaintextBody.size());
        std::copy(handler.plaintextBody.begin(), handler.plaintextBody.end(),
            result.image.begin() + cursor);
        cursor += handler.storageSize;
    }
    for (auto& handler : result.junkHandlers) {
        handler.storageOffset = cursor;
        handler.storageSize = static_cast<uint32_t>(handler.plaintextBody.size());
        std::copy(handler.plaintextBody.begin(), handler.plaintextBody.end(),
            result.image.begin() + cursor);
        cursor += handler.storageSize;
    }

    std::vector<const VMSynthesizedHandler*> bySlotVariant(
        static_cast<size_t>(VM_HANDLER_TABLE_SIZE) * config.variantCount, nullptr);
    const auto registerDispatch = [&](const VMSynthesizedHandler& handler) -> bool {
        const size_t index = static_cast<size_t>(handler.slot) * config.variantCount +
            handler.variant;
        if (index >= bySlotVariant.size() || bySlotVariant[index] != nullptr) return false;
        bySlotVariant[index] = &handler;
        return true;
    };
    for (const auto& handler : result.handlers) {
        if (!registerDispatch(handler)) {
            result.error = "semantic handler dispatch cell is duplicated";
            return result;
        }
    }
    for (const auto& handler : result.junkHandlers) {
        if (!registerDispatch(handler)) {
            result.error = "junk handler dispatch cell is duplicated";
            return result;
        }
    }
    for (uint32_t slot = 0; slot < VM_HANDLER_TABLE_SIZE; ++slot) {
        for (uint32_t variant = 0; variant < config.variantCount; ++variant) {
            const size_t index = static_cast<size_t>(slot) * config.variantCount + variant;
            const auto* handler = bySlotVariant[index];
            const uint32_t entryOffset = result.dispatchTableOffset +
                static_cast<uint32_t>(index) * pointerSize;
            const uint64_t targetOffset = handler ? handler->storageOffset : 0u;
            WritePointer(result.image, entryOffset, pointerSize,
                EncodeVMDispatchTableTarget(
                    targetOffset, pointerSize, result.dispatchTableCodec));
            if (!handler) continue;
            VMHandlerDispatchEntry entry{handler->slot, handler->semantic,
                handler->variant, 0, handler->storageOffset};
            if (handler->semantic == VM_HANDLER_JUNK)
                result.junkDispatchEntries.push_back(entry);
            else
                result.dispatchEntries.push_back(entry);
        }
    }

    const CipherParameters cipher = DeriveCipher(config);
    VMHandlerEntryCodegenConfig entryConfig{};
    entryConfig.architecture = static_cast<uint32_t>(config.architecture);
    entryConfig.buildSeed = config.buildSeed;
    entryConfig.variantCount = config.variantCount;
    entryConfig.layout.publicEntryOffset = result.entryOffset;
    entryConfig.layout.validationEntryOffset = result.validationEntryOffset;
    entryConfig.layout.decryptorOffset = result.decryptorOffset;
    entryConfig.layout.operandDecoderOffset = result.operandDecoderOffset;
    entryConfig.layout.flagMaterializerOffset = result.flagMaterializerOffset;
    entryConfig.layout.decryptionStateOffset = stateOffset;
    entryConfig.layout.keyMarkerOffset = result.keyMarkerOffset;
    entryConfig.layout.decodePlanTableOffset = result.decodePlanTableOffset;
    entryConfig.layout.decodePlanTableSize = result.decodePlanTableSize;
    entryConfig.layout.dispatchTableOffset = result.dispatchTableOffset;
    entryConfig.layout.encryptedHandlerOffset = result.encryptedHandlerOffset;
    entryConfig.layout.encryptedHandlerSize = result.encryptedHandlerSize;
    entryConfig.cipher.initialState = cipher.initialState;
    entryConfig.cipher.multiplier = cipher.multiplier;
    entryConfig.cipher.addend = cipher.addend;
    entryConfig.cipher.addByte = cipher.addByte;
    entryConfig.cipher.rotate = cipher.rotate;
    entryConfig.cipher.shiftLeftA = cipher.shiftLeftA;
    entryConfig.cipher.shiftRightB = cipher.shiftRightB;
    entryConfig.cipher.shiftLeftC = cipher.shiftLeftC;
    entryConfig.cipher.instructionVariant = cipher.instructionVariant;
    entryConfig.dispatchTableCodec = result.dispatchTableCodec;
    entryConfig.virtualProtectIatRVA = config.virtualProtectIatRVA;
    entryConfig.flushInstructionCacheIatRVA = config.flushInstructionCacheIatRVA;
    entryConfig.functionPlanCount = static_cast<uint32_t>(functionPlans.size());
    entryConfig.emitCetLandingPads = config.emitCetLandingPads;
    entryConfig.runtimeTraceEnabled = config.runtimeTraceEnabled;

    VMHandlerEntryCodegen entryGenerator;
    VMHandlerEntryCodegenResult entry = entryGenerator.Generate(entryConfig);
    if (!entry.success || !entry.publicEntryReady || !entry.validationEntryReady) {
        result.error = "runtime entry generation failed: " + entry.error;
        return result;
    }
    std::string entryValidationError;
    if (!VMHandlerEntryCodegen::Validate(entryConfig, entry, entryValidationError)) {
        result.error = "runtime entry validation failed: " + entryValidationError;
        return result;
    }
    if (!CopyRoutine(result.image, result.entryOffset, kPublicEntryReserve,
            entry.entryCode, "public runtime entry", result.error) ||
        !CopyRoutine(result.image, result.validationEntryOffset,
            kValidationEntryReserve, entry.validationEntryCode,
            "validation context entry", result.error) ||
        !CopyRoutine(result.image, result.decryptorOffset, kDecryptorReserve,
            entry.decryptorCode, "handler decryptor", result.error) ||
        !CopyRoutine(result.image, result.operandDecoderOffset,
            kOperandDecoderReserve, entry.operandDecoderCode,
            "operand decoder", result.error) ||
        !CopyRoutine(result.image, result.flagMaterializerOffset,
            kFlagMaterializerReserve, entry.flagMaterializerCode,
            "flag materializer", result.error)) {
        return result;
    }
    result.decryptorSize = static_cast<uint32_t>(entry.decryptorCode.size());
    if (entry.decryptorLoopOffset > entry.decryptorCode.size() ||
        entry.decryptorLoopSize == 0 ||
        entry.decryptorLoopSize >
            entry.decryptorCode.size() - entry.decryptorLoopOffset ||
        entry.decryptorLoopOffset >
            (std::numeric_limits<uint32_t>::max)() - result.decryptorOffset) {
        result.error = "handler decryptor did not publish a valid active loop";
        return result;
    }
    result.decryptorLoopOffset = result.decryptorOffset +
        entry.decryptorLoopOffset;
    result.decryptorLoopSize = entry.decryptorLoopSize;
    result.decryptorMutationPlan = PackCipherMutationPlan(cipher);
    result.decryptorLogicDigest = HashBytes(
        entry.decryptorCode.data() + entry.decryptorLoopOffset,
        entry.decryptorLoopSize,
        0x444543525950544FULL ^ result.decryptorMutationPlan);
    result.operandDecoderSize = static_cast<uint32_t>(entry.operandDecoderCode.size());
    result.flagMaterializerSize = static_cast<uint32_t>(entry.flagMaterializerCode.size());
    for (const auto& relocation : entry.relocations)
        result.relocations.push_back({relocation.offset, relocation.type, 0});

    for (const auto& unwind : entry.unwindRecords) {
        uint32_t unwindOffset = 0;
        if (!AlignUpChecked(static_cast<uint32_t>(result.image.size()), 4u,
                unwindOffset)) {
            result.error = "entry unwind layout overflows";
            return result;
        }
        result.image.resize(unwindOffset, 0);
        if (unwind.unwindInfo.size() > (std::numeric_limits<uint32_t>::max)() -
                result.image.size()) {
            result.error = "entry unwind data exceeds uint32 range";
            return result;
        }
        result.image.insert(result.image.end(), unwind.unwindInfo.begin(),
            unwind.unwindInfo.end());
        result.unwindEntries.push_back({unwind.beginOffset,
            unwind.endOffset, unwindOffset});
    }

    if (config.architecture == VMHandlerArchitecture::X64) {
        if (result.image.size() > (std::numeric_limits<uint32_t>::max)()) {
            result.error = "handler unwind layout exceeds uint32 range";
            return result;
        }
        const auto appendUnwindInfo = [&](const auto& info,
                                          uint32_t& offset) {
            if (result.image.size() > (std::numeric_limits<uint32_t>::max)() ||
                !AlignUpChecked(static_cast<uint32_t>(result.image.size()), 4u,
                    offset)) {
                return false;
            }
            result.image.resize(offset, 0);
            result.image.insert(result.image.end(), info.begin(), info.end());
            return true;
        };
        uint32_t smallAllocUnwindOffset = 0;
        uint32_t bridgeUnwindOffset = 0;
        uint32_t nativeCallUnwindOffset = 0;
        uint32_t cpuidUnwindOffset = 0;
        if (!appendUnwindInfo(kX64DirectTailUnwindInfo,
                smallAllocUnwindOffset) ||
            !appendUnwindInfo(kX64BridgeUnwindInfo, bridgeUnwindOffset) ||
            !appendUnwindInfo(kX64NativeCallUnwindInfo,
                nativeCallUnwindOffset) ||
            !appendUnwindInfo(kX64CpuidUnwindInfo, cpuidUnwindOffset)) {
            result.error = "handler canonical xdata layout overflows";
            return result;
        }

        const auto appendStackFunclet = [&](const VMSynthesizedHandler& handler,
                                             const VMSynthesizedStackFunclet& funclet) {
            if (funclet.offset > handler.plaintextBody.size() ||
                funclet.size == 0 ||
                funclet.size > handler.plaintextBody.size() - funclet.offset) {
                return false;
            }
            uint32_t unwindOffset = 0;
            if (funclet.kind == VMSynthesizedUnwindKind::StackAllocation &&
                funclet.stackBytes == kX64DirectTailStackSize &&
                funclet.prologSize == kX64DirectTailPrologSize &&
                funclet.nonvolatileRegister == 0) {
                unwindOffset = smallAllocUnwindOffset;
            } else if (funclet.kind ==
                           VMSynthesizedUnwindKind::StackAllocation &&
                       funclet.stackBytes == kX64BridgeStackSize &&
                       funclet.prologSize == 7u &&
                       funclet.nonvolatileRegister == 0) {
                unwindOffset = bridgeUnwindOffset;
            } else if (funclet.kind ==
                           VMSynthesizedUnwindKind::StackAllocation &&
                       funclet.stackBytes == kX64NativeCallStackSize &&
                       funclet.prologSize == 7u &&
                       funclet.nonvolatileRegister == 0) {
                unwindOffset = nativeCallUnwindOffset;
            } else if (funclet.kind ==
                           VMSynthesizedUnwindKind::PushNonvolatile &&
                       funclet.stackBytes == 0 && funclet.prologSize == 1u &&
                       funclet.nonvolatileRegister == 3u) {
                unwindOffset = cpuidUnwindOffset;
            } else {
                return false;
            }
            const uint64_t begin = static_cast<uint64_t>(handler.storageOffset) +
                funclet.offset;
            const uint64_t end = begin + funclet.size;
            if (end > (std::numeric_limits<uint32_t>::max)()) return false;
            result.unwindEntries.push_back({static_cast<uint32_t>(begin),
                static_cast<uint32_t>(end), unwindOffset});
            return true;
        };
        const auto appendTailUnwind = [&](const VMSynthesizedHandler& handler) {
            const uint64_t begin = static_cast<uint64_t>(handler.storageOffset) +
                handler.dispatchUnwindOffset;
            const uint64_t end = begin + handler.dispatchUnwindSize;
            if (handler.dispatchUnwindSize == 0 ||
                handler.dispatchUnwindOffset > handler.plaintextBody.size() ||
                handler.dispatchUnwindSize > handler.plaintextBody.size() -
                    handler.dispatchUnwindOffset ||
                end > (std::numeric_limits<uint32_t>::max)()) {
                return false;
            }
            result.unwindEntries.push_back({static_cast<uint32_t>(begin),
                static_cast<uint32_t>(end), smallAllocUnwindOffset});
            return true;
        };
        for (const auto& handler : result.handlers) {
            for (const auto& funclet : handler.semanticStackFunclets) {
                if (!appendStackFunclet(handler, funclet)) {
                    result.error = "semantic handler stack-funclet unwind is invalid";
                    return result;
                }
            }
            if (!appendTailUnwind(handler)) {
                result.error = "semantic handler-tail unwind range is invalid";
                return result;
            }
        }
        for (const auto& handler : result.junkHandlers) {
            if (!appendTailUnwind(handler)) {
                result.error = "junk handler-tail unwind range is invalid";
                return result;
            }
        }
        std::sort(result.unwindEntries.begin(), result.unwindEntries.end(),
            [](const VMSynthesizedUnwindEntry& left,
               const VMSynthesizedUnwindEntry& right) {
                return std::pair<uint32_t, uint32_t>(
                    left.beginOffset, left.endOffset) <
                    std::pair<uint32_t, uint32_t>(
                    right.beginOffset, right.endOffset);
            });
    }

    EncryptHandlerRegion(result.image, result.encryptedHandlerOffset,
        result.encryptedHandlerSize, cipher);
    for (auto& handler : result.handlers) {
        handler.ciphertextBody.assign(
            result.image.begin() + handler.storageOffset,
            result.image.begin() + handler.storageOffset + handler.storageSize);
    }
    for (auto& handler : result.junkHandlers) {
        handler.ciphertextBody.assign(
            result.image.begin() + handler.storageOffset,
            result.image.begin() + handler.storageOffset + handler.storageSize);
    }

    std::vector<uint8_t> mapMaterial;
    mapMaterial.insert(mapMaterial.end(), config.handlerSemanticToSlot.begin(),
        config.handlerSemanticToSlot.end());
    mapMaterial.insert(mapMaterial.end(), config.handlerSlotToSemantic.begin(),
        config.handlerSlotToSemantic.end());
    result.opcodeMapDigest = HashBytes(mapMaterial, 0x4F50434F44454D50ULL);
    result.dispatchKeyDigest = HashBytes(
        result.image.data() + result.dispatchTableOffset,
        result.dispatchTableSize,
        HashBytes(config.buildSeed.data(), config.buildSeed.size(),
            0x4449535041544348ULL));
    const auto plaintext = ExtractPlaintextBodies(result);
    result.microSelectionDigest = HashBytes(plaintext, 0x4D4943524F53454CULL);
    result.variantSelectorDigest = HashBytes(
        reinterpret_cast<const uint8_t*>(result.dispatchEntries.data()),
        result.dispatchEntries.size() * sizeof(VMHandlerDispatchEntry),
        0x56415253454C4543ULL ^ result.dispatchKeyDigest);

    result.publicEntryReady = entry.publicEntryReady;
    result.validationEntryReady = entry.validationEntryReady;
    result.usesTemporaryPageWrite = true;
    result.restoresExecuteRead = true;
    result.success = true;
    std::string validationError;
    if (!Validate(config, result, validationError)) {
        result.success = false;
        result.error = "synthesized runtime self-validation failed: " + validationError;
        return result;
    }
    return result;
}

bool VMHandlerSynthesizer::Validate(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    std::string& error)
{
    if (!ConfigValid(config, error)) return false;
    if (!result.success) {
        error = "synthesized runtime is not marked successful";
        return false;
    }
    if (result.fixedRuntimeBlobUsed || !result.directThreaded ||
        !result.handlerBodiesEncrypted || !result.publicEntryReady ||
        !result.validationEntryReady || !result.usesTemporaryPageWrite ||
        !result.restoresExecuteRead) {
        error = "runtime synthesis security mode is incomplete";
        return false;
    }
    if (result.image.empty() || result.entryOffset >= result.image.size() ||
        result.contextEntryOffset >= result.image.size() ||
        result.contextEntryOffset != result.validationEntryOffset ||
        result.decryptorSize == 0 || result.operandDecoderSize == 0 ||
        result.flagMaterializerSize == 0 ||
        result.decryptorLoopSize == 0 || result.decryptorMutationPlan == 0 ||
        result.decryptorLogicDigest == 0 ||
        result.decryptorOffset > result.image.size() ||
        result.decryptorSize > result.image.size() - result.decryptorOffset ||
        result.decryptorLoopOffset < result.decryptorOffset ||
        result.decryptorLoopOffset > result.image.size() ||
        result.decryptorLoopSize > result.image.size() - result.decryptorLoopOffset ||
        result.decryptorLoopOffset - result.decryptorOffset > result.decryptorSize ||
        result.decryptorLoopSize > result.decryptorSize -
            (result.decryptorLoopOffset - result.decryptorOffset) ||
        result.operandDecoderOffset > result.image.size() ||
        result.operandDecoderSize > result.image.size() - result.operandDecoderOffset ||
        result.flagMaterializerOffset > result.image.size() ||
        result.flagMaterializerSize > result.image.size() - result.flagMaterializerOffset ||
        result.dispatchTableOffset > result.image.size() ||
        result.dispatchTableSize > result.image.size() - result.dispatchTableOffset ||
        result.decodePlanTableOffset > result.image.size() ||
        result.decodePlanTableSize > result.image.size() - result.decodePlanTableOffset ||
        result.encryptedHandlerOffset > result.image.size() ||
        result.encryptedHandlerSize > result.image.size() - result.encryptedHandlerOffset ||
        result.keyMarkerOffset > result.image.size() ||
        VM_RUNTIME_KEY_SHARE_SIZE > result.image.size() - result.keyMarkerOffset) {
        error = "synthesized runtime range is invalid";
        return false;
    }

    size_t requiredSemanticCount = 0;
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        if (SemanticRequired(config, static_cast<uint8_t>(semantic)))
            ++requiredSemanticCount;
    }
    const size_t expected = requiredSemanticCount * config.variantCount;
    if (result.handlers.size() != expected || result.dispatchEntries.size() != expected) {
        error = "handler or dispatch K coverage is incomplete";
        return false;
    }
    const uint32_t pointerSize = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    const uint64_t expectedDispatchSize = static_cast<uint64_t>(VM_HANDLER_TABLE_SIZE) *
        config.variantCount * pointerSize;
    if (result.dispatchTableSize != expectedDispatchSize) {
        error = "dispatch table is not the exact slot-by-K layout";
        return false;
    }
    const VMDispatchTableCodec expectedDispatchCodec =
        DeriveVMDispatchTableCodec(config.buildSeed);
    if (result.dispatchTableCodec.encoding != expectedDispatchCodec.encoding ||
        result.dispatchTableCodec.key != expectedDispatchCodec.key ||
        result.dispatchTableCodec.rotate != expectedDispatchCodec.rotate ||
        result.dispatchTableCodec.key == 0u ||
        result.dispatchTableCodec.key > 0x7FFFFFFFu ||
        result.dispatchTableCodec.rotate == 0u ||
        result.dispatchTableCodec.rotate > 31u) {
        error = "dispatch table codec is not the per-build derived scheme";
        return false;
    }

    std::set<std::pair<uint32_t, uint32_t>> handlerKeys;
    std::set<std::pair<uint32_t, uint32_t>> dispatchKeys;
    std::set<std::pair<uint32_t, uint32_t>> expectedTailUnwindRanges;
    enum class HandlerUnwindEncoding : uint8_t {
        SmallAlloc,
        BridgeAlloc,
        NativeCallAlloc,
        PushRbx
    };
    std::map<std::pair<uint32_t, uint32_t>, HandlerUnwindEncoding>
        expectedHandlerUnwindRanges;
    std::unordered_set<uint32_t> targets;
    const bool x64Target = config.architecture == VMHandlerArchitecture::X64;
    const auto registerTailUnwindRange = [&](const VMSynthesizedHandler& handler) {
        if (!x64Target) {
            return handler.dispatchUnwindOffset == 0 &&
                handler.dispatchUnwindSize == 0 &&
                handler.semanticStackFunclets.empty();
        }
        const uint64_t bodyEnd = static_cast<uint64_t>(handler.dispatchUnwindOffset) +
            handler.dispatchUnwindSize + kX64DirectTailLeafCode.size();
        if (handler.dispatchUnwindOffset < handler.dispatchTailOffset ||
            handler.dispatchUnwindSize != kX64DirectTailStackCode.size() ||
            bodyEnd != handler.plaintextBody.size() ||
            !std::equal(kX64DirectTailStackCode.begin(),
                kX64DirectTailStackCode.end(),
                handler.plaintextBody.begin() + handler.dispatchUnwindOffset) ||
            !std::equal(kX64DirectTailLeafCode.begin(),
                kX64DirectTailLeafCode.end(),
                handler.plaintextBody.begin() + handler.dispatchUnwindOffset +
                    handler.dispatchUnwindSize)) {
            return false;
        }
        const uint64_t absoluteBegin = static_cast<uint64_t>(handler.storageOffset) +
            handler.dispatchUnwindOffset;
        const uint64_t absoluteEnd = absoluteBegin + handler.dispatchUnwindSize;
        if (absoluteEnd > (std::numeric_limits<uint32_t>::max)() ||
            absoluteBegin < result.encryptedHandlerOffset ||
            absoluteEnd > static_cast<uint64_t>(result.encryptedHandlerOffset) +
                result.encryptedHandlerSize) {
            return false;
        }
        const std::pair<uint32_t, uint32_t> range = {
            static_cast<uint32_t>(absoluteBegin),
            static_cast<uint32_t>(absoluteEnd)};
        return expectedTailUnwindRanges.insert(range).second &&
            expectedHandlerUnwindRanges.emplace(
                range, HandlerUnwindEncoding::SmallAlloc).second;
    };
    const auto registerSemanticUnwindRange = [&](const VMSynthesizedHandler& handler) {
        VMSynthesizedStackFunclet expectedFunclet{};
        const bool expectsFunclet = x64Target &&
            ExpectedSemanticStackFunclet(handler.semantic, expectedFunclet);
        if (handler.semanticStackFunclets.size() != (expectsFunclet ? 1u : 0u))
            return false;
        if (!expectsFunclet) return true;

        const VMSynthesizedStackFunclet& funclet =
            handler.semanticStackFunclets[0];
        if (funclet.offset > handler.plaintextBody.size() ||
            funclet.size == 0 ||
            funclet.size > handler.plaintextBody.size() - funclet.offset ||
            funclet.offset + funclet.size > handler.dispatchTailOffset ||
            funclet.kind != expectedFunclet.kind ||
            funclet.stackBytes != expectedFunclet.stackBytes ||
            funclet.prologSize != expectedFunclet.prologSize ||
            funclet.nonvolatileRegister !=
                expectedFunclet.nonvolatileRegister) {
            return false;
        }
        const auto begin = handler.plaintextBody.begin() + funclet.offset;
        const auto end = begin + funclet.size;
        HandlerUnwindEncoding encoding = HandlerUnwindEncoding::SmallAlloc;
        if (funclet.kind == VMSynthesizedUnwindKind::StackAllocation &&
            funclet.stackBytes == kX64DirectTailStackSize) {
            constexpr std::array<uint8_t, 10> expectedCode = {
                0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28
            };
            if (funclet.size != expectedCode.size() ||
                !std::equal(expectedCode.begin(), expectedCode.end(), begin)) {
                return false;
            }
        } else if (funclet.kind ==
                       VMSynthesizedUnwindKind::StackAllocation &&
                   funclet.stackBytes == kX64BridgeStackSize) {
            constexpr std::array<uint8_t, 7> prolog = {
                0x48,0x81,0xEC,0x98,0x04,0x00,0x00
            };
            constexpr std::array<uint8_t, 7> epilog = {
                0x48,0x81,0xC4,0x98,0x04,0x00,0x00
            };
            constexpr std::array<uint8_t, 2> call = {0xFF,0xD0};
            if (funclet.size < prolog.size() + epilog.size() + call.size() ||
                !std::equal(prolog.begin(), prolog.end(), begin) ||
                !std::equal(epilog.begin(), epilog.end(),
                    end - static_cast<ptrdiff_t>(epilog.size())) ||
                std::search(begin, end, call.begin(), call.end()) == end) {
                return false;
            }
            encoding = HandlerUnwindEncoding::BridgeAlloc;
        } else if (funclet.kind ==
                       VMSynthesizedUnwindKind::StackAllocation &&
                   funclet.stackBytes == kX64NativeCallStackSize) {
            constexpr std::array<uint8_t, 7> prolog = {
                0x48,0x81,0xEC,0x08,0x06,0x00,0x00
            };
            constexpr std::array<uint8_t, 7> epilog = {
                0x48,0x81,0xC4,0x08,0x06,0x00,0x00
            };
            constexpr std::array<uint8_t, 2> call = {0xFF,0xD0};
            if (funclet.size < prolog.size() + epilog.size() + call.size() ||
                !std::equal(prolog.begin(), prolog.end(), begin) ||
                !std::equal(epilog.begin(), epilog.end(),
                    end - static_cast<ptrdiff_t>(epilog.size())) ||
                std::search(begin, end, call.begin(), call.end()) == end) {
                return false;
            }
            encoding = HandlerUnwindEncoding::NativeCallAlloc;
        } else if (funclet.kind ==
                       VMSynthesizedUnwindKind::PushNonvolatile &&
                   funclet.nonvolatileRegister == 3u) {
            constexpr std::array<uint8_t, 2> cpuid = {0x0F,0xA2};
            if (funclet.size < 4u || *begin != 0x53 || *(end - 1) != 0x5B ||
                std::search(begin, end, cpuid.begin(), cpuid.end()) == end) {
                return false;
            }
            encoding = HandlerUnwindEncoding::PushRbx;
        } else {
            return false;
        }
        const uint64_t absoluteBegin =
            static_cast<uint64_t>(handler.storageOffset) + funclet.offset;
        const uint64_t absoluteEnd = absoluteBegin + funclet.size;
        if (absoluteEnd > (std::numeric_limits<uint32_t>::max)() ||
            absoluteBegin < result.encryptedHandlerOffset ||
            absoluteEnd > static_cast<uint64_t>(result.encryptedHandlerOffset) +
                result.encryptedHandlerSize) {
            return false;
        }
        return expectedHandlerUnwindRanges.emplace(
            std::pair<uint32_t, uint32_t>{
                static_cast<uint32_t>(absoluteBegin),
                static_cast<uint32_t>(absoluteEnd)}, encoding).second;
    };
    struct StoredRange {
        uint32_t offset;
        uint32_t size;
        const std::vector<uint8_t>* plaintext;
    };
    std::vector<StoredRange> storedRanges;
    storedRanges.reserve(result.handlers.size() + result.junkHandlers.size());
    uint64_t storedBytes = 0;
    for (const auto& handler : result.handlers) {
        if (handler.semantic >= VM_UOP_COUNT ||
            !SemanticRequired(config, handler.semantic) ||
            handler.variant >= config.variantCount ||
            handler.slot != config.handlerSemanticToSlot[handler.semantic] ||
            handler.plaintextBody.size() < config.minimumJunkBytesPerHandler ||
            handler.plaintextBody.size() != handler.ciphertextBody.size() ||
            handler.plaintextBody == handler.ciphertextBody ||
            handler.storageSize != handler.ciphertextBody.size() ||
            handler.storageOffset < result.encryptedHandlerOffset ||
            handler.storageOffset > result.image.size() ||
            handler.storageSize > result.image.size() - handler.storageOffset ||
            handler.dispatchTailSize == 0 ||
            handler.dispatchTailOffset + handler.dispatchTailSize !=
                handler.plaintextBody.size() ||
            handler.semanticBodySize == 0 ||
            handler.semanticBodyOffset > handler.dispatchTailOffset ||
            handler.semanticBodySize >
                handler.dispatchTailOffset - handler.semanticBodyOffset ||
            handler.semanticCoreSize == 0 ||
            handler.semanticCoreOffset < handler.semanticBodyOffset ||
            handler.semanticCoreSize > handler.semanticBodySize -
                (handler.semanticCoreOffset - handler.semanticBodyOffset) ||
            ((handler.semanticCoreVariantSize == 0) !=
                (handler.semanticCoreVariantOffset == 0)) ||
            (handler.semanticCoreVariantSize != 0 &&
                (handler.semanticCoreVariantOffset < handler.semanticCoreOffset ||
                 handler.semanticCoreVariantSize > handler.semanticCoreSize -
                    (handler.semanticCoreVariantOffset -
                        handler.semanticCoreOffset))) ||
            !handler.semanticComplete || handler.bodyDigest == 0 ||
            handler.dispatchTailDigest == 0) {
            error = "synthesized handler descriptor is inconsistent: semantic=" +
                std::to_string(handler.semantic) + " variant=" +
                std::to_string(handler.variant) + " body=" +
                std::to_string(handler.semanticBodyOffset) + "/" +
                std::to_string(handler.semanticBodySize) + " core=" +
                std::to_string(handler.semanticCoreOffset) + "/" +
                std::to_string(handler.semanticCoreSize) + " variant_core=" +
                std::to_string(handler.semanticCoreVariantOffset) + "/" +
                std::to_string(handler.semanticCoreVariantSize) + " tail=" +
                std::to_string(handler.dispatchTailOffset) + "/" +
                std::to_string(handler.dispatchTailSize);
            return false;
        }
        uint32_t previousCodecEnd = handler.semanticCoreOffset;
        for (const auto& range : handler.valueCodecRanges) {
            if (range.size < 32u || range.offset < previousCodecEnd ||
                range.offset < handler.semanticCoreOffset ||
                range.size > handler.semanticCoreSize -
                    (range.offset - handler.semanticCoreOffset)) {
                error = "synthesized value-codec range is invalid";
                return false;
            }
            previousCodecEnd = range.offset + range.size;
        }
        const uint64_t handlerDomain = 0x48414E444C455235ULL ^
            (static_cast<uint64_t>(handler.semantic) << 24u) ^
            (static_cast<uint64_t>(handler.variant) << 8u) ^
            static_cast<uint32_t>(config.architecture);
        const uint64_t expectedBodyDigest = HashBytes(handler.plaintextBody,
            handlerDomain ^ 0xB0D1B0D1B0D1B0D1ULL);
        const uint64_t expectedTailDigest = HashBytes(
            handler.plaintextBody.data() + handler.dispatchTailOffset,
            handler.dispatchTailSize,
            handlerDomain ^ 0xD15FA7C4D15FA7C4ULL);
        if (handler.bodyDigest != expectedBodyDigest ||
            handler.dispatchTailDigest != expectedTailDigest) {
            error = "synthesized handler digest does not match its machine code";
            return false;
        }
        if (!registerSemanticUnwindRange(handler) ||
            !registerTailUnwindRange(handler)) {
            error = "semantic handler direct-tail unwind range is invalid";
            return false;
        }
        if (!std::equal(handler.ciphertextBody.begin(), handler.ciphertextBody.end(),
                result.image.begin() + handler.storageOffset)) {
            error = "handler ciphertext does not match stored image";
            return false;
        }
        if (!handlerKeys.insert({handler.semantic, handler.variant}).second ||
            !targets.insert(handler.storageOffset).second) {
            error = "handler K variant is duplicated";
            return false;
        }
        storedBytes += handler.storageSize;
        storedRanges.push_back({handler.storageOffset, handler.storageSize,
            &handler.plaintextBody});
    }

    size_t expectedJunkHandlers = 0;
    for (uint32_t slot = 0; slot < VM_HANDLER_USABLE_SLOT_COUNT; ++slot) {
        if (config.handlerSlotToSemantic[slot] == VM_HANDLER_JUNK)
            expectedJunkHandlers += config.variantCount;
    }
    if (result.junkHandlers.size() != expectedJunkHandlers ||
        result.junkDispatchEntries.size() != expectedJunkHandlers) {
        error = "junk handler K coverage does not match metadata slots";
        return false;
    }
    std::set<std::pair<uint32_t, uint32_t>> junkKeys;
    for (const auto& handler : result.junkHandlers) {
        if (handler.semantic != VM_HANDLER_JUNK ||
            handler.slot >= VM_HANDLER_USABLE_SLOT_COUNT ||
            config.handlerSlotToSemantic[handler.slot] != VM_HANDLER_JUNK ||
            handler.variant >= config.variantCount || !handler.semanticComplete ||
            handler.plaintextBody.size() < config.minimumJunkBytesPerHandler ||
            handler.plaintextBody.size() != handler.ciphertextBody.size() ||
            handler.plaintextBody == handler.ciphertextBody ||
            handler.storageSize != handler.ciphertextBody.size() ||
            handler.dispatchTailSize == 0 ||
            handler.dispatchTailOffset + handler.dispatchTailSize !=
                handler.plaintextBody.size() ||
            !junkKeys.insert({handler.slot, handler.variant}).second ||
            !targets.insert(handler.storageOffset).second) {
            error = "junk handler is not a real no-effect direct-threaded K body";
            return false;
        }
        if (!std::equal(handler.ciphertextBody.begin(), handler.ciphertextBody.end(),
                result.image.begin() + handler.storageOffset)) {
            error = "junk handler ciphertext does not match stored image";
            return false;
        }
        const uint64_t handlerDomain = 0x4A554E4B48444C35ULL ^
            (static_cast<uint64_t>(handler.slot) << 16u) ^ handler.variant;
        const uint64_t expectedBodyDigest = HashBytes(handler.plaintextBody,
            handlerDomain ^ 0x4A554E4B424F4459ULL);
        const uint64_t expectedTailDigest = HashBytes(
            handler.plaintextBody.data() + handler.dispatchTailOffset,
            handler.dispatchTailSize,
            handlerDomain ^ 0x4A554E4B5441494CULL);
        if (handler.bodyDigest != expectedBodyDigest ||
            handler.dispatchTailDigest != expectedTailDigest) {
            error = "junk handler digest does not match its machine code";
            return false;
        }
        if (!registerSemanticUnwindRange(handler) ||
            !registerTailUnwindRange(handler)) {
            error = "junk handler direct-tail unwind range is invalid";
            return false;
        }
        storedBytes += handler.storageSize;
        storedRanges.push_back({handler.storageOffset, handler.storageSize,
            &handler.plaintextBody});
    }
    if (storedBytes != result.encryptedHandlerSize) {
        error = "encrypted handler range contains a gap or untracked body";
        return false;
    }
    std::sort(storedRanges.begin(), storedRanges.end(),
        [](const StoredRange& left, const StoredRange& right) {
            return left.offset < right.offset;
        });
    uint32_t expectedStorageOffset = result.encryptedHandlerOffset;
    std::vector<uint8_t> expectedCiphertext(result.encryptedHandlerSize, 0);
    for (const StoredRange& range : storedRanges) {
        const uint64_t relative64 = range.offset >= result.encryptedHandlerOffset
            ? static_cast<uint64_t>(range.offset - result.encryptedHandlerOffset)
            : static_cast<uint64_t>(result.encryptedHandlerSize) + 1u;
        if (range.offset != expectedStorageOffset || range.size == 0 ||
            relative64 > result.encryptedHandlerSize ||
            range.size > result.encryptedHandlerSize -
                static_cast<uint32_t>(relative64) ||
            range.plaintext == nullptr || range.plaintext->size() != range.size) {
            error = "encrypted handler storage has a gap, overlap, or bad range";
            return false;
        }
        const uint32_t relative = static_cast<uint32_t>(relative64);
        std::copy(range.plaintext->begin(), range.plaintext->end(),
            expectedCiphertext.begin() + relative);
        expectedStorageOffset += range.size;
    }
    if (expectedStorageOffset != result.encryptedHandlerOffset +
            result.encryptedHandlerSize) {
        error = "encrypted handler storage does not close at the declared boundary";
        return false;
    }
    const CipherParameters expectedCipher = DeriveCipher(config);
    if (result.decryptorMutationPlan != PackCipherMutationPlan(expectedCipher) ||
        result.decryptorLogicDigest != HashBytes(
            result.image.data() + result.decryptorLoopOffset,
            result.decryptorLoopSize,
            0x444543525950544FULL ^ result.decryptorMutationPlan)) {
        error = "decryptor active-loop mutation plan or machine-code digest is invalid";
        return false;
    }
    EncryptHandlerRegion(expectedCiphertext, 0,
        static_cast<uint32_t>(expectedCiphertext.size()), expectedCipher);
    if (!std::equal(expectedCiphertext.begin(), expectedCiphertext.end(),
            result.image.begin() + result.encryptedHandlerOffset)) {
        error = "stored handler ciphertext is not the per-build encryption of plaintext bodies";
        return false;
    }

    for (const auto& entry : result.dispatchEntries) {
        if (entry.semantic >= VM_UOP_COUNT || entry.variant >= config.variantCount ||
            entry.slot != config.handlerSemanticToSlot[entry.semantic] ||
            !dispatchKeys.insert({entry.semantic, entry.variant}).second) {
            error = "dispatch entry is duplicated or malformed";
            return false;
        }
        const auto found = std::find_if(result.handlers.begin(), result.handlers.end(),
            [&](const VMSynthesizedHandler& handler) {
                return handler.semantic == entry.semantic &&
                    handler.variant == entry.variant &&
                    handler.storageOffset == entry.targetOffset;
            });
        if (found == result.handlers.end()) {
            error = "dispatch entry does not reach its synthesized handler";
            return false;
        }
    }
    std::set<std::pair<uint32_t, uint32_t>> junkDispatchKeys;
    for (const auto& entry : result.junkDispatchEntries) {
        if (entry.semantic != VM_HANDLER_JUNK ||
            entry.slot >= VM_HANDLER_USABLE_SLOT_COUNT ||
            config.handlerSlotToSemantic[entry.slot] != VM_HANDLER_JUNK ||
            entry.variant >= config.variantCount ||
            !junkDispatchKeys.insert({entry.slot, entry.variant}).second) {
            error = "junk dispatch entry is malformed";
            return false;
        }
        const auto found = std::find_if(result.junkHandlers.begin(),
            result.junkHandlers.end(), [&](const VMSynthesizedHandler& handler) {
                return handler.slot == entry.slot && handler.variant == entry.variant &&
                    handler.storageOffset == entry.targetOffset;
            });
        if (found == result.junkHandlers.end()) {
            error = "junk dispatch entry does not reach its body";
            return false;
        }
    }
    if (handlerKeys != dispatchKeys || junkKeys != junkDispatchKeys) {
        error = "handler/dispatch bidirectional coverage is incomplete";
        return false;
    }

    // Verify the physical [slot][K] table, not only its descriptive vectors.
    // Every cell, including an unused zero target, is encoded.  The table must
    // contain neither raw relative offsets nor loader-relocatable pointers.
    const size_t dispatchCellCount = static_cast<size_t>(VM_HANDLER_TABLE_SIZE) *
        config.variantCount;
    std::vector<uint64_t> expectedPhysicalTargets(dispatchCellCount, 0);
    const auto registerExpectedTarget = [&](const VMSynthesizedHandler& handler) {
        const size_t cell = static_cast<size_t>(handler.slot) *
            config.variantCount + handler.variant;
        if (cell >= expectedPhysicalTargets.size() ||
            expectedPhysicalTargets[cell] != 0) return false;
        expectedPhysicalTargets[cell] = handler.storageOffset;
        return true;
    };
    for (const auto& handler : result.handlers) {
        if (!registerExpectedTarget(handler)) {
            error = "semantic handler has no unique physical dispatch cell";
            return false;
        }
    }
    for (const auto& handler : result.junkHandlers) {
        if (!registerExpectedTarget(handler)) {
            error = "junk handler has no unique physical dispatch cell";
            return false;
        }
    }
    for (size_t cell = 0; cell < expectedPhysicalTargets.size(); ++cell) {
        const uint64_t byteOffset64 = static_cast<uint64_t>(
            result.dispatchTableOffset) + static_cast<uint64_t>(cell) * pointerSize;
        if (byteOffset64 > (std::numeric_limits<uint32_t>::max)() ||
            byteOffset64 + pointerSize > result.image.size()) {
            error = "physical dispatch cell is outside the synthesized image";
            return false;
        }
        const uint32_t byteOffset = static_cast<uint32_t>(byteOffset64);
        uint64_t storedEncodedTarget = 0;
        std::memcpy(&storedEncodedTarget,
            result.image.data() + byteOffset, pointerSize);
        if (pointerSize == 4u) storedEncodedTarget &= 0xFFFFFFFFULL;
        const uint64_t expectedEncodedTarget = EncodeVMDispatchTableTarget(
            expectedPhysicalTargets[cell], pointerSize,
            result.dispatchTableCodec);
        if (storedEncodedTarget != expectedEncodedTarget) {
            error = "physical dispatch table ciphertext disagrees with handler layout";
            return false;
        }
        const uint64_t decodedTarget = DecodeVMDispatchTableTarget(
            storedEncodedTarget, pointerSize, result.dispatchTableCodec);
        if (decodedTarget != expectedPhysicalTargets[cell]) {
            error = "physical dispatch table codec does not round-trip its target";
            return false;
        }
        if (storedEncodedTarget == expectedPhysicalTargets[cell]) {
            error = "physical dispatch table leaks a plaintext target offset";
            return false;
        }
    }

    const uint16_t relocationType = pointerSize == 8
        ? kRelocationDir64 : kRelocationHighLow;
    std::set<uint32_t> relocationOffsets;
    for (const auto& relocation : result.relocations) {
        if (relocation.type != relocationType ||
            relocation.offset > result.image.size() ||
            pointerSize > result.image.size() - relocation.offset ||
            !relocationOffsets.insert(relocation.offset).second) {
            error = "synthesized runtime relocation is invalid or duplicated";
            return false;
        }
        const uint64_t dispatchEnd = static_cast<uint64_t>(
            result.dispatchTableOffset) + result.dispatchTableSize;
        if (relocation.offset >= result.dispatchTableOffset &&
            static_cast<uint64_t>(relocation.offset) < dispatchEnd) {
            error = "encoded dispatch table unexpectedly contains a base relocation";
            return false;
        }
    }

    if (x64Target) {
        const size_t expectedTailCount = result.handlers.size() +
            result.junkHandlers.size();
        if (expectedTailUnwindRanges.size() != expectedTailCount ||
            expectedHandlerUnwindRanges.size() < expectedTailCount ||
            result.unwindEntries.size() < expectedHandlerUnwindRanges.size() + 5u) {
            error = "x64 generated runtime lacks complete handler unwind coverage";
            return false;
        }
        std::set<std::pair<uint32_t, uint32_t>> allUnwindRanges;
        std::map<std::pair<uint32_t, uint32_t>, HandlerUnwindEncoding>
            actualHandlerUnwindRanges;
        const uint64_t encryptedEnd =
            static_cast<uint64_t>(result.encryptedHandlerOffset) +
            result.encryptedHandlerSize;
        size_t nonHandlerCount = 0;
        uint32_t previousEnd = 0;
        bool havePrevious = false;
        for (const auto& unwind : result.unwindEntries) {
            const std::pair<uint32_t, uint32_t> range = {
                unwind.beginOffset, unwind.endOffset};
            if (unwind.beginOffset >= unwind.endOffset ||
                unwind.endOffset > result.image.size() ||
                unwind.unwindOffset > result.image.size() ||
                4u > result.image.size() - unwind.unwindOffset ||
                (havePrevious && previousEnd > unwind.beginOffset) ||
                !allUnwindRanges.insert(range).second) {
                error = "x64 runtime unwind descriptors are invalid, unsorted, or overlapping";
                return false;
            }
            previousEnd = unwind.endOffset;
            havePrevious = true;
            const bool beginsInHandlerRegion =
                unwind.beginOffset >= result.encryptedHandlerOffset &&
                static_cast<uint64_t>(unwind.beginOffset) < encryptedEnd;
            if (!beginsInHandlerRegion) {
                ++nonHandlerCount;
                continue;
            }
            const auto expectedEncoding = expectedHandlerUnwindRanges.find(range);
            if (expectedEncoding == expectedHandlerUnwindRanges.end() ||
                unwind.unwindOffset < encryptedEnd) {
                error = "x64 handler range lacks declared stack-funclet metadata";
                return false;
            }
            const auto* expectedInfo = &kX64DirectTailUnwindInfo;
            if (expectedEncoding->second == HandlerUnwindEncoding::BridgeAlloc)
                expectedInfo = &kX64BridgeUnwindInfo;
            else if (expectedEncoding->second ==
                        HandlerUnwindEncoding::NativeCallAlloc)
                expectedInfo = &kX64NativeCallUnwindInfo;
            else if (expectedEncoding->second == HandlerUnwindEncoding::PushRbx)
                expectedInfo = &kX64CpuidUnwindInfo;
            if (expectedInfo->size() >
                    result.image.size() - unwind.unwindOffset ||
                !std::equal(expectedInfo->begin(), expectedInfo->end(),
                    result.image.begin() + unwind.unwindOffset) ||
                !actualHandlerUnwindRanges.emplace(
                    range, expectedEncoding->second).second) {
                error = "x64 handler funclet has non-canonical UNWIND_INFO";
                return false;
            }
        }
        if (nonHandlerCount < 5u ||
            actualHandlerUnwindRanges != expectedHandlerUnwindRanges) {
            error = "x64 handler unwind coverage is not bidirectionally complete";
            return false;
        }
    } else if (!result.unwindEntries.empty()) {
        error = "x86 generated runtime unexpectedly contains x64 unwind data";
        return false;
    }

    std::vector<uint8_t> expectedMapMaterial;
    expectedMapMaterial.insert(expectedMapMaterial.end(),
        config.handlerSemanticToSlot.begin(), config.handlerSemanticToSlot.end());
    expectedMapMaterial.insert(expectedMapMaterial.end(),
        config.handlerSlotToSemantic.begin(), config.handlerSlotToSemantic.end());
    const uint64_t expectedOpcodeMapDigest = HashBytes(
        expectedMapMaterial, 0x4F50434F44454D50ULL);
    const uint64_t expectedDispatchKeyDigest = HashBytes(
        result.image.data() + result.dispatchTableOffset,
        result.dispatchTableSize,
        HashBytes(config.buildSeed.data(), config.buildSeed.size(),
            0x4449535041544348ULL));
    const std::vector<uint8_t> expectedPlaintext = ExtractPlaintextBodies(result);
    const uint64_t expectedMicroSelectionDigest = HashBytes(
        expectedPlaintext, 0x4D4943524F53454CULL);
    const uint64_t expectedVariantSelectorDigest = HashBytes(
        reinterpret_cast<const uint8_t*>(result.dispatchEntries.data()),
        result.dispatchEntries.size() * sizeof(VMHandlerDispatchEntry),
        0x56415253454C4543ULL ^ expectedDispatchKeyDigest);
    if (result.opcodeMapDigest != expectedOpcodeMapDigest ||
        result.dispatchKeyDigest != expectedDispatchKeyDigest ||
        result.microSelectionDigest != expectedMicroSelectionDigest ||
        result.variantSelectorDigest != expectedVariantSelectorDigest) {
        error = "runtime diversity digest does not match physical synthesized bytes";
        return false;
    }
    return true;
}

std::vector<uint8_t> VMHandlerSynthesizer::ExtractPlaintextBodies(
    const VMHandlerSynthesisResult& result)
{
    std::vector<const VMSynthesizedHandler*> ordered;
    ordered.reserve(result.handlers.size() + result.junkHandlers.size());
    for (const auto& handler : result.handlers) ordered.push_back(&handler);
    for (const auto& handler : result.junkHandlers) ordered.push_back(&handler);
    std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
        if (left->semantic != right->semantic) return left->semantic < right->semantic;
        if (left->slot != right->slot) return left->slot < right->slot;
        return left->variant < right->variant;
    });
    size_t total = 0;
    for (const auto* handler : ordered) total += handler->plaintextBody.size();
    std::vector<uint8_t> output;
    output.reserve(total);
    for (const auto* handler : ordered)
        output.insert(output.end(), handler->plaintextBody.begin(),
            handler->plaintextBody.end());
    return output;
}

} // namespace CipherShell
