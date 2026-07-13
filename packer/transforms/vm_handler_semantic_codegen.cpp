#include "vm_handler_semantic_codegen.h"

#include "../vm/vm_schema.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

namespace CipherShell {
namespace {

class CodeBuffer {
public:
    using Label = size_t;

    void U8(uint8_t value) { bytes.push_back(value); }
    void U16(uint16_t value) {
        U8(static_cast<uint8_t>(value));
        U8(static_cast<uint8_t>(value >> 8u));
    }
    void U32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void U64(uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void Raw(std::initializer_list<uint8_t> values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    Label NewLabel() {
        labels.push_back((std::numeric_limits<size_t>::max)());
        return labels.size() - 1u;
    }
    void Bind(Label label) { labels[label] = bytes.size(); }
    void Jmp(Label label) { U8(0xE9); AddFixup(label); }
    void Call(Label label) { U8(0xE8); AddFixup(label); }
    void Jcc(uint8_t opcode, Label label) {
        Raw({0x0F, opcode});
        AddFixup(label);
    }
    bool Resolve(std::string& error) {
        for (const Fixup& fixup : fixups) {
            if (fixup.label >= labels.size() ||
                labels[fixup.label] == (std::numeric_limits<size_t>::max)()) {
                error = "semantic machine-code label was not bound";
                return false;
            }
            const int64_t relative = static_cast<int64_t>(labels[fixup.label]) -
                static_cast<int64_t>(fixup.displacement + 4u);
            if (relative < (std::numeric_limits<int32_t>::min)() ||
                relative > (std::numeric_limits<int32_t>::max)()) {
                error = "semantic machine-code rel32 exceeds range";
                return false;
            }
            const uint32_t encoded = static_cast<uint32_t>(static_cast<int32_t>(relative));
            for (unsigned i = 0; i < 4; ++i) {
                bytes[fixup.displacement + i] =
                    static_cast<uint8_t>(encoded >> (i * 8u));
            }
        }
        return true;
    }

    std::vector<VMHandlerSemanticStackFunclet> stackFunclets;
    std::vector<uint8_t> bytes;

private:
    struct Fixup { size_t displacement; Label label; };
    void AddFixup(Label label) {
        fixups.push_back({bytes.size(), label});
        U32(0);
    }
    std::vector<size_t> labels;
    std::vector<Fixup> fixups;
};

constexpr uint32_t kX64FlagCallStackBytes = 0x28u;
constexpr uint8_t kX64FlagCallPrologSize = 4u;
constexpr uint32_t kX64BridgeStateBase = 0x20u;
constexpr uint32_t kX64BridgeStackBytes =
    kX64BridgeStateBase + sizeof(VM_INSTRUCTION_BRIDGE_STATE);
constexpr uint8_t kX64BridgePrologSize = 7u;
constexpr uint8_t kX64CpuidPrologSize = 1u;
constexpr uint8_t kX64RbxUnwindRegister = 3u;

static_assert((kX64BridgeStackBytes & 0xFu) == 8u,
    "x64 bridge stack alignment changed");
static_assert((kX64BridgeStackBytes % 8u) == 0u &&
        kX64BridgeStackBytes / 8u <= 0xFFFFu,
    "x64 bridge stack allocation no longer fits UWOP_ALLOC_LARGE");

void RecordX64StackFunclet(
    CodeBuffer& code,
    size_t begin,
    VMHandlerSemanticUnwindKind kind,
    uint32_t stackBytes,
    uint8_t prologSize,
    uint8_t nonvolatileRegister = 0)
{
    const size_t size = code.bytes.size() - begin;
    VMHandlerSemanticStackFunclet funclet{};
    if (begin > (std::numeric_limits<uint32_t>::max)() ||
        size > (std::numeric_limits<uint32_t>::max)()) {
        funclet.offset = (std::numeric_limits<uint32_t>::max)();
    } else {
        funclet.offset = static_cast<uint32_t>(begin);
        funclet.size = static_cast<uint32_t>(size);
    }
    funclet.stackBytes = stackBytes;
    funclet.kind = kind;
    funclet.prologSize = prologSize;
    funclet.nonvolatileRegister = nonvolatileRegister;
    code.stackFunclets.push_back(funclet);
}

class SeedStream {
public:
    SeedStream(const std::array<uint8_t, 32>& seed, uint64_t domain) {
        uint64_t first = 0;
        uint64_t second = 0;
        std::memcpy(&first, seed.data(), sizeof(first));
        std::memcpy(&second, seed.data() + 16, sizeof(second));
        s0 = Mix(first ^ domain ^ 0xA0761D6478BD642FULL);
        s1 = Mix(second ^ (domain << 1u) ^ 0xE7037ED1A0B428DBULL);
        if ((s0 | s1) == 0) s1 = 1;
        for (unsigned i = 0; i < 12; ++i) Next64();
    }
    uint64_t Next64() {
        uint64_t value = s0;
        const uint64_t other = s1;
        s0 = other;
        value ^= value << 23u;
        s1 = value ^ other ^ (value >> 17u) ^ (other >> 26u);
        return s1 + other;
    }
    uint32_t Next32() { return static_cast<uint32_t>(Next64()); }

private:
    static uint64_t Mix(uint64_t value) {
        value ^= value >> 30u;
        value *= 0xBF58476D1CE4E5B9ULL;
        value ^= value >> 27u;
        value *= 0x94D049BB133111EBULL;
        return value ^ (value >> 31u);
    }
    uint64_t s0 = 0;
    uint64_t s1 = 0;
};

#define CTX_OFFSET(field) static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, field))
#define RECORD_OFFSET(base, field) \
    (base + static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, field)))

constexpr uint32_t CtxValues = CTX_OFFSET(values);
constexpr uint32_t CtxVregs = CTX_OFFSET(vregs);
constexpr uint32_t CtxTemps = CTX_OFFSET(temps);
constexpr uint32_t CtxCallStack = CTX_OFFSET(callStack);
constexpr uint32_t CtxValueDepth = CTX_OFFSET(valueDepth);
constexpr uint32_t CtxCallDepth = CTX_OFFSET(callDepth);
constexpr uint32_t CtxVip = CTX_OFFSET(vip);
constexpr uint32_t CtxBytecodeBegin = CTX_OFFSET(bytecodeBegin);
constexpr uint32_t CtxImageBase = CTX_OFFSET(imageBase);
constexpr uint32_t CtxRegisterMap = CTX_OFFSET(registerMap);
constexpr uint32_t CtxFlagMaterializer = CTX_OFFSET(flagMaterializer);
constexpr uint32_t CtxNativeFrame = CTX_OFFSET(nativeFrame);
constexpr uint32_t CtxExtendedState = CTX_OFFSET(extendedState);
constexpr uint32_t CtxNativeCallBridge = CTX_OFFSET(nativeCallBridge);
constexpr uint32_t CtxDecodedOperands = CTX_OFFSET(decodedOperands);
constexpr uint32_t CtxVirtualFlags = CTX_OFFSET(virtualFlags);
constexpr uint32_t CtxPendingFlags = CTX_OFFSET(pendingFlags);
constexpr uint32_t CtxLastAlu = CTX_OFFSET(lastAlu);
constexpr uint32_t CtxReturnStackCleanup = CTX_OFFSET(returnStackCleanup);
constexpr uint32_t CtxError = CTX_OFFSET(error);
constexpr uint32_t CtxHalted = CTX_OFFSET(halted);
constexpr uint32_t CtxMutationScratch = CTX_OFFSET(mutationScratch);

constexpr uint8_t JccO = 0x80;
constexpr uint8_t JccNO = 0x81;
constexpr uint8_t JccB = 0x82;
constexpr uint8_t JccAE = 0x83;
constexpr uint8_t JccE = 0x84;
constexpr uint8_t JccNE = 0x85;
constexpr uint8_t JccBE = 0x86;
constexpr uint8_t JccA = 0x87;
constexpr uint8_t JccS = 0x88;
constexpr uint8_t JccNS = 0x89;
constexpr uint8_t JccP = 0x8A;
constexpr uint8_t JccNP = 0x8B;
constexpr uint8_t JccL = 0x8C;
constexpr uint8_t JccGE = 0x8D;
constexpr uint8_t JccLE = 0x8E;
constexpr uint8_t JccG = 0x8F;

void X64LoadQ(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    const uint8_t rex = static_cast<uint8_t>(0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x8B, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64StoreQ(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64LoadD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x8B, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64StoreD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64LoadByte(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x0F, 0xB6, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64StoreByteImmediate(CodeBuffer& c, uint32_t displacement, uint8_t value) {
    c.Raw({0x41, 0xC6, 0x87});
    c.U32(displacement);
    c.U8(value);
}

void X64StoreDImmediate(CodeBuffer& c, uint32_t displacement, uint32_t value) {
    c.Raw({0x41, 0xC7, 0x87});
    c.U32(displacement);
    c.U32(value);
}

void X64LoadIndexedQ(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t index,
    uint32_t displacement)
{
    const uint8_t rex = static_cast<uint8_t>(0x49u |
        ((destination & 8u) ? 0x04u : 0u) |
        ((index & 8u) ? 0x02u : 0u));
    c.Raw({rex, 0x8B,
        static_cast<uint8_t>(0x84u | ((destination & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void X64StoreIndexedQ(
    CodeBuffer& c,
    uint32_t displacement,
    uint8_t index,
    uint8_t source)
{
    const uint8_t rex = static_cast<uint8_t>(0x49u |
        ((source & 8u) ? 0x04u : 0u) |
        ((index & 8u) ? 0x02u : 0u));
    c.Raw({rex, 0x89,
        static_cast<uint8_t>(0x84u | ((source & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    c.Raw({0x8B, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86StoreD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadByte(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    c.Raw({0x0F, 0xB6, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86StoreDImmediate(CodeBuffer& c, uint32_t displacement, uint32_t value) {
    c.Raw({0xC7, 0x87});
    c.U32(displacement);
    c.U32(value);
}

void X86StoreByteImmediate(CodeBuffer& c, uint32_t displacement, uint8_t value) {
    c.Raw({0xC6, 0x87});
    c.U32(displacement);
    c.U8(value);
}

void X64StoreByteRegister(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86StoreByteRegister(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x88,static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadIndexedD(CodeBuffer& c, uint8_t destination, uint32_t displacement) {
    c.Raw({0x8B, static_cast<uint8_t>(0x84u | ((destination & 7u) << 3u)), 0xCF});
    c.U32(displacement);
}

void X86StoreIndexedD(CodeBuffer& c, uint32_t displacement, uint8_t source) {
    c.Raw({0x89, static_cast<uint8_t>(0x84u | ((source & 7u) << 3u)), 0xCF});
    c.U32(displacement);
}

void EmitX64Failure(CodeBuffer& c, uint32_t error) {
    X64StoreDImmediate(c, CtxError, error);
    X64StoreDImmediate(c, CtxHalted, 1);
    c.U8(0xC3);
}

void EmitX86Failure(CodeBuffer& c, uint32_t error) {
    X86StoreDImmediate(c, CtxError, error);
    X86StoreDImmediate(c, CtxHalted, 1);
    c.U8(0xC3);
}

std::array<uint8_t, 4> DeriveVariantRegisters(
    bool x64,
    uint8_t variant,
    VM_MICRO_OPCODE semantic,
    const std::array<uint8_t, 32>& buildSeed)
{
    std::array<uint8_t, 4> output{};
    const size_t seedOffset = static_cast<size_t>(
        buildSeed[static_cast<uint8_t>(semantic) & 31u]);
    if (x64) {
        constexpr std::array<uint8_t, 7> pool = {0, 1, 2, 8, 9, 10, 11};
        const size_t start = (seedOffset + static_cast<size_t>(variant)) %
            pool.size();
        for (size_t index = 0; index < output.size(); ++index)
            output[index] = pool[(start + index * 2u) % pool.size()];
    } else {
        // EDI is the context, while EBX/ESI are direct-threaded ABI state.
        // Only caller-volatile EAX/ECX/EDX participate in the live allocation.
        constexpr std::array<uint8_t, 3> pool = {0, 1, 2};
        const size_t start = (seedOffset + static_cast<size_t>(variant)) %
            pool.size();
        for (size_t index = 0; index < output.size(); ++index)
            output[index] = pool[(start + index) % pool.size()];
    }
    return output;
}

enum class SemanticPathKind : uint8_t {
    ContextNative,
    ContextDword,
    StackTop,
    MappedVreg
};

struct SemanticPathSpec {
    SemanticPathKind kind = SemanticPathKind::ContextNative;
    uint32_t displacement = 0;
    uint8_t mappedFamily = 0;
};

struct SemanticMutationPlan {
    uint8_t strategy = 0;
    uint64_t key = 0;
};

SemanticMutationPlan DeriveSemanticMutationPlan(
    const VMHandlerSemanticCodegenConfig& config,
    uint64_t phaseDomain)
{
    SeedStream random(config.buildSeed,
        phaseDomain ^ (static_cast<uint64_t>(config.semantic) << 17u) ^
        (static_cast<uint64_t>(config.variant) << 43u) ^
        static_cast<uint64_t>(config.architecture));
    SemanticMutationPlan plan{};
    plan.strategy = static_cast<uint8_t>(
        (random.Next32() + config.variant +
         static_cast<uint8_t>(config.semantic)) % 3u);
    plan.key = random.Next64() | 1u;
    return plan;
}

bool HasBusinessCoreVariant(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_ADD:
        case VM_UOP_SUB:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_NOT:
        case VM_UOP_NEG:
        case VM_UOP_MUL:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
            return true;
        default:
            return false;
    }
}

uint8_t DeriveBusinessCoreStrategy(
    const VMHandlerSemanticCodegenConfig& config)
{
    return static_cast<uint8_t>(DeriveSemanticMutationPlan(
        config, 0x434F524556415249ULL).strategy & 1u);
}

SemanticPathSpec SemanticInputPath(
    const VMOpcodeDescriptor& descriptor,
    VM_MICRO_OPCODE semantic)
{
    if (descriptor.stackPops > 0)
        return {SemanticPathKind::StackTop, CtxValues, 0};
    if (semantic == VM_UOP_CPUID)
        return {SemanticPathKind::MappedVreg, CtxVregs, 0};
    if (descriptor.operandCount > 0)
        return {SemanticPathKind::ContextNative, CtxDecodedOperands, 0};
    switch (semantic) {
        case VM_UOP_PUSH_IP:
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        case VM_UOP_PUSH_IMAGE_BASE:
            return {SemanticPathKind::ContextNative, CtxImageBase, 0};
        case VM_UOP_FLAGS_PACK_AH:
            return {SemanticPathKind::ContextNative, CtxVirtualFlags, 0};
        case VM_UOP_RDTSC:
            return {SemanticPathKind::ContextNative, CtxRegisterMap, 0};
        case VM_UOP_INT3:
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        default:
            return {SemanticPathKind::ContextDword, CtxValueDepth, 0};
    }
}

SemanticPathSpec SemanticResultPath(
    const VMOpcodeDescriptor& descriptor,
    VM_MICRO_OPCODE semantic)
{
    if (descriptor.stackPushes > 0)
        return {SemanticPathKind::StackTop, CtxValues, 0};
    switch (descriptor.opcodeClass) {
        case VMOpcodeClass::Flags:
            if (semantic == VM_UOP_FLAGS_LAZY)
                return {SemanticPathKind::ContextNative, CtxPendingFlags, 0};
            return {SemanticPathKind::ContextNative, CtxVirtualFlags, 0};
        case VMOpcodeClass::ControlFlow:
        case VMOpcodeClass::Call:
            if (semantic == VM_UOP_RET || semantic == VM_UOP_EXIT)
                return {SemanticPathKind::ContextDword, CtxHalted, 0};
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        case VMOpcodeClass::Bridge:
            return {SemanticPathKind::ContextNative, CtxVregs, 0};
        case VMOpcodeClass::Special:
            if (semantic == VM_UOP_RDTSC || semantic == VM_UOP_CPUID)
                return {SemanticPathKind::MappedVreg, CtxVregs, 0};
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        default:
            break;
    }
    if (descriptor.stackPops > 0)
        return {SemanticPathKind::ContextDword, CtxValueDepth, 0};
    return {SemanticPathKind::ContextDword, CtxError, 0};
}

void X64MovImmediate(CodeBuffer& c, uint8_t reg, uint64_t value) {
    c.Raw({static_cast<uint8_t>(0x48u | ((reg & 8u) ? 1u : 0u)),
        static_cast<uint8_t>(0xB8u + (reg & 7u))});
    c.U64(value);
}

void X64MovRegister(CodeBuffer& c, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 4u : 0u) | ((destination & 8u) ? 1u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X64BinaryRegister(
    CodeBuffer& c,
    uint8_t opcode,
    uint8_t destination,
    uint8_t source)
{
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 4u : 0u) | ((destination & 8u) ? 1u : 0u));
    c.Raw({rex, opcode, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X86MovImmediate(CodeBuffer& c, uint8_t reg, uint32_t value) {
    c.U8(static_cast<uint8_t>(0xB8u + (reg & 7u)));
    c.U32(value);
}

void X86MovRegister(CodeBuffer& c, uint8_t destination, uint8_t source) {
    c.Raw({0x89, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X86BinaryRegister(
    CodeBuffer& c,
    uint8_t opcode,
    uint8_t destination,
    uint8_t source)
{
    c.Raw({opcode, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X64CompareDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    if (reg & 8u) c.U8(0x41);
    c.Raw({0x83, static_cast<uint8_t>(0xF8u | (reg & 7u)), value});
}

void X64SubDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    if (reg & 8u) c.U8(0x41);
    c.Raw({0x83, static_cast<uint8_t>(0xE8u | (reg & 7u)), value});
}

void X64TestQ(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((reg & 8u) ? 0x05u : 0u));
    c.Raw({rex, 0x85, static_cast<uint8_t>(0xC0u |
        ((reg & 7u) << 3u) | (reg & 7u))});
}

void X64LoadByteIndirect(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t base,
    uint8_t displacement)
{
    const uint8_t rex = static_cast<uint8_t>(0x40u |
        ((destination & 8u) ? 0x04u : 0u) |
        ((base & 8u) ? 0x01u : 0u));
    c.Raw({rex, 0x0F, 0xB6, static_cast<uint8_t>(0x40u |
        ((destination & 7u) << 3u) | (base & 7u)), displacement});
}

void X86CompareDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    c.Raw({0x83, static_cast<uint8_t>(0xF8u | (reg & 7u)), value});
}

void X86SubDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    c.Raw({0x83, static_cast<uint8_t>(0xE8u | (reg & 7u)), value});
}

void X86TestD(CodeBuffer& c, uint8_t reg) {
    c.Raw({0x85, static_cast<uint8_t>(0xC0u |
        ((reg & 7u) << 3u) | (reg & 7u))});
}

void X86LoadByteIndirect(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t base,
    uint8_t displacement)
{
    c.Raw({0x0F, 0xB6, static_cast<uint8_t>(0x40u |
        ((destination & 7u) << 3u) | (base & 7u)), displacement});
}

void X86LoadIndexedDVariant(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t index,
    uint32_t displacement)
{
    c.Raw({0x8B, static_cast<uint8_t>(0x84u |
        ((destination & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void X86StoreIndexedDVariant(
    CodeBuffer& c,
    uint32_t displacement,
    uint8_t index,
    uint8_t source)
{
    c.Raw({0x89, static_cast<uint8_t>(0x84u |
        ((source & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void EmitIdentityMBA(
    CodeBuffer& c,
    bool x64,
    uint8_t valueRegister,
    uint8_t keyRegister,
    const SemanticMutationPlan& plan)
{
    if (x64)
        X64MovImmediate(c, keyRegister, plan.key);
    else
        X86MovImmediate(c, keyRegister, static_cast<uint32_t>(plan.key));

    const uint8_t first = plan.strategy == 0u ? 0x31u :
        (plan.strategy == 1u ? 0x01u : 0x29u);
    const uint8_t second = plan.strategy == 0u ? 0x31u :
        (plan.strategy == 1u ? 0x29u : 0x01u);
    if (x64) {
        X64BinaryRegister(c, first, valueRegister, keyRegister);
        X64BinaryRegister(c, second, valueRegister, keyRegister);
    } else {
        X86BinaryRegister(c, first, valueRegister, keyRegister);
        X86BinaryRegister(c, second, valueRegister, keyRegister);
    }
}

void EmitSemanticInputPreparation(
    CodeBuffer& c,
    bool x64,
    const SemanticPathSpec& spec,
    const std::array<uint8_t, 4>& registers,
    uint8_t stackPops,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure)
{
    const uint8_t indexRegister = registers[2];
    if (spec.kind == SemanticPathKind::StackTop) {
        if (x64) {
            X64LoadD(c, indexRegister, CtxValueDepth);
            X64CompareDImmediate(c, indexRegister, stackPops);
            c.Jcc(JccB, stackFailure);
            X64SubDImmediate(c, indexRegister, 1u);
        } else {
            X86LoadD(c, indexRegister, CtxValueDepth);
            X86CompareDImmediate(c, indexRegister, stackPops);
            c.Jcc(JccB, stackFailure);
            X86SubDImmediate(c, indexRegister, 1u);
        }
    } else if (spec.kind == SemanticPathKind::MappedVreg) {
        if (x64) {
            X64LoadQ(c, indexRegister, CtxRegisterMap);
            X64TestQ(c, indexRegister);
            c.Jcc(JccE, rangeFailure);
        } else {
            X86LoadD(c, indexRegister, CtxRegisterMap);
            X86TestD(c, indexRegister);
            c.Jcc(JccE, rangeFailure);
        }
    }
}

void EmitSemanticIdentityPath(
    CodeBuffer& c,
    bool x64,
    const SemanticPathSpec& spec,
    const std::array<uint8_t, 4>& registers,
    const SemanticMutationPlan& plan,
    bool inputPath)
{
    const uint8_t valueRegister = inputPath ? registers[0] : registers[1];
    const uint8_t keyRegister = inputPath ? registers[1] : registers[2];
    const uint8_t indexRegister = inputPath ? registers[2] : registers[0];

    switch (spec.kind) {
        case SemanticPathKind::ContextNative:
            if (x64) X64LoadQ(c, valueRegister, spec.displacement);
            else X86LoadD(c, valueRegister, spec.displacement);
            break;
        case SemanticPathKind::ContextDword:
            if (x64) X64LoadD(c, valueRegister, spec.displacement);
            else X86LoadD(c, valueRegister, spec.displacement);
            break;
        case SemanticPathKind::StackTop:
            if (!inputPath) {
                if (x64) {
                    X64LoadD(c, indexRegister, CtxValueDepth);
                    X64SubDImmediate(c, indexRegister, 1u);
                } else {
                    X86LoadD(c, indexRegister, CtxValueDepth);
                    X86SubDImmediate(c, indexRegister, 1u);
                }
            }
            if (x64)
                X64LoadIndexedQ(c, valueRegister, indexRegister, spec.displacement);
            else
                X86LoadIndexedDVariant(c, valueRegister, indexRegister,
                    spec.displacement);
            break;
        case SemanticPathKind::MappedVreg:
            if (!inputPath) {
                if (x64) X64LoadQ(c, indexRegister, CtxRegisterMap);
                else X86LoadD(c, indexRegister, CtxRegisterMap);
            }
            if (x64) {
                X64LoadByteIndirect(c, indexRegister, indexRegister,
                    spec.mappedFamily);
                X64LoadIndexedQ(c, valueRegister, indexRegister,
                    spec.displacement);
            } else {
                X86LoadByteIndirect(c, indexRegister, indexRegister,
                    spec.mappedFamily);
                X86LoadIndexedDVariant(c, valueRegister, indexRegister,
                    spec.displacement);
            }
            break;
    }

    EmitIdentityMBA(c, x64, valueRegister, keyRegister, plan);

    switch (spec.kind) {
        case SemanticPathKind::ContextNative:
            if (x64) X64StoreQ(c, spec.displacement, valueRegister);
            else X86StoreD(c, spec.displacement, valueRegister);
            break;
        case SemanticPathKind::ContextDword:
            if (x64) X64StoreD(c, spec.displacement, valueRegister);
            else X86StoreD(c, spec.displacement, valueRegister);
            break;
        case SemanticPathKind::StackTop:
        case SemanticPathKind::MappedVreg:
            if (x64)
                X64StoreIndexedQ(c, spec.displacement, indexRegister,
                    valueRegister);
            else
                X86StoreIndexedDVariant(c, spec.displacement, indexRegister,
                    valueRegister);
            break;
    }
}

// 操作数宽度分派:SHL/SHR 等 K 变体核心与后段的多处 sized 发射都依赖它,
// 故定义在 EmitBusinessCoreVariant 之前。
struct WidthLabels {
    CodeBuffer::Label width1;
    CodeBuffer::Label width2;
    CodeBuffer::Label width4;
    CodeBuffer::Label width8;
    CodeBuffer::Label invalid;
};

WidthLabels MakeWidthLabels(CodeBuffer& c) {
    return {c.NewLabel(), c.NewLabel(), c.NewLabel(), c.NewLabel(), c.NewLabel()};
}

void X64DispatchWidth(
    CodeBuffer& c,
    uint8_t operand,
    const WidthLabels& labels)
{
    X64LoadByte(c, 11, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x41,0x83,0xFB,0x01}); c.Jcc(JccE, labels.width1);
    c.Raw({0x41,0x83,0xFB,0x02}); c.Jcc(JccE, labels.width2);
    c.Raw({0x41,0x83,0xFB,0x04}); c.Jcc(JccE, labels.width4);
    c.Raw({0x41,0x83,0xFB,0x08}); c.Jcc(JccE, labels.width8);
    c.Jmp(labels.invalid);
}

void X86DispatchWidth(
    CodeBuffer& c,
    uint8_t operand,
    const WidthLabels& labels)
{
    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x83,0xF9,0x01}); c.Jcc(JccE, labels.width1);
    c.Raw({0x83,0xF9,0x02}); c.Jcc(JccE, labels.width2);
    c.Raw({0x83,0xF9,0x04}); c.Jcc(JccE, labels.width4);
    c.Jmp(labels.invalid);
}

bool EmitBusinessCoreVariant(
    CodeBuffer& c,
    bool x64,
    VM_MICRO_OPCODE semantic,
    uint8_t strategy)
{
    strategy &= 1u;
    if (x64) {
        switch (semantic) {
            case VM_UOP_ADD:
                if (strategy == 0u) X64BinaryRegister(c, 0x01, 0, 2);
                else c.Raw({0x48,0x8D,0x04,0x10});
                return true;
            case VM_UOP_SUB:
                if (strategy == 0u) X64BinaryRegister(c, 0x29, 0, 2);
                else {
                    c.Raw({0x48,0xF7,0xDA});
                    X64BinaryRegister(c, 0x01, 0, 2);
                }
                return true;
            case VM_UOP_AND:
                if (strategy == 0u) X64BinaryRegister(c, 0x21, 0, 2);
                else {
                    c.Raw({0x48,0xF7,0xD0,0x48,0xF7,0xD2});
                    X64BinaryRegister(c, 0x09, 0, 2);
                    c.Raw({0x48,0xF7,0xD0});
                }
                return true;
            case VM_UOP_OR:
                if (strategy == 0u) X64BinaryRegister(c, 0x09, 0, 2);
                else {
                    c.Raw({0x48,0xF7,0xD0,0x48,0xF7,0xD2});
                    X64BinaryRegister(c, 0x21, 0, 2);
                    c.Raw({0x48,0xF7,0xD0});
                }
                return true;
            case VM_UOP_XOR:
                if (strategy == 0u) X64BinaryRegister(c, 0x31, 0, 2);
                else {
                    X64MovRegister(c, 10, 0);
                    X64BinaryRegister(c, 0x21, 10, 2);
                    X64BinaryRegister(c, 0x09, 0, 2);
                    X64BinaryRegister(c, 0x29, 0, 10);
                    X64BinaryRegister(c, 0x31, 10, 10);
                }
                return true;
            case VM_UOP_NOT:
                if (strategy == 0u) c.Raw({0x48,0xF7,0xD0});
                else X64BinaryRegister(c, 0x31, 0, 9);
                return true;
            case VM_UOP_NEG:
                if (strategy == 0u) c.Raw({0x48,0xF7,0xD8});
                else c.Raw({0x48,0xF7,0xD0,0x48,0xFF,0xC0});
                return true;
            case VM_UOP_MUL:
                // strategy 0: IMUL rax, rdx (two-operand signed multiply).
                // strategy 1: MUL rdx (one-operand unsigned multiply into
                // rdx:rax). Signed and unsigned multiply produce identical
                // low-order-64-bit results modulo 2^64, so the truncated
                // product in rax is the same either way; only the high
                // half (discarded here) and flags differ.  This clobbers
                // rdx, which is safe because a/b were already latched into
                // r8/r11 before the core runs.
                if (strategy == 0u) c.Raw({0x48,0x0F,0xAF,0xC2});
                else c.Raw({0x48,0xF7,0xE2});
                return true;
            case VM_UOP_BIT_TEST:
                // Common to both strategies: reduce the raw bit-index operand
                // (rdx) modulo the operand width in bits.
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    // strategy 0: manual shift-and-mask against the saved
                    // pre-core copy of a (r8).
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    X64MovRegister(c, 0, 8);
                } else {
                    // strategy 1: native BT — CF *is* the tested bit by
                    // hardware definition; BT never modifies its r/m operand.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xA3,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_BIT_SET:
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    c.Raw({0xB8,0x01,0x00,0x00,0x00}); // mov eax,1
                    c.Raw({0x48,0xD3,0xE0});           // shl rax,cl
                    X64BinaryRegister(c, 0x09, 0, 8);
                } else {
                    // strategy 1: native BTS sets the bit and reports the old
                    // value in CF in the same instruction.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xAB,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_BIT_RESET:
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    c.Raw({0xB8,0x01,0x00,0x00,0x00}); // mov eax,1
                    c.Raw({0x48,0xD3,0xE0});           // shl rax,cl
                    c.Raw({0x48,0xF7,0xD0});           // not rax
                    X64BinaryRegister(c, 0x21, 0, 8);
                } else {
                    // strategy 1: native BTR resets the bit and reports the
                    // old value in CF in the same instruction.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xB3,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_SHL: {
                // strategy 0: native SHL rax,cl.
                // strategy 1: SHLD rax, r10(=0), cl — a zero source makes shld
                //   pull zeroes into the top, so dst = dst<<cl ≡ SHL.  r10 is
                //   zeroed by the binary-ALU prologue (auxiliary=0) and shld
                //   leaves its source untouched, so auxiliary stays 0.
                //
                // x86 masks the shift count to 5 bits for 1/2/4-byte operands
                // and 6 bits for 8-byte.  The width mask r9 is all-ones ONLY for
                // width 8, so (sar r9,63) & 32 is 32 for width 8 and 0 otherwise;
                // OR 31 yields exactly the 5/6-bit count mask with no width
                // branch.  Pre-masking cl that way lets a single 64-bit
                // shl/shld cover every width (operand is zero-extended; the outer
                // `and rax,r9` trims to width).  This is label-free — every byte
                // is a fixed Raw — so the variant kernel validator's isolated
                // re-emission matches the inline bytes exactly.
                c.Raw({0x48,0x89,0xD1});            // mov rcx, rdx  (count)
                c.Raw({0x4D,0x89,0xCB});            // mov r11, r9   (width mask)
                c.Raw({0x49,0xC1,0xFB,0x3F});       // sar r11, 63
                c.Raw({0x49,0x83,0xE3,0x20});       // and r11, 32
                c.Raw({0x49,0x83,0xCB,0x1F});       // or  r11, 31
                c.Raw({0x44,0x20,0xD9});            // and cl, r11b  (REX.R for r11b source)
                if (strategy == 0u) c.Raw({0x48,0xD3,0xE0});      // shl rax, cl
                else                c.Raw({0x4C,0x0F,0xA5,0xD0}); // shld rax, r10, cl
                return true;
            }
            case VM_UOP_SHR: {
                // Same count pre-mask as SHL.
                // strategy 0: native SHR rax,cl.
                // strategy 1: SHRD rax, r10(=0), cl pulls zeroes into the bottom
                //   so dst = dst>>cl ≡ SHR.
                c.Raw({0x48,0x89,0xD1});            // mov rcx, rdx  (count)
                c.Raw({0x4D,0x89,0xCB});            // mov r11, r9   (width mask)
                c.Raw({0x49,0xC1,0xFB,0x3F});       // sar r11, 63
                c.Raw({0x49,0x83,0xE3,0x20});       // and r11, 32
                c.Raw({0x49,0x83,0xCB,0x1F});       // or  r11, 31
                c.Raw({0x44,0x20,0xD9});            // and cl, r11b  (REX.R for r11b source)
                if (strategy == 0u) c.Raw({0x48,0xD3,0xE8});      // shr rax, cl
                else                c.Raw({0x4C,0x0F,0xAC,0xD0}); // shrd rax, r10, cl
                return true;
            }
            default:
                return false;
        }
    }

    switch (semantic) {
        case VM_UOP_ADD:
            if (strategy == 0u) c.Raw({0x01,0xD0});
            else c.Raw({0x8D,0x04,0x10});
            return true;
        case VM_UOP_SUB:
            if (strategy == 0u) c.Raw({0x29,0xD0});
            else c.Raw({0xF7,0xDA,0x01,0xD0});
            return true;
        case VM_UOP_AND:
            if (strategy == 0u) c.Raw({0x21,0xD0});
            else c.Raw({0xF7,0xD0,0xF7,0xD2,0x09,0xD0,0xF7,0xD0});
            return true;
        case VM_UOP_OR:
            if (strategy == 0u) c.Raw({0x09,0xD0});
            else c.Raw({0xF7,0xD0,0xF7,0xD2,0x21,0xD0,0xF7,0xD0});
            return true;
        case VM_UOP_XOR:
            if (strategy == 0u) c.Raw({0x31,0xD0});
            else c.Raw({0x89,0xC1,0x21,0xD1,0x09,0xD0,0x29,0xC8});
            return true;
        case VM_UOP_NOT:
            if (strategy == 0u) c.Raw({0xF7,0xD0});
            else { c.Raw({0x33,0x87}); c.U32(CtxMutationScratch); }
            return true;
        case VM_UOP_NEG:
            if (strategy == 0u) c.Raw({0xF7,0xD8});
            else c.Raw({0xF7,0xD0,0x40});
            return true;
        case VM_UOP_MUL:
            // Same identity as the x64 case: IMUL EAX,EDX vs. MUL EDX give
            // the same truncated 32-bit product in eax; the clobbered edx
            // is safe for the same reason (a/b already latched earlier).
            if (strategy == 0u) c.Raw({0x0F,0xAF,0xC2});
            else c.Raw({0xF7,0xE2});
            return true;
        case VM_UOP_BIT_TEST:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
            } else {
                // strategy 1: native BT — CF is the tested bit; the r/m
                // operand (eax) is left unmodified by BT.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xA3,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_BIT_SET:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
                c.Raw({0xBE,0x01,0x00,0x00,0x00,0xD3,0xE6});
                c.Raw({0x09,0xF0});
            } else {
                // strategy 1: native BTS sets the bit and reports the old
                // value in CF in the same instruction.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xAB,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_BIT_RESET:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
                c.Raw({0xBE,0x01,0x00,0x00,0x00,0xD3,0xE6});
                c.Raw({0xF7,0xD6,0x21,0xF0});
            } else {
                // strategy 1: native BTR resets the bit and reports the old
                // value in CF in the same instruction.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xB3,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_SHL: {
            // strategy 0: native SHL eax,cl.  strategy 1: SHLD eax,ebx(=0),cl ≡
            //   SHL (zero source pulls zeroes into the top).  32-bit mode has no
            //   8-byte operand, so every width (1/2/4) masks the count to 5
            //   bits; a single `and cl,31` then one 32-bit shl/shld covers all
            //   widths (operand zero-extended, outer `and eax,[scratch]` trims
            //   to width).  Label-free so the validator's isolated re-emission
            //   matches byte-for-byte.  ebx is free across EmitX86BinaryAlu.
            c.Raw({0x88,0xD1});            // mov cl, dl  (count)
            c.Raw({0x80,0xE1,0x1F});       // and cl, 31
            if (strategy == 0u) {
                c.Raw({0xD3,0xE0});        // shl eax, cl
            } else {
                c.Raw({0x31,0xDB});        // xor ebx,ebx (zero src)
                c.Raw({0x0F,0xA5,0xD8});   // shld eax, ebx, cl
            }
            return true;
        }
        case VM_UOP_SHR: {
            // Same count pre-mask as SHL.
            // strategy 0: native SHR eax,cl.  strategy 1: SHRD eax,ebx(=0),cl ≡
            //   SHR (zero source pulls zeroes into the bottom).
            c.Raw({0x88,0xD1});            // mov cl, dl  (count)
            c.Raw({0x80,0xE1,0x1F});       // and cl, 31
            if (strategy == 0u) {
                c.Raw({0xD3,0xE8});        // shr eax, cl
            } else {
                c.Raw({0x31,0xDB});        // xor ebx,ebx (zero src)
                c.Raw({0x0F,0xAC,0xD8});   // shrd eax, ebx, cl
            }
            return true;
        }
        default:
            return false;
    }
}

void EmitExecutableSeedJunk(
    CodeBuffer& c,
    bool x64,
    const std::array<uint8_t, 4>& registers,
    SeedStream& random,
    uint32_t instructionCount)
{
    for (uint32_t index = 0; index < instructionCount; ++index) {
        const uint8_t reg = registers[index & 3u];
        if (x64)
            X64MovImmediate(c, reg, random.Next64());
        else
            X86MovImmediate(c, reg, random.Next32());
    }
}

void EmitLiveIdentityMBA(
    CodeBuffer& c,
    bool x64,
    uint8_t variant,
    const std::array<uint8_t, 4>& registers,
    SeedStream& random)
{
    // Every pair is executed and restores mutationScratch exactly.  The
    // selected physical registers are the allocation published in the result.
    for (uint32_t round = 0; round < 12u; ++round) {
        const uint8_t destination = registers[round & 3u];
        uint8_t source = registers[(round + 1u) & 3u];
        if (source == destination) source = registers[(round + 2u) & 3u];
        const uint64_t key = random.Next64() | 1u;
        if (x64) {
            X64LoadQ(c, destination, CtxMutationScratch);
            X64MovImmediate(c, source, key);
            switch ((variant + round) % 3u) {
                case 0:
                    X64BinaryRegister(c, 0x31, destination, source);
                    X64BinaryRegister(c, 0x31, destination, source);
                    break;
                case 1:
                    X64BinaryRegister(c, 0x01, destination, source);
                    X64BinaryRegister(c, 0x29, destination, source);
                    break;
                default:
                    X64BinaryRegister(c, 0x29, destination, source);
                    X64BinaryRegister(c, 0x01, destination, source);
                    break;
            }
            X64StoreQ(c, CtxMutationScratch, destination);
        } else {
            X86LoadD(c, destination, CtxMutationScratch);
            X86MovImmediate(c, source, static_cast<uint32_t>(key));
            switch ((variant + round) % 3u) {
                case 0:
                    X86BinaryRegister(c, 0x31, destination, source);
                    X86BinaryRegister(c, 0x31, destination, source);
                    break;
                case 1:
                    X86BinaryRegister(c, 0x01, destination, source);
                    X86BinaryRegister(c, 0x29, destination, source);
                    break;
                default:
                    X86BinaryRegister(c, 0x29, destination, source);
                    X86BinaryRegister(c, 0x01, destination, source);
                    break;
            }
            X86StoreD(c, CtxMutationScratch, destination);
        }
    }
}

void EmitOpaqueEvenProductPredicate(
    CodeBuffer& c,
    bool x64,
    const std::array<uint8_t, 4>& registers,
    CodeBuffer::Label impossible)
{
    const uint8_t value = registers[0];
    uint8_t product = registers[1];
    if (product == value) product = registers[2];
    if (x64) {
        X64LoadQ(c, value, CtxMutationScratch);
        X64MovRegister(c, product, value);
        const uint8_t rexProduct = static_cast<uint8_t>(0x48u |
            ((product & 8u) ? 1u : 0u));
        c.Raw({rexProduct, 0xFF,
            static_cast<uint8_t>(0xC0u | (product & 7u))});
        const uint8_t rexImul = static_cast<uint8_t>(0x48u |
            ((product & 8u) ? 4u : 0u) | ((value & 8u) ? 1u : 0u));
        c.Raw({rexImul, 0x0F, 0xAF, static_cast<uint8_t>(0xC0u |
            ((product & 7u) << 3u) | (value & 7u))});
        c.Raw({rexProduct, 0xF7,
            static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.U32(1u);
    } else {
        X86LoadD(c, value, CtxMutationScratch);
        X86MovRegister(c, product, value);
        c.Raw({0xFF, static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.Raw({0x0F, 0xAF, static_cast<uint8_t>(0xC0u |
            ((product & 7u) << 3u) | (value & 7u))});
        c.Raw({0xF7, static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.U32(1u);
    }
    // n*(n+1) is even for every machine integer, so this branch is a live,
    // internally-derived opaque predicate rather than an unconditional jump.
    c.Jcc(JccNE, impossible);
}

void X64RequireAndPop(
    CodeBuffer& c,
    uint8_t count,
    CodeBuffer::Label stackFailure)
{
    X64LoadD(c, 1, CtxValueDepth);             // ecx = old depth
    c.Raw({0x83,0xF9,count});                  // cmp ecx,count
    c.Jcc(JccB, stackFailure);
    c.Raw({0x83,0xE9,count});                  // ecx = first popped slot
    X64StoreD(c, CtxValueDepth, 1);
    if (count >= 1) X64LoadIndexedQ(c, 0, 1, CtxValues);
    if (count >= 2) X64LoadIndexedQ(c, 2, 1, CtxValues + 8u);
    if (count >= 3) X64LoadIndexedQ(c, 8, 1, CtxValues + 16u);
}

void X64PushOne(
    CodeBuffer& c,
    uint8_t source,
    CodeBuffer::Label stackFailure)
{
    X64LoadD(c, 1, CtxValueDepth);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jcc(JccAE, stackFailure);
    X64StoreIndexedQ(c, CtxValues, 1, source);
    c.Raw({0xFF,0xC1});
    X64StoreD(c, CtxValueDepth, 1);
}

void X64PushTwo(
    CodeBuffer& c,
    uint8_t first,
    uint8_t second,
    CodeBuffer::Label stackFailure)
{
    X64LoadD(c, 1, CtxValueDepth);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jcc(JccAE, stackFailure);
    X64StoreIndexedQ(c, CtxValues, 1, first);
    X64StoreIndexedQ(c, CtxValues + 8u, 1, second);
    c.Raw({0x83,0xC1,0x02});
    X64StoreD(c, CtxValueDepth, 1);
}

void X86RequireAndPop(
    CodeBuffer& c,
    uint8_t count,
    CodeBuffer::Label stackFailure)
{
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x83,0xF9,count});
    c.Jcc(JccB, stackFailure);
    c.Raw({0x83,0xE9,count});
    X86StoreD(c, CtxValueDepth, 1);
    if (count >= 1) X86LoadIndexedD(c, 0, CtxValues);
    if (count >= 2) X86LoadIndexedD(c, 2, CtxValues + 8u);
    if (count >= 3) X86LoadIndexedD(c, 1, CtxValues + 16u);
}

void X86PushOne(
    CodeBuffer& c,
    uint8_t source,
    CodeBuffer::Label stackFailure)
{
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jcc(JccAE, stackFailure);
    X86StoreIndexedD(c, CtxValues, source);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 4u); c.U32(0);
    c.Raw({0x41});
    X86StoreD(c, CtxValueDepth, 1);
}

void X86PushTwo(
    CodeBuffer& c,
    uint8_t first,
    uint8_t second,
    CodeBuffer::Label stackFailure)
{
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jcc(JccAE, stackFailure);
    X86StoreIndexedD(c, CtxValues, first);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 4u); c.U32(0);
    X86StoreIndexedD(c, CtxValues + 8u, second);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 12u); c.U32(0);
    c.Raw({0x83,0xC1,0x02});
    X86StoreD(c, CtxValueDepth, 1);
}

void X64DispatchPendingWidth(CodeBuffer& c, const WidthLabels& labels) {
    X64LoadByte(c, 11, RECORD_OFFSET(CtxPendingFlags, width));
    c.Raw({0x41,0x83,0xFB,0x01}); c.Jcc(JccE, labels.width1);
    c.Raw({0x41,0x83,0xFB,0x02}); c.Jcc(JccE, labels.width2);
    c.Raw({0x41,0x83,0xFB,0x04}); c.Jcc(JccE, labels.width4);
    c.Raw({0x41,0x83,0xFB,0x08}); c.Jcc(JccE, labels.width8);
    c.Jmp(labels.invalid);
}

void X86DispatchPendingWidth(CodeBuffer& c, const WidthLabels& labels) {
    X86LoadByte(c, 1, RECORD_OFFSET(CtxPendingFlags, width));
    c.Raw({0x83,0xF9,0x01}); c.Jcc(JccE, labels.width1);
    c.Raw({0x83,0xF9,0x02}); c.Jcc(JccE, labels.width2);
    c.Raw({0x83,0xF9,0x04}); c.Jcc(JccE, labels.width4);
    c.Jmp(labels.invalid);
}

void X64MaskForWidthInR11(CodeBuffer& c) {
    /* r9 = UINT64_MAX >> ((8-r11d)*8). */
    c.Raw({0xB9,0x08,0x00,0x00,0x00});
    c.Raw({0x44,0x29,0xD9,0xC1,0xE1,0x03});
    c.Raw({0x49,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF});
    c.Raw({0x49,0xD3,0xE9});
}

void X86BuildMaskInScratch(CodeBuffer& c) {
    /* ecx contains a validated width. Preserve eax/edx and publish the mask
       in the low half; the high half is an independent 32-bit spill slot. */
    c.Raw({0x50,0x51,0xB8,0x04,0x00,0x00,0x00,0x29,0xC8,
           0xC1,0xE0,0x03,0x89,0xC1,0xB8,0xFF,0xFF,0xFF,0xFF,
           0xD3,0xE8});
    X86StoreD(c, CtxMutationScratch, 0);
    c.Raw({0x59,0x58});
}

void X64ClearLastAlu(CodeBuffer& c) {
    for (uint32_t offset = 0; offset < 40u; offset += 8u) {
        c.Raw({0x49,0xC7,0x87}); c.U32(CtxLastAlu + offset); c.U32(0);
    }
    X64StoreDImmediate(c, CtxLastAlu + 40u, 0);
}

void X64Latch(
    CodeBuffer& c,
    uint8_t a,
    uint8_t b,
    uint8_t result,
    uint8_t auxiliary,
    uint8_t widthRegister)
{
    X64ClearLastAlu(c);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), a);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), b);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, result), result);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliary);
    X64StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, definedMask), 0);
    X64StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, preserveMask), 0);
    /* mov byte ptr [r15+width], r11b/r8b. */
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((widthRegister & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X64StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void X86ClearLastAlu(CodeBuffer& c) {
    for (uint32_t offset = 0; offset < sizeof(VM_LAZY_FLAGS_RECORD); offset += 4u) {
        X86StoreDImmediate(c, CtxLastAlu + offset, 0);
    }
}

void X86LatchFromStoredOperands(
    CodeBuffer& c,
    uint8_t resultRegister,
    uint8_t auxiliaryRegister,
    uint8_t widthRegister)
{
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, result), resultRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, result) + 4u, 0);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliaryRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, auxiliary) + 4u, 0);
    c.Raw({0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X86StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void X86BeginLatch(CodeBuffer& c, uint8_t aRegister, uint8_t bRegister) {
    X86ClearLastAlu(c);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, a), aRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, a) + 4u, 0);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, b), bRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, b) + 4u, 0);
}

void X64Move(CodeBuffer& c, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 0x04u : 0u) | ((destination & 8u) ? 0x01u : 0u));
    c.Raw({rex,0x89,static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) |
        (destination & 7u))});
}

void X64Binary(CodeBuffer& c, uint8_t opcode, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 0x04u : 0u) | ((destination & 8u) ? 0x01u : 0u));
    c.Raw({rex,opcode,static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) |
        (destination & 7u))});
}

void X64Not(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xF7,static_cast<uint8_t>(0xD0u | (reg & 7u))});
}

void X64Neg(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xF7,static_cast<uint8_t>(0xD8u | (reg & 7u))});
}

void X64ShiftImmediate(CodeBuffer& c, uint8_t group, uint8_t reg, uint8_t count) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xC1,static_cast<uint8_t>(0xC0u | (group << 3u) | (reg & 7u)),count});
}

void X64ShiftCl(CodeBuffer& c, uint8_t group, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xD3,static_cast<uint8_t>(0xC0u | (group << 3u) | (reg & 7u))});
}

void X64CallFlagMaterializer(
    CodeBuffer& c,
    uint8_t maskOperand,
    bool immediate,
    uint32_t immediateMask,
    CodeBuffer::Label failure)
{
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x4C,0x89,0xF9});                 // rcx = context
    if (immediate) { c.Raw({0xBA}); c.U32(immediateMask); }
    else X64LoadD(c, 2, CtxDecodedOperands + static_cast<uint32_t>(maskOperand) * 8u);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64FlagCallStackBytes, kX64FlagCallPrologSize);
}

void X86CallFlagMaterializer(
    CodeBuffer& c,
    uint8_t maskOperand,
    bool immediate,
    uint32_t immediateMask,
    CodeBuffer::Label failure)
{
    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, failure);
    if (immediate) { c.Raw({0x68}); c.U32(immediateMask); }
    else { X86LoadD(c, 2, CtxDecodedOperands + static_cast<uint32_t>(maskOperand) * 8u); c.U8(0x52); }
    c.U8(0x57);                               // context
    c.Raw({0xFF,0xD0,0x83,0xC4,0x08});
}

void X64CallFlagMaterializerForPreviousRecord(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x4C,0x89,0xF9});
    c.Raw({0xBA}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64FlagCallStackBytes, kX64FlagCallPrologSize);
}

void X86CallFlagMaterializerForPreviousRecord(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x68}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    c.Raw({0x57,0xFF,0xD0,0x83,0xC4,0x08});
}

void X64EvaluateCondition(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    std::array<CodeBuffer::Label, VM_CONDITION_G + 1u> cases{};
    for (auto& label : cases) label = c.NewLabel();
    const auto done = c.NewLabel();
    X64LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    for (uint8_t condition = VM_CONDITION_ALWAYS; condition <= VM_CONDITION_G; ++condition) {
        c.Raw({0x83,0xF9,condition}); c.Jcc(JccE, cases[condition]);
    }
    c.Jmp(invalid);

    c.Bind(cases[VM_CONDITION_ALWAYS]);
    c.Raw({0xB8,0x01,0x00,0x00,0x00}); c.Jmp(done);
    const auto emitTest = [&](VM_CONDITION condition, uint32_t mask, bool inverse) {
        c.Bind(cases[condition]);
        X64LoadQ(c, 2, CtxVirtualFlags);
        c.Raw({0x48,0xF7,0xC2}); c.U32(mask);
        c.Raw({0x0F,static_cast<uint8_t>(inverse ? 0x94 : 0x95),0xC0,0x0F,0xB6,0xC0});
        c.Jmp(done);
    };
    emitTest(VM_CONDITION_O, VM_FLAG_OF, false);
    emitTest(VM_CONDITION_NO, VM_FLAG_OF, true);
    emitTest(VM_CONDITION_B, VM_FLAG_CF, false);
    emitTest(VM_CONDITION_AE, VM_FLAG_CF, true);
    emitTest(VM_CONDITION_E, VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_NE, VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_BE, VM_FLAG_CF | VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_A, VM_FLAG_CF | VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_S, VM_FLAG_SF, false);
    emitTest(VM_CONDITION_NS, VM_FLAG_SF, true);
    emitTest(VM_CONDITION_P, VM_FLAG_PF, false);
    emitTest(VM_CONDITION_NP, VM_FLAG_PF, true);

    const auto emitSigned = [&](VM_CONDITION condition, bool invert, bool includeZero) {
        c.Bind(cases[condition]);
        X64LoadQ(c, 2, CtxVirtualFlags);
        c.Raw({0x48,0x89,0xD0,0x48,0xC1,0xE8,0x07,0x83,0xE0,0x01,
               0x48,0xC1,0xEA,0x0B,0x83,0xE2,0x01,0x31,0xD0});
        if (invert) c.Raw({0x83,0xF0,0x01});
        if (includeZero) {
            X64LoadQ(c, 2, CtxVirtualFlags);
            c.Raw({0x48,0xC1,0xEA,0x06,0x83,0xE2,0x01,0x09,0xD0});
        } else if (condition == VM_CONDITION_G) {
            X64LoadQ(c, 2, CtxVirtualFlags);
            c.Raw({0x48,0xC1,0xEA,0x06,0x83,0xE2,0x01,0x83,0xF2,0x01,0x21,0xD0});
        }
        c.Jmp(done);
    };
    emitSigned(VM_CONDITION_L, false, false);
    emitSigned(VM_CONDITION_GE, true, false);
    emitSigned(VM_CONDITION_LE, false, true);
    emitSigned(VM_CONDITION_G, true, false);
    c.Bind(done);
}

void X86EvaluateCondition(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    std::array<CodeBuffer::Label, VM_CONDITION_G + 1u> cases{};
    for (auto& label : cases) label = c.NewLabel();
    const auto done = c.NewLabel();
    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    for (uint8_t condition = VM_CONDITION_ALWAYS; condition <= VM_CONDITION_G; ++condition) {
        c.Raw({0x83,0xF9,condition}); c.Jcc(JccE, cases[condition]);
    }
    c.Jmp(invalid);
    c.Bind(cases[VM_CONDITION_ALWAYS]);
    c.Raw({0xB8,0x01,0x00,0x00,0x00}); c.Jmp(done);
    const auto emitTest = [&](VM_CONDITION condition, uint32_t mask, bool inverse) {
        c.Bind(cases[condition]);
        X86LoadD(c, 2, CtxVirtualFlags);
        c.Raw({0xF7,0xC2}); c.U32(mask);
        c.Raw({0x0F,static_cast<uint8_t>(inverse ? 0x94 : 0x95),0xC0,0x0F,0xB6,0xC0});
        c.Jmp(done);
    };
    emitTest(VM_CONDITION_O, VM_FLAG_OF, false);
    emitTest(VM_CONDITION_NO, VM_FLAG_OF, true);
    emitTest(VM_CONDITION_B, VM_FLAG_CF, false);
    emitTest(VM_CONDITION_AE, VM_FLAG_CF, true);
    emitTest(VM_CONDITION_E, VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_NE, VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_BE, VM_FLAG_CF | VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_A, VM_FLAG_CF | VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_S, VM_FLAG_SF, false);
    emitTest(VM_CONDITION_NS, VM_FLAG_SF, true);
    emitTest(VM_CONDITION_P, VM_FLAG_PF, false);
    emitTest(VM_CONDITION_NP, VM_FLAG_PF, true);
    const auto emitSigned = [&](VM_CONDITION condition, bool invert, bool includeZero) {
        c.Bind(cases[condition]);
        X86LoadD(c, 2, CtxVirtualFlags);
        c.Raw({0x89,0xD0,0xC1,0xE8,0x07,0x83,0xE0,0x01,
               0xC1,0xEA,0x0B,0x83,0xE2,0x01,0x31,0xD0});
        if (invert) c.Raw({0x83,0xF0,0x01});
        if (includeZero) {
            X86LoadD(c, 2, CtxVirtualFlags);
            c.Raw({0xC1,0xEA,0x06,0x83,0xE2,0x01,0x09,0xD0});
        } else if (condition == VM_CONDITION_G) {
            X86LoadD(c, 2, CtxVirtualFlags);
            c.Raw({0xC1,0xEA,0x06,0x83,0xE2,0x01,0x83,0xF2,0x01,0x21,0xD0});
        }
        c.Jmp(done);
    };
    emitSigned(VM_CONDITION_L, false, false);
    emitSigned(VM_CONDITION_GE, true, false);
    emitSigned(VM_CONDITION_LE, false, true);
    emitSigned(VM_CONDITION_G, true, false);
    c.Bind(done);
}

void X64ValidateWidth(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    const auto valid = c.NewLabel();
    X64LoadByte(c, 11, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x41,0x83,0xFB,0x01}); c.Jcc(JccE, valid);
    c.Raw({0x41,0x83,0xFB,0x02}); c.Jcc(JccE, valid);
    c.Raw({0x41,0x83,0xFB,0x04}); c.Jcc(JccE, valid);
    c.Raw({0x41,0x83,0xFB,0x08}); c.Jcc(JccNE, invalid);
    c.Bind(valid);
}

void X86ValidateWidth(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    const auto valid = c.NewLabel();
    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x83,0xF9,0x01}); c.Jcc(JccE, valid);
    c.Raw({0x83,0xF9,0x02}); c.Jcc(JccE, valid);
    c.Raw({0x83,0xF9,0x04}); c.Jcc(JccNE, invalid);
    c.Bind(valid);
}

void X64CopyRecord(CodeBuffer& c, uint32_t destination, uint32_t source) {
    for (uint32_t offset = 0; offset < 40u; offset += 8u) {
        X64LoadQ(c, 0, source + offset);
        X64StoreQ(c, destination + offset, 0);
    }
    X64LoadD(c, 0, source + 40u);
    X64StoreD(c, destination + 40u, 0);
}

void X86CopyRecord(CodeBuffer& c, uint32_t destination, uint32_t source) {
    for (uint32_t offset = 0; offset < sizeof(VM_LAZY_FLAGS_RECORD); offset += 4u) {
        X86LoadD(c, 0, source + offset);
        X86StoreD(c, destination + offset, 0);
    }
}

bool IsBinaryAlu(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_ADD:
        case VM_UOP_SUB:
        case VM_UOP_MUL:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
        case VM_UOP_SAR:
        case VM_UOP_ROL:
        case VM_UOP_ROR:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
            return true;
        default:
            return false;
    }
}

bool IsUnaryAlu(VM_MICRO_OPCODE semantic) {
    return semantic == VM_UOP_NOT || semantic == VM_UOP_NEG ||
        semantic == VM_UOP_BSWAP;
}

bool HasConcreteEmitter(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_PUSH_VREG:
        case VM_UOP_PUSH_IMM:
        case VM_UOP_PUSH_FLAGS:
        case VM_UOP_PUSH_IP:
        case VM_UOP_PUSH_IMAGE_BASE:
        case VM_UOP_POP_VREG:
        case VM_UOP_LOAD_TEMP:
        case VM_UOP_STORE_TEMP:
        case VM_UOP_DUP:
        case VM_UOP_SWAP:
        case VM_UOP_ROT:
        case VM_UOP_DROP:
        case VM_UOP_LOAD:
        case VM_UOP_STORE:
        case VM_UOP_ADD:
        case VM_UOP_ADD_CARRY:
        case VM_UOP_SUB:
        case VM_UOP_SUB_BORROW:
        case VM_UOP_MUL:
        case VM_UOP_UMUL_WIDE:
        case VM_UOP_SMUL_WIDE:
        case VM_UOP_UDIV_WIDE:
        case VM_UOP_IDIV_WIDE:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_NOT:
        case VM_UOP_NEG:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
        case VM_UOP_SAR:
        case VM_UOP_ROL:
        case VM_UOP_ROR:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
        case VM_UOP_BSWAP:
        case VM_UOP_ZERO_EXTEND:
        case VM_UOP_SIGN_EXTEND:
        case VM_UOP_FLAGS_LAZY:
        case VM_UOP_FLAGS_MATERIALIZE:
        case VM_UOP_FLAGS_WRITE:
        case VM_UOP_FLAGS_UPDATE:
        case VM_UOP_FLAGS_PACK_AH:
        case VM_UOP_FLAGS_UNPACK_AH:
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT:
        case VM_UOP_BRANCH:
        case VM_UOP_BRANCH_IF:
        case VM_UOP_CALL_VM:
        case VM_UOP_RET:
        case VM_UOP_EXIT:
        case VM_UOP_BRIDGE_EXTENDED:
        case VM_UOP_RDTSC:
        case VM_UOP_CPUID:
        case VM_UOP_INT3:
            return true;
        case VM_UOP_TRAP:
        case VM_UOP_CALL_HOST:
        case VM_UOP_COUNT:
        default:
            return false;
    }
}

bool ExpectedX64StackFunclet(
    VM_MICRO_OPCODE semantic,
    VMHandlerSemanticStackFunclet& expected)
{
    expected = {};
    switch (semantic) {
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
            expected.kind = VMHandlerSemanticUnwindKind::StackAllocation;
            expected.stackBytes = kX64FlagCallStackBytes;
            expected.prologSize = kX64FlagCallPrologSize;
            return true;
        case VM_UOP_BRIDGE_EXTENDED:
            expected.kind = VMHandlerSemanticUnwindKind::StackAllocation;
            expected.stackBytes = kX64BridgeStackBytes;
            expected.prologSize = kX64BridgePrologSize;
            return true;
        case VM_UOP_CPUID:
            expected.kind = VMHandlerSemanticUnwindKind::PushNonvolatile;
            expected.prologSize = kX64CpuidPrologSize;
            expected.nonvolatileRegister = kX64RbxUnwindRegister;
            return true;
        default:
            return false;
    }
}

void EmitX64SizedShiftOrRotate(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emit = [&](uint8_t bytes, CodeBuffer::Label label) {
        c.Bind(label);
        c.Raw({0x48,0x89,0xD1});
        uint8_t modrm = 0xE0;
        if (semantic == VM_UOP_SHR) modrm = 0xE8;
        else if (semantic == VM_UOP_SAR) modrm = 0xF8;
        else if (semantic == VM_UOP_ROL) modrm = 0xC0;
        else if (semantic == VM_UOP_ROR) modrm = 0xC8;
        if (bytes == 1u) c.Raw({0xD2,modrm});
        else {
            if (bytes == 2u) c.U8(0x66);
            if (bytes == 8u) c.U8(0x48);
            c.Raw({0xD3,modrm});
        }
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        else if (bytes == 4u) c.Raw({0x89,0xC0});
        c.Jmp(done);
    };
    emit(1, width.width1);
    emit(2, width.width2);
    emit(4, width.width4);
    emit(8, width.width8);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void EmitX86SizedShiftOrRotate(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto emit = [&](uint8_t bytes, CodeBuffer::Label label) {
        c.Bind(label);
        c.Raw({0x89,0xD1});
        uint8_t modrm = 0xE0;
        if (semantic == VM_UOP_SHR) modrm = 0xE8;
        else if (semantic == VM_UOP_SAR) modrm = 0xF8;
        else if (semantic == VM_UOP_ROL) modrm = 0xC0;
        else if (semantic == VM_UOP_ROR) modrm = 0xC8;
        if (bytes == 1u) c.Raw({0xD2,modrm});
        else {
            if (bytes == 2u) c.U8(0x66);
            c.Raw({0xD3,modrm});
        }
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        c.Jmp(done);
    };
    emit(1, width.width1);
    emit(2, width.width2);
    emit(4, width.width4);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X64LoadMemoryByWidth(
    CodeBuffer& c,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x48,0x0F,0xB6,0x00}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x48,0x0F,0xB7,0x00}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x8B,0x00}); c.Jmp(done);
    c.Bind(width.width8); c.Raw({0x48,0x8B,0x00}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X64StoreMemoryByWidth(
    CodeBuffer& c,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x88,0x10}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x66,0x89,0x10}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x89,0x10}); c.Jmp(done);
    c.Bind(width.width8); c.Raw({0x48,0x89,0x10}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X86LoadMemoryByWidth(CodeBuffer& c, CodeBuffer::Label widthFailure) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x0F,0xB6,0x00}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x0F,0xB7,0x00}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x8B,0x00}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X86StoreMemoryByWidth(CodeBuffer& c, CodeBuffer::Label widthFailure) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x88,0x10}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x66,0x89,0x10}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x89,0x10}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void EmitX64DataSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    switch (semantic) {
        case VM_UOP_PUSH_VREG: {
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_REGISTER_COUNT});
            c.Jcc(JccAE, rangeFailure);
            X64LoadByte(c, 11, CtxDecodedOperands + 8u);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x41,0x0F,0xB6,0xD3,0xC1,0xE2,0x03,0x01,0xCA,
                   0x83,0xFA,0x40});
            c.Jcc(JccA, rangeFailure);
            X64LoadIndexedQ(c, 0, 10, CtxVregs);
            X64ShiftCl(c, 5, 0);
            X64MaskForWidthInR11(c);
            X64Binary(c, 0x21, 0, 9);
            X64PushOne(c, 0, stackFailure);
            return;
        }
        case VM_UOP_PUSH_IMM:
            X64LoadQ(c, 0, CtxDecodedOperands);
            X64ValidateWidth(c, 1, widthFailure);
            X64MaskForWidthInR11(c); X64Binary(c, 0x21, 0, 9);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_FLAGS:
            X64CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            X64LoadQ(c, 0, CtxVirtualFlags); X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_IP:
            X64LoadQ(c, 0, CtxVip); X64LoadQ(c, 2, CtxBytecodeBegin);
            X64Binary(c, 0x29, 0, 2); X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_IMAGE_BASE:
            X64LoadQ(c, 0, CtxImageBase); X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_POP_VREG: {
            X64RequireAndPop(c, 1, stackFailure);
            X64StoreQ(c, CtxMutationScratch, 0);
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x41,0x0F,0xB6,0xD3,0xC1,0xE2,0x03,0x01,0xCA,
                   0x83,0xFA,0x40}); c.Jcc(JccA, rangeFailure);
            X64MaskForWidthInR11(c);
            X64LoadQ(c, 0, CtxMutationScratch); X64Binary(c, 0x21, 0, 9);
            X64LoadD(c, 8, CtxDecodedOperands + 24u);
            c.Raw({0x41,0x83,0xF8,0x01}); c.Jcc(JccA, rangeFailure);
            const auto merge = c.NewLabel(); const auto store = c.NewLabel();
            c.Raw({0x45,0x85,0xC0}); c.Jcc(JccE, merge);
            X64StoreIndexedQ(c, CtxVregs, 10, 0); c.Jmp(store);
            c.Bind(merge);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            X64ShiftCl(c, 4, 0);
            X64Move(c, 8, 9); X64ShiftCl(c, 4, 8); X64Not(c, 8);
            X64LoadIndexedQ(c, 2, 10, CtxVregs); X64Binary(c, 0x21, 2, 8);
            X64Binary(c, 0x09, 0, 2); X64StoreIndexedQ(c, CtxVregs, 10, 0);
            c.Bind(store);
            return;
        }
        case VM_UOP_LOAD_TEMP:
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            X64LoadIndexedQ(c, 0, 10, CtxTemps); X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_STORE_TEMP:
            X64RequireAndPop(c, 1, stackFailure); X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            X64StoreIndexedQ(c, CtxTemps, 10, 0); return;
        case VM_UOP_DUP:
            X64RequireAndPop(c, 1, stackFailure); X64PushTwo(c, 0, 0, stackFailure); return;
        case VM_UOP_SWAP:
            X64RequireAndPop(c, 2, stackFailure); X64PushTwo(c, 2, 0, stackFailure); return;
        case VM_UOP_ROT:
            X64RequireAndPop(c, 3, stackFailure);
            X64PushOne(c, 2, stackFailure); X64PushOne(c, 8, stackFailure);
            X64PushOne(c, 0, stackFailure); return;
        case VM_UOP_DROP:
            X64RequireAndPop(c, 1, stackFailure); return;
        case VM_UOP_LOAD:
            X64RequireAndPop(c, 1, stackFailure); X64ValidateWidth(c, 0, widthFailure);
            c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            X64LoadMemoryByWidth(c, widthFailure); X64PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE:
            X64RequireAndPop(c, 2, stackFailure); X64ValidateWidth(c, 0, widthFailure);
            c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            X64StoreMemoryByWidth(c, widthFailure); return;
        default:
            return;
    }
}

void EmitX86DataSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    switch (semantic) {
        case VM_UOP_PUSH_VREG:
            X86LoadD(c, 2, CtxDecodedOperands);
            c.Raw({0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x0F,0xB6,0x87}); c.U32(CtxDecodedOperands + 8u);
            c.Raw({0xC1,0xE0,0x03,0x01,0xC8,0x83,0xF8,0x20}); c.Jcc(JccA, rangeFailure);
            c.Raw({0x89,0xD1}); X86LoadIndexedD(c, 0, CtxVregs);
            X86LoadD(c, 1, CtxDecodedOperands + 16u); c.Raw({0xD3,0xE8});
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IMM:
            X86LoadD(c, 0, CtxDecodedOperands); X86ValidateWidth(c, 1, widthFailure);
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_FLAGS:
            X86CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            X86LoadD(c, 0, CtxVirtualFlags); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IP:
            X86LoadD(c, 0, CtxVip); X86LoadD(c, 2, CtxBytecodeBegin);
            c.Raw({0x29,0xD0}); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IMAGE_BASE:
            X86LoadD(c, 0, CtxImageBase); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_POP_VREG: {
            X86RequireAndPop(c, 1, stackFailure);
            X86StoreD(c, CtxMutationScratch + 4u, 0);
            X86LoadD(c, 2, CtxDecodedOperands);
            c.Raw({0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u);
            X86LoadByte(c, 0, CtxDecodedOperands + 8u);
            c.Raw({0xC1,0xE0,0x03,0x01,0xC8,0x83,0xF8,0x20}); c.Jcc(JccA, rangeFailure);
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            X86LoadD(c, 0, CtxMutationScratch + 4u);
            c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
            X86LoadD(c, 1, CtxDecodedOperands + 24u);
            c.Raw({0x83,0xF9,0x01}); c.Jcc(JccA, rangeFailure);
            const auto merge = c.NewLabel(); const auto done = c.NewLabel();
            c.Raw({0x85,0xC9}); c.Jcc(JccE, merge);
            c.Raw({0x89,0xD1}); X86StoreIndexedD(c, CtxVregs, 0);
            c.Raw({0xC7,0x84,0xCF}); c.U32(CtxVregs + 4u); c.U32(0); c.Jmp(done);
            c.Bind(merge);
            X86LoadD(c, 1, CtxDecodedOperands + 16u); c.Raw({0xD3,0xE0});
            X86LoadD(c, 1, CtxMutationScratch); c.Raw({0xD3,0xE1,0xF7,0xD1});
            c.Raw({0x89,0xD3,0x89,0xD1}); X86LoadIndexedD(c, 2, CtxVregs);
            c.Raw({0x21,0xCA,0x09,0xD0,0x89,0xD9}); X86StoreIndexedD(c, CtxVregs, 0);
            c.Raw({0xC7,0x84,0xCF}); c.U32(CtxVregs + 4u); c.U32(0);
            c.Bind(done); return;
        }
        case VM_UOP_LOAD_TEMP:
            X86LoadD(c, 1, CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86LoadIndexedD(c, 0, CtxTemps); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE_TEMP:
            X86RequireAndPop(c, 1, stackFailure); X86LoadD(c, 1, CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86StoreIndexedD(c, CtxTemps, 0);
            c.Raw({0xC7,0x84,0xCF}); c.U32(CtxTemps + 4u); c.U32(0); return;
        case VM_UOP_DUP:
            X86RequireAndPop(c, 1, stackFailure); X86PushTwo(c, 0, 0, stackFailure); return;
        case VM_UOP_SWAP:
            X86RequireAndPop(c, 2, stackFailure); X86PushTwo(c, 2, 0, stackFailure); return;
        case VM_UOP_ROT:
            X86RequireAndPop(c, 3, stackFailure);
            X86StoreD(c, CtxMutationScratch, 1);       // c
            X86StoreD(c, CtxMutationScratch + 4u, 0);  // a
            X86PushOne(c, 2, stackFailure);
            X86LoadD(c, 0, CtxMutationScratch); X86PushOne(c, 0, stackFailure);
            X86LoadD(c, 0, CtxMutationScratch + 4u); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_DROP: X86RequireAndPop(c, 1, stackFailure); return;
        case VM_UOP_LOAD:
            X86RequireAndPop(c, 1, stackFailure); X86ValidateWidth(c, 0, widthFailure);
            c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            X86LoadMemoryByWidth(c, widthFailure); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE:
            X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
            c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            X86StoreMemoryByWidth(c, widthFailure); return;
        default: return;
    }
}

void X64FinishPrelatched(
    CodeBuffer& c,
    uint8_t resultRegister,
    uint8_t auxiliaryRegister,
    uint8_t widthRegister)
{
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, result), resultRegister);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliaryRegister);
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((widthRegister & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X64StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void EmitX64BinaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 2, stackFailure);
    X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    X64Move(c, 8, 0); X64Move(c, 11, 2);
    // Width dispatch for shifts/rotates uses r11d, so latch both original
    // operands before the semantic core is allowed to reuse that register.
    // Keeping b in r11 until the end silently changed a zero count into the
    // operand width and corrupted the subsequent lazy-flags record.
    X64ClearLastAlu(c);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), 8);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), 11);
    c.Raw({0x45,0x31,0xD2});                  // auxiliary = 0
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitBusinessCoreVariant(c, true, semantic, coreStrategy)) {
        coreVariantSize = static_cast<uint32_t>(c.bytes.size()) -
            coreVariantOffset;
    } else {
        coreVariantOffset = 0;
        switch (semantic) {
            case VM_UOP_SHL:
            case VM_UOP_SHR:
            case VM_UOP_SAR:
            case VM_UOP_ROL:
            case VM_UOP_ROR:
                EmitX64SizedShiftOrRotate(c, semantic, widthFailure);
                break;
            default: break;
        }
    }
    X64Binary(c, 0x21, 0, 9);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64FinishPrelatched(c, 0, 10, 1);
    X64PushOne(c, 0, stackFailure);
}

void EmitX64CarryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure)
{
    X64RequireAndPop(c, 3, stackFailure);
    X64ValidateWidth(c, 0, widthFailure); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    c.Raw({0x49,0x83,0xE0,0x01});
    X64Move(c, 10, 0); X64Move(c, 11, 2);
    if (semantic == VM_UOP_ADD_CARRY) {
        X64Binary(c, 0x01, 0, 2); X64Binary(c, 0x01, 0, 8);
    } else {
        X64Binary(c, 0x29, 0, 2); X64Binary(c, 0x29, 0, 8);
    }
    X64Binary(c, 0x21, 0, 9);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 10, 11, 0, 8, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64UnaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 1, stackFailure); X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c); X64Binary(c, 0x21, 0, 9); X64Move(c, 8, 0);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitBusinessCoreVariant(c, true, semantic, coreStrategy)) {
        coreVariantSize = static_cast<uint32_t>(c.bytes.size()) -
            coreVariantOffset;
    } else {
        coreVariantOffset = 0;
        const WidthLabels width = MakeWidthLabels(c); const auto done = c.NewLabel();
        X64DispatchWidth(c, 0, width);
        c.Bind(width.width1); c.Jmp(done);
        c.Bind(width.width2); c.Raw({0x66,0xC1,0xC0,0x08}); c.Jmp(done);
        c.Bind(width.width4); c.Raw({0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.width8); c.Raw({0x48,0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(done);
    }
    X64Binary(c, 0x21, 0, 9); c.Raw({0x31,0xD2,0x45,0x31,0xD2});
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 8, 2, 0, 10, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64Extend(
    CodeBuffer& c,
    bool signExtend,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure)
{
    X64RequireAndPop(c, 1, stackFailure);
    X64ValidateWidth(c, 0, widthFailure); X64LoadByte(c, 10, CtxDecodedOperands);
    X64ValidateWidth(c, 1, widthFailure);       // r11 = to width
    c.Raw({0x45,0x39,0xDA}); c.Jcc(JccAE, rangeFailure);
    X64MaskForWidthInR11(c);                   // destination mask r9
    X64Move(c, 8, 0);
    X64LoadByte(c, 1, CtxDecodedOperands);     // from width
    c.Raw({0xBA,0x08,0x00,0x00,0x00,0x29,0xCA,0xC1,0xE2,0x03,
           0x89,0xD1});
    if (signExtend) {
        X64ShiftCl(c, 4, 0); X64Move(c, 1, 2); X64ShiftCl(c, 7, 0);
    } else {
        c.Raw({0x49,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF}); X64ShiftCl(c, 5, 9);
        X64Binary(c, 0x21, 0, 9);
    }
    X64LoadByte(c, 11, CtxDecodedOperands + 8u); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); c.Raw({0x31,0xD2,0x45,0x31,0xD2});
    X64LoadByte(c, 1, CtxDecodedOperands + 8u);
    X64Latch(c, 8, 2, 0, 10, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64WideMultiply(
    CodeBuffer& c,
    bool signedMultiply,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure)
{
    X64RequireAndPop(c, 2, stackFailure); X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c); X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    X64Move(c, 8, 0); X64Move(c, 11, 2); X64Move(c, 9, 2);
    const WidthLabels width = MakeWidthLabels(c); const auto product = c.NewLabel();
    const auto split = c.NewLabel(); const auto finish = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emitNarrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        if (signedMultiply) {
            if (bytes == 1u) c.Raw({0x48,0x0F,0xBE,0xC0,0x4D,0x0F,0xBE,0xC9});
            else if (bytes == 2u) c.Raw({0x48,0x0F,0xBF,0xC0,0x4D,0x0F,0xBF,0xC9});
            else c.Raw({0x48,0x63,0xC0,0x4D,0x63,0xC9});
            c.Raw({0x49,0xF7,0xE9});
        } else c.Raw({0x49,0xF7,0xE1});
        c.Raw({0x48,0x89,0xC2});
        c.Raw({0xB9}); c.U32(bytes * 8u); c.Raw({0x48,0xD3,0xEA});
        X64LoadByte(c, 11, CtxDecodedOperands); X64MaskForWidthInR11(c);
        X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); c.Jmp(finish);
    };
    emitNarrow(width.width1,1); emitNarrow(width.width2,2); emitNarrow(width.width4,4);
    c.Bind(width.width8);
    if (signedMultiply) c.Raw({0x49,0xF7,0xE9}); else c.Raw({0x49,0xF7,0xE1});
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(product); c.Bind(split);
    c.Bind(finish);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 8, 11, 0, 2, 1); X64PushTwo(c, 0, 2, stackFailure);
}

void EmitX64WideDivide(
    CodeBuffer& c,
    bool signedDivide,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label divideFailure)
{
    X64RequireAndPop(c, 3, stackFailure);       // rax=high, rdx=low, r8=divisor
    X64ValidateWidth(c, 0, widthFailure); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); X64Binary(c, 0x21, 8, 9);
    X64ClearLastAlu(c); X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), 0);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), 8);
    X64StoreQ(c, CtxMutationScratch, 8);
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emitNarrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        X64Move(c, 10, 0); c.Raw({0xB9}); c.U32(bytes * 8u); X64ShiftCl(c, 4, 10);
        X64Binary(c, 0x09, 10, 2); X64Move(c, 0, 10);
        X64LoadQ(c, 9, CtxMutationScratch);
        if (signedDivide) {
            if (bytes == 1u) c.Raw({0x48,0x0F,0xBF,0xC0,0x4D,0x0F,0xBE,0xC9});
            else if (bytes == 2u) c.Raw({0x48,0x63,0xC0,0x4D,0x0F,0xBF,0xC9});
            else c.Raw({0x4D,0x63,0xC9});
            c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
            const auto safe = c.NewLabel();
            c.Raw({0x48,0xBA,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,
                   0x48,0x39,0xD0}); c.Jcc(JccNE, safe);
            c.Raw({0x49,0x83,0xF9,0xFF}); c.Jcc(JccE, divideFailure); c.Bind(safe);
            c.Raw({0x48,0x99,0x49,0xF7,0xF9});
        } else {
            c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x31,0xD2,0x49,0xF7,0xF1});
        }
        X64LoadByte(c, 11, CtxDecodedOperands); X64MaskForWidthInR11(c);
        if (signedDivide) {
            X64Move(c, 10, 0); X64Binary(c, 0x21, 10, 9);
            c.Raw({0xB9}); c.U32(8u - bytes); c.Raw({0xC1,0xE1,0x03});
            X64ShiftCl(c, 4, 10); X64ShiftCl(c, 7, 10);
            c.Raw({0x49,0x39,0xC2}); c.Jcc(JccNE, divideFailure);
        } else {
            X64Move(c, 10, 0); X64Binary(c, 0x21, 10, 9);
            c.Raw({0x49,0x39,0xC2}); c.Jcc(JccNE, divideFailure);
        }
        X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); c.Jmp(finish);
    };
    emitNarrow(width.width1,1); emitNarrow(width.width2,2); emitNarrow(width.width4,4);
    c.Bind(width.width8);
    X64LoadQ(c, 9, CtxMutationScratch);
    if (!signedDivide) {
        c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
        c.Raw({0x4C,0x39,0xC8}); c.Jcc(JccAE, divideFailure);
        X64Move(c, 10, 0); X64Move(c, 0, 2); X64Move(c, 2, 10);
        c.Raw({0x49,0xF7,0xF1});
    } else {
        /* Signed 128/64 uses magnitudes, avoiding a host #DE. */
        X64Move(c, 10, 0); X64Move(c, 11, 2); c.Raw({0x31,0xC9});
        const auto dividendPositive = c.NewLabel(); const auto divisorPositive = c.NewLabel();
        c.Raw({0x4D,0x85,0xD2}); c.Jcc(JccNS, dividendPositive);
        c.Raw({0x83,0xC9,0x01}); X64Not(c, 10); X64Not(c, 11);
        c.Raw({0x49,0x83,0xC3,0x01,0x49,0x83,0xD2,0x00}); c.Bind(dividendPositive);
        c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccNS, divisorPositive);
        c.Raw({0x83,0xC9,0x02}); X64Neg(c, 9); c.Bind(divisorPositive);
        c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
        c.Raw({0x4D,0x39,0xCA}); c.Jcc(JccAE, divideFailure);
        X64Move(c, 0, 11); X64Move(c, 2, 10); c.Raw({0x49,0xF7,0xF1});
        c.Raw({0x89,0xCE,0xC1,0xEE,0x01,0x31,0xCE,0x83,0xE6,0x01});
        const auto qPositive = c.NewLabel(); const auto qRangeDone = c.NewLabel();
        c.Raw({0x85,0xF6}); c.Jcc(JccE, qPositive);
        c.Raw({0x49,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,
               0x4C,0x39,0xC0}); c.Jcc(JccA, divideFailure); X64Neg(c, 0); c.Jmp(qRangeDone);
        c.Bind(qPositive); c.Raw({0x48,0x85,0xC0}); c.Jcc(JccS, divideFailure);
        c.Bind(qRangeDone);
        c.Raw({0xF6,0xC1,0x01}); const auto remPositive = c.NewLabel();
        c.Jcc(JccE, remPositive); X64Neg(c, 2); c.Bind(remPositive);
    }
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(finish);
    X64LoadByte(c, 1, CtxDecodedOperands); X64FinishPrelatched(c, 0, 2, 1);
    X64PushTwo(c, 0, 2, stackFailure);
}

void EmitX86BinaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitBusinessCoreVariant(c, false, semantic, coreStrategy)) {
        coreVariantSize = static_cast<uint32_t>(c.bytes.size()) -
            coreVariantOffset;
    } else {
        coreVariantOffset = 0;
        switch (semantic) {
            case VM_UOP_SHL:
            case VM_UOP_SHR:
            case VM_UOP_SAR:
            case VM_UOP_ROL:
            case VM_UOP_ROR:
                EmitX86SizedShiftOrRotate(c, semantic, widthFailure);
                break;
            default: break;
        }
    }
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    X86LoadD(c, 2, CtxMutationScratch + 4u);
    if (semantic != VM_UOP_BIT_TEST && semantic != VM_UOP_BIT_SET &&
        semantic != VM_UOP_BIT_RESET) c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86CarryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure)
{
    X86RequireAndPop(c, 3, stackFailure);       // eax=a, edx=b, ecx=carry
    X86StoreD(c, CtxMutationScratch + 4u, 1);
    X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 3, CtxDecodedOperands);     // ebx=width
    c.Raw({0x89,0xD9}); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2);
    X86LoadD(c, 1, CtxMutationScratch + 4u); c.Raw({0x83,0xE1,0x01});
    if (semantic == VM_UOP_ADD_CARRY) c.Raw({0x01,0xD0,0x01,0xC8});
    else c.Raw({0x29,0xD0,0x29,0xC8});
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x89,0xCA}); X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86UnaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 1, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86BeginLatch(c, 0, 2);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitBusinessCoreVariant(c, false, semantic, coreStrategy)) {
        coreVariantSize = static_cast<uint32_t>(c.bytes.size()) -
            coreVariantOffset;
    } else {
        coreVariantOffset = 0;
        const WidthLabels width = MakeWidthLabels(c); const auto done = c.NewLabel();
        X86DispatchWidth(c, 0, width);
        c.Bind(width.width1); c.Jmp(done);
        c.Bind(width.width2); c.Raw({0x66,0xC1,0xC0,0x08}); c.Jmp(done);
        c.Bind(width.width4); c.Raw({0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(done);
    }
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86Extend(
    CodeBuffer& c,
    bool signExtend,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure)
{
    X86RequireAndPop(c, 1, stackFailure); X86StoreD(c, CtxMutationScratch + 4u, 0);
    X86ValidateWidth(c, 0, widthFailure); X86LoadByte(c, 2, CtxDecodedOperands);
    X86ValidateWidth(c, 1, widthFailure); X86LoadByte(c, 1, CtxDecodedOperands + 8u);
    c.Raw({0x39,0xCA}); c.Jcc(JccAE, rangeFailure);
    X86LoadD(c, 0, CtxMutationScratch + 4u); c.Raw({0x31,0xD2}); X86BeginLatch(c, 0, 2);
    X86LoadByte(c, 1, CtxDecodedOperands);
    c.Raw({0xBA,0x04,0x00,0x00,0x00,0x29,0xCA,0xC1,0xE2,0x03,0x89,0xD1});
    if (signExtend) c.Raw({0xD3,0xE0,0x89,0xD1,0xD3,0xF8});
    else {
        c.Raw({0xBA,0xFF,0xFF,0xFF,0xFF,0xD3,0xEA,0x21,0xD0});
    }
    X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands + 8u);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86WideMultiply(
    CodeBuffer& c,
    bool signedMultiply,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure)
{
    X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2); c.Raw({0x89,0xD1});
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto narrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
        if (signedMultiply) {
            if (bytes == 1u) c.Raw({0x0F,0xBE,0xC0,0x0F,0xBE,0xC9});
            else c.Raw({0x0F,0xBF,0xC0,0x0F,0xBF,0xC9});
            c.Raw({0xF7,0xE9});
        } else c.Raw({0xF7,0xE1});
        c.Raw({0x89,0xC2,0xB9}); c.U32(bytes * 8u); c.Raw({0xD3,0xEA});
        X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
        c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
        c.Jmp(finish);
    };
    narrow(width.width1,1); narrow(width.width2,2);
    c.Bind(width.width4); X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b)); c.Raw(signedMultiply ?
        std::initializer_list<uint8_t>{0xF7,0xE9} : std::initializer_list<uint8_t>{0xF7,0xE1});
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(finish);
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushTwo(c, 0, 2, stackFailure);
}

void EmitX86WideDivide(
    CodeBuffer& c,
    bool signedDivide,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label divideFailure)
{
    X86RequireAndPop(c, 3, stackFailure);       // eax=high, edx=low, ecx=divisor
    X86BeginLatch(c, 0, 1);                    // preserve high and divisor
    X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b)); c.Raw({0x23,0x8F}); c.U32(CtxMutationScratch);
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto narrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label); X86LoadD(c, 3, RECORD_OFFSET(CtxLastAlu, b));
        c.Raw({0x89,0xC6,0xB9}); c.U32(bytes * 8u);
        c.Raw({0xD3,0xE6,0x09,0xD6,0x89,0xF0,0x89,0xD9});
        if (signedDivide) {
            if (bytes == 1u) c.Raw({0x0F,0xBF,0xC0,0x0F,0xBE,0xCB});
            else c.Raw({0x0F,0xBF,0xCB});
            c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x99,0xF7,0xF9});
        } else {
            c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x31,0xD2,0xF7,0xF1});
        }
        X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
        c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
        c.Jmp(finish);
    };
    narrow(width.width1,1); narrow(width.width2,2);
    c.Bind(width.width4);
    X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
    c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
    if (!signedDivide) {
        c.Raw({0x39,0xC8}); c.Jcc(JccAE, divideFailure);
        c.Raw({0x89,0xC6,0x89,0xD0,0x89,0xF2,0xF7,0xF1});
    } else {
        /* Magnitude precheck prevents native IDIV overflow. */
        // EBP belongs to the x86 validation-entry frame and must survive the
        // direct-threaded handler chain.  Save it around the signed-magnitude
        // scratch use, including every branch to the intentional #DE path.
        const auto signedFailure = c.NewLabel();
        const auto signedDone = c.NewLabel();
        c.Raw({0x55,0x89,0xC6,0x89,0xD3,0x31,0xED,0x85,0xF6});
        const auto dp = c.NewLabel(); const auto sp = c.NewLabel();
        c.Jcc(JccNS, dp); c.Raw({0x83,0xCD,0x01,0xF7,0xD6,0xF7,0xD3,
                                 0x83,0xC3,0x01,0x83,0xD6,0x00}); c.Bind(dp);
        c.Raw({0x85,0xC9}); c.Jcc(JccNS, sp); c.Raw({0x83,0xCD,0x02,0xF7,0xD9}); c.Bind(sp);
        c.Raw({0x85,0xC9}); c.Jcc(JccE, signedFailure);
        c.Raw({0x39,0xCE}); c.Jcc(JccAE, signedFailure);
        c.Raw({0x89,0xD8,0x89,0xF2,0xF7,0xF1});
        c.Raw({0x89,0xEE,0xD1,0xEE,0x31,0xEE,0x83,0xE6,0x01});
        const auto qp = c.NewLabel(); const auto qdone = c.NewLabel();
        c.Raw({0x85,0xF6}); c.Jcc(JccE, qp); c.Raw({0x3D,0x00,0x00,0x00,0x80});
        c.Jcc(JccA, signedFailure); c.Raw({0xF7,0xD8}); c.Jmp(qdone);
        c.Bind(qp); c.Raw({0x85,0xC0}); c.Jcc(JccS, signedFailure); c.Bind(qdone);
        // F6 /0 cannot address BPL in 32-bit mode (r/m=5 is CH).  Test the
        // saved dividend-sign bit as a full EBP value before signing remainder.
        c.Raw({0xF7,0xC5,0x01,0x00,0x00,0x00});
        const auto rp = c.NewLabel(); c.Jcc(JccE, rp);
        c.Raw({0xF7,0xDA}); c.Bind(rp); c.Raw({0x5D}); c.Jmp(signedDone);
        c.Bind(signedFailure); c.Raw({0x5D}); c.Jmp(divideFailure);
        c.Bind(signedDone);
    }
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(finish);
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushTwo(c, 0, 2, stackFailure);
}

void EmitX64FlagsSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    switch (semantic) {
        case VM_UOP_PUSH_FLAGS:
            X64CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            X64LoadQ(c, 0, CtxVirtualFlags);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_FLAGS_LAZY: {
            X64LoadByte(c, 0, RECORD_OFFSET(CtxLastAlu, valid));
            c.Raw({0x85,0xC0}); c.Jcc(JccE, flagsFailure);
            X64CallFlagMaterializerForPreviousRecord(c, flagsFailure);
            X64LoadByte(c, 0, CtxDecodedOperands);
            c.Raw({0x83,0xF8,VM_LAZY_ADD}); c.Jcc(JccB, flagsFailure);
            c.Raw({0x83,0xF8,VM_LAZY_BIT_TEST}); c.Jcc(JccA, flagsFailure);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            X64LoadD(c, 2, CtxDecodedOperands + 24u);
            c.Raw({0x89,0xC8,0x09,0xD0,0xA9});
            c.U32(~static_cast<uint32_t>(VM_FLAG_ARCHITECTURAL_MASK));
            c.Jcc(JccNE, flagsFailure); c.Raw({0x85,0xD1}); c.Jcc(JccNE, flagsFailure);
            X64CopyRecord(c, CtxPendingFlags, CtxLastAlu);
            X64LoadByte(c, 0, CtxDecodedOperands); X64StoreByteRegister(c,
                RECORD_OFFSET(CtxPendingFlags, operation), 0);
            X64LoadByte(c, 0, CtxDecodedOperands + 8u); X64StoreByteRegister(c,
                RECORD_OFFSET(CtxPendingFlags, width), 0);
            X64LoadD(c, 0, CtxDecodedOperands + 16u); X64StoreD(c,
                RECORD_OFFSET(CtxPendingFlags, definedMask), 0);
            X64LoadD(c, 0, CtxDecodedOperands + 24u); X64StoreD(c,
                RECORD_OFFSET(CtxPendingFlags, preserveMask), 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 1);
            return;
        }
        case VM_UOP_FLAGS_MATERIALIZE:
            X64CallFlagMaterializer(c, 0, false, 0, flagsFailure); return;
        case VM_UOP_FLAGS_WRITE: {
            X64RequireAndPop(c, 1, stackFailure); X64StoreQ(c, CtxMutationScratch, 0);
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadQ(c, 1, CtxDecodedOperands); X64LoadQ(c, 0, CtxVirtualFlags);
            X64Move(c, 2, 1); X64Not(c, 2); X64Binary(c, 0x21, 0, 2);
            X64LoadQ(c, 2, CtxMutationScratch); X64Binary(c, 0x21, 2, 1);
            X64Binary(c, 0x09, 0, 2); X64StoreQ(c, CtxVirtualFlags, 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_FLAGS_UPDATE: {
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadD(c, 1, CtxDecodedOperands); c.Raw({0x83,0xF9,VM_FLAG_UPDATE_TOGGLE});
            c.Jcc(JccA, rangeFailure);
            X64LoadQ(c, 2, CtxDecodedOperands + 8u); X64LoadQ(c, 0, CtxVirtualFlags);
            const auto clear = c.NewLabel(); const auto set = c.NewLabel(); const auto done = c.NewLabel();
            c.Raw({0x85,0xC9}); c.Jcc(JccE, clear);
            c.Raw({0x83,0xF9,VM_FLAG_UPDATE_SET}); c.Jcc(JccE, set);
            X64Binary(c, 0x31, 0, 2); c.Jmp(done);
            c.Bind(clear); X64Not(c, 2); X64Binary(c, 0x21, 0, 2); c.Jmp(done);
            c.Bind(set); X64Binary(c, 0x09, 0, 2); c.Bind(done);
            X64StoreQ(c, CtxVirtualFlags, 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_FLAGS_PACK_AH: {
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF, flagsFailure);
            X64LoadQ(c, 2, CtxVirtualFlags); c.Raw({0xB8,0x02,0x00,0x00,0x00});
            const auto bit = [&](uint32_t source, uint8_t destination) {
                X64Move(c, 1, 2); X64ShiftImmediate(c, 5, 1, static_cast<uint8_t>(source));
                c.Raw({0x83,0xE1,0x01}); if (destination) c.Raw({0xC1,0xE1,destination});
                c.Raw({0x09,0xC8});
            };
            bit(7,7); bit(6,6); bit(4,4); bit(2,2); bit(0,0);
            X64PushOne(c, 0, stackFailure); return;
        }
        case VM_UOP_FLAGS_UNPACK_AH: {
            X64RequireAndPop(c, 1, stackFailure); X64StoreQ(c, CtxMutationScratch, 0);
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadQ(c, 0, CtxMutationScratch); X64LoadQ(c, 2, CtxVirtualFlags);
            c.Raw({0x48,0x81,0xE2});
            c.U32(~static_cast<uint32_t>(
                VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF));
            X64Move(c, 1, 0); c.Raw({0x48,0x81,0xE1,0xD5,0x00,0x00,0x00});
            X64Binary(c, 0x09, 2, 1); X64StoreQ(c, CtxVirtualFlags, 2);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_PUSH_CONDITION:
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_STATUS_MASK, flagsFailure);
            X64EvaluateCondition(c, 0, rangeFailure); X64PushOne(c, 0, stackFailure); return;
        case VM_UOP_SELECT: {
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_STATUS_MASK, flagsFailure);
            X64EvaluateCondition(c, 0, rangeFailure); X64Move(c, 10, 0);
            X64RequireAndPop(c, 2, stackFailure);
            c.Raw({0x45,0x85,0xD2}); const auto chooseA = c.NewLabel(); const auto chosen = c.NewLabel();
            c.Jcc(JccE, chooseA); X64Move(c, 0, 2); c.Jmp(chosen);
            c.Bind(chooseA); c.Bind(chosen); X64PushOne(c, 0, stackFailure); return;
        }
        default: return;
    }
}

void EmitX86FlagsSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    switch (semantic) {
        case VM_UOP_PUSH_FLAGS:
            X86CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            X86LoadD(c, 0, CtxVirtualFlags);
            X86PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_FLAGS_LAZY:
            X86LoadByte(c, 0, RECORD_OFFSET(CtxLastAlu, valid)); c.Raw({0x85,0xC0}); c.Jcc(JccE, flagsFailure);
            X86CallFlagMaterializerForPreviousRecord(c, flagsFailure);
            X86LoadByte(c, 0, CtxDecodedOperands); c.Raw({0x83,0xF8,VM_LAZY_ADD}); c.Jcc(JccB, flagsFailure);
            c.Raw({0x83,0xF8,VM_LAZY_BIT_TEST}); c.Jcc(JccA, flagsFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u); X86LoadD(c, 2, CtxDecodedOperands + 24u);
            c.Raw({0x89,0xC8,0x09,0xD0,0xA9});
            c.U32(~static_cast<uint32_t>(VM_FLAG_ARCHITECTURAL_MASK));
            c.Jcc(JccNE, flagsFailure);
            c.Raw({0x85,0xD1}); c.Jcc(JccNE, flagsFailure); X86CopyRecord(c, CtxPendingFlags, CtxLastAlu);
            X86LoadByte(c, 0, CtxDecodedOperands); X86StoreByteRegister(c, RECORD_OFFSET(CtxPendingFlags, operation), 0);
            X86LoadByte(c, 0, CtxDecodedOperands + 8u); X86StoreByteRegister(c, RECORD_OFFSET(CtxPendingFlags, width), 0);
            X86LoadD(c, 0, CtxDecodedOperands + 16u); X86StoreD(c, RECORD_OFFSET(CtxPendingFlags, definedMask), 0);
            X86LoadD(c, 0, CtxDecodedOperands + 24u); X86StoreD(c, RECORD_OFFSET(CtxPendingFlags, preserveMask), 0);
            X86StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 1); return;
        case VM_UOP_FLAGS_MATERIALIZE: X86CallFlagMaterializer(c,0,false,0,flagsFailure); return;
        case VM_UOP_FLAGS_WRITE:
            X86RequireAndPop(c,1,stackFailure); X86StoreD(c,CtxMutationScratch,0);
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,1,CtxDecodedOperands); X86LoadD(c,0,CtxVirtualFlags);
            c.Raw({0x89,0xCA,0xF7,0xD2,0x21,0xD0}); X86LoadD(c,2,CtxMutationScratch);
            c.Raw({0x21,0xCA,0x09,0xD0}); X86StoreD(c,CtxVirtualFlags,0);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        case VM_UOP_FLAGS_UPDATE: {
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,1,CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_FLAG_UPDATE_TOGGLE}); c.Jcc(JccA,rangeFailure);
            X86LoadD(c,2,CtxDecodedOperands+8u); X86LoadD(c,0,CtxVirtualFlags);
            const auto clear=c.NewLabel(), set=c.NewLabel(), done=c.NewLabel();
            c.Raw({0x85,0xC9}); c.Jcc(JccE,clear); c.Raw({0x83,0xF9,VM_FLAG_UPDATE_SET}); c.Jcc(JccE,set);
            c.Raw({0x31,0xD0}); c.Jmp(done); c.Bind(clear); c.Raw({0xF7,0xD2,0x21,0xD0}); c.Jmp(done);
            c.Bind(set); c.Raw({0x09,0xD0}); c.Bind(done); X86StoreD(c,CtxVirtualFlags,0);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        }
        case VM_UOP_FLAGS_PACK_AH:
            X86CallFlagMaterializer(c,0,true,VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF,flagsFailure);
            X86LoadD(c,2,CtxVirtualFlags); c.Raw({0xB8,0x02,0x00,0x00,0x00});
            c.Raw({0x89,0xD1,0xC1,0xE9,0x07,0x83,0xE1,0x01,0xC1,0xE1,0x07,0x09,0xC8,
                   0x89,0xD1,0xC1,0xE9,0x06,0x83,0xE1,0x01,0xC1,0xE1,0x06,0x09,0xC8,
                   0x89,0xD1,0xC1,0xE9,0x04,0x83,0xE1,0x01,0xC1,0xE1,0x04,0x09,0xC8,
                   0x89,0xD1,0xC1,0xE9,0x02,0x83,0xE1,0x01,0xC1,0xE1,0x02,0x09,0xC8,
                   0x83,0xE2,0x01,0x09,0xD0}); X86PushOne(c,0,stackFailure); return;
        case VM_UOP_FLAGS_UNPACK_AH:
            X86RequireAndPop(c,1,stackFailure); X86StoreD(c,CtxMutationScratch,0);
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,0,CtxMutationScratch); X86LoadD(c,2,CtxVirtualFlags);
            c.Raw({0x81,0xE2});
            c.U32(~static_cast<uint32_t>(
                VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF));
            c.Raw({0x25,0xD5,0x00,0x00,0x00,0x09,0xC2}); X86StoreD(c,CtxVirtualFlags,2);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        case VM_UOP_PUSH_CONDITION:
            X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X86EvaluateCondition(c,0,rangeFailure); X86PushOne(c,0,stackFailure); return;
        case VM_UOP_SELECT: {
            X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X86EvaluateCondition(c,0,rangeFailure); X86StoreD(c,CtxMutationScratch,0);
            X86RequireAndPop(c,2,stackFailure); X86LoadD(c,1,CtxMutationScratch);
            c.Raw({0x85,0xC9}); const auto chooseA=c.NewLabel(),chosen=c.NewLabel(); c.Jcc(JccE,chooseA);
            c.Raw({0x89,0xD0}); c.Jmp(chosen); c.Bind(chooseA); c.Bind(chosen); X86PushOne(c,0,stackFailure); return;
        }
        default:return;
    }
}

void EmitX64ControlSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    (void)stackFailure;
    switch (semantic) {
        case VM_UOP_BRANCH:
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands);
            X64Binary(c,0x01,0,2); X64StoreQ(c,CtxVip,0); return;
        case VM_UOP_BRANCH_IF: {
            X64CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X64EvaluateCondition(c,0,rangeFailure); c.Raw({0x85,0xC0}); const auto done=c.NewLabel(); c.Jcc(JccE,done);
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands+8u);
            X64Binary(c,0x01,0,2); X64StoreQ(c,CtxVip,0); c.Bind(done); return;
        }
        case VM_UOP_CALL_VM: {
            X64LoadD(c,1,CtxCallDepth); c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_CALL_DEPTH); c.Jcc(JccAE,rangeFailure);
            X64LoadQ(c,0,CtxVip); X64LoadQ(c,2,CtxBytecodeBegin); X64Binary(c,0x29,0,2);
            c.Raw({0x41,0x89,0x84,0x8F}); c.U32(CtxCallStack); c.Raw({0xFF,0xC1}); X64StoreD(c,CtxCallDepth,1);
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands); X64Binary(c,0x01,0,2); X64StoreQ(c,CtxVip,0); return;
        }
        case VM_UOP_RET: {
            X64LoadD(c,1,CtxCallDepth); c.Raw({0x85,0xC9}); const auto top=c.NewLabel(),done=c.NewLabel(); c.Jcc(JccE,top);
            c.Raw({0xFF,0xC9}); X64StoreD(c,CtxCallDepth,1); c.Raw({0x41,0x8B,0x84,0x8F}); c.U32(CtxCallStack);
            X64LoadQ(c,2,CtxBytecodeBegin); X64Binary(c,0x01,0,2); X64StoreQ(c,CtxVip,0); c.Jmp(done);
            c.Bind(top); X64LoadD(c,0,CtxDecodedOperands); X64StoreD(c,CtxReturnStackCleanup,0); X64StoreDImmediate(c,CtxHalted,1);
            c.Bind(done); return;
        }
        case VM_UOP_EXIT:
            X64LoadD(c,0,CtxDecodedOperands); X64StoreD(c,CtxReturnStackCleanup,0); X64StoreDImmediate(c,CtxHalted,1); return;
        default:return;
    }
}

void EmitX86ControlSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    (void)stackFailure;
    switch(semantic){
        case VM_UOP_BRANCH:X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands);c.Raw({0x01,0xD0});X86StoreD(c,CtxVip,0);return;
        case VM_UOP_BRANCH_IF:{X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);X86EvaluateCondition(c,0,rangeFailure);
            c.Raw({0x85,0xC0});const auto done=c.NewLabel();c.Jcc(JccE,done);X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands+8u);
            c.Raw({0x01,0xD0});X86StoreD(c,CtxVip,0);c.Bind(done);return;}
        case VM_UOP_CALL_VM:{X86LoadD(c,1,CtxCallDepth);c.Raw({0x81,0xF9});c.U32(VM_RUNTIME_CALL_DEPTH);c.Jcc(JccAE,rangeFailure);
            X86LoadD(c,0,CtxVip);X86LoadD(c,2,CtxBytecodeBegin);c.Raw({0x29,0xD0,0x89,0x84,0x8F});c.U32(CtxCallStack);
            c.Raw({0x41});X86StoreD(c,CtxCallDepth,1);X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands);c.Raw({0x01,0xD0});X86StoreD(c,CtxVip,0);return;}
        case VM_UOP_RET:{X86LoadD(c,1,CtxCallDepth);c.Raw({0x85,0xC9});const auto top=c.NewLabel(),done=c.NewLabel();c.Jcc(JccE,top);
            c.Raw({0x49});X86StoreD(c,CtxCallDepth,1);c.Raw({0x8B,0x84,0x8F});c.U32(CtxCallStack);X86LoadD(c,2,CtxBytecodeBegin);c.Raw({0x01,0xD0});
            X86StoreD(c,CtxVip,0);c.Jmp(done);c.Bind(top);X86LoadD(c,0,CtxDecodedOperands);X86StoreD(c,CtxReturnStackCleanup,0);X86StoreDImmediate(c,CtxHalted,1);c.Bind(done);return;}
        case VM_UOP_EXIT:X86LoadD(c,0,CtxDecodedOperands);X86StoreD(c,CtxReturnStackCleanup,0);X86StoreDImmediate(c,CtxHalted,1);return;
        default:return;
    }
}

void X64StoreStackQ(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x89,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X64LoadStackQ(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x8B,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X86StoreStackD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x89,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X86LoadStackD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    c.Raw({0x8B,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void EmitX64BridgeExtended(
    CodeBuffer& c,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    constexpr uint32_t stateBase = kX64BridgeStateBase;
    constexpr uint32_t allocation = kX64BridgeStackBytes;
    (void)flagsFailure;
    X64LoadD(c,0,CtxDecodedOperands+8u); c.Raw({0xA9}); c.U32(~VM_MICRO_BRIDGE_KNOWN_MASK);
    c.Jcc(JccNE,rangeFailure);
    X64LoadQ(c,0,CtxImageBase); X64LoadD(c,2,CtxDecodedOperands); X64Binary(c,0x01,0,2);
    X64StoreQ(c,CtxMutationScratch,0);
    X64LoadQ(c,11,CtxRegisterMap); c.Raw({0x4D,0x85,0xDB}); c.Jcc(JccE,rangeFailure);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x81,0xEC}); c.U32(allocation);
    for(uint8_t family=0;family<16;++family){
        c.Raw({0x41,0x0F,0xB6,0x4B,family});
        X64LoadIndexedQ(c,0,1,CtxVregs);
        X64StoreStackQ(c,stateBase+static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr))+family*8u,0);
    }
    c.Raw({0xB8,0x02,0x02,0x00,0x00});
    X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,rflags),0);
    X64LoadQ(c,0,CtxMutationScratch); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,target),0);
    X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,guardTarget),0);
    X64LoadQ(c,0,CtxExtendedState); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedState),0);
    X64LoadD(c,0,CtxDecodedOperands+8u); c.Raw({0x89,0xC2,0x81,0xE2}); c.U32(VM_MICRO_BRIDGE_AVX);
    c.Raw({0xC1,0xEA,0x08}); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedStateFlags),2);
    c.Raw({0x83,0xE0,VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK}); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,hiddenRegister),0);
    X64LoadStackQ(c,0,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,target));
    c.Raw({0x48,0x8D,0x8C,0x24}); c.U32(stateBase); c.Raw({0xFF,0xD0});
    X64LoadQ(c,11,CtxRegisterMap);
    for(uint8_t family=0;family<16;++family){
        X64LoadStackQ(c,0,stateBase+static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr))+family*8u);
        c.Raw({0x41,0x0F,0xB6,0x4B,family}); X64StoreIndexedQ(c,CtxVregs,1,0);
    }
    c.Raw({0x48,0x81,0xC4}); c.U32(allocation);
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        allocation, kX64BridgePrologSize);
}

void EmitX86BridgeExtended(
    CodeBuffer& c,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure)
{
    constexpr uint32_t allocation=sizeof(VM_INSTRUCTION_BRIDGE_STATE);
    (void)flagsFailure;
    X86LoadD(c,0,CtxDecodedOperands+8u);c.Raw({0xA9});c.U32(~VM_MICRO_BRIDGE_KNOWN_MASK);c.Jcc(JccNE,rangeFailure);
    X86LoadD(c,0,CtxImageBase);X86LoadD(c,2,CtxDecodedOperands);c.Raw({0x01,0xD0});X86StoreD(c,CtxMutationScratch,0);
    X86LoadD(c,2,CtxRegisterMap);c.Raw({0x85,0xD2});c.Jcc(JccE,rangeFailure);
    c.Raw({0x81,0xEC});c.U32(allocation);
    for(uint8_t family=0;family<8;++family){
        c.Raw({0x0F,0xB6,0x4A,family});X86LoadIndexedD(c,0,CtxVregs);
        X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u,0);
        c.Raw({0xC7,0x84,0x24});c.U32(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u+4u);c.U32(0);
    }
    c.Raw({0xB8,0x02,0x02,0x00,0x00});X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,rflags),0);
    X86LoadD(c,0,CtxMutationScratch);X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,target),0);
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,guardTarget),0);
    X86LoadD(c,0,CtxExtendedState);X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedState),0);
    X86LoadD(c,0,CtxDecodedOperands+8u);c.Raw({0x89,0xC2,0x81,0xE2});c.U32(VM_MICRO_BRIDGE_AVX);c.Raw({0xC1,0xEA,0x08});
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedStateFlags),2);c.Raw({0x83,0xE0,VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK});
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,hiddenRegister),0);
    X86LoadStackD(c,0,offsetof(VM_INSTRUCTION_BRIDGE_STATE,target));c.Raw({0x54,0xFF,0xD0,0x83,0xC4,0x04});
    X86LoadD(c,2,CtxRegisterMap);
    for(uint8_t family=0;family<8;++family){
        X86LoadStackD(c,0,offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u);
        c.Raw({0x0F,0xB6,0x4A,family});X86StoreIndexedD(c,CtxVregs,0);
        c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);
    }
    c.Raw({0x81,0xC4});c.U32(allocation);
}

void EmitX64SpecialSemantic(CodeBuffer& c,VM_MICRO_OPCODE semantic,CodeBuffer::Label rangeFailure){
    if(semantic==VM_UOP_INT3){c.U8(0xCC);return;}
    X64LoadQ(c,11,CtxRegisterMap);c.Raw({0x4D,0x85,0xDB});c.Jcc(JccE,rangeFailure);
    if(semantic==VM_UOP_RDTSC){
        c.Raw({0x0F,0x31,0x41,0x89,0xC0,0x41,0x89,0xD1});
        c.Raw({0x41,0x0F,0xB6,0x0B});X64StoreIndexedQ(c,CtxVregs,1,8);
        c.Raw({0x41,0x0F,0xB6,0x4B,0x02});X64StoreIndexedQ(c,CtxVregs,1,9);return;
    }
    const size_t funcletBegin = c.bytes.size();
    c.U8(0x53);c.Raw({0x41,0x0F,0xB6,0x0B});X64LoadIndexedQ(c,0,1,CtxVregs);
    c.Raw({0x41,0x0F,0xB6,0x4B,0x01});X64LoadIndexedQ(c,1,1,CtxVregs);c.Raw({0x0F,0xA2,
        0x41,0x89,0xC0,0x41,0x89,0xD9,0x41,0x89,0xCA,0x41,0x89,0xD3,0x5B});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::PushNonvolatile,
        0, kX64CpuidPrologSize, kX64RbxUnwindRegister);
    X64LoadQ(c,0,CtxRegisterMap);c.Raw({0x0F,0xB6,0x08});X64StoreIndexedQ(c,CtxVregs,1,8);
    c.Raw({0x0F,0xB6,0x48,0x03});X64StoreIndexedQ(c,CtxVregs,1,9);
    c.Raw({0x0F,0xB6,0x48,0x01});X64StoreIndexedQ(c,CtxVregs,1,10);
    c.Raw({0x0F,0xB6,0x48,0x02});X64StoreIndexedQ(c,CtxVregs,1,11);
}

void EmitX86SpecialSemantic(CodeBuffer& c,VM_MICRO_OPCODE semantic,CodeBuffer::Label rangeFailure){
    if(semantic==VM_UOP_INT3){c.U8(0xCC);return;}
    X86LoadD(c,2,CtxRegisterMap);c.Raw({0x85,0xD2});c.Jcc(JccE,rangeFailure);
    if(semantic==VM_UOP_RDTSC){c.Raw({0x0F,0x31,0x52,0x50});X86LoadD(c,2,CtxRegisterMap);
        c.Raw({0x0F,0xB6,0x0A,0x58});X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);
        c.Raw({0x0F,0xB6,0x4A,0x02,0x58});X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);return;}
    c.U8(0x53);c.Raw({0x0F,0xB6,0x0A});X86LoadIndexedD(c,0,CtxVregs);c.Raw({0x0F,0xB6,0x4A,0x01});X86LoadIndexedD(c,1,CtxVregs);
    c.Raw({0x0F,0xA2,0x52,0x51,0x53,0x50});X86LoadD(c,2,CtxRegisterMap);
    const uint8_t families[4]={0,3,1,2};for(uint8_t i=0;i<4;++i){c.U8(0x58);c.Raw({0x0F,0xB6,static_cast<uint8_t>(0x4A),families[i]});
        X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);}c.U8(0x5B);
}



} // namespace

VMHandlerSemanticCodegenResult GenerateVMHandlerSemanticKernel(
    const VMHandlerSemanticCodegenConfig& config)
{
    VMHandlerSemanticCodegenResult result{};
    if (config.architecture != VM_ARCH_X64 && config.architecture != VM_ARCH_X86) {
        result.error = "semantic code generator received an unknown architecture";
        return result;
    }
    if (config.semantic <= VM_UOP_TRAP || config.semantic >= VM_UOP_COUNT) {
        result.error = "TRAP/out-of-range semantic has no successful kernel";
        return result;
    }
    const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(config.semantic);
    if (!descriptor) {
        result.error = "semantic descriptor is missing";
        return result;
    }
    const bool x64 = config.architecture == VM_ARCH_X64;
    if ((x64 && !descriptor->runtimeSupportedX64) ||
        (!x64 && !descriptor->runtimeSupportedX86)) {
        result.error = "semantic is intentionally fail-closed for this architecture";
        return result;
    }
    if (config.semantic == VM_UOP_CALL_HOST) {
        result.error = "CALL_HOST has no production native-call bridge contract";
        return result;
    }
    if (!HasConcreteEmitter(config.semantic)) {
        result.error = "semantic has no concrete fail-closed emitter";
        return result;
    }

    CodeBuffer code;
    SeedStream random(config.buildSeed,
        0x53454D414E544943ULL ^ (static_cast<uint64_t>(config.semantic) << 16u) ^
        (static_cast<uint64_t>(config.variant) << 40u) ^ config.architecture);
    result.registerAssignment = DeriveVariantRegisters(
        x64, config.variant, config.semantic, config.buildSeed);
    result.variantPrefixOffset = static_cast<uint32_t>(code.bytes.size());
    EmitExecutableSeedJunk(code, x64, result.registerAssignment, random,
        x64 ? 96u : 192u);
    EmitLiveIdentityMBA(code, x64, config.variant,
        result.registerAssignment, random);
    const auto impossibleOpaqueBranch = code.NewLabel();
    const auto afterOpaquePredicate = code.NewLabel();
    result.opaquePredicateOffset = static_cast<uint32_t>(code.bytes.size());
    EmitOpaqueEvenProductPredicate(code, x64, result.registerAssignment,
        impossibleOpaqueBranch);
    code.Jmp(afterOpaquePredicate);
    code.Bind(impossibleOpaqueBranch);
    if (x64) EmitX64Failure(code, VM_MICRO_ERR_HANDLER_BUG);
    else EmitX86Failure(code, VM_MICRO_ERR_HANDLER_BUG);
    code.Bind(afterOpaquePredicate);
    result.opaquePredicateSize = static_cast<uint32_t>(code.bytes.size()) -
        result.opaquePredicateOffset;
    result.variantPrefixSize = static_cast<uint32_t>(code.bytes.size()) -
        result.variantPrefixOffset;
    result.semanticBodyOffset = static_cast<uint32_t>(code.bytes.size());
    const auto stackFailure = code.NewLabel();
    const auto widthFailure = code.NewLabel();
    const auto rangeFailure = code.NewLabel();
    const auto flagsFailure = code.NewLabel();
    const auto divideFailure = code.NewLabel();
    const auto success = code.NewLabel();

    const SemanticPathSpec inputPath = SemanticInputPath(
        *descriptor, config.semantic);
    const SemanticPathSpec outputPath = SemanticResultPath(
        *descriptor, config.semantic);
    const SemanticMutationPlan inputPlan = DeriveSemanticMutationPlan(
        config, 0x494E505554504154ULL);
    const SemanticMutationPlan outputPlan = DeriveSemanticMutationPlan(
        config, 0x4F55545055545041ULL);
    result.semanticInputStrategy = inputPlan.strategy;
    result.semanticCoreStrategy = DeriveBusinessCoreStrategy(config);
    result.semanticResultStrategy = outputPlan.strategy;
    EmitSemanticInputPreparation(code, x64, inputPath,
        result.registerAssignment,
        descriptor->stackPops > 0
            ? static_cast<uint8_t>(descriptor->stackPops)
            : 0u,
        stackFailure, rangeFailure);
    result.semanticInputPathOffset = static_cast<uint32_t>(code.bytes.size());
    EmitSemanticIdentityPath(code, x64, inputPath,
        result.registerAssignment, inputPlan, true);
    result.semanticInputPathSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticInputPathOffset;
    result.semanticCoreOffset = static_cast<uint32_t>(code.bytes.size());

    if (x64) {
        switch (descriptor->opcodeClass) {
            case VMOpcodeClass::Data:
            case VMOpcodeClass::Stack:
            case VMOpcodeClass::Memory:
                EmitX64DataSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Arithmetic:
                if (IsBinaryAlu(config.semantic))
                    EmitX64BinaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ADD_CARRY ||
                         config.semantic == VM_UOP_SUB_BORROW)
                    EmitX64CarryAlu(code, config.semantic, stackFailure, widthFailure);
                else if (IsUnaryAlu(config.semantic))
                    EmitX64UnaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ZERO_EXTEND ||
                         config.semantic == VM_UOP_SIGN_EXTEND)
                    EmitX64Extend(code, config.semantic == VM_UOP_SIGN_EXTEND,
                        stackFailure, widthFailure, rangeFailure);
                else if (config.semantic == VM_UOP_UMUL_WIDE ||
                         config.semantic == VM_UOP_SMUL_WIDE)
                    EmitX64WideMultiply(code, config.semantic == VM_UOP_SMUL_WIDE,
                        stackFailure, widthFailure);
                else if (config.semantic == VM_UOP_UDIV_WIDE ||
                         config.semantic == VM_UOP_IDIV_WIDE)
                    EmitX64WideDivide(code, config.semantic == VM_UOP_IDIV_WIDE,
                        stackFailure, widthFailure, divideFailure);
                else {
                    result.error = "arithmetic semantic has no x64 emitter";
                    return result;
                }
                break;
            case VMOpcodeClass::Flags:
                EmitX64FlagsSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::ControlFlow:
            case VMOpcodeClass::Call:
                EmitX64ControlSemantic(code, config.semantic, stackFailure,
                    rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Bridge:
                EmitX64BridgeExtended(code, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Special:
                EmitX64SpecialSemantic(code, config.semantic, rangeFailure);
                break;
            default:
                result.error = "semantic opcode class is not executable";
                return result;
        }
    } else {
        switch (descriptor->opcodeClass) {
            case VMOpcodeClass::Data:
            case VMOpcodeClass::Stack:
            case VMOpcodeClass::Memory:
                EmitX86DataSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Arithmetic:
                if (IsBinaryAlu(config.semantic))
                    EmitX86BinaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ADD_CARRY ||
                         config.semantic == VM_UOP_SUB_BORROW)
                    EmitX86CarryAlu(code, config.semantic, stackFailure, widthFailure);
                else if (IsUnaryAlu(config.semantic))
                    EmitX86UnaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ZERO_EXTEND ||
                         config.semantic == VM_UOP_SIGN_EXTEND)
                    EmitX86Extend(code, config.semantic == VM_UOP_SIGN_EXTEND,
                        stackFailure, widthFailure, rangeFailure);
                else if (config.semantic == VM_UOP_UMUL_WIDE ||
                         config.semantic == VM_UOP_SMUL_WIDE)
                    EmitX86WideMultiply(code, config.semantic == VM_UOP_SMUL_WIDE,
                        stackFailure, widthFailure);
                else if (config.semantic == VM_UOP_UDIV_WIDE ||
                         config.semantic == VM_UOP_IDIV_WIDE)
                    EmitX86WideDivide(code, config.semantic == VM_UOP_IDIV_WIDE,
                        stackFailure, widthFailure, divideFailure);
                else {
                    result.error = "arithmetic semantic has no x86 emitter";
                    return result;
                }
                break;
            case VMOpcodeClass::Flags:
                EmitX86FlagsSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::ControlFlow:
            case VMOpcodeClass::Call:
                EmitX86ControlSemantic(code, config.semantic, stackFailure,
                    rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Bridge:
                EmitX86BridgeExtended(code, rangeFailure, flagsFailure);
                break;
            case VMOpcodeClass::Special:
                EmitX86SpecialSemantic(code, config.semantic, rangeFailure);
                break;
            default:
                result.error = "semantic opcode class is not executable";
                return result;
        }
    }
    result.semanticCoreSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticCoreOffset;
    result.semanticResultPathOffset = static_cast<uint32_t>(code.bytes.size());
    EmitSemanticIdentityPath(code, x64, outputPath,
        result.registerAssignment, outputPlan, false);
    result.semanticResultPathSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticResultPathOffset;
    result.semanticBodySize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticBodyOffset;
    result.variantSuffixOffset = static_cast<uint32_t>(code.bytes.size());
    EmitExecutableSeedJunk(code, x64, result.registerAssignment, random,
        x64 ? 96u : 192u);
    EmitLiveIdentityMBA(code, x64, static_cast<uint8_t>(config.variant + 1u),
        result.registerAssignment, random);
    result.variantSuffixSize = static_cast<uint32_t>(code.bytes.size()) -
        result.variantSuffixOffset;
    code.Jmp(success);

    const std::array<CodeBuffer::Label, 5> failureLabels = {
        stackFailure, widthFailure, rangeFailure, flagsFailure, divideFailure
    };
    const std::array<uint32_t, 4> failureErrors = {
        VM_MICRO_ERR_VALUE_STACK_UNDERFLOW,
        VM_MICRO_ERR_OPCODE_UNSUPPORTED,
        VM_MICRO_ERR_HANDLER_BUG,
        VM_MICRO_ERR_FLAGS_STATE
    };
    const uint32_t failureRotation = config.variant %
        static_cast<uint8_t>(failureLabels.size());
    for (uint32_t order = 0;
         order < static_cast<uint32_t>(failureLabels.size()); ++order) {
        const uint32_t failure = (order + failureRotation) %
            static_cast<uint32_t>(failureLabels.size());
        code.Bind(failureLabels[failure]);
        result.failureBlockOffsets[failure] =
            static_cast<uint32_t>(code.bytes.size());
        if (failure < failureErrors.size()) {
            if (x64) EmitX64Failure(code, failureErrors[failure]);
            else EmitX86Failure(code, failureErrors[failure]);
        } else if (x64) {
            code.Raw({0x31,0xC9,0x31,0xD2,0xB8,0x01,0x00,0x00,0x00,
                      0x48,0xF7,0xF1});
        } else {
            code.Raw({0x31,0xC9,0x31,0xD2,0xB8,0x01,0x00,0x00,0x00,0xF7,0xF1});
        }
    }
    code.Bind(success);

    if (!code.Resolve(result.error)) return result;
    result.operandCount = descriptor->operandCount;
    result.stackPops = descriptor->stackPops;
    result.stackPushes = descriptor->stackPushes;
    result.decodedOperandCount = descriptor->operandCount;
    result.stackFunclets = std::move(code.stackFunclets);
    result.code = std::move(code.bytes);
    result.semanticComplete = !result.code.empty();
    result.success = result.semanticComplete;
    std::string evidenceError;
    if (!ValidateVMHandlerSemanticVariantKernel(config, result, evidenceError)) {
        result.success = false;
        result.semanticComplete = false;
        result.error = "variant machine-code evidence failed: " + evidenceError;
    }
    return result;
}

bool ValidateVMHandlerSemanticVariantKernel(
    const VMHandlerSemanticCodegenConfig& config,
    const VMHandlerSemanticCodegenResult& result,
    std::string& error)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    if ((!x64 && config.architecture != VM_ARCH_X86) || result.code.empty()) {
        error = "variant evidence has invalid architecture or empty code";
        return false;
    }
    const auto rangeValid = [&](uint32_t offset, uint32_t size) {
        return offset <= result.code.size() &&
            size <= result.code.size() - offset;
    };
    const auto rangeInside = [](uint32_t outerOffset, uint32_t outerSize,
                                uint32_t innerOffset, uint32_t innerSize) {
        return innerOffset >= outerOffset &&
            innerOffset - outerOffset <= outerSize &&
            innerSize <= outerSize - (innerOffset - outerOffset);
    };
    if (!rangeValid(result.variantPrefixOffset, result.variantPrefixSize) ||
        !rangeValid(result.semanticBodyOffset, result.semanticBodySize) ||
        !rangeValid(result.semanticInputPathOffset,
            result.semanticInputPathSize) ||
        !rangeValid(result.semanticCoreOffset, result.semanticCoreSize) ||
        !rangeValid(result.semanticResultPathOffset,
            result.semanticResultPathSize) ||
        !rangeValid(result.variantSuffixOffset, result.variantSuffixSize) ||
        !rangeValid(result.opaquePredicateOffset, result.opaquePredicateSize) ||
        result.variantPrefixOffset != 0 ||
        result.variantPrefixOffset + result.variantPrefixSize !=
            result.semanticBodyOffset ||
        result.semanticBodyOffset + result.semanticBodySize !=
            result.variantSuffixOffset ||
        result.variantPrefixSize < 1024u || result.variantSuffixSize < 1024u ||
        result.semanticBodySize == 0 || result.semanticInputPathSize == 0 ||
        result.semanticCoreSize == 0 || result.semanticResultPathSize == 0 ||
        result.opaquePredicateSize < 16u) {
        error = "variant executable ranges are missing, overlapping, or too small";
        return false;
    }
    if (!rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticInputPathOffset, result.semanticInputPathSize) ||
        !rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticCoreOffset, result.semanticCoreSize) ||
        !rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticResultPathOffset, result.semanticResultPathSize) ||
        result.semanticInputPathOffset + result.semanticInputPathSize !=
            result.semanticCoreOffset ||
        result.semanticCoreOffset + result.semanticCoreSize !=
            result.semanticResultPathOffset ||
        result.semanticResultPathOffset + result.semanticResultPathSize !=
            result.semanticBodyOffset + result.semanticBodySize) {
        error = "semantic input/core/result evidence is outside semanticBody";
        return false;
    }
    const std::array<uint8_t, 4> expectedRegisters = DeriveVariantRegisters(
        x64, config.variant, config.semantic, config.buildSeed);
    if (result.registerAssignment != expectedRegisters) {
        error = "published register allocation does not match variant/seed";
        return false;
    }
    if (result.registerAssignment[0] == result.registerAssignment[1] ||
        result.registerAssignment[0] == result.registerAssignment[2] ||
        result.registerAssignment[1] == result.registerAssignment[2]) {
        error = "semantic data path lacks three distinct physical registers";
        return false;
    }
    for (uint8_t reg : result.registerAssignment) {
        const bool valid = x64
            ? (reg == 0 || reg == 1 || reg == 2 ||
               reg == 8 || reg == 9 || reg == 10 || reg == 11)
            : (reg <= 2);
        if (!valid) {
            error = "variant register allocation contains an ABI-unsafe register";
            return false;
        }
    }

    const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(config.semantic);
    if (!descriptor) {
        error = "semantic data-path descriptor is missing";
        return false;
    }
    VMHandlerSemanticStackFunclet expectedFunclet{};
    const bool expectsFunclet = x64 && ExpectedX64StackFunclet(
        config.semantic, expectedFunclet);
    if ((!x64 && !result.stackFunclets.empty()) ||
        result.stackFunclets.size() != (expectsFunclet ? 1u : 0u)) {
        error = "semantic stack-funclet coverage is incomplete or unexpected";
        return false;
    }
    if (expectsFunclet) {
        const VMHandlerSemanticStackFunclet& funclet = result.stackFunclets[0];
        if (!rangeValid(funclet.offset, funclet.size) || funclet.size == 0 ||
            !rangeInside(result.semanticCoreOffset, result.semanticCoreSize,
                funclet.offset, funclet.size) ||
            funclet.kind != expectedFunclet.kind ||
            funclet.stackBytes != expectedFunclet.stackBytes ||
            funclet.prologSize != expectedFunclet.prologSize ||
            funclet.nonvolatileRegister !=
                expectedFunclet.nonvolatileRegister) {
            error = "semantic stack-funclet metadata disagrees with emitted core";
            return false;
        }
        const auto begin = result.code.begin() + funclet.offset;
        const auto end = begin + funclet.size;
        if (funclet.kind ==
                VMHandlerSemanticUnwindKind::StackAllocation &&
            funclet.stackBytes == kX64FlagCallStackBytes) {
            constexpr std::array<uint8_t, 10> expectedCode = {
                0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28
            };
            if (funclet.size != expectedCode.size() ||
                !std::equal(expectedCode.begin(), expectedCode.end(), begin)) {
                error = "flag-materializer funclet bytes are not canonical";
                return false;
            }
        } else if (funclet.kind ==
                       VMHandlerSemanticUnwindKind::StackAllocation &&
                   funclet.stackBytes == kX64BridgeStackBytes) {
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
                error = "extended-bridge funclet bytes are not canonical";
                return false;
            }
        } else if (funclet.kind ==
                       VMHandlerSemanticUnwindKind::PushNonvolatile &&
                   funclet.nonvolatileRegister == kX64RbxUnwindRegister) {
            constexpr std::array<uint8_t, 2> cpuid = {0x0F,0xA2};
            if (funclet.size < 4u || *begin != 0x53 || *(end - 1) != 0x5B ||
                std::search(begin, end, cpuid.begin(), cpuid.end()) == end) {
                error = "CPUID RBX-save funclet bytes are not canonical";
                return false;
            }
        } else {
            error = "semantic stack-funclet kind is unsupported";
            return false;
        }
    }
    const SemanticMutationPlan expectedInputPlan = DeriveSemanticMutationPlan(
        config, 0x494E505554504154ULL);
    const SemanticMutationPlan expectedOutputPlan = DeriveSemanticMutationPlan(
        config, 0x4F55545055545041ULL);
    const uint8_t expectedCoreStrategy = DeriveBusinessCoreStrategy(config);
    if (result.semanticInputStrategy != expectedInputPlan.strategy ||
        result.semanticCoreStrategy != expectedCoreStrategy ||
        result.semanticResultStrategy != expectedOutputPlan.strategy) {
        error = "semantic strategy metadata does not match variant/seed";
        return false;
    }

    const auto rangeEquals = [&](uint32_t offset, uint32_t size,
                                 const std::vector<uint8_t>& expected) {
        return size == expected.size() && rangeValid(offset, size) &&
            std::equal(expected.begin(), expected.end(),
                result.code.begin() + offset);
    };
    CodeBuffer expectedInput;
    EmitSemanticIdentityPath(expectedInput, x64,
        SemanticInputPath(*descriptor, config.semantic), expectedRegisters,
        expectedInputPlan, true);
    if (!rangeEquals(result.semanticInputPathOffset,
            result.semanticInputPathSize, expectedInput.bytes)) {
        error = "semanticBody input path lacks seed-derived live operand evidence";
        return false;
    }
    CodeBuffer expectedOutput;
    EmitSemanticIdentityPath(expectedOutput, x64,
        SemanticResultPath(*descriptor, config.semantic), expectedRegisters,
        expectedOutputPlan, false);
    if (!rangeEquals(result.semanticResultPathOffset,
            result.semanticResultPathSize, expectedOutput.bytes)) {
        error = "semanticBody result path lacks seed-derived live result evidence";
        return false;
    }

    if (HasBusinessCoreVariant(config.semantic)) {
        if (!rangeValid(result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize) ||
            !rangeInside(result.semanticCoreOffset, result.semanticCoreSize,
                result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize)) {
            error = "business core variant evidence is outside semantic core";
            return false;
        }
        CodeBuffer expectedCoreVariant;
        if (!EmitBusinessCoreVariant(expectedCoreVariant, x64,
                config.semantic, expectedCoreStrategy) ||
            !rangeEquals(result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize,
                expectedCoreVariant.bytes)) {
            error = "business core is fixed or disagrees with variant/seed";
            return false;
        }
    } else if (result.semanticCoreVariantOffset != 0 ||
               result.semanticCoreVariantSize != 0) {
        error = "semantic without a business alternative published false core evidence";
        return false;
    }

    const auto contains = [&](uint32_t offset, uint32_t size,
                              const std::vector<uint8_t>& needle) {
        if (needle.empty() || !rangeValid(offset, size)) return false;
        const auto begin = result.code.begin() + offset;
        const auto end = begin + size;
        return std::search(begin, end, needle.begin(), needle.end()) != end;
    };
    const auto append32 = [](std::vector<uint8_t>& bytes, uint32_t value) {
        for (unsigned index = 0; index < 4u; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8u)));
    };
    std::vector<uint8_t> load;
    std::vector<uint8_t> store;
    const uint8_t evidenceRegister = result.registerAssignment[0];
    if (x64) {
        const uint8_t rex = static_cast<uint8_t>(0x49u |
            ((evidenceRegister & 8u) ? 4u : 0u));
        load = {rex, 0x8B, static_cast<uint8_t>(0x87u |
            ((evidenceRegister & 7u) << 3u))};
        store = {rex, 0x89, static_cast<uint8_t>(0x87u |
            ((evidenceRegister & 7u) << 3u))};
    } else {
        load = {0x8B, static_cast<uint8_t>(0x87u |
            ((evidenceRegister & 7u) << 3u))};
        store = {0x89, static_cast<uint8_t>(0x87u |
            ((evidenceRegister & 7u) << 3u))};
    }
    append32(load, CtxMutationScratch);
    append32(store, CtxMutationScratch);
    if (!contains(result.variantPrefixOffset, result.variantPrefixSize, load) ||
        !contains(result.variantPrefixOffset, result.variantPrefixSize, store) ||
        !contains(result.variantSuffixOffset, result.variantSuffixSize, load) ||
        !contains(result.variantSuffixOffset, result.variantSuffixSize, store)) {
        error = "published register allocation is absent from live mutation bytes";
        return false;
    }
    for (uint8_t reg : result.registerAssignment) {
        const std::vector<uint8_t> moveImmediate = x64
            ? std::vector<uint8_t>{static_cast<uint8_t>(0x48u |
                  ((reg & 8u) ? 1u : 0u)),
                  static_cast<uint8_t>(0xB8u + (reg & 7u))}
            : std::vector<uint8_t>{static_cast<uint8_t>(0xB8u + reg)};
        if (!contains(result.variantPrefixOffset, result.variantPrefixSize,
                moveImmediate) ||
            !contains(result.variantSuffixOffset, result.variantSuffixSize,
                moveImmediate)) {
            error = "one published register is not encoded in both live variant regions";
            return false;
        }
    }
    if (!contains(result.opaquePredicateOffset, result.opaquePredicateSize,
            {0x0F, 0xAF}) ||
        !contains(result.opaquePredicateOffset, result.opaquePredicateSize,
            {0x0F, JccNE})) {
        error = "opaque predicate lacks executable IMUL/JNE evidence";
        return false;
    }

    const uint32_t failureRotation = config.variant % 5u;
    uint32_t previousOffset = 0;
    for (uint32_t order = 0; order < 5u; ++order) {
        const uint32_t failure = (order + failureRotation) % 5u;
        const uint32_t offset = result.failureBlockOffsets[failure];
        if (offset >= result.code.size() || (order != 0 && offset <= previousOffset)) {
            error = "variant failure-block physical order does not follow its layout";
            return false;
        }
        previousOffset = offset;
        if (failure < 4u) {
            const std::vector<uint8_t> prefix = x64
                ? std::vector<uint8_t>{0x41, 0xC7, 0x87}
                : std::vector<uint8_t>{0xC7, 0x87};
            if (!contains(offset,
                    static_cast<uint32_t>(result.code.size() - offset), prefix)) {
                error = "failure block offset does not point at emitted machine code";
                return false;
            }
        } else if (!contains(offset,
                static_cast<uint32_t>(result.code.size() - offset),
                {0x31, 0xC9, 0x31, 0xD2})) {
            error = "divide failure block is not the native #DE path";
            return false;
        }
    }
    return true;
}

} // namespace CipherShell
