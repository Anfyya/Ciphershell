#include "packer/analysis/hotspot_analyzer.h"
#include "packer/mutation/mutation_engine.h"
#include "packer/transforms/translator.h"
#include "packer/vm/micro_semantics.h"
#include "packer/vm/vm_schema.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

using CipherShell::DecodedMicroInstruction;
using CipherShell::MicroInstruction;
using CipherShell::MutatedISA;
using CipherShell::MutationConfig;
using CipherShell::MutationEngine;
using CipherShell::TranslationConfig;
using CipherShell::TranslationResult;
using CipherShell::Translator;
using CipherShell::VMMicroDensity;
using CipherShell::VMMicroExecutionOptions;
using CipherShell::VMMicroFault;
using CipherShell::VMMicroMachineState;
using CipherShell::VMMicroMemoryView;
using CipherShell::VMMicroSemanticExecutor;
using CipherShell::VMOpcodeDescriptor;
using CipherShell::VMSchema;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

#if defined(_WIN32)
struct NativeProbeState {
    uint64_t gpr[16]{};
    uint64_t rflags = 0;
    uint64_t observedInitialFlags = 0;
};

using NativeProbeFunction = void (*)(NativeProbeState*);

bool InvokeNativeProbe(
    NativeProbeFunction function,
    NativeProbeState* state,
    uint32_t& exceptionCode)
{
    exceptionCode = 0;
    __try {
        function(state);
        return true;
    } __except((exceptionCode = static_cast<uint32_t>(GetExceptionCode())),
               EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

class NativeProbeCode final {
public:
    explicit NativeProbeCode(const std::vector<uint8_t>& bytes) {
        m_size = bytes.size();
        m_memory = VirtualAlloc(nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Require(m_memory != nullptr, "VirtualAlloc for native probe failed");
        std::memcpy(m_memory, bytes.data(), bytes.size());
        DWORD oldProtection = 0;
        Require(VirtualProtect(m_memory, m_size, PAGE_EXECUTE_READ, &oldProtection) != FALSE,
            "native probe W^X transition failed");
        Require(FlushInstructionCache(GetCurrentProcess(), m_memory, m_size) != FALSE,
            "native probe instruction cache flush failed");
    }

    ~NativeProbeCode() {
        if (m_memory) VirtualFree(m_memory, 0, MEM_RELEASE);
    }

    NativeProbeFunction Function() const {
        return reinterpret_cast<NativeProbeFunction>(m_memory);
    }

    NativeProbeCode(const NativeProbeCode&) = delete;
    NativeProbeCode& operator=(const NativeProbeCode&) = delete;

private:
    void* m_memory = nullptr;
    size_t m_size = 0;
};

void AppendU32(std::vector<uint8_t>& code, uint32_t value) {
    for (unsigned byte = 0; byte < 4; ++byte) {
        code.push_back(static_cast<uint8_t>(value >> (byte * 8u)));
    }
}

#if defined(_M_X64)
void NativeLoadRegister(std::vector<uint8_t>& code, uint8_t family) {
    static constexpr uint8_t modrm[] = {0x83, 0x8B, 0x93, 0x9B};
    const uint32_t offset = static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t));
    if (family <= 3u) {
        code.insert(code.end(), {0x49, 0x8B, modrm[family]});
    } else if (family == 10u) {
        code.insert(code.end(), {0x4D, 0x8B, 0x93});
    } else {
        throw TestFailure("native probe register encoder received unsupported family");
    }
    AppendU32(code, offset);
}

void NativeStoreRegister(std::vector<uint8_t>& code, uint8_t family) {
    static constexpr uint8_t modrm[] = {0x83, 0x8B, 0x93, 0x9B};
    const uint32_t offset = static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t));
    if (family <= 3u) {
        code.insert(code.end(), {0x49, 0x89, modrm[family]});
    } else if (family == 10u) {
        code.insert(code.end(), {0x4D, 0x89, 0x93});
    } else {
        throw TestFailure("native probe register encoder received unsupported family");
    }
    AppendU32(code, offset);
}

std::vector<uint8_t> NativeProbePrefix() {
    std::vector<uint8_t> code{0x49, 0x89, 0xCB}; /* r11 = state */
    code.insert(code.end(), {0x41, 0xFF, 0xB3}); /* push [r11+rflags] */
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, rflags)));
    code.push_back(0x9D); /* popfq */
    code.push_back(0x9C); /* pushfq */
    code.insert(code.end(), {0x41, 0x8F, 0x83});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, observedInitialFlags)));
    return code;
}

void NativeProbeSuffix(std::vector<uint8_t>& code) {
    code.push_back(0x9C); /* pushfq */
    code.insert(code.end(), {0x41, 0x8F, 0x83});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, rflags)));
    code.insert(code.end(), {0xFC, 0xC3}); /* restore ABI DF=0; ret */
}
#elif defined(_M_IX86)
std::vector<uint8_t> NativeProbePrefixX86() {
    std::vector<uint8_t> code{0x8B, 0x4C, 0x24, 0x04}; /* ecx = state */
    code.insert(code.end(), {0xFF, 0xB1});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, rflags)));
    code.push_back(0x9D); /* popfd */
    code.push_back(0x9C); /* pushfd */
    code.insert(code.end(), {0x8F, 0x81});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, observedInitialFlags)));
    return code;
}

void NativeProbeSuffixX86(std::vector<uint8_t>& code) {
    code.push_back(0x9C);
    code.insert(code.end(), {0x8F, 0x81});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, rflags)));
    code.insert(code.end(), {0xFC, 0xC3});
}

void X86LoadEax(std::vector<uint8_t>& code, uint8_t family) {
    code.insert(code.end(), {0x8B, 0x81});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t)));
}

void X86LoadEdx(std::vector<uint8_t>& code, uint8_t family) {
    code.insert(code.end(), {0x8B, 0x91});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t)));
}

void X86StoreEax(std::vector<uint8_t>& code, uint8_t family) {
    code.insert(code.end(), {0x89, 0x81});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t)));
}

void X86StoreEdx(std::vector<uint8_t>& code, uint8_t family) {
    code.insert(code.end(), {0x89, 0x91});
    AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        family * sizeof(uint64_t)));
}
#endif
#endif

std::array<uint8_t, 32> MakeSeed(uint8_t domain) {
    std::array<uint8_t, 32> seed{};
    uint32_t state = 0xA341316Cu ^ (static_cast<uint32_t>(domain) * 0x9E3779B9u);
    for (size_t index = 0; index < seed.size(); ++index) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        seed[index] = static_cast<uint8_t>(state >> ((index & 3u) * 8u));
    }
    return seed;
}

struct OpcodeMaps {
    std::unordered_map<uint8_t, uint8_t> forward;
    std::array<uint8_t, 256> reverse{};
};

OpcodeMaps MakeOpcodeMaps(const std::array<uint8_t, 32>& seed) {
    MutationConfig config{};
    config.seed = seed;
    config.registerCount = 32;
    config.randomizeOpcodeMap = true;
    config.randomizeRegisterMap = true;
    config.mutateHandlers = true;
    config.embedJunkHandlers = true;
    config.requestedJunkHandlerCount = 8;
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        config.validOpcodes.push_back(static_cast<uint8_t>(semantic));
    }
    MutationEngine engine;
    Require(engine.Initialize(config), "MutationEngine 初始化失败");
    const MutatedISA isa = engine.GenerateMutatedISA();
    Require(!isa.opcodeMap.empty(), "MutationEngine 未生成 opcode map");

    OpcodeMaps maps{};
    maps.forward = isa.opcodeMap;
    maps.reverse.fill(VM_HANDLER_INVALID);
    for (const auto& item : maps.forward) {
        maps.reverse[item.second] = item.first;
    }
    return maps;
}

void KeepRuntimeSupportedOpcodes(OpcodeMaps& maps, bool x64) {
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool supported = x64
            ? descriptor.runtimeSupportedX64
            : descriptor.runtimeSupportedX86;
        if (supported) continue;
        const auto found = maps.forward.find(static_cast<uint8_t>(descriptor.opcode));
        if (found == maps.forward.end()) continue;
        maps.reverse[found->second] = VM_HANDLER_INVALID;
        maps.forward.erase(found);
    }
}

uint64_t OperandValue(VM_MICRO_OPERAND_KIND kind, uint8_t operandIndex) {
    switch (kind) {
        case VM_MICRO_OPERAND_U8: return static_cast<uint64_t>(0x31u + operandIndex);
        case VM_MICRO_OPERAND_U16: return static_cast<uint64_t>(0x9234u + operandIndex);
        case VM_MICRO_OPERAND_U32: return 0x89ABCDEFu - operandIndex;
        case VM_MICRO_OPERAND_U64: return 0xFEDCBA9876543210ULL - operandIndex;
        case VM_MICRO_OPERAND_VAR_UINT: return 0xFEDCBA9876543210ULL - operandIndex;
        case VM_MICRO_OPERAND_VAR_SINT:
            return static_cast<uint64_t>(static_cast<int64_t>(-0x123456789LL - operandIndex));
        case VM_MICRO_OPERAND_REGISTER: return static_cast<uint64_t>(2u + operandIndex);
        case VM_MICRO_OPERAND_TEMP: return static_cast<uint64_t>(3u + operandIndex);
        case VM_MICRO_OPERAND_WIDTH: return 8;
        case VM_MICRO_OPERAND_CONDITION: return VM_CONDITION_G;
        case VM_MICRO_OPERAND_FLAG_MASK: return VM_FLAG_STATUS_MASK;
        case VM_MICRO_OPERAND_LAZY_KIND: return VM_LAZY_ADD;
        case VM_MICRO_OPERAND_CALL_KIND: return VM_MICRO_CALL_NATIVE_RVA;
        case VM_MICRO_OPERAND_NONE: return 0;
    }
    return 0;
}

MicroInstruction MakeInstruction(
    const VMOpcodeDescriptor& descriptor,
    uint8_t variant = 0)
{
    MicroInstruction instruction{};
    instruction.opcode = descriptor.opcode;
    instruction.handlerVariant = variant;
    instruction.operandCount = descriptor.operandCount;
    for (uint8_t index = 0; index < descriptor.operandCount; ++index) {
        instruction.operands[index] = OperandValue(descriptor.operands[index], index);
    }

    switch (instruction.opcode) {
        case VM_UOP_PUSH_VREG:
            instruction.operands[2] = 0;
            break;
        case VM_UOP_POP_VREG:
            instruction.operands[2] = 0;
            instruction.operands[3] = 1;
            break;
        case VM_UOP_ZERO_EXTEND:
        case VM_UOP_SIGN_EXTEND:
            instruction.operands[0] = 1;
            instruction.operands[1] = 8;
            break;
        case VM_UOP_FLAGS_LAZY:
            instruction.operands[0] = VM_LAZY_ADD;
            instruction.operands[1] = 8;
            instruction.operands[2] = VM_FLAG_STATUS_MASK;
            instruction.operands[3] = VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF;
            break;
        case VM_UOP_FLAGS_UPDATE:
            instruction.operands[0] = VM_FLAG_UPDATE_TOGGLE;
            instruction.operands[1] = VM_FLAG_CF;
            break;
        case VM_UOP_CALL_HOST:
            instruction.operands[0] = VM_MICRO_CALL_NATIVE_RVA;
            instruction.operands[1] = VM_ABI_WIN64;
            instruction.operands[2] = 32;
            break;
        default:
            break;
    }
    return instruction;
}

MicroInstruction Uop(
    VM_MICRO_OPCODE opcode,
    std::initializer_list<uint64_t> operands = {},
    uint8_t variant = 0)
{
    const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(opcode);
    Require(descriptor != nullptr, "测试引用不存在的微操作");
    Require(operands.size() == descriptor->operandCount, "测试微操作参数数量错误");
    MicroInstruction instruction{};
    instruction.opcode = opcode;
    instruction.handlerVariant = variant;
    instruction.operandCount = descriptor->operandCount;
    size_t index = 0;
    for (uint64_t value : operands) instruction.operands[index++] = value;
    return instruction;
}

bool SameInstruction(const MicroInstruction& left, const MicroInstruction& right) {
    if (left.opcode != right.opcode ||
        left.handlerVariant != right.handlerVariant ||
        left.operandCount != right.operandCount) return false;
    for (uint8_t index = 0; index < left.operandCount; ++index) {
        if (left.operands[index] != right.operands[index]) return false;
    }
    return true;
}

std::vector<uint8_t> EncodeOne(
    const MicroInstruction& instruction,
    const OpcodeMaps& maps,
    const VM_OPERAND_CODEC& codec)
{
    std::vector<uint8_t> encoded;
    std::string error;
    Require(VMSchema::Encode(instruction, maps.forward, codec, encoded, error),
        "编码微操作失败: " + error);
    uint32_t expectedSize = 0;
    Require(VMSchema::EncodedSize(instruction, codec, expectedSize, error),
        "计算微操作长度失败: " + error);
    Require(encoded.size() == expectedSize, "EncodedSize 与实际紧凑编码长度不一致");
    return encoded;
}

std::vector<uint8_t> EncodeProgram(
    const std::vector<MicroInstruction>& instructions,
    const OpcodeMaps& maps,
    const VM_OPERAND_CODEC& codec)
{
    std::vector<uint8_t> bytecode;
    for (const auto& instruction : instructions) {
        std::string error;
        const bool encoded = VMSchema::Encode(
            instruction, maps.forward, codec, bytecode, error);
        if (!encoded) {
            const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(instruction.opcode);
            throw TestFailure(std::string("编码微操作程序失败: ") +
                (descriptor ? descriptor->name : "unknown") + ": " + error);
        }
    }
    return bytecode;
}

std::vector<uint32_t> EncodedOffsets(
    const std::vector<MicroInstruction>& instructions,
    const OpcodeMaps& maps,
    const VM_OPERAND_CODEC& codec)
{
    std::vector<uint32_t> offsets;
    uint64_t offset = 0;
    for (const auto& instruction : instructions) {
        Require(offset <= std::numeric_limits<uint32_t>::max(),
            "测试程序编码偏移溢出");
        offsets.push_back(static_cast<uint32_t>(offset));
        offset += EncodeOne(instruction, maps, codec).size();
    }
    Require(offset <= std::numeric_limits<uint32_t>::max(),
        "测试程序总长度溢出");
    return offsets;
}

uint64_t WidthMask(uint8_t width) {
    return width == 8u ? std::numeric_limits<uint64_t>::max() :
        ((1ULL << (width * 8u)) - 1ULL);
}

uint64_t SignBit(uint8_t width) {
    return 1ULL << (width * 8u - 1u);
}

bool EvenParity(uint8_t value) {
    value ^= static_cast<uint8_t>(value >> 4u);
    value &= 0x0Fu;
    return ((0x6996u >> value) & 1u) == 0u;
}

void SetFlag(uint64_t& flags, uint64_t flag, bool enabled) {
    if (enabled) flags |= flag;
    else flags &= ~flag;
}

uint64_t NativeAddSubFlags(
    bool subtract,
    uint64_t a,
    uint64_t b,
    uint8_t width,
    uint64_t initialFlags,
    uint64_t& result)
{
    const uint64_t mask = WidthMask(width);
    const uint64_t sign = SignBit(width);
    a &= mask;
    b &= mask;
    result = subtract ? ((a - b) & mask) : ((a + b) & mask);
    uint64_t flags = initialFlags;
    SetFlag(flags, VM_FLAG_CF, subtract ? a < b : result < a);
    SetFlag(flags, VM_FLAG_OF, subtract ?
        (((a ^ b) & (a ^ result) & sign) != 0) :
        ((~(a ^ b) & (a ^ result) & sign) != 0));
    SetFlag(flags, VM_FLAG_AF, ((a ^ b ^ result) & 0x10u) != 0);
    SetFlag(flags, VM_FLAG_ZF, result == 0);
    SetFlag(flags, VM_FLAG_SF, (result & sign) != 0);
    SetFlag(flags, VM_FLAG_PF, EvenParity(static_cast<uint8_t>(result)));
    return flags;
}

bool NativeCondition(uint64_t flags, VM_CONDITION condition) {
    const bool cf = (flags & VM_FLAG_CF) != 0;
    const bool pf = (flags & VM_FLAG_PF) != 0;
    const bool zf = (flags & VM_FLAG_ZF) != 0;
    const bool sf = (flags & VM_FLAG_SF) != 0;
    const bool of = (flags & VM_FLAG_OF) != 0;
    switch (condition) {
        case VM_CONDITION_ALWAYS: return true;
        case VM_CONDITION_O: return of;
        case VM_CONDITION_NO: return !of;
        case VM_CONDITION_B: return cf;
        case VM_CONDITION_AE: return !cf;
        case VM_CONDITION_E: return zf;
        case VM_CONDITION_NE: return !zf;
        case VM_CONDITION_BE: return cf || zf;
        case VM_CONDITION_A: return !cf && !zf;
        case VM_CONDITION_S: return sf;
        case VM_CONDITION_NS: return !sf;
        case VM_CONDITION_P: return pf;
        case VM_CONDITION_NP: return !pf;
        case VM_CONDITION_L: return sf != of;
        case VM_CONDITION_GE: return sf == of;
        case VM_CONDITION_LE: return zf || (sf != of);
        case VM_CONDITION_G: return !zf && sf == of;
    }
    return false;
}

uint64_t NextFuzz(uint64_t& state) {
    state ^= state << 13u;
    state ^= state >> 7u;
    state ^= state << 17u;
    return state;
}

struct EncodedEnvironment {
    OpcodeMaps maps;
    VM_OPERAND_CODEC codec{};
    VMMicroExecutionOptions options{};
};

EncodedEnvironment MakeEnvironment(uint8_t domain, uint32_t functionRva) {
    EncodedEnvironment environment{};
    environment.maps = MakeOpcodeMaps(MakeSeed(domain));
    environment.codec = VMSchema::DeriveOperandCodec(
        0xD1B54A32D192ED03ULL ^ domain, functionRva);
    environment.options.registerCount = 32;
    environment.options.maxSteps = 100000;
    environment.options.addressWidth = 8;
    return environment;
}

bool ExecuteEncoded(
    const std::vector<MicroInstruction>& program,
    const EncodedEnvironment& environment,
    VMMicroMachineState& state,
    std::vector<uint8_t>& memory,
    uint64_t memoryBase,
    std::string& error)
{
    const std::vector<uint8_t> bytecode = EncodeProgram(
        program, environment.maps, environment.codec);
    VMMicroMemoryView view{};
    view.data = memory.empty() ? nullptr : memory.data();
    view.size = memory.size();
    view.baseAddress = memoryBase;
    return VMMicroSemanticExecutor::Execute(
        bytecode.data(), bytecode.size(), environment.maps.reverse.data(),
        environment.codec, state, view, environment.options, error);
}

std::vector<MicroInstruction> BinaryMemoryProgram(
    VM_MICRO_OPCODE opcode,
    VM_LAZY_FLAG_KIND lazyKind,
    uint8_t width,
    uint64_t address)
{
    const uint64_t zeroExtend = width == 4u ? 1u : 0u;
    return {
        Uop(VM_UOP_PUSH_VREG, {0, width, 0}, 0),
        Uop(VM_UOP_PUSH_VREG, {1, width, 0}, 1),
        Uop(opcode, {width}, 2),
        Uop(VM_UOP_FLAGS_LAZY,
            {static_cast<uint64_t>(lazyKind), width, VM_FLAG_STATUS_MASK,
             VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 3),
        Uop(VM_UOP_DUP, {}, 0),
        Uop(VM_UOP_POP_VREG, {2, width, 0, zeroExtend}, 1),
        Uop(VM_UOP_PUSH_IMM, {address, 8}, 2),
        Uop(VM_UOP_SWAP, {}, 3),
        Uop(VM_UOP_STORE, {width}, 0),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_STATUS_MASK}, 1),
        Uop(VM_UOP_EXIT, {0}, 2),
    };
}

void WriteLittleEndian(
    std::vector<uint8_t>& memory,
    size_t offset,
    uint8_t width,
    uint64_t value)
{
    for (uint8_t index = 0; index < width; ++index) {
        memory[offset + index] = static_cast<uint8_t>(value >> (index * 8u));
    }
}

void TestCodecAllSemanticsRoundTrip() {
    const auto seed = MakeSeed(0x41);
    const OpcodeMaps maps = MakeOpcodeMaps(seed);
    const VM_OPERAND_CODEC codec = VMSchema::DeriveOperandCodec(
        0x1020304050607080ULL, 0x123450u);
    size_t tested = 0;
    for (const VMOpcodeDescriptor& descriptor : VMSchema::Opcodes()) {
        if (descriptor.opcode == VM_UOP_TRAP) continue;
        for (const uint8_t variant : {static_cast<uint8_t>(0), static_cast<uint8_t>(3)}) {
            const MicroInstruction source = MakeInstruction(descriptor, variant);
            std::string validationError;
            Require(VMSchema::ValidateInstruction(source, 32, validationError),
                std::string("合法微操作被拒绝: ") + descriptor.name + ": " + validationError);
            const std::vector<uint8_t> encoded = EncodeOne(source, maps, codec);

            MicroInstruction decoded{};
            uint32_t consumed = 0;
            std::string decodeError;
            Require(VMSchema::DecodeOne(encoded.data(), encoded.size(), maps.reverse.data(),
                    codec, decoded, consumed, decodeError),
                std::string("微操作往返解码失败: ") + descriptor.name + ": " + decodeError);
            Require(consumed == encoded.size(), "DecodeOne 未精确消费一条变长指令");
            Require(SameInstruction(source, decoded), "微操作编码往返改变语义/操作数/variant");
            ++tested;
        }
    }
    Require(tested == (static_cast<size_t>(VM_UOP_COUNT) - 1u) * 2u,
        "未覆盖全部生产微操作语义");
}

void TestVariableLengthAndBoundaries() {
    const OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x52));
    const VM_OPERAND_CODEC codec = VMSchema::DeriveOperandCodec(0x55AA771122334466ULL, 0x4000);
    const MicroInstruction small = Uop(VM_UOP_PUSH_IMM, {0x7Fu, 8}, 0);
    const MicroInstruction medium = Uop(VM_UOP_PUSH_IMM, {0x80u, 8}, 1);
    const MicroInstruction large = Uop(
        VM_UOP_PUSH_IMM, {std::numeric_limits<uint64_t>::max(), 8}, 2);
    const auto encodedSmall = EncodeOne(small, maps, codec);
    const auto encodedMedium = EncodeOne(medium, maps, codec);
    const auto encodedLarge = EncodeOne(large, maps, codec);
    Require(encodedSmall.size() < encodedMedium.size() &&
        encodedMedium.size() < encodedLarge.size(),
        "VAR_UINT 未形成真实变长紧凑编码");
    Require(encodedSmall.size() != 48 && encodedMedium.size() != 48 &&
        encodedLarge.size() != 48, "仍出现旧 48-byte stride");

    for (const auto* encoded : {&encodedSmall, &encodedMedium, &encodedLarge}) {
        for (size_t truncated = 0; truncated < encoded->size(); ++truncated) {
            MicroInstruction decoded{};
            uint32_t consumed = 999;
            std::string error;
            Require(!VMSchema::DecodeOne(encoded->data(), truncated, maps.reverse.data(),
                    codec, decoded, consumed, error),
                "截断的变长微操作被错误接受");
            Require(consumed == 0, "失败解码泄漏了伪消费边界");
        }
    }

    std::vector<uint8_t> joined = encodedSmall;
    joined.insert(joined.end(), encodedLarge.begin(), encodedLarge.end());
    MicroInstruction first{};
    uint32_t firstSize = 0;
    std::string error;
    Require(VMSchema::DecodeOne(joined.data(), joined.size(), maps.reverse.data(), codec,
            first, firstSize, error), "拼接流第一条解码失败: " + error);
    Require(firstSize == encodedSmall.size() && SameInstruction(first, small),
        "DecodeOne 跨越了第一条变长边界");
    MicroInstruction second{};
    uint32_t secondSize = 0;
    Require(VMSchema::DecodeOne(joined.data() + firstSize, joined.size() - firstSize,
            maps.reverse.data(), codec, second, secondSize, error),
        "拼接流第二条解码失败: " + error);
    Require(secondSize == encodedLarge.size() && SameInstruction(second, large),
        "第二条变长边界消费错误");
}

void TestRejectsNonCanonicalVarint() {
    const OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x5A));
    const VM_OPERAND_CODEC codec = VMSchema::DeriveOperandCodec(
        0x8877665544332211ULL, 0x4100);
    VM_RUNTIME_DECODE_PLAN plans[VM_UOP_COUNT]{};
    std::string planError;
    Require(VMSchema::BuildRuntimeDecodePlans(codec, plans, planError),
        "runtime decode plan generation failed: " + planError);
    std::vector<uint8_t> overlong = EncodeOne(
        Uop(VM_UOP_PUSH_IMM, {0, 8}, 0), maps, codec);
    const VM_RUNTIME_DECODE_PLAN& plan = plans[VM_UOP_PUSH_IMM];
    size_t valueOffset = 2;
    for (uint8_t position = 0; position < plan.operandCount; ++position) {
        if (plan.fieldOrder[position] == 0u) break;
        ++valueOffset;
    }
    auto rotl7 = [](uint8_t value, unsigned count) {
        value &= 0x7Fu;
        count %= 7u;
        return count == 0u ? value : static_cast<uint8_t>(
            ((value << count) | (value >> (7u - count))) & 0x7Fu);
    };
    const auto& valuePlan = plan.operands[0];
    overlong[valueOffset] = static_cast<uint8_t>(
        rotl7(valuePlan.varintXor[0], valuePlan.varintRotate[0]) | 0x80u);
    overlong.insert(overlong.begin() + static_cast<std::ptrdiff_t>(valueOffset + 1u),
        rotl7(valuePlan.varintXor[1], valuePlan.varintRotate[1]));

    MicroInstruction decoded{};
    uint32_t consumed = 0;
    std::string error;
    Require(!VMSchema::DecodeOne(overlong.data(), overlong.size(), maps.reverse.data(),
            codec, decoded, consumed, error),
        "non-canonical overlong varint was accepted");
    Require(consumed == 0,
        "overlong varint rejection leaked a consumed boundary");
}

void TestPerBuildOperandAndOpcodeVariation() {
    const auto seedA = MakeSeed(0x61);
    const auto seedB = MakeSeed(0xE1);
    OpcodeMaps mapsA = MakeOpcodeMaps(seedA);
    OpcodeMaps mapsB = MakeOpcodeMaps(seedB);
    KeepRuntimeSupportedOpcodes(mapsA, true);
    KeepRuntimeSupportedOpcodes(mapsB, true);
    bool opcodeDifference = false;
    for (uint32_t semantic = 1; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        const uint8_t key = static_cast<uint8_t>(semantic);
        if (mapsA.forward.at(key) != mapsB.forward.at(key)) {
            opcodeDifference = true;
            break;
        }
    }
    Require(opcodeDifference, "两个 build seed 生成了相同 opcode map");

    const VM_OPERAND_CODEC codecA = VMSchema::DeriveOperandCodec(
        0x0123456789ABCDEFULL, 0x2210);
    const VM_OPERAND_CODEC codecB = VMSchema::DeriveOperandCodec(
        0xFEDCBA9876543210ULL, 0x2210);
    Require(std::memcmp(&codecA, &codecB, sizeof(codecA)) != 0,
        "两个 build seed 生成了相同 operand codec");

    const MicroInstruction instruction = Uop(
        VM_UOP_PUSH_IMM, {0x8877665544332211ULL, 8}, 2);
    const auto encodedA = EncodeOne(instruction, mapsA, codecA);
    const auto encodedB = EncodeOne(instruction, mapsA, codecB);
    Require(encodedA.size() == encodedB.size(), "seed 变异意外改变固定值的 varint 长度");
    Require(encodedA[0] == encodedB[0], "同一 opcode map 的 opcode byte 意外变化");
    Require(!std::equal(encodedA.begin() + 1, encodedA.end(), encodedB.begin() + 1),
        "操作数与 variant 编码未随 build seed 变化");

    MicroInstruction wrongDecoded{};
    uint32_t consumed = 0;
    std::string error;
    const bool wrongAccepted = VMSchema::DecodeOne(encodedA.data(), encodedA.size(),
        mapsA.reverse.data(), codecB, wrongDecoded, consumed, error);
    Require(!wrongAccepted || !SameInstruction(wrongDecoded, instruction),
        "错误 build codec 可无损解码另一 build 的字节码");
}

void TestPerInstructionVariantSelector() {
    const OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x73));
    const VM_OPERAND_CODEC codec = VMSchema::DeriveOperandCodec(0xCAFEBABE12345678ULL, 0x7000);
    std::vector<std::vector<uint8_t>> encodings;
    for (uint8_t variant = 0; variant < VM_HANDLER_VARIANT_COUNT; ++variant) {
        const MicroInstruction instruction = Uop(VM_UOP_ADD, {8}, variant);
        encodings.push_back(EncodeOne(instruction, maps, codec));
        MicroInstruction decoded{};
        uint32_t consumed = 0;
        std::string error;
        Require(VMSchema::DecodeOne(encodings.back().data(), encodings.back().size(),
                maps.reverse.data(), codec, decoded, consumed, error),
            "variant selector 解码失败: " + error);
        Require(decoded.handlerVariant == variant, "variant selector 往返丢失");
    }
    for (size_t left = 0; left < encodings.size(); ++left) {
        for (size_t right = left + 1; right < encodings.size(); ++right) {
            Require(encodings[left] != encodings[right],
                "同一微语义的不同 handler variant 引用字节完全相同");
        }
    }
}

void TestStreamVerifierFailClosed() {
    const OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x84));
    const VM_OPERAND_CODEC codec = VMSchema::DeriveOperandCodec(0x3141592653589793ULL, 0x8200);
    const std::vector<MicroInstruction> valid = {
        Uop(VM_UOP_PUSH_IMM, {42, 8}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_EXIT, {0})
    };
    const auto validBytes = EncodeProgram(valid, maps, codec);
    const auto validation = VMSchema::ValidateStream(validBytes.data(), validBytes.size(),
        maps.reverse.data(), codec, 32);
    Require(validation.success, "合法变长流未通过 verifier: " + validation.error);
    Require(validation.microOpCount == valid.size(), "verifier micro-op 计数错误");
    Require(validation.maxOperandStackDepth == 1, "verifier 栈深度错误");
    Require(validation.decoded[1].byteOffset != validation.decoded[0].byteOffset + 48,
        "verifier 仍按 48-byte stride 前进");

    const auto underflowBytes = EncodeProgram({Uop(VM_UOP_DROP), Uop(VM_UOP_EXIT, {0})},
        maps, codec);
    Require(!VMSchema::ValidateStream(underflowBytes.data(), underflowBytes.size(),
            maps.reverse.data(), codec, 32).success,
        "operand stack underflow 未 fail-closed");

    const auto fallthroughBytes = EncodeProgram({Uop(VM_UOP_PUSH_IMM, {1, 8})}, maps, codec);
    Require(!VMSchema::ValidateStream(fallthroughBytes.data(), fallthroughBytes.size(),
            maps.reverse.data(), codec, 32).success,
        "流尾 fallthrough 未 fail-closed");

    MicroInstruction trap = Uop(VM_UOP_TRAP);
    std::vector<uint8_t> trapBytes;
    std::string error;
    Require(!VMSchema::Encode(trap, maps.forward, codec, trapBytes, error),
        "显式 TRAP 被编码成可执行生产语义");

    MicroInstruction badRegister = Uop(VM_UOP_PUSH_VREG, {VM_REGISTER_INVALID, 8, 0});
    Require(!VMSchema::Encode(badRegister, maps.forward, codec, trapBytes, error),
        "越界 vreg 未 fail-closed");
    MicroInstruction badWidth = Uop(VM_UOP_ADD, {3});
    Require(!VMSchema::Encode(badWidth, maps.forward, codec, trapBytes, error),
        "非法 operand width 未 fail-closed");

    const auto openTerminalBytes = EncodeProgram({
        Uop(VM_UOP_PUSH_IMM, {1, 8}), Uop(VM_UOP_EXIT, {0})}, maps, codec);
    Require(!VMSchema::ValidateStream(openTerminalBytes.data(), openTerminalBytes.size(),
            maps.reverse.data(), codec, 32).success,
        "terminal micro instruction accepted an open operand stack");
    MicroInstruction badFlagUpdate = Uop(VM_UOP_FLAGS_UPDATE,
        {static_cast<uint64_t>(VM_FLAG_UPDATE_TOGGLE) + 1u, VM_FLAG_CF});
    Require(!VMSchema::Encode(badFlagUpdate, maps.forward, codec, trapBytes, error),
        "invalid FLAGS_UPDATE operation was encoded");
    MicroInstruction badZeroExtend = Uop(VM_UOP_POP_VREG, {0, 1, 8, 1});
    Require(!VMSchema::Encode(badZeroExtend, maps.forward, codec, trapBytes, error),
        "partial high-byte POP_VREG accepted whole-register zero extension");

    std::array<uint8_t, 1> unknown{{0}};
    bool foundUnknown = false;
    for (uint32_t encodedOpcode = 0; encodedOpcode < 256; ++encodedOpcode) {
        const uint8_t semantic = maps.reverse[encodedOpcode];
        if (semantic == VM_HANDLER_INVALID || semantic == VM_UOP_TRAP ||
            semantic >= static_cast<uint8_t>(VM_UOP_COUNT)) {
            unknown[0] = static_cast<uint8_t>(encodedOpcode);
            foundUnknown = true;
            break;
        }
    }
    Require(foundUnknown, "测试 opcode map 中没有可用于拒绝测试的空洞");
    MicroInstruction decoded{};
    uint32_t consumed = 0;
    Require(!VMSchema::DecodeOne(unknown.data(), unknown.size(), maps.reverse.data(),
            codec, decoded, consumed, error),
        "未映射 opcode 未 fail-closed");
}

void TestDifferentialArchitectureState() {
    const EncodedEnvironment environment = MakeEnvironment(0x95, 0x9500);
    constexpr uint64_t memoryBase = 0x0000000140000000ULL;
    constexpr size_t writeOffset = 37;
    uint64_t random = 0x4D595DF4D0F33173ULL;
    size_t corpusCount = 0;

    for (const auto operation : {
            std::pair<VM_MICRO_OPCODE, VM_LAZY_FLAG_KIND>{VM_UOP_ADD, VM_LAZY_ADD},
            std::pair<VM_MICRO_OPCODE, VM_LAZY_FLAG_KIND>{VM_UOP_SUB, VM_LAZY_SUB}}) {
        for (const uint8_t width : {static_cast<uint8_t>(1), static_cast<uint8_t>(2),
                static_cast<uint8_t>(4), static_cast<uint8_t>(8)}) {
            const uint64_t address = memoryBase + writeOffset;
            const auto program = BinaryMemoryProgram(
                operation.first, operation.second, width, address);
            const std::vector<uint8_t> bytecode = EncodeProgram(
                program, environment.maps, environment.codec);
            const auto verified = VMSchema::ValidateStream(
                bytecode.data(), bytecode.size(), environment.maps.reverse.data(),
                environment.codec, environment.options.registerCount);
            Require(verified.success, "差分语料程序未通过生产 verifier: " + verified.error);
            Require(verified.microOpCount >= VM_MICRO_HEAVY_MIN_RATIO,
                "单条 x86 算术语义未炸成至少 8 条微操作");

            for (uint32_t sample = 0; sample < 512; ++sample) {
                VMMicroMachineState actual{};
                for (uint64_t& gpr : actual.gpr) gpr = NextFuzz(random);
                actual.rflags = NextFuzz(random) | 0x02u;
                const auto initialGpr = actual.gpr;
                const uint64_t initialFlags = actual.rflags;

                std::vector<uint8_t> actualMemory(96);
                for (uint8_t& byte : actualMemory) {
                    byte = static_cast<uint8_t>(NextFuzz(random));
                }
                std::vector<uint8_t> expectedMemory = actualMemory;
                auto expectedGpr = initialGpr;
                uint64_t expectedResult = 0;
                const bool subtract = operation.first == VM_UOP_SUB;
                const uint64_t expectedFlags = NativeAddSubFlags(
                    subtract, initialGpr[0], initialGpr[1], width,
                    initialFlags, expectedResult);
                if (width == 4u) {
                    expectedGpr[2] = expectedResult;
                } else {
                    const uint64_t mask = WidthMask(width);
                    expectedGpr[2] = (expectedGpr[2] & ~mask) | expectedResult;
                }
                WriteLittleEndian(expectedMemory, writeOffset, width, expectedResult);

                VMMicroMemoryView view{};
                view.data = actualMemory.data();
                view.size = actualMemory.size();
                view.baseAddress = memoryBase;
                std::string error;
                Require(VMMicroSemanticExecutor::Execute(
                        bytecode.data(), bytecode.size(), environment.maps.reverse.data(),
                        environment.codec, actual, view, environment.options, error),
                    "生产 executor 在合法差分语料上失败: " + error);
                Require(actual.fault == VMMicroFault::None && actual.finished,
                    "生产 executor 未以无 fault EXIT 结束");
                Require(actual.operandStackDepth == 0,
                    "生产 executor 泄漏虚拟操作数栈");
                Require(actual.gpr == expectedGpr,
                    "差分失败: 完整 GPR 状态与 native 模型不一致");
                Require(actual.rflags == expectedFlags,
                    "差分失败: 完整 flags 状态与 native 模型不一致");
                Require(actualMemory == expectedMemory,
                    "差分失败: 内存副作用与 native 模型不一致");
                ++corpusCount;
            }
        }
    }
    Require(corpusCount == 4096, "差分模糊语料数量不足");
}

void TestLazyFlagsAndConsumers() {
    const EncodedEnvironment environment = MakeEnvironment(0xA6, 0xA600);
    VMMicroMachineState state{};
    state.rflags = 0x202u | VM_FLAG_CF | VM_FLAG_OF | VM_FLAG_SF;
    const uint64_t initialFlags = state.rflags;
    std::string error;
    VMMicroMemoryView noMemory{};

    const std::vector<MicroInstruction> prefix = {
        Uop(VM_UOP_PUSH_IMM, {0xFFu, 1}),
        Uop(VM_UOP_PUSH_IMM, {1, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
    };
    uint32_t fallthrough = 1;
    for (const auto& instruction : prefix) {
        Require(VMMicroSemanticExecutor::ExecuteOne(
                instruction, fallthrough++, state, noMemory, environment.options, error),
            "逐步执行 lazy flags 前缀失败: " + error);
    }
    Require(state.rflags == initialFlags,
        "FLAGS_LAZY 在无消费者时提前改写 architectural flags");
    Require(state.pendingFlags.valid != 0 &&
        state.pendingFlags.operation == VM_LAZY_ADD &&
        state.pendingFlags.a == 0xFFu && state.pendingFlags.b == 1u &&
        state.pendingFlags.result == 0,
        "lazy pending record 未登记完整 (op,a,b,result,width)");

    uint64_t expectedResult = 0;
    const uint64_t expectedFlags = NativeAddSubFlags(
        false, 0xFFu, 1u, 1, initialFlags, expectedResult);
    VMMicroSemanticExecutor::MaterializeFlags(state, VM_FLAG_ZF);
    Require((state.rflags & VM_FLAG_ZF) == (expectedFlags & VM_FLAG_ZF),
        "按需 materialize ZF 错误");
    Require((state.rflags & ~static_cast<uint64_t>(VM_FLAG_ZF)) ==
        (initialFlags & ~static_cast<uint64_t>(VM_FLAG_ZF)),
        "只请求 ZF 时改写了其他 flags");
    VMMicroSemanticExecutor::MaterializeFlags(state, VM_FLAG_STATUS_MASK);
    Require(state.rflags == expectedFlags, "lazy flags 全量现算与 native 不一致");

    const std::array<std::pair<uint64_t, uint64_t>, 4> operandPairs{{
        {5, 5}, {1, 2}, {0x8000000000000000ULL, 1},
        {0x7FFFFFFFFFFFFFFFULL, std::numeric_limits<uint64_t>::max()}
    }};
    for (const auto& operands : operandPairs) {
        for (uint32_t rawCondition = VM_CONDITION_ALWAYS;
                rawCondition <= VM_CONDITION_G; ++rawCondition) {
            const auto condition = static_cast<VM_CONDITION>(rawCondition);
            std::vector<MicroInstruction> program = {
                Uop(VM_UOP_PUSH_IMM, {operands.first, 8}),
                Uop(VM_UOP_PUSH_IMM, {operands.second, 8}),
                Uop(VM_UOP_SUB, {8}),
                Uop(VM_UOP_FLAGS_LAZY,
                    {VM_LAZY_SUB, 8, VM_FLAG_STATUS_MASK,
                     VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
                Uop(VM_UOP_DROP),
                Uop(VM_UOP_PUSH_CONDITION, {static_cast<uint64_t>(condition)}),
                Uop(VM_UOP_POP_VREG, {3, 8, 0, 1}),
                Uop(VM_UOP_EXIT, {0}),
            };
            VMMicroMachineState conditionState{};
            conditionState.rflags = 0x202u;
            std::vector<uint8_t> memory;
            Require(ExecuteEncoded(program, environment, conditionState, memory, 0, error),
                "JCC 条件消费者执行失败: " + error);
            uint64_t result = 0;
            const uint64_t nativeFlags = NativeAddSubFlags(
                true, operands.first, operands.second, 8, 0x202u, result);
            Require(conditionState.gpr[3] ==
                (NativeCondition(nativeFlags, condition) ? 1u : 0u),
                "JCC 条件消费者与 native flags 判定不一致");
        }
    }

    for (const bool equal : {false, true}) {
        std::vector<MicroInstruction> selectProgram = {
            Uop(VM_UOP_PUSH_IMM, {7, 8}),
            Uop(VM_UOP_PUSH_IMM, {equal ? 7u : 8u, 8}),
            Uop(VM_UOP_SUB, {8}),
            Uop(VM_UOP_FLAGS_LAZY,
                {VM_LAZY_SUB, 8, VM_FLAG_STATUS_MASK,
                 VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
            Uop(VM_UOP_DROP),
            Uop(VM_UOP_PUSH_IMM, {0x11, 1}),
            Uop(VM_UOP_PUSH_IMM, {0x22, 1}),
            Uop(VM_UOP_SELECT, {VM_CONDITION_E}),
            Uop(VM_UOP_POP_VREG, {4, 1, 0, 0}),
            Uop(VM_UOP_EXIT, {0}),
        };
        VMMicroMachineState selectState{};
        std::vector<uint8_t> memory;
        Require(ExecuteEncoded(selectProgram, environment, selectState, memory, 0, error),
            "SETcc/SELECT 消费者执行失败: " + error);
        Require((selectState.gpr[4] & 0xFFu) == (equal ? 0x22u : 0x11u),
            "SETcc/SELECT 未按 lazy ZF 选择值");
    }

    std::vector<MicroInstruction> adcProgram = {
        Uop(VM_UOP_PUSH_IMM, {0xFF, 1}),
        Uop(VM_UOP_PUSH_IMM, {1, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_PUSH_IMM, {0x10, 1}),
        Uop(VM_UOP_PUSH_IMM, {0x20, 1}),
        Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_CF}),
        Uop(VM_UOP_ADD_CARRY, {1}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADC, 1, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
        Uop(VM_UOP_POP_VREG, {5, 1, 0, 0}),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_STATUS_MASK}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState adcState{};
    adcState.rflags = 0x202u;
    std::vector<uint8_t> memory;
    Require(ExecuteEncoded(adcProgram, environment, adcState, memory, 0, error),
        "ADC lazy CF 消费路径执行失败: " + error);
    Require((adcState.gpr[5] & 0xFFu) == 0x31u,
        "ADC 未消费 VM 内 lazy CF");
    uint64_t adcResult = 0;
    const uint64_t adcExpectedFlags = NativeAddSubFlags(
        false, 0x10u, 0x21u, 1, 0x202u, adcResult);
    Require(adcState.rflags == adcExpectedFlags,
        "ADC lazy flags 与 native CF/PF/AF/ZF/SF/OF 不一致");

    std::vector<MicroInstruction> readFlagsProgram = {
        Uop(VM_UOP_PUSH_IMM, {0xFF, 1}),
        Uop(VM_UOP_PUSH_IMM, {1, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_STATUS_MASK}),
        Uop(VM_UOP_POP_VREG, {6, 8, 0, 1}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState flagsState{};
    flagsState.rflags = 0x202u;
    Require(ExecuteEncoded(readFlagsProgram, environment, flagsState, memory, 0, error),
        "读 flags 消费路径执行失败: " + error);
    uint64_t flagsResult = 0;
    const uint64_t flagsExpected = NativeAddSubFlags(
        false, 0xFFu, 1u, 1, 0x202u, flagsResult);
    Require(flagsState.gpr[6] == flagsExpected,
        "读 flags 未获得 VM 内惰性现算结果");
}

void TestLazyFlagsOverwriteAndExplicitUpdatePreservation() {
    const EncodedEnvironment environment = MakeEnvironment(0xAD, 0xAD00);
    std::string error;
    std::vector<uint8_t> memory;
    const std::vector<MicroInstruction> logicProgram = {
        Uop(VM_UOP_PUSH_IMM, {0x0Fu, 1}),
        Uop(VM_UOP_PUSH_IMM, {1u, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY, {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, 0}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_PUSH_IMM, {1u, 1}),
        Uop(VM_UOP_PUSH_IMM, {1u, 1}),
        Uop(VM_UOP_AND, {1}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_LOGIC, 1,
             VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF, 0}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState logic{};
    logic.rflags = 0x202u;
    Require(ExecuteEncoded(logicProgram, environment, logic, memory, 0, error),
        "ADD->AND lazy overwrite execution failed: " + error);
    Require((logic.rflags & VM_FLAG_AF) != 0,
        "undefined AF policy lost the preceding lazy ADD auxiliary carry");

    const std::vector<MicroInstruction> updateProgram = {
        Uop(VM_UOP_PUSH_IMM, {0x7Fu, 1}),
        Uop(VM_UOP_PUSH_IMM, {1u, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY, {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, 0}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_FLAGS_UPDATE, {VM_FLAG_UPDATE_CLEAR, VM_FLAG_CF}),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState updated{};
    updated.rflags = 0x202u | VM_FLAG_CF;
    Require(ExecuteEncoded(updateProgram, environment, updated, memory, 0, error),
        "lazy FLAGS_UPDATE execution failed: " + error);
    uint64_t nativeResult = 0;
    uint64_t expected = NativeAddSubFlags(
        false, 0x7Fu, 1u, 1, 0x202u | VM_FLAG_CF, nativeResult);
    expected &= ~static_cast<uint64_t>(VM_FLAG_CF);
    Require(updated.rflags == expected,
        "FLAGS_UPDATE discarded non-CF bits from the preceding lazy record");

    const std::vector<MicroInstruction> sahfProgram = {
        Uop(VM_UOP_PUSH_IMM, {0x7Fu, 1}),
        Uop(VM_UOP_PUSH_IMM, {1u, 1}),
        Uop(VM_UOP_ADD, {1}),
        Uop(VM_UOP_FLAGS_LAZY, {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK, 0}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_PUSH_IMM, {0x02u, 1}),
        Uop(VM_UOP_FLAGS_UNPACK_AH),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState unpacked{};
    unpacked.rflags = 0x202u;
    Require(ExecuteEncoded(sahfProgram, environment, unpacked, memory, 0, error),
        "lazy SAHF execution failed: " + error);
    Require((unpacked.rflags & VM_FLAG_OF) != 0 &&
        (unpacked.rflags & (VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_AF |
            VM_FLAG_ZF | VM_FLAG_SF)) == 0,
        "SAHF discarded preserved OF or wrote an incorrect AH flag bit");
}

std::vector<MicroInstruction> ConditionalBranchProgram(bool equal) {
    return {
        Uop(VM_UOP_PUSH_IMM, {9, 8}),
        Uop(VM_UOP_PUSH_IMM, {equal ? 9u : 10u, 8}),
        Uop(VM_UOP_SUB, {8}),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_SUB, 8, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}),
        Uop(VM_UOP_DROP),
        Uop(VM_UOP_BRANCH_IF, {VM_CONDITION_E, 0}),
        Uop(VM_UOP_PUSH_IMM, {0, 8}),
        Uop(VM_UOP_POP_VREG, {7, 8, 0, 1}),
        Uop(VM_UOP_EXIT, {0}),
        Uop(VM_UOP_PUSH_IMM, {1, 8}),
        Uop(VM_UOP_POP_VREG, {7, 8, 0, 1}),
        Uop(VM_UOP_EXIT, {0}),
    };
}

void TestLazyFlagsConditionalBranch() {
    const EncodedEnvironment environment = MakeEnvironment(0xB7, 0xB700);
    for (const bool equal : {false, true}) {
        std::vector<MicroInstruction> program = ConditionalBranchProgram(equal);
        const auto offsets = EncodedOffsets(program, environment.maps, environment.codec);
        program[5].operands[1] = offsets[9];
        const auto bytecode = EncodeProgram(program, environment.maps, environment.codec);
        const auto validation = VMSchema::ValidateStream(
            bytecode.data(), bytecode.size(), environment.maps.reverse.data(),
            environment.codec, environment.options.registerCount);
        Require(validation.success, "BRANCH_IF 流未通过 verifier: " + validation.error);
        VMMicroMachineState state{};
        state.rflags = 0x202u;
        std::vector<uint8_t> memory;
        std::string error;
        Require(ExecuteEncoded(program, environment, state, memory, 0, error),
            "BRANCH_IF lazy flags 消费失败: " + error);
        Require(state.gpr[7] == (equal ? 1u : 0u),
            "BRANCH_IF 未按 lazy ZF 跳转到精确变长边界");
    }
}

struct WideDivideResult {
    bool divideError = true;
    uint64_t quotient = 0;
    uint64_t remainder = 0;
};

WideDivideResult NativeUnsignedDivide128(
    uint64_t high,
    uint64_t low,
    uint64_t divisor)
{
    WideDivideResult result{};
    if (divisor == 0 || high >= divisor) return result;
    uint64_t quotient = 0;
    uint64_t remainder = high;
    for (int bit = 63; bit >= 0; --bit) {
        const bool carry = (remainder >> 63u) != 0;
        remainder = (remainder << 1u) | ((low >> bit) & 1u);
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= 1ULL << bit;
        }
    }
    result.divideError = false;
    result.quotient = quotient;
    result.remainder = remainder;
    return result;
}

WideDivideResult NativeSignedDivide128(
    uint64_t high,
    uint64_t low,
    uint64_t divisorBits)
{
    WideDivideResult result{};
    if (divisorBits == 0) return result;
    const bool dividendNegative = (high >> 63u) != 0;
    const bool divisorNegative = (divisorBits >> 63u) != 0;
    uint64_t magnitudeHigh = high;
    uint64_t magnitudeLow = low;
    if (dividendNegative) {
        magnitudeLow = ~magnitudeLow + 1u;
        magnitudeHigh = ~magnitudeHigh + (magnitudeLow == 0 ? 1u : 0u);
    }
    const uint64_t divisorMagnitude = divisorNegative ?
        (~divisorBits + 1u) : divisorBits;
    WideDivideResult magnitude = NativeUnsignedDivide128(
        magnitudeHigh, magnitudeLow, divisorMagnitude);
    if (magnitude.divideError) return result;
    const bool quotientNegative = dividendNegative != divisorNegative;
    if ((!quotientNegative && magnitude.quotient >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) ||
        (quotientNegative && magnitude.quotient > (1ULL << 63u))) {
        return result;
    }
    result.divideError = false;
    result.quotient = quotientNegative ?
        (~magnitude.quotient + 1u) : magnitude.quotient;
    result.remainder = dividendNegative ?
        (~magnitude.remainder + 1u) : magnitude.remainder;
    return result;
}

std::vector<MicroInstruction> DivideProgram(
    VM_MICRO_OPCODE opcode,
    uint64_t high,
    uint64_t low,
    uint64_t divisor)
{
    return {
        Uop(VM_UOP_PUSH_IMM, {high, 8}, 0),
        Uop(VM_UOP_PUSH_IMM, {low, 8}, 1),
        Uop(VM_UOP_PUSH_IMM, {divisor, 8}, 2),
        Uop(opcode, {8}, 3),
        Uop(VM_UOP_POP_VREG, {1, 8, 0, 1}, 0),
        Uop(VM_UOP_POP_VREG, {0, 8, 0, 1}, 1),
        Uop(VM_UOP_EXIT, {0}, 2),
    };
}

void CheckDivideSuccess(
    const EncodedEnvironment& environment,
    VM_MICRO_OPCODE opcode,
    uint64_t high,
    uint64_t low,
    uint64_t divisor,
    const WideDivideResult& expected)
{
    Require(!expected.divideError, "测试语料错误地要求 #DE case 成功");
    VMMicroMachineState state{};
    uint64_t random = high ^ low ^ divisor ^ 0x8CB92BA72F3D8DD7ULL;
    for (uint64_t& gpr : state.gpr) gpr = NextFuzz(random);
    state.rflags = NextFuzz(random) | 0x02u;
    auto expectedGpr = state.gpr;
    expectedGpr[0] = expected.quotient;
    expectedGpr[1] = expected.remainder;
    const uint64_t expectedFlags = state.rflags;
    std::vector<uint8_t> memory(32, 0xA5);
    const auto expectedMemory = memory;
    std::string error;
    Require(ExecuteEncoded(DivideProgram(opcode, high, low, divisor),
            environment, state, memory, 0x1000, error),
        "合法宽除法被拒绝: " + error);
    Require(state.fault == VMMicroFault::None && state.finished,
        "合法宽除法未正常 EXIT");
    Require(state.gpr == expectedGpr, "宽除法 quotient/remainder 或其他 GPR 不一致");
    Require(state.rflags == expectedFlags, "宽除法破坏了其未定义 flags 的确定性策略");
    Require(memory == expectedMemory, "宽除法产生了意外内存副作用");
}

void CheckDivideError(
    const EncodedEnvironment& environment,
    VM_MICRO_OPCODE opcode,
    uint64_t high,
    uint64_t low,
    uint64_t divisor)
{
    VMMicroMachineState state{};
    uint64_t random = high ^ low ^ divisor ^ 0xDB4F0B9175AE2165ULL;
    for (uint64_t& gpr : state.gpr) gpr = NextFuzz(random);
    state.rflags = NextFuzz(random) | 0x02u;
    const auto expectedGpr = state.gpr;
    const uint64_t expectedFlags = state.rflags;
    std::vector<uint8_t> memory(32, 0x5A);
    const auto expectedMemory = memory;
    std::string error;
    Require(!ExecuteEncoded(DivideProgram(opcode, high, low, divisor),
            environment, state, memory, 0x2000, error),
        "应触发 #DE 的宽除法被错误接受");
    Require(state.fault == VMMicroFault::DivideError,
        "除零/商溢出未映射为精确 #DE fault");
    Require(state.gpr == expectedGpr, "#DE 路径改写了 architectural GPR");
    Require(state.rflags == expectedFlags, "#DE 路径改写了 architectural flags");
    Require(memory == expectedMemory, "#DE 路径产生了内存副作用");
}

void TestWideDivIdivAndDivideError() {
    const EncodedEnvironment environment = MakeEnvironment(0xC8, 0xC800);
    uint64_t random = 0x243F6A8885A308D3ULL;
    for (uint32_t sample = 0; sample < 512; ++sample) {
        const uint64_t divisor = NextFuzz(random) | 1u;
        const uint64_t high = NextFuzz(random) % divisor;
        const uint64_t low = NextFuzz(random);
        const WideDivideResult expected = NativeUnsignedDivide128(high, low, divisor);
        CheckDivideSuccess(environment, VM_UOP_UDIV_WIDE,
            high, low, divisor, expected);
    }

    const std::array<std::array<uint64_t, 3>, 6> signedCases{{
        {0, 100, 7},
        {std::numeric_limits<uint64_t>::max(),
            static_cast<uint64_t>(static_cast<int64_t>(-100)), 7},
        {std::numeric_limits<uint64_t>::max(),
            static_cast<uint64_t>(static_cast<int64_t>(-100)),
            static_cast<uint64_t>(static_cast<int64_t>(-7))},
        {0, 100, static_cast<uint64_t>(static_cast<int64_t>(-7))},
        {1, 0, 3},
        {std::numeric_limits<uint64_t>::max(), 0, 3},
    }};
    for (const auto& item : signedCases) {
        const WideDivideResult expected = NativeSignedDivide128(item[0], item[1], item[2]);
        CheckDivideSuccess(environment, VM_UOP_IDIV_WIDE,
            item[0], item[1], item[2], expected);
    }

    CheckDivideError(environment, VM_UOP_UDIV_WIDE, 0, 1, 0);
    CheckDivideError(environment, VM_UOP_UDIV_WIDE, 9, 0, 9);
    CheckDivideError(environment, VM_UOP_IDIV_WIDE, 0, 1, 0);
    CheckDivideError(environment, VM_UOP_IDIV_WIDE,
        std::numeric_limits<uint64_t>::max(), 0x8000000000000000ULL,
        std::numeric_limits<uint64_t>::max());
    CheckDivideError(environment, VM_UOP_IDIV_WIDE,
        0, 0x8000000000000000ULL, 1);
}

std::vector<MicroInstruction> AddressLoadProgram(
    uint64_t base,
    uint64_t displacement,
    uint8_t width)
{
    return {
        Uop(VM_UOP_PUSH_IMM, {base, 8}),
        Uop(VM_UOP_PUSH_IMM, {displacement, 8}),
        Uop(VM_UOP_ADD, {8}),
        Uop(VM_UOP_LOAD, {width}),
        Uop(VM_UOP_POP_VREG, {8, width, 0, width == 4u ? 1u : 0u}),
        Uop(VM_UOP_EXIT, {0}),
    };
}

uint64_t ReadLittleEndian(
    const std::vector<uint8_t>& memory,
    size_t offset,
    uint8_t width)
{
    uint64_t value = 0;
    for (uint8_t index = 0; index < width; ++index) {
        value |= static_cast<uint64_t>(memory[offset + index]) << (index * 8u);
    }
    return value;
}

void TestAddressingAndMemoryBoundaries() {
    const EncodedEnvironment environment = MakeEnvironment(0xD9, 0xD900);
    constexpr uint64_t memoryBase = 0x00007FF700001000ULL;
    std::vector<uint8_t> memory(64);
    for (size_t index = 0; index < memory.size(); ++index) {
        memory[index] = static_cast<uint8_t>(index * 3u + 1u);
    }
    std::string error;

    VMMicroMachineState validLoad{};
    validLoad.rflags = 0xA02u | VM_FLAG_CF | VM_FLAG_ZF;
    const uint64_t loadFlags = validLoad.rflags;
    Require(ExecuteEncoded(AddressLoadProgram(memoryBase, 56, 8),
            environment, validLoad, memory, memoryBase, error),
        "内存末端合法 LOAD 被拒绝: " + error);
    Require(validLoad.gpr[8] == ReadLittleEndian(memory, 56, 8),
        "内存末端合法 LOAD 值错误");
    Require(validLoad.rflags == loadFlags,
        "寻址 VADD 未登记 FLAGS_LAZY 却污染 architectural flags");

    const auto beforeInvalidLoad = memory;
    VMMicroMachineState invalidLoad{};
    invalidLoad.rflags = 0x202u | VM_FLAG_OF;
    const auto invalidLoadGpr = invalidLoad.gpr;
    const uint64_t invalidLoadFlags = invalidLoad.rflags;
    Require(!ExecuteEncoded(AddressLoadProgram(memoryBase, 57, 8),
            environment, invalidLoad, memory, memoryBase, error),
        "跨越 memory view 一字节的 LOAD 被接受");
    Require(invalidLoad.fault == VMMicroFault::Memory,
        "越界 LOAD 未产生 Memory fault");
    Require(invalidLoad.gpr == invalidLoadGpr &&
        invalidLoad.rflags == invalidLoadFlags && memory == beforeInvalidLoad,
        "越界 LOAD 改写了架构状态或内存");

    std::vector<MicroInstruction> storeProgram = {
        Uop(VM_UOP_PUSH_IMM, {memoryBase + 60, 8}),
        Uop(VM_UOP_PUSH_IMM, {0xA1B2C3D4u, 4}),
        Uop(VM_UOP_STORE, {4}),
        Uop(VM_UOP_EXIT, {0}),
    };
    VMMicroMachineState validStore{};
    Require(ExecuteEncoded(storeProgram, environment, validStore, memory, memoryBase, error),
        "内存末端合法 STORE 被拒绝: " + error);
    Require(ReadLittleEndian(memory, 60, 4) == 0xA1B2C3D4u,
        "内存末端合法 STORE 副作用错误");

    const auto beforeInvalidStore = memory;
    storeProgram[0].operands[0] = memoryBase + 61;
    VMMicroMachineState invalidStore{};
    invalidStore.rflags = 0x602u;
    const auto invalidStoreGpr = invalidStore.gpr;
    Require(!ExecuteEncoded(storeProgram, environment, invalidStore, memory, memoryBase, error),
        "跨越 memory view 的 STORE 被接受");
    Require(invalidStore.fault == VMMicroFault::Memory &&
        invalidStore.gpr == invalidStoreGpr && invalidStore.rflags == 0x602u &&
        memory == beforeInvalidStore,
        "越界 STORE 未保持架构状态与内存原子性");

    constexpr uint64_t highBase = std::numeric_limits<uint64_t>::max() - 15u;
    std::vector<uint8_t> highMemory(16, 0xCC);
    WriteLittleEndian(highMemory, 8, 8, 0x1122334455667788ULL);
    VMMicroMachineState highValid{};
    Require(ExecuteEncoded(AddressLoadProgram(highBase, 8, 8),
            environment, highValid, highMemory, highBase, error),
        "高地址无回绕边界 LOAD 被拒绝: " + error);
    Require(highValid.gpr[8] == 0x1122334455667788ULL,
        "高地址边界 LOAD 值错误");

    VMMicroMachineState wrapped{};
    const auto beforeWrapped = highMemory;
    Require(!ExecuteEncoded(AddressLoadProgram(highBase, 16, 8),
            environment, wrapped, highMemory, highBase, error),
        "地址加法回绕后的 LOAD 被接受");
    Require(wrapped.fault == VMMicroFault::Memory && highMemory == beforeWrapped,
        "地址回绕未 fail-closed");
}

void TestExecutorRejectsMalformedStreamBeforeSideEffects() {
    const EncodedEnvironment environment = MakeEnvironment(0xEA, 0xEA00);
    const auto program = BinaryMemoryProgram(
        VM_UOP_ADD, VM_LAZY_ADD, 8, 0x5008);
    std::vector<uint8_t> bytecode = EncodeProgram(
        program, environment.maps, environment.codec);
    Require(bytecode.size() > 1, "测试 bytecode 意外为空");
    bytecode.pop_back();

    VMMicroMachineState state{};
    state.gpr[0] = 1;
    state.gpr[1] = 2;
    state.rflags = 0x202u;
    const auto expectedGpr = state.gpr;
    const uint64_t expectedFlags = state.rflags;
    std::vector<uint8_t> memory(32, 0x77);
    const auto expectedMemory = memory;
    VMMicroMemoryView view{memory.data(), memory.size(), 0x5000};
    std::string error;
    Require(!VMMicroSemanticExecutor::Execute(
            bytecode.data(), bytecode.size(), environment.maps.reverse.data(),
            environment.codec, state, view, environment.options, error),
        "截断 bytecode 被 executor 接受");
    Require(state.fault == VMMicroFault::Decode,
        "截断 bytecode 未产生 Decode fault");
    Require(state.gpr == expectedGpr && state.rflags == expectedFlags &&
        memory == expectedMemory,
        "executor 在完整流验证前产生了副作用");
}

CipherShell::OperandIR RegisterOperand(
    CipherShell::RegisterId id,
    CipherShell::OperandAction action)
{
    CipherShell::OperandIR operand{};
    operand.type = CipherShell::OperandType::Register;
    operand.action = action;
    operand.visibility = CipherShell::OperandVisibility::Explicit;
    operand.width = 64;
    operand.reg = id;
    operand.regInfo = CipherShell::DescribeRegister(id);
    return operand;
}

CipherShell::Function MakeAddFunction() {
    CipherShell::InstructionIR add{};
    add.address = 0x1000;
    add.rva = 0x1000;
    add.length = 3;
    add.rawBytes[0] = 0x48;
    add.rawBytes[1] = 0x01;
    add.rawBytes[2] = 0xC8;
    add.mnemonic = CipherShell::InstructionMnemonic::Add;
    add.category = CipherShell::InstructionCategory::Arithmetic;
    add.machineMode = CipherShell::MachineMode::X64;
    add.encoding = CipherShell::InstructionEncoding::Legacy;
    add.instructionSet = CipherShell::InstructionSetClass::Scalar;
    add.operandWidth = 64;
    add.flagsWritten = VM_FLAG_STATUS_MASK;
    add.mnemonicText = "add";
    add.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RAX, CipherShell::OperandAction::ReadWrite));
    add.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RCX, CipherShell::OperandAction::Read));

    CipherShell::InstructionIR ret{};
    ret.address = 0x1003;
    ret.rva = 0x1003;
    ret.length = 1;
    ret.rawBytes[0] = 0xC3;
    ret.mnemonic = CipherShell::InstructionMnemonic::Ret;
    ret.category = CipherShell::InstructionCategory::Return;
    ret.branchKind = CipherShell::BranchKind::Return;
    ret.machineMode = CipherShell::MachineMode::X64;
    ret.encoding = CipherShell::InstructionEncoding::Legacy;
    ret.instructionSet = CipherShell::InstructionSetClass::Scalar;
    ret.mnemonicText = "ret";

    CipherShell::BasicBlock block{};
    block.startAddress = 0x1000;
    block.endAddress = 0x1004;
    block.instructionCount = 2;
    block.instructions = {add, ret};
    block.isFunctionEntry = true;

    CipherShell::Function function{};
    function.entryAddress = 0x1000;
    function.size = 4;
    function.name = "micro_gate_add";
    function.blocks.push_back(std::move(block));
    function.isLeaf = true;
    function.boundaryTrusted = true;
    function.decodedBytes = 4;
    return function;
}

CipherShell::Function MakeMemoryAddFunction() {
    CipherShell::OperandIR destination{};
    destination.type = CipherShell::OperandType::Memory;
    destination.action = CipherShell::OperandAction::ReadWrite;
    destination.visibility = CipherShell::OperandVisibility::Explicit;
    destination.width = 64;
    destination.memory.segment = CipherShell::RegisterId::None;
    destination.memory.base = CipherShell::RegisterId::RBX;
    destination.memory.index = CipherShell::RegisterId::RCX;
    destination.memory.baseInfo = CipherShell::DescribeRegister(CipherShell::RegisterId::RBX);
    destination.memory.indexInfo = CipherShell::DescribeRegister(CipherShell::RegisterId::RCX);
    destination.memory.scale = 4;
    destination.memory.displacement = 8;
    destination.memory.width = 64;
    destination.memory.hasBase = true;
    destination.memory.hasIndex = true;
    destination.memory.hasDisplacement = true;

    CipherShell::InstructionIR add{};
    add.address = 0x2000;
    add.rva = 0x2000;
    add.length = 5;
    add.rawBytes[0] = 0x48;
    add.rawBytes[1] = 0x01;
    add.rawBytes[2] = 0x44;
    add.rawBytes[3] = 0x8B;
    add.rawBytes[4] = 0x08;
    add.mnemonic = CipherShell::InstructionMnemonic::Add;
    add.category = CipherShell::InstructionCategory::Arithmetic;
    add.machineMode = CipherShell::MachineMode::X64;
    add.encoding = CipherShell::InstructionEncoding::Legacy;
    add.instructionSet = CipherShell::InstructionSetClass::Scalar;
    add.operandWidth = 64;
    add.flagsWritten = VM_FLAG_STATUS_MASK;
    add.mnemonicText = "add";
    add.operands.push_back(destination);
    add.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RAX, CipherShell::OperandAction::Read));

    CipherShell::InstructionIR ret{};
    ret.address = 0x2005;
    ret.rva = 0x2005;
    ret.length = 1;
    ret.rawBytes[0] = 0xC3;
    ret.mnemonic = CipherShell::InstructionMnemonic::Ret;
    ret.category = CipherShell::InstructionCategory::Return;
    ret.branchKind = CipherShell::BranchKind::Return;
    ret.machineMode = CipherShell::MachineMode::X64;
    ret.encoding = CipherShell::InstructionEncoding::Legacy;
    ret.instructionSet = CipherShell::InstructionSetClass::Scalar;

    CipherShell::BasicBlock block{};
    block.startAddress = 0x2000;
    block.endAddress = 0x2006;
    block.instructionCount = 2;
    block.instructions = {add, ret};
    block.isFunctionEntry = true;

    CipherShell::Function function{};
    function.entryAddress = 0x2000;
    function.size = 6;
    function.name = "micro_gate_memory_add";
    function.blocks.push_back(std::move(block));
    function.isLeaf = true;
    function.boundaryTrusted = true;
    function.decodedBytes = 6;
    return function;
}

TranslationResult TranslateForGate(
    const CipherShell::Function& function,
    uint64_t buildSeed,
    VMMicroDensity density,
    uint32_t minimumRatio,
    const OpcodeMaps& maps)
{
    TranslationConfig config{};
    config.virtualRegisterCount = 32;
    config.buildSeed = buildSeed;
    config.density = density;
    config.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
    config.heavyMinimumRatio = minimumRatio;
    config.enableSimdBridge = true;
    config.enableX87Bridge = true;
    Translator translator;
    Require(translator.Initialize(config), "Translator 拒绝合法微操作配置");
    translator.SetOpcodeMap(maps.forward);
    std::unordered_map<uint8_t, uint8_t> registers;
    for (uint8_t family = 0; family < 16; ++family) registers[family] = family;
    translator.SetRegisterMap(registers);
    return translator.TranslateFunction(function);
}

bool SameMicroProgram(
    const std::vector<MicroInstruction>& left,
    const std::vector<MicroInstruction>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t index = 0; index < left.size(); ++index) {
        if (!SameInstruction(left[index], right[index])) return false;
    }
    return true;
}

bool SameSemanticChoices(
    const std::vector<MicroInstruction>& left,
    const std::vector<MicroInstruction>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t index = 0; index < left.size(); ++index) {
        if (left[index].opcode != right[index].opcode ||
            left[index].operandCount != right[index].operandCount) return false;
        for (uint8_t operand = 0; operand < left[index].operandCount; ++operand) {
            if (left[index].operands[operand] != right[index].operands[operand]) return false;
        }
    }
    return true;
}

void TestTranslatorHeavyRatioSeedVariationAndDifferential() {
    const CipherShell::Function function = MakeAddFunction();
    const auto seedA = MakeSeed(0x1B);
    const auto seedB = MakeSeed(0x9B);
    const OpcodeMaps mapsA = MakeOpcodeMaps(seedA);
    const OpcodeMaps mapsB = MakeOpcodeMaps(seedB);
    constexpr uint64_t buildSeedA = 0x0123456789ABCDEFULL;
    constexpr uint64_t buildSeedB = 0xF0E1D2C3B4A59687ULL;

    const TranslationResult heavyA = TranslateForGate(
        function, buildSeedA, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, mapsA);
    const TranslationResult heavyB = TranslateForGate(
        function, buildSeedB, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, mapsB);
    Require(heavyA.success && heavyB.success,
        "重型 Translator 未生成生产微操作流");
    Require(heavyA.nativeInstructionCount == 2 &&
        heavyA.microOpCount == heavyA.instructions.size(),
        "Translator 的 native/micro 统计不可信");
    Require(heavyA.microOpRatio >= static_cast<double>(VM_MICRO_HEAVY_MIN_RATIO) &&
        heavyA.microOpCount >= heavyA.nativeInstructionCount * VM_MICRO_HEAVY_MIN_RATIO,
        "重型 Translator 未达到平均 8:1 micro-op 比");
    std::unordered_map<uint32_t, uint32_t> microsPerSource;
    for (const auto& micro : heavyA.instructions) {
        ++microsPerSource[micro.sourceRva];
        Require(micro.opcode > VM_UOP_TRAP && micro.opcode < VM_UOP_COUNT,
            "Translator 产出非微操作/粗粒度语义");
        Require(micro.handlerVariant < VM_HANDLER_VARIANT_COUNT,
            "Translator 产出不可达 handler variant");
    }
    Require(microsPerSource[0x1000] >= VM_MICRO_HEAVY_MIN_RATIO &&
        microsPerSource[0x1003] >= VM_MICRO_HEAVY_MIN_RATIO,
        "存在单条 x86 指令的 1:1 粗粒度直译残留");
    Require(heavyA.microSelectionDigest != 0 &&
        heavyA.microSelectionDigest != heavyB.microSelectionDigest,
        "不同 build seed 未改变微操作选择 digest");
    Require(!SameMicroProgram(heavyA.instructions, heavyB.instructions),
        "不同 build seed 未改变微操作序列/variant");
    Require(heavyA.bytecode != heavyB.bytecode,
        "不同 build seed 生成了相同紧凑 bytecode");

    const TranslationResult replayA = TranslateForGate(
        function, buildSeedA, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, mapsA);
    Require(replayA.success && replayA.bytecode == heavyA.bytecode &&
        replayA.microSelectionDigest == heavyA.microSelectionDigest &&
        SameMicroProgram(replayA.instructions, heavyA.instructions),
        "相同 build seed 无法重放 Translator 结果");

    VMMicroExecutionOptions options{};
    options.registerCount = 32;
    options.maxSteps = 100000;
    options.addressWidth = 8;
    uint64_t random = 0x13198A2E03707344ULL;
    for (uint32_t sample = 0; sample < 512; ++sample) {
        VMMicroMachineState actual{};
        for (uint64_t& gpr : actual.gpr) gpr = NextFuzz(random);
        actual.rflags = NextFuzz(random) | 0x02u;
        auto expectedGpr = actual.gpr;
        uint64_t expectedResult = 0;
        const uint64_t expectedFlags = NativeAddSubFlags(
            false, actual.gpr[0], actual.gpr[1], 8,
            actual.rflags, expectedResult);
        expectedGpr[0] = expectedResult;
        VMMicroMemoryView noMemory{};
        std::string error;
        Require(VMMicroSemanticExecutor::Execute(
                heavyA.bytecode.data(), heavyA.bytecode.size(), mapsA.reverse.data(),
                heavyA.operandCodec, actual, noMemory, options, error),
            "Translator 产出的生产流执行失败: " + error);
        Require(actual.gpr == expectedGpr && actual.rflags == expectedFlags &&
            actual.fault == VMMicroFault::None && actual.finished,
            "Translator→codec→executor 完整链与 native 架构状态不等价");
    }

    const TranslationResult light = TranslateForGate(
        function, buildSeedA, VMMicroDensity::Light,
        VM_MICRO_HEAVY_MIN_RATIO, mapsA);
    Require(light.success && light.density == VMMicroDensity::Light &&
        light.microOpCount > light.nativeInstructionCount,
        "轻型档未继续使用同一微操作 ISA");

    const TranslationResult impossibleRatio = TranslateForGate(
        function, buildSeedA, VMMicroDensity::Heavy, 64, mapsA);
    Require(!impossibleRatio.success && !impossibleRatio.failures.empty(),
        "重型 micro-op 比不足时未 fail-closed");
}

void TestTranslatorComplexAddressDifferential() {
    const CipherShell::Function function = MakeMemoryAddFunction();
    OpcodeMaps mapsA = MakeOpcodeMaps(MakeSeed(0x3D));
    OpcodeMaps mapsB = MakeOpcodeMaps(MakeSeed(0xBD));
    KeepRuntimeSupportedOpcodes(mapsA, true);
    KeepRuntimeSupportedOpcodes(mapsB, true);
    const TranslationResult buildA = TranslateForGate(
        function, 0x1029384756ABCDEFULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, mapsA);
    const TranslationResult buildB = TranslateForGate(
        function, 0xEFCDAB6748392011ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, mapsB);
    Require(buildA.success && buildB.success,
        "复杂 SIB+disp 内存算术未被 Translator 微操作化");
    Require(buildA.microOpRatio >= static_cast<double>(VM_MICRO_HEAVY_MIN_RATIO),
        "复杂寻址重型微操作比不足 8:1");
    Require(!SameSemanticChoices(buildA.instructions, buildB.instructions),
        "不同 seed 未改变寻址 MUL/ADD 等价微操作选择");

    VMMicroExecutionOptions options{};
    options.registerCount = 32;
    options.maxSteps = 100000;
    options.addressWidth = 8;
    constexpr uint64_t memoryBase = 0x0000000180000000ULL;
    uint64_t random = 0xA4093822299F31D0ULL;
    for (uint32_t sample = 0; sample < 512; ++sample) {
        VMMicroMachineState actual{};
        for (uint64_t& gpr : actual.gpr) gpr = NextFuzz(random);
        actual.gpr[3] = memoryBase + 16;
        actual.gpr[1] = sample & 7u;
        actual.gpr[0] = NextFuzz(random);
        actual.rflags = NextFuzz(random) | 0x02u;
        const auto expectedGpr = actual.gpr;

        std::vector<uint8_t> memory(96);
        for (uint8_t& byte : memory) byte = static_cast<uint8_t>(NextFuzz(random));
        std::vector<uint8_t> expectedMemory = memory;
        const size_t effectiveOffset = 16u + static_cast<size_t>(actual.gpr[1]) * 4u + 8u;
        const uint64_t original = ReadLittleEndian(memory, effectiveOffset, 8);
        uint64_t expectedResult = 0;
        const uint64_t expectedFlags = NativeAddSubFlags(
            false, original, actual.gpr[0], 8, actual.rflags, expectedResult);
        WriteLittleEndian(expectedMemory, effectiveOffset, 8, expectedResult);

        VMMicroMemoryView view{memory.data(), memory.size(), memoryBase};
        std::string error;
        Require(VMMicroSemanticExecutor::Execute(
                buildA.bytecode.data(), buildA.bytecode.size(), mapsA.reverse.data(),
                buildA.operandCodec, actual, view, options, error),
            "复杂寻址 Translator 流执行失败: " + error);
        Require(actual.gpr == expectedGpr,
            "复杂寻址内存 ADD 意外污染 GPR");
        Require(actual.rflags == expectedFlags,
            "复杂寻址内存 ADD flags 与 native 不一致");
        Require(memory == expectedMemory,
            "复杂寻址内存 ADD 副作用与 native 不一致");
    }
}

std::unordered_map<uint8_t, uint8_t> IdentityRegisterMap() {
    std::unordered_map<uint8_t, uint8_t> registers;
    for (uint8_t family = 0; family < 16; ++family) registers[family] = family;
    return registers;
}

void RequireIRModelPreflight(
    const CipherShell::Function& function,
    const TranslationResult& translation,
    const OpcodeMaps& maps,
    uint64_t corpusSeed)
{
    CipherShell::VMIRModelPreflightConfig config{};
    config.corpusSeed = corpusSeed;
    config.corpusCount = 256;
    config.memorySize = 0x10000;
    config.maxSteps = 100000;
    const auto verified = CipherShell::VMIRModelPreflightVerifier::Verify(
        function, translation, maps.forward, IdentityRegisterMap(), config);
    Require(verified.success && verified.casesExecuted == config.corpusCount,
        "IR model preflight failed: " + verified.error);
}

enum class NativeEvidenceFixtureMode : uint8_t {
    Complete,
    NativeNotExecuted,
    HandlerNotExecuted,
    TimedOut,
    Faulted,
    IncompleteFlags,
    Unbound,
    NoIsolation,
    GprMismatch,
    FlagsMismatch,
    MemoryMismatch
};

class NativeEvidenceFixtureProvider final :
    public CipherShell::VMNativeDifferentialEvidenceProvider {
public:
    explicit NativeEvidenceFixtureProvider(NativeEvidenceFixtureMode mode) :
        m_mode(mode) {}

    bool ExecuteCase(
        const CipherShell::Function&,
        const TranslationResult&,
        const std::unordered_map<uint8_t, uint8_t>&,
        const std::unordered_map<uint8_t, uint8_t>&,
        const CipherShell::VMNativeDifferentialCaseRequest& request,
        CipherShell::VMNativeDifferentialCaseEvidence& evidence,
        std::string&) const override
    {
        evidence.corpusIndex = request.corpusIndex;
        evidence.architecture = request.architecture;
        evidence.functionRVA = request.functionRVA;
        evidence.translationIdentity = request.translationIdentity;
        evidence.handlerImageDigest = request.handlerImageDigest;
        evidence.inputIdentity = request.inputIdentity;
        evidence.isolatedWorker = true;
        evidence.timeoutEnforced = true;
        evidence.nativeCpuExecuted = true;
        evidence.synthesizedHandlersExecuted = true;
        evidence.nativeInstructionCount = 1;
        evidence.handlerInstructionCount = 1;
        evidence.nativeState.gpr = request.initialGpr;
        evidence.vmState.gpr = request.initialGpr;
        evidence.nativeState.rflags = request.initialRflags;
        evidence.vmState.rflags = request.initialRflags;
        evidence.nativeState.validRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
        evidence.vmState.validRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
        evidence.nativeState.memory = request.initialMemory;
        evidence.vmState.memory = request.initialMemory;

        switch (m_mode) {
            case NativeEvidenceFixtureMode::Complete:
                break;
            case NativeEvidenceFixtureMode::NativeNotExecuted:
                evidence.nativeCpuExecuted = false;
                evidence.nativeInstructionCount = 0;
                break;
            case NativeEvidenceFixtureMode::HandlerNotExecuted:
                evidence.synthesizedHandlersExecuted = false;
                evidence.handlerInstructionCount = 0;
                break;
            case NativeEvidenceFixtureMode::TimedOut:
                evidence.timedOut = true;
                break;
            case NativeEvidenceFixtureMode::Faulted:
                evidence.nativeFaulted = true;
                evidence.nativeExceptionCode = 0xC0000094u;
                break;
            case NativeEvidenceFixtureMode::IncompleteFlags:
                evidence.nativeState.validRflagsMask = VM_FLAG_STATUS_MASK;
                break;
            case NativeEvidenceFixtureMode::Unbound:
                evidence.translationIdentity ^= 1u;
                break;
            case NativeEvidenceFixtureMode::NoIsolation:
                evidence.isolatedWorker = false;
                break;
            case NativeEvidenceFixtureMode::GprMismatch:
                evidence.vmState.gpr[15] ^= 1u;
                break;
            case NativeEvidenceFixtureMode::FlagsMismatch:
                evidence.vmState.rflags ^= VM_FLAG_OF;
                break;
            case NativeEvidenceFixtureMode::MemoryMismatch:
                evidence.vmState.memory.back() ^= 1u;
                break;
        }
        return true;
    }

private:
    NativeEvidenceFixtureMode m_mode;
};

void TestNativeDifferentialEvidenceContractFailClosed() {
    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0xD7));
    KeepRuntimeSupportedOpcodes(maps, true);
    const CipherShell::Function function = MakeAddFunction();
    const TranslationResult translation = TranslateForGate(
        function, 0xD7D1FFD7D1FFD7D1ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(translation.success,
        "native differential evidence fixture translation failed");
    const auto registers = IdentityRegisterMap();

    CipherShell::VMIRModelPreflightConfig modelConfig{};
    modelConfig.corpusCount = 2;
    modelConfig.memorySize = 0x1000;
    const auto model = CipherShell::VMIRModelPreflightVerifier::Verify(
        function, translation, maps.forward, registers, modelConfig);
    Require(model.success,
        "software model preflight fixture unexpectedly failed: " + model.error);

    CipherShell::VMNativeDifferentialConfig config{};
    config.corpusSeed = modelConfig.corpusSeed;
    config.corpusCount = 2;
    config.memorySize = 0x1000;
    config.timeoutMilliseconds = 100;
    config.expectedHandlerImageDigest = 0xD1FFE71D3E57ULL;

    const auto missing = CipherShell::VMNativeDifferentialVerifier::Verify(
        function, translation, maps.forward, registers, config);
    Require(!missing.success &&
            missing.error.find("provider") != std::string::npos,
        "software model preflight was accepted as native evidence");

    auto requireRejected = [&](NativeEvidenceFixtureMode mode,
                               const char* expectedReason) {
        NativeEvidenceFixtureProvider provider(mode);
        config.evidenceProvider = &provider;
        const auto rejected = CipherShell::VMNativeDifferentialVerifier::Verify(
            function, translation, maps.forward, registers, config);
        Require(!rejected.success &&
                rejected.error.find(expectedReason) != std::string::npos,
            std::string("native evidence contract accepted invalid evidence: ") +
                expectedReason + " (actual: " + rejected.error + ")");
    };
    requireRejected(NativeEvidenceFixtureMode::NativeNotExecuted,
        "actual CPU execution");
    requireRejected(NativeEvidenceFixtureMode::HandlerNotExecuted,
        "synthesized handler execution");
    requireRejected(NativeEvidenceFixtureMode::TimedOut, "timed out");
    requireRejected(NativeEvidenceFixtureMode::Faulted, "exception or VM fault");
    requireRejected(NativeEvidenceFixtureMode::IncompleteFlags,
        "complete flags or memory");
    requireRejected(NativeEvidenceFixtureMode::Unbound,
        "not bound to the requested case");
    requireRejected(NativeEvidenceFixtureMode::NoIsolation,
        "isolation or deadline");
    requireRejected(NativeEvidenceFixtureMode::GprMismatch, "GPR mismatch");
    requireRejected(NativeEvidenceFixtureMode::FlagsMismatch,
        "RFLAGS mismatch");
    requireRejected(NativeEvidenceFixtureMode::MemoryMismatch,
        "memory side-effect mismatch");

    NativeEvidenceFixtureProvider complete(NativeEvidenceFixtureMode::Complete);
    config.evidenceProvider = &complete;
    const auto accepted = CipherShell::VMNativeDifferentialVerifier::Verify(
        function, translation, maps.forward, registers, config);
    Require(accepted.success && accepted.casesVerified == config.corpusCount &&
            accepted.nativeCpuEvidenceVerified &&
            accepted.synthesizedHandlerEvidenceVerified,
        "complete evidence contract fixture was rejected: " + accepted.error);
}

void AppendAccumulatorSelfCompare(
    CipherShell::Function& function,
    CipherShell::RegisterId accumulator,
    uint16_t width)
{
    Require(function.blocks.size() == 1u &&
            !function.blocks[0].instructions.empty() &&
            function.blocks[0].instructions.back().IsReturn(),
        "status-defining compare requires one terminal block");
    auto& block = function.blocks[0];
    CipherShell::InstructionIR terminal = block.instructions.back();
    block.instructions.pop_back();

    CipherShell::InstructionIR compare{};
    compare.address = terminal.address;
    compare.rva = terminal.rva;
    compare.length = width == 64u ? 3u : 2u;
    if (width == 64u) {
        compare.rawBytes[0] = 0x48;
        compare.rawBytes[1] = 0x39;
        compare.rawBytes[2] = 0xC0;
    } else {
        compare.rawBytes[0] = 0x39;
        compare.rawBytes[1] = 0xC0;
    }
    compare.mnemonic = CipherShell::InstructionMnemonic::Cmp;
    compare.category = CipherShell::InstructionCategory::Compare;
    compare.machineMode = block.instructions.front().machineMode;
    compare.encoding = CipherShell::InstructionEncoding::Legacy;
    compare.instructionSet = CipherShell::InstructionSetClass::Scalar;
    compare.addressWidth = compare.machineMode == CipherShell::MachineMode::X64 ? 64u : 32u;
    compare.operandWidth = width;
    compare.stackWidth = compare.addressWidth;
    compare.flagsWritten = VM_FLAG_STATUS_MASK;
    compare.mnemonicText = "cmp";
    auto left = RegisterOperand(accumulator, CipherShell::OperandAction::Read);
    auto right = left;
    left.width = width;
    right.width = width;
    compare.operands = {left, right};

    terminal.address += compare.length;
    terminal.rva += compare.length;
    block.instructions.push_back(compare);
    block.instructions.push_back(terminal);
    block.instructionCount = static_cast<uint32_t>(block.instructions.size());
    block.endAddress += compare.length;
    function.size += compare.length;
    function.decodedBytes += compare.length;
}

void TestTranslatorWideDivideDifferentialAndZeroExtend() {
    CipherShell::Function function = MakeAddFunction();
    auto& divide = function.blocks[0].instructions[0];
    divide.mnemonic = CipherShell::InstructionMnemonic::Div;
    divide.mnemonicText = "div";
    divide.operandWidth = 32;
    divide.flagsWritten = 0;
    divide.flagsUndefined = VM_FLAG_STATUS_MASK;
    divide.operands.clear();
    CipherShell::OperandIR divisor = RegisterOperand(
        CipherShell::RegisterId::EBX, CipherShell::OperandAction::Read);
    divisor.width = 32;
    divide.operands.push_back(divisor);
    AppendAccumulatorSelfCompare(
        function, CipherShell::RegisterId::EAX, 32u);

    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0xD4));
    KeepRuntimeSupportedOpcodes(maps, true);
    const TranslationResult translation = TranslateForGate(
        function, 0xD1F1D1F1D1F1D1F1ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(translation.success, "x64 DIV r/m32 lowering failed");
    bool eaxZeroExtend = false;
    bool edxZeroExtend = false;
    for (const auto& micro : translation.instructions) {
        if (micro.opcode != VM_UOP_POP_VREG || micro.operands[1] != 4u ||
            micro.operands[2] != 0u || micro.operands[3] != 1u) continue;
        eaxZeroExtend = eaxZeroExtend || micro.operands[0] == 0u;
        edxZeroExtend = edxZeroExtend || micro.operands[0] == 2u;
    }
    Require(eaxZeroExtend && edxZeroExtend,
        "implicit EAX/EDX DIV writeback did not zero upper 32 bits");
    RequireIRModelPreflight(function, translation, maps, 0xD1A1D3ULL);
}

void TestTranslatorInternalCallAndAddressSizeDifferential() {
    CipherShell::Function called = MakeAddFunction();
    CipherShell::InstructionIR add = called.blocks[0].instructions[0];
    CipherShell::InstructionIR terminalRet = called.blocks[0].instructions[1];
    CipherShell::InstructionIR call{};
    call.address = call.rva = 0x3000;
    call.length = 4;
    call.mnemonic = CipherShell::InstructionMnemonic::Call;
    call.mnemonicText = "call";
    call.category = CipherShell::InstructionCategory::Call;
    call.branchKind = CipherShell::BranchKind::Call;
    call.machineMode = CipherShell::MachineMode::X64;
    call.encoding = CipherShell::InstructionEncoding::Legacy;
    call.instructionSet = CipherShell::InstructionSetClass::Scalar;
    call.hasBranchTarget = true;
    call.branchTargetRVA = 0x3005;
    terminalRet.address = terminalRet.rva = 0x3004;
    add.address = add.rva = 0x3005;
    CipherShell::InstructionIR innerRet = terminalRet;
    innerRet.address = innerRet.rva = 0x3008;
    CipherShell::BasicBlock block{};
    block.startAddress = 0x3000;
    block.endAddress = 0x3009;
    block.instructionCount = 4;
    block.instructions = {call, terminalRet, add, innerRet};
    block.isFunctionEntry = true;
    CipherShell::Function function{};
    function.entryAddress = 0x3000;
    function.size = 9;
    function.blocks.push_back(block);
    function.boundaryTrusted = true;
    function.decodedBytes = 9;

    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0xC1));
    KeepRuntimeSupportedOpcodes(maps, true);
    const TranslationResult callTranslation = TranslateForGate(
        function, 0xCA11CA11CA11CA11ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(callTranslation.success, "internal CALL/RET lowering failed");
    RequireIRModelPreflight(function, callTranslation, maps, 0xCA11D1FFULL);

    CipherShell::Function address32 = MakeMemoryAddFunction();
    address32.blocks[0].instructions[0].addressWidth = 32;
    const TranslationResult addressTranslation = TranslateForGate(
        address32, 0xADD232ADD232ADD2ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(addressTranslation.success, "x64 address-size override lowering failed");
    RequireIRModelPreflight(address32, addressTranslation, maps, 0xADD232ULL);
}

void TestTranslatorRejectsImplicitAtomicMemoryXchg() {
    CipherShell::Function function = MakeMemoryAddFunction();
    auto& xchg = function.blocks[0].instructions[0];
    xchg.mnemonic = CipherShell::InstructionMnemonic::Xchg;
    xchg.mnemonicText = "xchg";
    xchg.flagsWritten = 0;
    const OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0xA7));
    const TranslationResult rejected = TranslateForGate(
        function, 0xA70A70A70A70A70ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(!rejected.success && !rejected.failures.empty(),
        "implicitly atomic memory XCHG was translated as non-atomic micro stores");
}

void TestTranslatorStackAndImplicitFlagsDifferential() {
    uint32_t rva = 0x3800;
    auto implicit = [&](CipherShell::InstructionMnemonic mnemonic,
                        CipherShell::InstructionCategory category,
                        const char* name) {
        CipherShell::InstructionIR instruction{};
        instruction.address = instruction.rva = rva++;
        instruction.length = 1;
        instruction.rawBytes[0] = 0x90;
        instruction.mnemonic = mnemonic;
        instruction.category = category;
        instruction.machineMode = CipherShell::MachineMode::X64;
        instruction.encoding = CipherShell::InstructionEncoding::Legacy;
        instruction.instructionSet = CipherShell::InstructionSetClass::Scalar;
        instruction.operandWidth = 64;
        instruction.stackWidth = 64;
        instruction.mnemonicText = name;
        return instruction;
    };
    std::vector<CipherShell::InstructionIR> instructions;
    auto push = implicit(CipherShell::InstructionMnemonic::Push,
        CipherShell::InstructionCategory::Stack, "push");
    push.addressWidth = 32;
    push.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RAX, CipherShell::OperandAction::Read));
    instructions.push_back(push);
    auto pop = implicit(CipherShell::InstructionMnemonic::Pop,
        CipherShell::InstructionCategory::Stack, "pop");
    pop.addressWidth = 32;
    pop.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RCX, CipherShell::OperandAction::Write));
    instructions.push_back(pop);
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::PushFlags,
        CipherShell::InstructionCategory::Stack, "pushfq"));
    instructions.back().flagsRead = VM_FLAG_ARCHITECTURAL_MASK;
    auto popFlagsImage = implicit(CipherShell::InstructionMnemonic::Pop,
        CipherShell::InstructionCategory::Stack, "pop");
    popFlagsImage.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RDX, CipherShell::OperandAction::Write));
    instructions.push_back(popFlagsImage);
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Clc,
        CipherShell::InstructionCategory::Other, "clc"));
    instructions.back().flagsWritten = VM_FLAG_CF;
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Stc,
        CipherShell::InstructionCategory::Other, "stc"));
    instructions.back().flagsWritten = VM_FLAG_CF;
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Cmc,
        CipherShell::InstructionCategory::Other, "cmc"));
    instructions.back().flagsRead = VM_FLAG_CF;
    instructions.back().flagsWritten = VM_FLAG_CF;
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Lahf,
        CipherShell::InstructionCategory::DataTransfer, "lahf"));
    instructions.back().flagsRead = VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF |
        VM_FLAG_PF | VM_FLAG_CF;
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Sahf,
        CipherShell::InstructionCategory::Other, "sahf"));
    instructions.back().flagsWritten = VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF |
        VM_FLAG_PF | VM_FLAG_CF;
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::ExtendAccumulator,
        CipherShell::InstructionCategory::DataTransfer, "cdqe"));
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::SignExtendAccumulator,
        CipherShell::InstructionCategory::Arithmetic, "cqo"));
    instructions.push_back(implicit(CipherShell::InstructionMnemonic::Leave,
        CipherShell::InstructionCategory::Stack, "leave"));
    auto ret = implicit(CipherShell::InstructionMnemonic::Ret,
        CipherShell::InstructionCategory::Return, "ret");
    ret.branchKind = CipherShell::BranchKind::Return;
    instructions.push_back(ret);

    CipherShell::BasicBlock block{};
    block.startAddress = 0x3800;
    block.endAddress = rva;
    block.instructionCount = static_cast<uint32_t>(instructions.size());
    block.instructions = instructions;
    block.isFunctionEntry = true;
    CipherShell::Function function{};
    function.entryAddress = 0x3800;
    function.size = rva - 0x3800;
    function.blocks.push_back(block);
    function.boundaryTrusted = true;
    function.decodedBytes = function.size;

    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0xF1));
    KeepRuntimeSupportedOpcodes(maps, true);
    const TranslationResult translation = TranslateForGate(
        function, 0xF1A65A5AF1A65A5AULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(translation.success, "stack/implicit-flags lowering failed");
    RequireIRModelPreflight(function, translation, maps, 0xF1A65A5AULL);

    CipherShell::Function pushf = MakeAddFunction();
    auto pushfInstruction = implicit(CipherShell::InstructionMnemonic::PushFlags,
        CipherShell::InstructionCategory::Stack, "pushfq");
    pushfInstruction.address = pushf.entryAddress;
    pushfInstruction.rva = static_cast<uint32_t>(pushf.entryAddress);
    pushfInstruction.rawBytes[0] = 0x9C;
    pushfInstruction.flagsRead = VM_FLAG_ARCHITECTURAL_MASK;
    auto popImage = implicit(CipherShell::InstructionMnemonic::Pop,
        CipherShell::InstructionCategory::Stack, "pop");
    popImage.address = pushf.entryAddress + 1u;
    popImage.rva = static_cast<uint32_t>(pushf.entryAddress + 1u);
    popImage.rawBytes[0] = 0x58;
    popImage.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RAX, CipherShell::OperandAction::Write));
    auto pushfRet = pushf.blocks[0].instructions.back();
    pushfRet.address = pushf.entryAddress + 2u;
    pushfRet.rva = static_cast<uint32_t>(pushf.entryAddress + 2u);
    pushf.blocks[0].instructions = {pushfInstruction, popImage, pushfRet};
    pushf.blocks[0].instructionCount = 3u;
    pushf.blocks[0].endAddress = pushf.entryAddress + 3u;
    pushf.size = pushf.decodedBytes = 3u;
    const TranslationResult pushfTranslation = TranslateForGate(
        pushf, 0xF1A65A5AF1A65A5CULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(pushfTranslation.success, "PUSHF full-image lowering failed");
    std::vector<uint8_t> pushfMemory(128u, 0xA5u);
    const uint64_t pushfMemoryBase = 0x0000000123000000ULL;
    VMMicroMachineState pushfState{};
    pushfState.gpr[4] = pushfMemoryBase + 96u;
    pushfState.rflags = 0x202u | VM_FLAG_CF | VM_FLAG_RF | VM_FLAG_VM |
        VM_FLAG_AC | VM_FLAG_ID;
    VMMicroMemoryView pushfView{
        pushfMemory.data(), pushfMemory.size(), pushfMemoryBase};
    VMMicroExecutionOptions pushfOptions{};
    pushfOptions.registerCount = 32u;
    pushfOptions.addressWidth = 8u;
    std::string pushfError;
    Require(VMMicroSemanticExecutor::Execute(
            pushfTranslation.bytecode.data(), pushfTranslation.bytecode.size(),
            maps.reverse.data(), pushfTranslation.operandCodec,
            pushfState, pushfView, pushfOptions, pushfError),
        "PUSHF full-image stream failed: " + pushfError);
    Require(pushfState.gpr[0] ==
            ((0x202u | VM_FLAG_CF | VM_FLAG_AC | VM_FLAG_ID) &
                ~static_cast<uint64_t>(VM_FLAG_PUSH_CLEARED_MASK)),
        "PUSHF did not clear RF/VM while preserving the remaining flag image");

    CipherShell::Function popf = MakeAddFunction();
    auto& popfInstruction = popf.blocks[0].instructions[0];
    popfInstruction = implicit(CipherShell::InstructionMnemonic::PopFlags,
        CipherShell::InstructionCategory::Stack, "popfq");
    popfInstruction.address = popf.entryAddress;
    popfInstruction.rva = static_cast<uint32_t>(popf.entryAddress);
    popfInstruction.rawBytes[0] = 0x9D;
    popfInstruction.flagsWritten = VM_FLAG_ARCHITECTURAL_MASK;
    auto& popfRet = popf.blocks[0].instructions[1];
    popfRet.address = popf.entryAddress + 1u;
    popfRet.rva = static_cast<uint32_t>(popf.entryAddress + 1u);
    popf.blocks[0].endAddress = popf.entryAddress + 2u;
    popf.size = popf.decodedBytes = 2u;
    const TranslationResult popfRejected = TranslateForGate(
        popf, 0xF1A65A5AF1A65A5BULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(!popfRejected.success && !popfRejected.failures.empty() &&
            popfRejected.failures.front().reason.find("POPF") != std::string::npos,
        "POPF privilege/trap semantics were not rejected fail-closed");
}

#if defined(_WIN32) && defined(_M_X64)
void ExecuteNativeVsTranslatedCorpus(
    const CipherShell::Function& function,
    const TranslationResult& translation,
    const OpcodeMaps& maps,
    const std::vector<uint8_t>& nativeCode,
    bool memoryProbe,
    bool equalityCorpus,
    uint32_t corpusCount,
    uint64_t seed)
{
    NativeProbeCode executable(nativeCode);
    uint64_t random = seed;
    for (uint32_t sample = 0; sample < corpusCount; ++sample) {
        std::vector<uint8_t> memory(128);
        for (uint8_t& byte : memory) byte = static_cast<uint8_t>(NextFuzz(random));
        const std::vector<uint8_t> initialMemory = memory;
        NativeProbeState initial{};
        for (uint64_t& value : initial.gpr) value = NextFuzz(random);
        if (equalityCorpus) {
            initial.gpr[1] = (sample & 1u) == 0u ? initial.gpr[0] :
                (initial.gpr[0] ^ 0xA5A5A5A5A5A5A5A5ULL);
        }
        initial.rflags = 0x02u | (NextFuzz(random) &
            static_cast<uint64_t>(VM_FLAG_STATUS_MASK | VM_FLAG_DF));
        if (memoryProbe) initial.gpr[10] =
            reinterpret_cast<uint64_t>(memory.data());

        NativeProbeState native = initial;
        uint32_t exceptionCode = 0;
        Require(InvokeNativeProbe(executable.Function(), &native, exceptionCode),
            "generated native probe faulted unexpectedly: " +
                std::to_string(exceptionCode));
        const std::vector<uint8_t> expectedMemory = memory;
        memory = initialMemory;

        VMMicroMachineState micro{};
        std::copy(std::begin(initial.gpr), std::end(initial.gpr), micro.gpr.begin());
        micro.rflags = native.observedInitialFlags;
        VMMicroMemoryView view{};
        if (memoryProbe) {
            view.data = memory.data();
            view.size = memory.size();
            view.baseAddress = reinterpret_cast<uint64_t>(memory.data());
        }
        VMMicroExecutionOptions options{};
        options.registerCount = 32;
        options.maxSteps = 100000;
        options.addressWidth = 8;
        std::string error;
        Require(VMMicroSemanticExecutor::Execute(
                translation.bytecode.data(), translation.bytecode.size(),
                maps.reverse.data(), translation.operandCodec,
                micro, view, options, error),
            "translated native-probe corpus failed: " + error);
        for (uint8_t family = 0; family < 16; ++family) {
            Require(micro.gpr[family] == native.gpr[family],
                "native-probe GPR mismatch at family " + std::to_string(family));
        }
        Require(micro.rflags == native.rflags,
            "native-probe complete observable RFLAGS mismatch");
        Require(memory == expectedMemory,
            "native-probe memory side-effect mismatch");
    }
    (void)function;
}

CipherShell::Function MakeNativeProbeDivideFunction(bool signedDivide) {
    CipherShell::Function function = MakeAddFunction();
    auto& divide = function.blocks[0].instructions[0];
    divide.mnemonic = signedDivide ? CipherShell::InstructionMnemonic::Idiv :
        CipherShell::InstructionMnemonic::Div;
    divide.mnemonicText = signedDivide ? "idiv" : "div";
    divide.operandWidth = 64;
    divide.flagsWritten = 0;
    divide.flagsUndefined = VM_FLAG_STATUS_MASK;
    divide.operands.clear();
    divide.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::R10, CipherShell::OperandAction::Read));
    AppendAccumulatorSelfCompare(
        function, CipherShell::RegisterId::RAX, 64u);
    return function;
}

void TestNativeMachineCodeDifferentialGate() {
    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x6E));
    KeepRuntimeSupportedOpcodes(maps, true);

    const CipherShell::Function addFunction = MakeAddFunction();
    const TranslationResult addTranslation = TranslateForGate(
        addFunction, 0x6EADD6EADD6EADDULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(addTranslation.success, "native ADD probe translation failed");
    std::vector<uint8_t> addCode = NativeProbePrefix();
    NativeLoadRegister(addCode, 0);
    NativeLoadRegister(addCode, 1);
    addCode.insert(addCode.end(), {0x48, 0x01, 0xC8}); /* add rax, rcx */
    NativeStoreRegister(addCode, 0);
    NativeProbeSuffix(addCode);
    ExecuteNativeVsTranslatedCorpus(addFunction, addTranslation, maps,
        addCode, false, false, 256, 0x6EADD001ULL);

    CipherShell::Function memoryFunction = MakeMemoryAddFunction();
    auto& memoryAdd = memoryFunction.blocks[0].instructions[0];
    auto& memoryOperand = memoryAdd.operands[0].memory;
    memoryOperand.base = CipherShell::RegisterId::R10;
    memoryOperand.baseInfo = CipherShell::DescribeRegister(CipherShell::RegisterId::R10);
    memoryOperand.hasIndex = false;
    memoryOperand.index = CipherShell::RegisterId::None;
    memoryOperand.indexInfo = {};
    memoryOperand.scale = 1;
    memoryOperand.displacement = 0;
    memoryOperand.hasDisplacement = false;
    const TranslationResult memoryTranslation = TranslateForGate(
        memoryFunction, 0x6E0E6E0E6E0E6E0EULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(memoryTranslation.success, "native memory ADD probe translation failed");
    std::vector<uint8_t> memoryCode = NativeProbePrefix();
    NativeLoadRegister(memoryCode, 10);
    NativeLoadRegister(memoryCode, 0);
    memoryCode.insert(memoryCode.end(), {0x49, 0x01, 0x02}); /* add [r10], rax */
    NativeProbeSuffix(memoryCode);
    ExecuteNativeVsTranslatedCorpus(memoryFunction, memoryTranslation, maps,
        memoryCode, true, false, 128, 0x6E0E0001ULL);

    CipherShell::InstructionIR compare{};
    compare.address = compare.rva = 0x5000;
    compare.length = 3;
    compare.mnemonic = CipherShell::InstructionMnemonic::Cmp;
    compare.mnemonicText = "cmp";
    compare.category = CipherShell::InstructionCategory::Compare;
    compare.machineMode = CipherShell::MachineMode::X64;
    compare.encoding = CipherShell::InstructionEncoding::Legacy;
    compare.instructionSet = CipherShell::InstructionSetClass::Scalar;
    compare.operandWidth = 64;
    compare.flagsWritten = VM_FLAG_STATUS_MASK;
    compare.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RAX, CipherShell::OperandAction::Read));
    compare.operands.push_back(RegisterOperand(
        CipherShell::RegisterId::RCX, CipherShell::OperandAction::Read));
    CipherShell::InstructionIR branch{};
    branch.address = branch.rva = 0x5003;
    branch.length = 2;
    branch.mnemonic = CipherShell::InstructionMnemonic::Jz;
    branch.mnemonicText = "jz";
    branch.category = CipherShell::InstructionCategory::ConditionalBranch;
    branch.branchKind = CipherShell::BranchKind::Equal;
    branch.machineMode = CipherShell::MachineMode::X64;
    branch.encoding = CipherShell::InstructionEncoding::Legacy;
    branch.instructionSet = CipherShell::InstructionSetClass::Scalar;
    branch.flagsRead = VM_FLAG_ZF;
    branch.hasBranchTarget = true;
    branch.branchTargetRVA = 0x500D;
    auto moveImmediate = [](uint32_t rva, uint64_t immediate) {
        CipherShell::InstructionIR move{};
        move.address = move.rva = rva;
        move.length = 7;
        move.mnemonic = CipherShell::InstructionMnemonic::Mov;
        move.mnemonicText = "mov";
        move.category = CipherShell::InstructionCategory::DataTransfer;
        move.machineMode = CipherShell::MachineMode::X64;
        move.encoding = CipherShell::InstructionEncoding::Legacy;
        move.instructionSet = CipherShell::InstructionSetClass::Scalar;
        move.operandWidth = 64;
        move.operands.push_back(RegisterOperand(
            CipherShell::RegisterId::RDX, CipherShell::OperandAction::Write));
        CipherShell::OperandIR source{};
        source.type = CipherShell::OperandType::Immediate;
        source.action = CipherShell::OperandAction::Read;
        source.visibility = CipherShell::OperandVisibility::Explicit;
        source.width = 64;
        source.immediate = immediate;
        move.operands.push_back(source);
        return move;
    };
    CipherShell::InstructionIR falseMove = moveImmediate(0x5005, 0x111);
    CipherShell::InstructionIR falseRet = MakeAddFunction().blocks[0].instructions[1];
    falseRet.address = falseRet.rva = 0x500C;
    CipherShell::InstructionIR trueMove = moveImmediate(0x500D, 0x222);
    CipherShell::InstructionIR trueRet = falseRet;
    trueRet.address = trueRet.rva = 0x5014;
    CipherShell::BasicBlock branchBlock{};
    branchBlock.startAddress = 0x5000;
    branchBlock.endAddress = 0x5015;
    branchBlock.instructionCount = 6;
    branchBlock.instructions = {
        compare, branch, falseMove, falseRet, trueMove, trueRet};
    branchBlock.isFunctionEntry = true;
    CipherShell::Function branchFunction{};
    branchFunction.entryAddress = 0x5000;
    branchFunction.size = 0x15;
    branchFunction.blocks.push_back(branchBlock);
    branchFunction.boundaryTrusted = true;
    branchFunction.decodedBytes = 0x15;
    const TranslationResult branchTranslation = TranslateForGate(
        branchFunction, 0x6EB12A6EB12A6EB1ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(branchTranslation.success, "native Jcc probe translation failed");
    std::vector<uint8_t> branchCode = NativeProbePrefix();
    NativeLoadRegister(branchCode, 0);
    NativeLoadRegister(branchCode, 1);
    branchCode.insert(branchCode.end(), {0x48, 0x39, 0xC8, 0x75, 0x09,
        0x48, 0xC7, 0xC2, 0x22, 0x02, 0x00, 0x00, 0xEB, 0x07,
        0x48, 0xC7, 0xC2, 0x11, 0x01, 0x00, 0x00});
    NativeStoreRegister(branchCode, 2);
    NativeProbeSuffix(branchCode);
    ExecuteNativeVsTranslatedCorpus(branchFunction, branchTranslation, maps,
        branchCode, false, true, 256, 0x6EB12001ULL);

    for (const bool signedDivide : {false, true}) {
        const CipherShell::Function divideFunction =
            MakeNativeProbeDivideFunction(signedDivide);
        const TranslationResult divideTranslation = TranslateForGate(
            divideFunction, signedDivide ? 0x1D1F1D1F1D1F1D1FULL :
                0xD1F0D1F0D1F0D1F0ULL,
            VMMicroDensity::Heavy, VM_MICRO_HEAVY_MIN_RATIO, maps);
        Require(divideTranslation.success, "native DIV/IDIV probe translation failed");
        std::vector<uint8_t> divideCode = NativeProbePrefix();
        NativeLoadRegister(divideCode, 0);
        NativeLoadRegister(divideCode, 2);
        NativeLoadRegister(divideCode, 10);
        divideCode.insert(divideCode.end(), signedDivide ?
            std::initializer_list<uint8_t>{0x49, 0xF7, 0xFA} :
            std::initializer_list<uint8_t>{0x49, 0xF7, 0xF2});
        divideCode.insert(divideCode.end(), {0x48, 0x39, 0xC0});
        NativeStoreRegister(divideCode, 0);
        NativeStoreRegister(divideCode, 2);
        NativeProbeSuffix(divideCode);
        NativeProbeCode executable(divideCode);
        uint64_t random = signedDivide ? 0x1D1F001ULL : 0xD1F0001ULL;
        for (uint32_t sample = 0; sample < 128; ++sample) {
            NativeProbeState initial{};
            for (uint64_t& value : initial.gpr) value = NextFuzz(random);
            initial.rflags = 0x02u | (NextFuzz(random) &
                static_cast<uint64_t>(VM_FLAG_STATUS_MASK | VM_FLAG_DF));
            if (signedDivide) {
                const int64_t dividend = static_cast<int64_t>(NextFuzz(random) >> 2u);
                initial.gpr[0] = static_cast<uint64_t>(dividend);
                initial.gpr[2] = dividend < 0 ? UINT64_MAX : 0;
                int64_t divisor = static_cast<int64_t>((NextFuzz(random) | 1u) >> 1u);
                if (divisor == 0 || divisor == -1) divisor = 3;
                initial.gpr[10] = static_cast<uint64_t>(divisor);
            } else {
                initial.gpr[2] = 0;
                initial.gpr[10] = NextFuzz(random) | 1u;
            }
            NativeProbeState native = initial;
            uint32_t exceptionCode = 0;
            Require(InvokeNativeProbe(executable.Function(), &native, exceptionCode),
                "normal native DIV/IDIV probe raised #DE");
            VMMicroMachineState micro{};
            std::copy(std::begin(initial.gpr), std::end(initial.gpr), micro.gpr.begin());
            micro.rflags = native.observedInitialFlags;
            VMMicroExecutionOptions options{};
            options.registerCount = 32;
            options.maxSteps = 100000;
            VMMicroMemoryView noMemory{};
            std::string error;
            Require(VMMicroSemanticExecutor::Execute(
                    divideTranslation.bytecode.data(), divideTranslation.bytecode.size(),
                    maps.reverse.data(), divideTranslation.operandCodec,
                    micro, noMemory, options, error),
                "translated normal DIV/IDIV probe failed: " + error);
            for (uint8_t family = 0; family < 16; ++family) {
                Require(micro.gpr[family] == native.gpr[family],
                    "native DIV/IDIV GPR mismatch at family " + std::to_string(family));
            }
            Require(micro.rflags == native.rflags,
                "native DIV/IDIV observable RFLAGS mismatch");
        }

        NativeProbeState divideByZero{};
        divideByZero.rflags = 0x202u;
        divideByZero.gpr[0] = 1;
        divideByZero.gpr[2] = 0;
        divideByZero.gpr[10] = 0;
        uint32_t exceptionCode = 0;
        Require(!InvokeNativeProbe(executable.Function(), &divideByZero, exceptionCode) &&
            exceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO,
            "generated native divide-by-zero probe did not raise #DE");
        VMMicroMachineState microFault{};
        microFault.gpr[0] = 1;
        microFault.gpr[10] = 0;
        microFault.rflags = 0x202u;
        VMMicroExecutionOptions options{};
        options.registerCount = 32;
        VMMicroMemoryView noMemory{};
        std::string error;
        Require(!VMMicroSemanticExecutor::Execute(
                divideTranslation.bytecode.data(), divideTranslation.bytecode.size(),
                maps.reverse.data(), divideTranslation.operandCodec,
                microFault, noMemory, options, error) &&
            microFault.fault == VMMicroFault::DivideError,
            "translated divide-by-zero did not produce VM #DE");
    }
}
#elif defined(_WIN32) && defined(_M_IX86)
void TestNativeMachineCodeDifferentialGate() {
    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x3E));
    KeepRuntimeSupportedOpcodes(maps, false);
    auto x86Register = [](CipherShell::RegisterId id,
                          CipherShell::OperandAction action) {
        CipherShell::OperandIR operand = RegisterOperand(id, action);
        operand.width = 32;
        return operand;
    };
    auto convertFunction = [&](CipherShell::Function function) {
        for (auto& block : function.blocks) {
            for (auto& instruction : block.instructions) {
                instruction.machineMode = CipherShell::MachineMode::X86;
                instruction.addressWidth = 32;
                instruction.operandWidth = 32;
                instruction.stackWidth = 32;
            }
        }
        return function;
    };
    auto runCorpus = [&](const TranslationResult& translation,
                         const std::vector<uint8_t>& code,
                         bool memoryProbe,
                         uint8_t mode,
                         uint32_t count) {
        NativeProbeCode executable(code);
        uint64_t random = 0x3E000001ULL + mode;
        for (uint32_t sample = 0; sample < count; ++sample) {
            std::vector<uint8_t> memory(128);
            for (uint8_t& byte : memory) byte = static_cast<uint8_t>(NextFuzz(random));
            const auto initialMemory = memory;
            NativeProbeState initial{};
            for (uint8_t family = 0; family < 8; ++family) {
                initial.gpr[family] = static_cast<uint32_t>(NextFuzz(random));
            }
            if (mode == 2u) {
                initial.gpr[3] = (sample & 1u) == 0u ? initial.gpr[0] :
                    static_cast<uint32_t>(initial.gpr[0] ^ 0xA5A5A5A5u);
            } else if (mode == 3u) {
                initial.gpr[2] = 0;
                initial.gpr[3] = static_cast<uint32_t>(NextFuzz(random)) | 1u;
            } else if (mode == 4u) {
                const int32_t dividend = static_cast<int32_t>(NextFuzz(random) >> 3u);
                initial.gpr[0] = static_cast<uint32_t>(dividend);
                initial.gpr[2] = dividend < 0 ? UINT32_MAX : 0;
                int32_t divisor = static_cast<int32_t>((NextFuzz(random) | 1u) >> 2u);
                if (divisor == 0 || divisor == -1) divisor = 3;
                initial.gpr[3] = static_cast<uint32_t>(divisor);
            }
            if (memoryProbe) initial.gpr[2] =
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(memory.data()));
            initial.rflags = 0x02u | (NextFuzz(random) &
                static_cast<uint64_t>(VM_FLAG_STATUS_MASK | VM_FLAG_DF));
            NativeProbeState native = initial;
            uint32_t exceptionCode = 0;
            Require(InvokeNativeProbe(executable.Function(), &native, exceptionCode),
                "Win32 generated native probe faulted unexpectedly");
            const auto expectedMemory = memory;
            memory = initialMemory;
            VMMicroMachineState micro{};
            std::copy(std::begin(initial.gpr), std::end(initial.gpr), micro.gpr.begin());
            micro.rflags = native.observedInitialFlags;
            VMMicroMemoryView view{};
            if (memoryProbe) {
                view.data = memory.data();
                view.size = memory.size();
                view.baseAddress = reinterpret_cast<uintptr_t>(memory.data());
            }
            VMMicroExecutionOptions options{};
            options.registerCount = 32;
            options.addressWidth = 4;
            options.maxSteps = 100000;
            std::string error;
            Require(VMMicroSemanticExecutor::Execute(
                    translation.bytecode.data(), translation.bytecode.size(),
                    maps.reverse.data(), translation.operandCodec,
                    micro, view, options, error),
                "Win32 translated native probe failed: " + error);
            for (uint8_t family = 0; family < 8; ++family) {
                Require(static_cast<uint32_t>(micro.gpr[family]) ==
                    static_cast<uint32_t>(native.gpr[family]),
                    "Win32 native-probe GPR mismatch at family " +
                        std::to_string(family));
            }
            Require(static_cast<uint32_t>(micro.rflags) ==
                static_cast<uint32_t>(native.rflags),
                "Win32 native-probe observable EFLAGS mismatch");
            Require(memory == expectedMemory,
                "Win32 native-probe memory mismatch");
        }
    };

    CipherShell::Function addFunction = convertFunction(MakeAddFunction());
    auto& add = addFunction.blocks[0].instructions[0];
    add.operands = {
        x86Register(CipherShell::RegisterId::EAX, CipherShell::OperandAction::ReadWrite),
        x86Register(CipherShell::RegisterId::EBX, CipherShell::OperandAction::Read)};
    const TranslationResult addTranslation = TranslateForGate(
        addFunction, 0x3EADD3EADD3EADDULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(addTranslation.success, "Win32 ADD probe translation failed");
    std::vector<uint8_t> addCode = NativeProbePrefixX86();
    X86LoadEax(addCode, 0);
    addCode.insert(addCode.end(), {0x03, 0x81});
    AppendU32(addCode, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        3u * sizeof(uint64_t)));
    X86StoreEax(addCode, 0);
    NativeProbeSuffixX86(addCode);
    runCorpus(addTranslation, addCode, false, 0, 256);

    CipherShell::Function memoryFunction = convertFunction(MakeMemoryAddFunction());
    auto& memoryAdd = memoryFunction.blocks[0].instructions[0];
    memoryAdd.operands[0].width = 32;
    memoryAdd.operands[0].memory.width = 32;
    memoryAdd.operands[0].memory.base = CipherShell::RegisterId::EDX;
    memoryAdd.operands[0].memory.baseInfo =
        CipherShell::DescribeRegister(CipherShell::RegisterId::EDX);
    memoryAdd.operands[0].memory.hasIndex = false;
    memoryAdd.operands[0].memory.hasDisplacement = false;
    memoryAdd.operands[0].memory.displacement = 0;
    memoryAdd.operands[1] = x86Register(
        CipherShell::RegisterId::EAX, CipherShell::OperandAction::Read);
    const TranslationResult memoryTranslation = TranslateForGate(
        memoryFunction, 0x3E0E3E0E3E0E3E0EULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(memoryTranslation.success, "Win32 memory ADD probe translation failed");
    std::vector<uint8_t> memoryCode = NativeProbePrefixX86();
    X86LoadEax(memoryCode, 0);
    X86LoadEdx(memoryCode, 2);
    memoryCode.insert(memoryCode.end(), {0x01, 0x02});
    NativeProbeSuffixX86(memoryCode);
    runCorpus(memoryTranslation, memoryCode, true, 1, 128);

    CipherShell::InstructionIR compare = add;
    compare.address = compare.rva = 0x6000;
    compare.mnemonic = CipherShell::InstructionMnemonic::Cmp;
    compare.mnemonicText = "cmp";
    compare.category = CipherShell::InstructionCategory::Compare;
    compare.flagsWritten = VM_FLAG_STATUS_MASK;
    compare.operands[0].action = CipherShell::OperandAction::Read;
    CipherShell::InstructionIR branch{};
    branch.address = branch.rva = 0x6003;
    branch.length = 2;
    branch.mnemonic = CipherShell::InstructionMnemonic::Jz;
    branch.mnemonicText = "jz";
    branch.category = CipherShell::InstructionCategory::ConditionalBranch;
    branch.branchKind = CipherShell::BranchKind::Equal;
    branch.machineMode = CipherShell::MachineMode::X86;
    branch.addressWidth = branch.operandWidth = branch.stackWidth = 32;
    branch.encoding = CipherShell::InstructionEncoding::Legacy;
    branch.instructionSet = CipherShell::InstructionSetClass::Scalar;
    branch.flagsRead = VM_FLAG_ZF;
    branch.hasBranchTarget = true;
    branch.branchTargetRVA = 0x600B;
    auto x86Move = [&](uint32_t rva, uint32_t value) {
        CipherShell::InstructionIR move{};
        move.address = move.rva = rva;
        move.length = 5;
        move.mnemonic = CipherShell::InstructionMnemonic::Mov;
        move.mnemonicText = "mov";
        move.category = CipherShell::InstructionCategory::DataTransfer;
        move.machineMode = CipherShell::MachineMode::X86;
        move.addressWidth = move.operandWidth = move.stackWidth = 32;
        move.encoding = CipherShell::InstructionEncoding::Legacy;
        move.instructionSet = CipherShell::InstructionSetClass::Scalar;
        move.operands.push_back(x86Register(
            CipherShell::RegisterId::EDX, CipherShell::OperandAction::Write));
        CipherShell::OperandIR immediate{};
        immediate.type = CipherShell::OperandType::Immediate;
        immediate.action = CipherShell::OperandAction::Read;
        immediate.visibility = CipherShell::OperandVisibility::Explicit;
        immediate.width = 32;
        immediate.immediate = value;
        move.operands.push_back(immediate);
        return move;
    };
    auto falseMove = x86Move(0x6005, 0x111);
    auto ret = addFunction.blocks[0].instructions[1];
    ret.address = ret.rva = 0x600A;
    auto trueMove = x86Move(0x600B, 0x222);
    auto trueRet = ret;
    trueRet.address = trueRet.rva = 0x6010;
    CipherShell::BasicBlock branchBlock{};
    branchBlock.startAddress = 0x6000;
    branchBlock.endAddress = 0x6011;
    branchBlock.instructionCount = 6;
    branchBlock.instructions = {compare, branch, falseMove, ret, trueMove, trueRet};
    CipherShell::Function branchFunction{};
    branchFunction.entryAddress = 0x6000;
    branchFunction.size = 0x11;
    branchFunction.blocks.push_back(branchBlock);
    branchFunction.boundaryTrusted = true;
    const TranslationResult branchTranslation = TranslateForGate(
        branchFunction, 0x3EB12A3EB12A3EB1ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(branchTranslation.success, "Win32 Jcc probe translation failed");
    std::vector<uint8_t> branchCode = NativeProbePrefixX86();
    X86LoadEax(branchCode, 0);
    branchCode.insert(branchCode.end(), {0x3B, 0x81});
    AppendU32(branchCode, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
        3u * sizeof(uint64_t)));
    branchCode.insert(branchCode.end(), {0x75, 0x07,
        0xBA, 0x22, 0x02, 0x00, 0x00, 0xEB, 0x05,
        0xBA, 0x11, 0x01, 0x00, 0x00});
    X86StoreEdx(branchCode, 2);
    NativeProbeSuffixX86(branchCode);
    runCorpus(branchTranslation, branchCode, false, 2, 256);

    for (const bool signedDivide : {false, true}) {
        CipherShell::Function divideFunction = convertFunction(MakeAddFunction());
        auto& divide = divideFunction.blocks[0].instructions[0];
        divide.mnemonic = signedDivide ? CipherShell::InstructionMnemonic::Idiv :
            CipherShell::InstructionMnemonic::Div;
        divide.mnemonicText = signedDivide ? "idiv" : "div";
        divide.flagsWritten = 0;
        divide.flagsUndefined = VM_FLAG_STATUS_MASK;
        divide.operands = {x86Register(
            CipherShell::RegisterId::EBX, CipherShell::OperandAction::Read)};
        AppendAccumulatorSelfCompare(
            divideFunction, CipherShell::RegisterId::EAX, 32u);
        const TranslationResult translation = TranslateForGate(
            divideFunction, signedDivide ? 0x31D1F31D1F31D1F3ULL :
                0x3D1F03D1F03D1F03ULL,
            VMMicroDensity::Heavy, VM_MICRO_HEAVY_MIN_RATIO, maps);
        Require(translation.success, "Win32 DIV/IDIV probe translation failed");
        std::vector<uint8_t> code = NativeProbePrefixX86();
        X86LoadEax(code, 0);
        X86LoadEdx(code, 2);
        code.insert(code.end(), signedDivide ?
            std::initializer_list<uint8_t>{0xF7, 0xB9} :
            std::initializer_list<uint8_t>{0xF7, 0xB1});
        AppendU32(code, static_cast<uint32_t>(offsetof(NativeProbeState, gpr) +
            3u * sizeof(uint64_t)));
        code.insert(code.end(), {0x39, 0xC0});
        X86StoreEax(code, 0);
        X86StoreEdx(code, 2);
        NativeProbeSuffixX86(code);
        runCorpus(translation, code, false, signedDivide ? 4u : 3u, 128);

        NativeProbeCode executable(code);
        NativeProbeState zero{};
        zero.rflags = 0x202u;
        zero.gpr[0] = 1;
        zero.gpr[3] = 0;
        uint32_t exceptionCode = 0;
        Require(!InvokeNativeProbe(executable.Function(), &zero, exceptionCode) &&
            exceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO,
            "Win32 native divide-by-zero did not raise #DE");
        VMMicroMachineState micro{};
        micro.gpr[0] = 1;
        micro.gpr[3] = 0;
        micro.rflags = 0x202u;
        VMMicroExecutionOptions options{};
        options.registerCount = 32;
        options.addressWidth = 4;
        VMMicroMemoryView noMemory{};
        std::string error;
        Require(!VMMicroSemanticExecutor::Execute(
                translation.bytecode.data(), translation.bytecode.size(),
                maps.reverse.data(), translation.operandCodec,
                micro, noMemory, options, error) &&
            micro.fault == VMMicroFault::DivideError,
            "Win32 translated divide-by-zero did not produce VM #DE");
    }
}
#else
void TestNativeMachineCodeDifferentialGate() {
    throw TestFailure("native machine-code differential gate requires an MSVC x86/x64 target");
}
#endif

void TestTranslatorUnsupportedAndFlagsBridgeFailClosed() {
    CipherShell::Function unsupported = MakeAddFunction();
    auto& first = unsupported.blocks[0].instructions[0];
    first.mnemonic = CipherShell::InstructionMnemonic::Unsupported;
    first.category = CipherShell::InstructionCategory::Other;
    first.operands.clear();
    first.flagsWritten = 0;
    OpcodeMaps maps = MakeOpcodeMaps(MakeSeed(0x2C));
    KeepRuntimeSupportedOpcodes(maps, true);
    const TranslationResult rejected = TranslateForGate(
        unsupported, 0x2222333344445555ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(!rejected.success && !rejected.failures.empty(),
        "不支持 x86 指令未 fail-closed");

    CipherShell::Function bridgeFlags = MakeAddFunction();
    auto& simd = bridgeFlags.blocks[0].instructions[0];
    simd.mnemonic = CipherShell::InstructionMnemonic::Simd;
    simd.category = CipherShell::InstructionCategory::Simd;
    simd.instructionSet = CipherShell::InstructionSetClass::Sse;
    simd.operands.clear();
    simd.flagsWritten = VM_FLAG_ZF;
    const TranslationResult bridgeRejected = TranslateForGate(
        bridgeFlags, 0x6666777788889999ULL, VMMicroDensity::Heavy,
        VM_MICRO_HEAVY_MIN_RATIO, maps);
    Require(!bridgeRejected.success && !bridgeRejected.failures.empty(),
        "读写算术 flags 的 native bridge 未 fail-closed");
}

void TestHotspotTierCapAndAutoDowngrade() {
    CipherShell::HotspotAnalyzer analyzer;
    CipherShell::HotspotConfig config{};
    config.frequencyThreshold = 100;
    config.loopDepthThreshold = 2;
    config.maxAllowedLevel = 2;
    config.autoDowngrade = true;

    CipherShell::Function function = MakeAddFunction();
    function.name = "render_loop";
    function.isLeaf = false;
    function.assignedLevel = 5;
    std::vector<CipherShell::Function> functions = {function};
    auto hotspots = analyzer.AnalyzeFunctions(functions, config);
    Require(hotspots.size() == 1 && !hotspots.front().isCritical,
        "hotspot regression fixture was not classified as the intended low-score hotspot");

    analyzer.GenerateSuggestions(hotspots, 5, config);
    Require(hotspots.front().suggestedLevel == config.maxAllowedLevel,
        "auto hotspot downgrade exceeded maxAllowedLevel");
    analyzer.ApplySuggestions(functions, hotspots);
    Require(functions.front().assignedLevel == config.maxAllowedLevel,
        "hotspot tier cap was not applied to the production function profile");

    config.autoDowngrade = false;
    config.maxAllowedLevel = 1;
    hotspots = analyzer.AnalyzeFunctions(functions, config);
    Require(hotspots.size() == 1, "disabled auto-downgrade fixture lost hotspot classification");
    analyzer.GenerateSuggestions(hotspots, 5, config);
    Require(hotspots.front().suggestedLevel == hotspots.front().currentLevel,
        "disabled autoDowngrade changed the current protection level");
}

void Run(const char* name, void (*test)(), int& failures) {
    try {
        test();
        std::cout << "[PASS] " << name << '\n';
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
    }
}

} // namespace

int main() {
    int failures = 0;
    Run("全微语义紧凑编码往返", &TestCodecAllSemanticsRoundTrip, failures);
    Run("变长边界与截断 fail-closed", &TestVariableLengthAndBoundaries, failures);
    Run("non-canonical varint fail-closed", &TestRejectsNonCanonicalVarint, failures);
    Run("per-build opcode/operand 编码变异", &TestPerBuildOperandAndOpcodeVariation, failures);
    Run("per-instruction K variant selector", &TestPerInstructionVariantSelector, failures);
    Run("变长流 verifier fail-closed", &TestStreamVerifierFailClosed, failures);
    Run("完整架构状态差分模糊语料", &TestDifferentialArchitectureState, failures);
    Run("lazy flags 全消费者路径", &TestLazyFlagsAndConsumers, failures);
    Run("lazy flags overwrite/update preservation",
        &TestLazyFlagsOverwriteAndExplicitUpdatePreservation, failures);
    Run("lazy flags 条件跳转", &TestLazyFlagsConditionalBranch, failures);
    Run("DIV/IDIV 128-bit 与 #DE", &TestWideDivIdivAndDivideError, failures);
    Run("寻址与内存边界", &TestAddressingAndMemoryBoundaries, failures);
    Run("executor 完整流预验证", &TestExecutorRejectsMalformedStreamBeforeSideEffects, failures);
    Run("Translator 8:1/seed差异/链路差分", &TestTranslatorHeavyRatioSeedVariationAndDifferential,
        failures);
    Run("Translator SIB寻址差分", &TestTranslatorComplexAddressDifferential, failures);
    Run("Translator DIV/#DE/32-bit implicit writeback differential",
        &TestTranslatorWideDivideDifferentialAndZeroExtend, failures);
    Run("Translator internal CALL/address-size differential",
        &TestTranslatorInternalCallAndAddressSizeDifferential, failures);
    Run("Translator implicit atomic XCHG fail-closed",
        &TestTranslatorRejectsImplicitAtomicMemoryXchg, failures);
    Run("Translator stack/implicit flags differential",
        &TestTranslatorStackAndImplicitFlagsDifferential, failures);
    Run("native differential evidence contract fail-closed",
        &TestNativeDifferentialEvidenceContractFailClosed, failures);
    Run("controlled native CPU probes (partial non-production evidence)",
        &TestNativeMachineCodeDifferentialGate, failures);
    Run("Translator unsupported/flags bridge fail-closed",
        &TestTranslatorUnsupportedAndFlagsBridgeFailClosed, failures);
    Run("hotspot heavy/light/CFG tier cap",
        &TestHotspotTierCapAndAutoDowngrade, failures);
    return failures == 0 ? 0 : 1;
}
