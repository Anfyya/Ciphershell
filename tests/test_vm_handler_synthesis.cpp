#include "packer/mutation/mutation_engine.h"
#include "packer/transforms/vm_handler_semantic_codegen.h"
#include "packer/transforms/vm_handler_synthesizer.h"
#include "packer/vm/micro_semantics.h"
#include "packer/vm/vm_schema.h"

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using CipherShell::MutatedISA;
using CipherShell::MutationConfig;
using CipherShell::MutationEngine;
using CipherShell::VMHandlerArchitecture;
using CipherShell::VMHandlerSemanticCodegenConfig;
using CipherShell::VMHandlerSemanticCodegenResult;
using CipherShell::VMHandlerSynthesisConfig;
using CipherShell::VMHandlerSynthesisResult;
using CipherShell::VMHandlerSynthesizer;
using CipherShell::GenerateVMHandlerSemanticKernel;
using CipherShell::ValidateVMHandlerSemanticVariantKernel;
using CipherShell::VMOpcodeDescriptor;
using CipherShell::VMSynthesizedHandler;
using CipherShell::MicroInstruction;
using CipherShell::VMMicroExecutionOptions;
using CipherShell::VMMicroFault;
using CipherShell::VMMicroMachineState;
using CipherShell::VMMicroMemoryView;
using CipherShell::VMMicroSemanticExecutor;
using CipherShell::VMSchema;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

constexpr uint32_t kTestVirtualProtectIatRVA = 0x100u;
constexpr uint32_t kTestFlushInstructionCacheIatRVA = 0x110u;
constexpr size_t kTestImageSize = 0x200u;
constexpr uint32_t kCallHostImportSlotRVA = 0x140u;
constexpr uint32_t kCallHostNativeTargetRVA = 0x180u;
constexpr uint32_t kInstructionBridgeTargetRVA = 0x300u;
constexpr size_t kCallHostImageSize = 0x1000u;
constexpr DWORD kIntegerOverflowExceptionCode = 0xC0000095u;
constexpr std::array<uint8_t, 4> kSemanticWidths = {1u, 2u, 4u, 8u};
constexpr std::array<uint8_t, 2> kCoreStrategies = {0u, 1u};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

std::array<uint8_t, 32> MakeSeed(uint8_t domain) {
    std::array<uint8_t, 32> seed{};
    uint32_t state = 0x9E3779B9u ^ (static_cast<uint32_t>(domain) * 0x85EBCA6Bu);
    for (size_t index = 0; index < seed.size(); ++index) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        seed[index] = static_cast<uint8_t>((state >> ((index & 3u) * 8u)) ^ index);
    }
    return seed;
}

VMHandlerSynthesisConfig MakeConfig(
    VMHandlerArchitecture architecture,
    const std::array<uint8_t, 32>& seed)
{
    MutationConfig mutation{};
    mutation.seed = seed;
    mutation.registerCount = 24;
    mutation.randomizeOpcodeMap = true;
    mutation.randomizeRegisterMap = true;
    mutation.mutateHandlers = true;
    mutation.embedJunkHandlers = true;
    mutation.requestedJunkHandlerCount = 12;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool supported = architecture == VMHandlerArchitecture::X64
            ? descriptor.runtimeSupportedX64
            : descriptor.runtimeSupportedX86;
        if (supported) {
            mutation.validOpcodes.push_back(
                static_cast<uint8_t>(descriptor.opcode));
        }
    }

    MutationEngine engine;
    Require(engine.Initialize(mutation), "MutationEngine 拒绝固定测试 seed");
    const MutatedISA isa = engine.GenerateMutatedISA();

    VMHandlerSynthesisConfig config{};
    config.architecture = architecture;
    config.buildSeed = seed;
    config.handlerSemanticToSlot = isa.handlerSemanticToSlot;
    config.handlerSlotToSemantic = isa.handlerSlotToSemantic;
    config.handlerVariants = isa.handlerVariants;
    config.operandCodec.opcodeXor = static_cast<uint8_t>(seed[3] | 1u);
    config.operandCodec.opcodeAdd = static_cast<uint8_t>(seed[7] | 1u);
    config.operandCodec.opcodeRotate = static_cast<uint8_t>((seed[11] % 7u) + 1u);
    config.variantCount = VM_HANDLER_VARIANT_COUNT;
    config.minimumJunkBytesPerHandler = 96;
    config.virtualProtectIatRVA = kTestVirtualProtectIatRVA;
    // 入口从 context 获取这两个 API；真实 PE 路径也可用非零 IAT RVA 覆盖。
    config.flushInstructionCacheIatRVA = kTestFlushInstructionCacheIatRVA;
    config.encryptHandlerBodies = true;
    config.emitCetLandingPads = true;
    Require(config.virtualProtectIatRVA != 0,
        "测试配置未设置 VirtualProtect IAT RVA");
    Require(config.flushInstructionCacheIatRVA != 0,
        "测试配置未设置 FlushInstructionCache IAT RVA");
    return config;
}

bool RangeInside(size_t total, uint32_t offset, uint32_t size) {
    return offset <= total && size <= total - offset;
}

std::vector<uint8_t> Slice(
    const std::vector<uint8_t>& bytes,
    uint32_t offset,
    uint32_t size)
{
    Require(RangeInside(bytes.size(), offset, size), "切片越过合成 image 边界");
    return std::vector<uint8_t>(bytes.begin() + offset, bytes.begin() + offset + size);
}

constexpr std::array<uint8_t, 22> kExpectedX64TailStackCode = {
    0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x85,0xC0,0x75,0x07,
    0x48,0x8D,0x05,0x09,0x00,0x00,0x00,0x48,0x83,0xC4,0x28
};
constexpr std::array<uint8_t, 6> kExpectedX64TailLeafCode = {
    0x48,0x85,0xC0,0xFF,0xE0,0xC3
};
constexpr std::array<uint8_t, 8> kExpectedX64TailUnwindInfo = {
    0x01,0x04,0x01,0x00,0x04,0x42,0x00,0x00
};

void ValidateDirectTailUnwindCoverage(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result)
{
    std::vector<const VMSynthesizedHandler*> handlers;
    handlers.reserve(result.handlers.size() + result.junkHandlers.size());
    for (const auto& handler : result.handlers) handlers.push_back(&handler);
    for (const auto& handler : result.junkHandlers) handlers.push_back(&handler);

    if (config.architecture == VMHandlerArchitecture::X86) {
        Require(result.unwindEntries.empty(),
            "x86 handler 合成不应产生 Win64 unwind 记录");
        for (const auto* handler : handlers) {
            Require(handler->dispatchUnwindOffset == 0 &&
                    handler->dispatchUnwindSize == 0,
                "x86 handler 意外声明 direct-tail unwind 范围");
        }
        return;
    }

    std::set<std::pair<uint32_t, uint32_t>> expectedRanges;
    for (const auto* handler : handlers) {
        Require(handler->dispatchUnwindOffset >= handler->dispatchTailOffset &&
                handler->dispatchUnwindSize == kExpectedX64TailStackCode.size() &&
                static_cast<uint64_t>(handler->dispatchUnwindOffset) +
                    handler->dispatchUnwindSize +
                    kExpectedX64TailLeafCode.size() ==
                    handler->plaintextBody.size(),
            "x64 handler direct-tail unwind 相对范围错误");
        Require(std::equal(kExpectedX64TailStackCode.begin(),
                    kExpectedX64TailStackCode.end(),
                    handler->plaintextBody.begin() +
                        handler->dispatchUnwindOffset) &&
                std::equal(kExpectedX64TailLeafCode.begin(),
                    kExpectedX64TailLeafCode.end(),
                    handler->plaintextBody.begin() +
                        handler->dispatchUnwindOffset +
                        handler->dispatchUnwindSize),
            "x64 handler direct-tail 栈帧机器码与 unwind 契约不一致");
        const uint64_t begin64 = static_cast<uint64_t>(handler->storageOffset) +
            handler->dispatchUnwindOffset;
        const uint64_t end64 = begin64 + handler->dispatchUnwindSize;
        Require(end64 <= (std::numeric_limits<uint32_t>::max)(),
            "x64 handler direct-tail unwind 绝对范围溢出");
        const std::pair<uint32_t, uint32_t> range = {
            static_cast<uint32_t>(begin64), static_cast<uint32_t>(end64)};
        Require(expectedRanges.insert(range).second,
            "x64 handler direct-tail unwind 范围重复");

        size_t matches = 0;
        for (const auto& unwind : result.unwindEntries) {
            if (unwind.beginOffset != range.first ||
                unwind.endOffset != range.second) continue;
            ++matches;
            Require(RangeInside(result.image.size(), unwind.unwindOffset,
                        static_cast<uint32_t>(kExpectedX64TailUnwindInfo.size())) &&
                    std::equal(kExpectedX64TailUnwindInfo.begin(),
                        kExpectedX64TailUnwindInfo.end(),
                        result.image.begin() + unwind.unwindOffset),
                "x64 handler direct-tail UNWIND_INFO 编码错误");
        }
        Require(matches == 1,
            "每个 x64 semantic/junk handler 必须恰有一条 direct-tail unwind 记录");

        // 部分语义（flags/control 类 micro-op、CPUID 桥接等）在核心体内还会调用
        // flag-materializer 等辅助函数，需要临时调整栈指针；这段调整同样是
        // 非叶子代码，必须有独立的 UNWIND_INFO 记录才能被 SEH 正确展开。
        // 这类记录与 direct-tail 记录一样合法，必须一并计入预期集合。
        for (const auto& funclet : handler->semanticStackFunclets) {
            const uint64_t fBegin64 =
                static_cast<uint64_t>(handler->storageOffset) + funclet.offset;
            const uint64_t fEnd64 = fBegin64 + funclet.size;
            Require(fEnd64 <= (std::numeric_limits<uint32_t>::max)(),
                "x64 handler stack-funclet unwind 绝对范围溢出");
            const std::pair<uint32_t, uint32_t> fRange = {
                static_cast<uint32_t>(fBegin64), static_cast<uint32_t>(fEnd64)};
            Require(expectedRanges.insert(fRange).second,
                "x64 handler stack-funclet unwind 范围重复");

            size_t fMatches = 0;
            for (const auto& unwind : result.unwindEntries) {
                if (unwind.beginOffset != fRange.first ||
                    unwind.endOffset != fRange.second) continue;
                ++fMatches;
            }
            Require(fMatches == 1,
                "每条语义 stack-funclet 必须恰有一条对应的 unwind 记录");
        }
    }

    size_t expectedFuncletCount = 0;
    for (const auto* handler : handlers)
        expectedFuncletCount += handler->semanticStackFunclets.size();

    size_t physicalTailEntries = 0;
    const uint64_t encryptedEnd =
        static_cast<uint64_t>(result.encryptedHandlerOffset) +
        result.encryptedHandlerSize;
    for (const auto& unwind : result.unwindEntries) {
        if (unwind.beginOffset < result.encryptedHandlerOffset ||
            static_cast<uint64_t>(unwind.beginOffset) >= encryptedEnd) continue;
        ++physicalTailEntries;
        Require(expectedRanges.count({unwind.beginOffset, unwind.endOffset}) == 1,
            "handler 密文区存在未绑定 semantic/junk tail 的 unwind 记录");
    }
    Require(physicalTailEntries == handlers.size() + expectedFuncletCount,
        "x64 handler direct-tail/stack-funclet unwind 物理覆盖数量不完整");
}

std::vector<const VMSynthesizedHandler*> SortedHandlers(
    const VMHandlerSynthesisResult& result)
{
    std::vector<const VMSynthesizedHandler*> handlers;
    handlers.reserve(result.handlers.size());
    for (const auto& handler : result.handlers) handlers.push_back(&handler);
    std::sort(handlers.begin(), handlers.end(), [](const auto* left, const auto* right) {
        return std::pair<uint8_t, uint8_t>(left->semantic, left->variant) <
            std::pair<uint8_t, uint8_t>(right->semantic, right->variant);
    });
    return handlers;
}

std::vector<uint8_t> CanonicalPlaintext(const VMHandlerSynthesisResult& result) {
    std::vector<uint8_t> bytes;
    for (const VMSynthesizedHandler* handler : SortedHandlers(result)) {
        bytes.push_back(handler->semantic);
        bytes.push_back(handler->variant);
        const uint32_t size = static_cast<uint32_t>(handler->plaintextBody.size());
        bytes.push_back(static_cast<uint8_t>(size));
        bytes.push_back(static_cast<uint8_t>(size >> 8));
        bytes.push_back(static_cast<uint8_t>(size >> 16));
        bytes.push_back(static_cast<uint8_t>(size >> 24));
        bytes.insert(bytes.end(), handler->plaintextBody.begin(), handler->plaintextBody.end());
    }
    return bytes;
}

std::unordered_map<uint32_t, size_t> FourGramCounts(const std::vector<uint8_t>& bytes) {
    std::unordered_map<uint32_t, size_t> counts;
    if (bytes.size() < 4) return counts;
    for (size_t index = 0; index + 4 <= bytes.size(); ++index) {
        const uint32_t gram = static_cast<uint32_t>(bytes[index]) |
            (static_cast<uint32_t>(bytes[index + 1]) << 8) |
            (static_cast<uint32_t>(bytes[index + 2]) << 16) |
            (static_cast<uint32_t>(bytes[index + 3]) << 24);
        ++counts[gram];
    }
    return counts;
}

double FourGramDiceSimilarity(
    const std::vector<uint8_t>& left,
    const std::vector<uint8_t>& right)
{
    const auto leftCounts = FourGramCounts(left);
    const auto rightCounts = FourGramCounts(right);
    size_t leftTotal = 0;
    size_t rightTotal = 0;
    size_t intersection = 0;
    for (const auto& item : leftCounts) leftTotal += item.second;
    for (const auto& item : rightCounts) rightTotal += item.second;
    for (const auto& item : leftCounts) {
        const auto found = rightCounts.find(item.first);
        if (found != rightCounts.end()) intersection += std::min(item.second, found->second);
    }
    if (leftTotal + rightTotal == 0) return left == right ? 1.0 : 0.0;
    return (2.0 * static_cast<double>(intersection)) /
        static_cast<double>(leftTotal + rightTotal);
}

struct RuntimeEncoding {
    std::unordered_map<uint8_t, uint8_t> forward;
    std::array<uint8_t, 256> reverse{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> semanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> slotToSemantic{};
    VM_OPERAND_CODEC codec{};
};

RuntimeEncoding MakeRuntimeEncoding(
    VMHandlerArchitecture architecture,
    const std::array<uint8_t, 32>& seed)
{
    MutationConfig mutation{};
    mutation.seed = seed;
    mutation.registerCount = 24;
    mutation.randomizeOpcodeMap = true;
    mutation.randomizeRegisterMap = true;
    mutation.mutateHandlers = true;
    mutation.embedJunkHandlers = true;
    mutation.requestedJunkHandlerCount = 12;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool supported = architecture == VMHandlerArchitecture::X64
            ? descriptor.runtimeSupportedX64
            : descriptor.runtimeSupportedX86;
        if (supported) {
            mutation.validOpcodes.push_back(
                static_cast<uint8_t>(descriptor.opcode));
        }
    }
    MutationEngine engine;
    Require(engine.Initialize(mutation), "执行门禁 MutationEngine 初始化失败");
    const MutatedISA isa = engine.GenerateMutatedISA();
    RuntimeEncoding encoding{};
    encoding.forward = isa.opcodeMap;
    encoding.reverse.fill(VM_HANDLER_INVALID);
    for (const auto& item : encoding.forward) encoding.reverse[item.second] = item.first;
    encoding.semanticToSlot = isa.handlerSemanticToSlot;
    encoding.slotToSemantic = isa.handlerSlotToSemantic;
    uint64_t seed64 = 0;
    std::memcpy(&seed64, seed.data(), sizeof(seed64));
    encoding.codec = VMSchema::DeriveOperandCodec(seed64, 0);
    return encoding;
}

MicroInstruction Uop(
    VM_MICRO_OPCODE opcode,
    std::initializer_list<uint64_t> operands = {},
    uint8_t variant = 0)
{
    const auto* descriptor = VMSchema::Lookup(opcode);
    Require(descriptor != nullptr && descriptor->operandCount == operands.size(),
        "执行门禁微操作参数数量错误");
    MicroInstruction instruction{};
    instruction.opcode = opcode;
    instruction.handlerVariant = variant;
    instruction.operandCount = descriptor->operandCount;
    size_t index = 0;
    for (uint64_t value : operands) instruction.operands[index++] = value;
    return instruction;
}

std::vector<uint8_t> EncodeRuntimeProgram(
    std::vector<MicroInstruction>& program,
    const RuntimeEncoding& encoding)
{
    std::vector<uint32_t> offsets;
    uint32_t offset = 0;
    for (const auto& instruction : program) {
        offsets.push_back(offset);
        uint32_t size = 0;
        std::string error;
        Require(VMSchema::EncodedSize(instruction, encoding.codec, size, error),
            "执行门禁无法计算微操作长度: " + error);
        Require(size <= std::numeric_limits<uint32_t>::max() - offset,
            "执行门禁 bytecode 偏移溢出");
        offset += size;
    }
    // 固定 U32 branch operand 不改变编码长度。
    Require(program.size() == 38, "执行门禁关键 handler 程序布局意外变化");
    program[31].operands[1] = offsets[35];
    program[34].operands[0] = offsets[37];

    std::vector<uint8_t> bytecode;
    for (const auto& instruction : program) {
        std::string error;
        Require(VMSchema::Encode(
                instruction, encoding.forward, encoding.codec, bytecode, error),
            "执行门禁无法编码微操作: " + error);
    }
    const auto validation = VMSchema::ValidateStream(
        bytecode.data(), bytecode.size(), encoding.reverse.data(), encoding.codec, 32);
    Require(validation.success, "执行门禁关键 handler 流验证失败: " + validation.error);
    return bytecode;
}

std::vector<uint8_t> EncodeStraightLineRuntimeProgram(
    const std::vector<MicroInstruction>& program,
    const RuntimeEncoding& encoding)
{
    std::vector<uint8_t> bytecode;
    for (const auto& instruction : program) {
        std::string error;
        Require(VMSchema::Encode(
                instruction, encoding.forward, encoding.codec, bytecode, error),
            "无法编码直线微操作流: " + error);
    }
    const auto validation = VMSchema::ValidateStream(
        bytecode.data(), bytecode.size(), encoding.reverse.data(),
        encoding.codec, 24);
    Require(validation.success, "直线微操作流校验失败: " + validation.error);
    return bytecode;
}

std::vector<MicroInstruction> CriticalHandlerProgram(
    uint64_t memoryAddress,
    bool equalComparison,
    uint8_t width)
{
    const uint64_t signedHigh = width == 8u
        ? (std::numeric_limits<uint64_t>::max)()
        : (std::numeric_limits<uint32_t>::max)();
    const uint64_t signedLow = width == 8u
        ? static_cast<uint64_t>(static_cast<int64_t>(-100))
        : static_cast<uint32_t>(static_cast<int32_t>(-100));
    std::vector<MicroInstruction> program = {
        Uop(VM_UOP_PUSH_VREG, {0, width, 0}, 0),
        Uop(VM_UOP_STORE_TEMP, {0}, 1),
        Uop(VM_UOP_LOAD_TEMP, {0}, 2),
        Uop(VM_UOP_PUSH_IMM, {5, width}, 3),
        Uop(VM_UOP_ADD, {width}, 0),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADD, width, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 1),
        Uop(VM_UOP_DUP, {}, 2),
        Uop(VM_UOP_POP_VREG, {1, width, 0, 1}, 3),
        Uop(VM_UOP_PUSH_IMM, {memoryAddress, width}, 0),
        Uop(VM_UOP_SWAP, {}, 1),
        Uop(VM_UOP_STORE, {width}, 2),
        Uop(VM_UOP_PUSH_IMM, {memoryAddress, width}, 3),
        Uop(VM_UOP_LOAD, {width}, 0),
        Uop(VM_UOP_STORE_TEMP, {1}, 1),
        Uop(VM_UOP_PUSH_IMM, {0, width}, 2),
        Uop(VM_UOP_PUSH_IMM, {100, width}, 3),
        Uop(VM_UOP_PUSH_IMM, {7, width}, 0),
        Uop(VM_UOP_UDIV_WIDE, {width}, 1),
        Uop(VM_UOP_POP_VREG, {3, width, 0, 1}, 2),
        Uop(VM_UOP_POP_VREG, {2, width, 0, 1}, 3),
        Uop(VM_UOP_PUSH_IMM, {signedHigh, width}, 0),
        Uop(VM_UOP_PUSH_IMM, {signedLow, width}, 1),
        Uop(VM_UOP_PUSH_IMM, {7, width}, 2),
        Uop(VM_UOP_IDIV_WIDE, {width}, 3),
        Uop(VM_UOP_POP_VREG, {6, width, 0, 1}, 0),
        Uop(VM_UOP_POP_VREG, {5, width, 0, 1}, 1),
        Uop(VM_UOP_PUSH_IMM, {9, width}, 2),
        Uop(VM_UOP_PUSH_IMM, {equalComparison ? 9u : 10u, width}, 3),
        Uop(VM_UOP_SUB, {width}, 0),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_SUB, width, VM_FLAG_STATUS_MASK, VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 1),
        Uop(VM_UOP_DROP, {}, 2),
        Uop(VM_UOP_BRANCH_IF, {VM_CONDITION_E, 0}, 3),
        Uop(VM_UOP_PUSH_IMM, {0, width}, 0),
        Uop(VM_UOP_POP_VREG, {4, width, 0, 1}, 1),
        Uop(VM_UOP_BRANCH, {0}, 2),
        Uop(VM_UOP_PUSH_IMM, {1, width}, 3),
        Uop(VM_UOP_POP_VREG, {4, width, 0, 1}, 0),
        Uop(VM_UOP_RET, {0}, 1),
    };
    return program;
}

class LoadedSynthImage final {
public:
    LoadedSynthImage() = default;
    ~LoadedSynthImage() {
#if defined(_M_X64)
        if (m_functionTableRegistered && !m_unwind.empty()) {
            RtlDeleteFunctionTable(m_unwind.data());
        }
#endif
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
    }
    LoadedSynthImage(const LoadedSynthImage&) = delete;
    LoadedSynthImage& operator=(const LoadedSynthImage&) = delete;

    bool Load(const VMHandlerSynthesisResult& result, std::string& error) {
        m_size = result.image.size();
        m_base = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m_base) {
            error = "VirtualAlloc 合成 image 失败";
            return false;
        }
        std::memcpy(m_base, result.image.data(), result.image.size());
        for (const auto& relocation : result.relocations) {
            if (relocation.offset > m_size) {
                error = "合成 image relocation 越界";
                return false;
            }
            if (relocation.type == IMAGE_REL_BASED_DIR64) {
                if (sizeof(uint64_t) > m_size - relocation.offset) {
                    error = "DIR64 relocation 越界";
                    return false;
                }
                uint64_t value = 0;
                std::memcpy(&value, m_base + relocation.offset, sizeof(value));
                value += reinterpret_cast<uintptr_t>(m_base);
                std::memcpy(m_base + relocation.offset, &value, sizeof(value));
            } else if (relocation.type == IMAGE_REL_BASED_HIGHLOW) {
                if (sizeof(uint32_t) > m_size - relocation.offset) {
                    error = "HIGHLOW relocation 越界";
                    return false;
                }
                uint32_t value = 0;
                std::memcpy(&value, m_base + relocation.offset, sizeof(value));
                value += static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_base));
                std::memcpy(m_base + relocation.offset, &value, sizeof(value));
            } else {
                error = "合成 image 出现未知 relocation 类型";
                return false;
            }
        }
        DWORD oldProtection = 0;
        if (!VirtualProtect(m_base, m_size, PAGE_EXECUTE_READ, &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(), m_base, m_size)) {
            error = "无法将合成 image 设置为 RX";
            return false;
        }
#if defined(_M_X64)
        if (result.architecture == VM_ARCH_X64) {
            m_unwind.reserve(result.unwindEntries.size());
            for (const auto& unwind : result.unwindEntries) {
                if (unwind.beginOffset >= unwind.endOffset ||
                    unwind.endOffset > m_size || unwind.unwindOffset >= m_size) {
                    error = "生成 runtime 的 unwind 描述越界";
                    return false;
                }
                RUNTIME_FUNCTION function{};
                function.BeginAddress = unwind.beginOffset;
                function.EndAddress = unwind.endOffset;
                function.UnwindData = unwind.unwindOffset;
                m_unwind.push_back(function);
            }
            if (m_unwind.empty() || !RtlAddFunctionTable(
                    m_unwind.data(), static_cast<DWORD>(m_unwind.size()),
                    reinterpret_cast<DWORD64>(m_base))) {
                error = "无法注册生成 runtime 的 x64 unwind 表";
                return false;
            }
            m_functionTableRegistered = true;
        }
#endif
        return true;
    }

    uint8_t* Base() const { return m_base; }

private:
    uint8_t* m_base = nullptr;
    size_t m_size = 0;
#if defined(_M_X64)
    std::vector<RUNTIME_FUNCTION> m_unwind;
    bool m_functionTableRegistered = false;
#endif
};

#if defined(_M_X64)
using SynthEntry = uint32_t (__fastcall*)(VM_MICRO_EXECUTION_CONTEXT*);
#elif defined(_M_IX86)
using SynthEntry = uint32_t (__cdecl*)(VM_MICRO_EXECUTION_CONTEXT*);
#endif

#if defined(_M_X64) || defined(_M_IX86)
uintptr_t gLastExceptionAddress = 0;

uint32_t InvokeSynthEntry(
    SynthEntry entry,
    VM_MICRO_EXECUTION_CONTEXT* context,
    DWORD* exceptionCode)
{
    *exceptionCode = 0;
    gLastExceptionAddress = 0;
    __try {
        return entry(context);
    } __except((*exceptionCode = GetExceptionCode(),
        gLastExceptionAddress = reinterpret_cast<uintptr_t>(
            GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
        EXCEPTION_EXECUTE_HANDLER)) {
        return VM_MICRO_ERR_HANDLER_BUG;
    }
}
#endif

void ValidateOneBuild(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result);

#if defined(_M_X64) || defined(_M_IX86)
volatile LONG gVirtualProtectCalls = 0;
volatile LONG gFlushInstructionCacheCalls = 0;
volatile LONG gLastVirtualProtectError = 0;
volatile LONG gLastFlushInstructionCacheError = 0;

BOOL WINAPI GateVirtualProtect(
    LPVOID address,
    SIZE_T size,
    DWORD protection,
    PDWORD oldProtection)
{
    InterlockedIncrement(&gVirtualProtectCalls);
    const BOOL success = ::VirtualProtect(address, size, protection, oldProtection);
    if (!success) InterlockedExchange(&gLastVirtualProtectError, GetLastError());
    return success;
}

BOOL WINAPI GateFlushInstructionCache(
    HANDLE process,
    LPCVOID address,
    SIZE_T size)
{
    InterlockedIncrement(&gFlushInstructionCacheCalls);
    const BOOL success = ::FlushInstructionCache(process, address, size);
    if (!success) InterlockedExchange(&gLastFlushInstructionCacheError, GetLastError());
    return success;
}

struct TestRuntimeIatImage {
    std::array<uint8_t, kTestImageSize> bytes{};
    VM_METADATA_HEADER metadata{};

    TestRuntimeIatImage() {
        const uintptr_t virtualProtect =
            reinterpret_cast<uintptr_t>(&GateVirtualProtect);
        const uintptr_t flushInstructionCache =
            reinterpret_cast<uintptr_t>(&GateFlushInstructionCache);
        std::memcpy(bytes.data() + kTestVirtualProtectIatRVA,
            &virtualProtect, sizeof(virtualProtect));
        std::memcpy(bytes.data() + kTestFlushInstructionCacheIatRVA,
            &flushInstructionCache, sizeof(flushInstructionCache));
        metadata.imageSize = static_cast<uint32_t>(bytes.size());
    }
};

class CallHostTestImage final {
public:
    explicit CallHostTestImage(
        uintptr_t importTarget,
        uintptr_t instructionBridgeTarget = 0)
    {
        m_base = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, kCallHostImageSize, MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE));
        if (!m_base) throw TestFailure("CALL_HOST test image VirtualAlloc 失败");
        std::memset(m_base, 0, kCallHostImageSize);

        const uintptr_t virtualProtect =
            reinterpret_cast<uintptr_t>(&GateVirtualProtect);
        const uintptr_t flushInstructionCache =
            reinterpret_cast<uintptr_t>(&GateFlushInstructionCache);
        std::memcpy(m_base + kTestVirtualProtectIatRVA,
            &virtualProtect, sizeof(virtualProtect));
        std::memcpy(m_base + kTestFlushInstructionCacheIatRVA,
            &flushInstructionCache, sizeof(flushInstructionCache));
        std::memcpy(m_base + kCallHostImportSlotRVA,
            &importTarget, sizeof(importTarget));

#if defined(_M_X64)
        constexpr uint64_t nativeResult = 0xC011A05764B17D5EULL;
        constexpr uint64_t noCarryResult = 0x0BADF00D12345678ULL;
        const std::array<uint8_t, 30> nativeTarget = {
            0xF3,0x0F,0x1E,0xFA,             // endbr64
            0x48,0xB8,                       // mov rax, imm64
            static_cast<uint8_t>(noCarryResult),
            static_cast<uint8_t>(noCarryResult >> 8u),
            static_cast<uint8_t>(noCarryResult >> 16u),
            static_cast<uint8_t>(noCarryResult >> 24u),
            static_cast<uint8_t>(noCarryResult >> 32u),
            static_cast<uint8_t>(noCarryResult >> 40u),
            static_cast<uint8_t>(noCarryResult >> 48u),
            static_cast<uint8_t>(noCarryResult >> 56u),
            0x48,0xBA,                       // mov rdx, imm64
            static_cast<uint8_t>(nativeResult),
            static_cast<uint8_t>(nativeResult >> 8u),
            static_cast<uint8_t>(nativeResult >> 16u),
            static_cast<uint8_t>(nativeResult >> 24u),
            static_cast<uint8_t>(nativeResult >> 32u),
            static_cast<uint8_t>(nativeResult >> 40u),
            static_cast<uint8_t>(nativeResult >> 48u),
            static_cast<uint8_t>(nativeResult >> 56u),
            0x48,0x0F,0x42,0xC2,             // cmovc rax, rdx
            0xF8,                            // clc: exported CF must clear
            0xC3
        };
#else
        constexpr uint32_t nativeResult = 0x64B17D5Eu;
        constexpr uint32_t noCarryResult = 0x12345678u;
        const std::array<uint8_t, 19> nativeTarget = {
            0xF3,0x0F,0x1E,0xFB,             // endbr32
            0xB8,                            // mov eax, imm32
            static_cast<uint8_t>(noCarryResult),
            static_cast<uint8_t>(noCarryResult >> 8u),
            static_cast<uint8_t>(noCarryResult >> 16u),
            static_cast<uint8_t>(noCarryResult >> 24u),
            0xBA,                            // mov edx, imm32
            static_cast<uint8_t>(nativeResult),
            static_cast<uint8_t>(nativeResult >> 8u),
            static_cast<uint8_t>(nativeResult >> 16u),
            static_cast<uint8_t>(nativeResult >> 24u),
            0x0F,0x42,0xC2,                  // cmovc eax, edx
            0xF8,                            // clc
            0xC3
        };
#endif
        std::memcpy(m_base + kCallHostNativeTargetRVA,
            nativeTarget.data(), nativeTarget.size());
        if (instructionBridgeTarget != 0) {
#if defined(_M_X64)
            const std::array<uint8_t, 12> bridgeTrampoline = {
                0x48,0xB8,                       // mov rax, imm64
                static_cast<uint8_t>(instructionBridgeTarget),
                static_cast<uint8_t>(instructionBridgeTarget >> 8u),
                static_cast<uint8_t>(instructionBridgeTarget >> 16u),
                static_cast<uint8_t>(instructionBridgeTarget >> 24u),
                static_cast<uint8_t>(instructionBridgeTarget >> 32u),
                static_cast<uint8_t>(instructionBridgeTarget >> 40u),
                static_cast<uint8_t>(instructionBridgeTarget >> 48u),
                static_cast<uint8_t>(instructionBridgeTarget >> 56u),
                0xFF,0xE0                        // jmp rax
            };
#else
            const std::array<uint8_t, 7> bridgeTrampoline = {
                0xB8,                            // mov eax, imm32
                static_cast<uint8_t>(instructionBridgeTarget),
                static_cast<uint8_t>(instructionBridgeTarget >> 8u),
                static_cast<uint8_t>(instructionBridgeTarget >> 16u),
                static_cast<uint8_t>(instructionBridgeTarget >> 24u),
                0xFF,0xE0                        // jmp eax
            };
#endif
            std::memcpy(m_base + kInstructionBridgeTargetRVA,
                bridgeTrampoline.data(), bridgeTrampoline.size());
        }
        m_metadata.imageSize = static_cast<uint32_t>(kCallHostImageSize);

        DWORD oldProtection = 0;
        if (!VirtualProtect(m_base, kCallHostImageSize, PAGE_EXECUTE_READ,
                &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(), m_base,
                kCallHostImageSize)) {
            const DWORD error = GetLastError();
            VirtualFree(m_base, 0, MEM_RELEASE);
            m_base = nullptr;
            throw TestFailure("CALL_HOST test image 无法转为 RX: " +
                std::to_string(error));
        }
    }

    ~CallHostTestImage() {
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
    }
    CallHostTestImage(const CallHostTestImage&) = delete;
    CallHostTestImage& operator=(const CallHostTestImage&) = delete;

    uint8_t* Base() const { return m_base; }
    VM_METADATA_HEADER* Metadata() { return &m_metadata; }

#if defined(_M_X64)
    static constexpr uint64_t NativeResult() { return 0xC011A05764B17D5EULL; }
#else
    static constexpr uint64_t NativeResult() { return 0x64B17D5Eu; }
#endif

private:
    uint8_t* m_base = nullptr;
    VM_METADATA_HEADER m_metadata{};
};

void CaptureCallHostExtendedState(VM_EXTENDED_STATE& state) {
    std::memset(&state, 0, sizeof(state));
#if defined(_M_X64)
    _fxsave64(state.xsaveArea);
#else
    _fxsave(state.xsaveArea);
#endif
    state.flags = 0;
}

VM_MICRO_EXECUTION_CONTEXT MakeRuntimeContext(
    const std::vector<uint8_t>& bytecode,
    const RuntimeEncoding& encoding,
    const VMHandlerSynthesisConfig& config,
    const std::array<uint8_t, VM_REGISTER_MAP_SIZE>& registerMap,
    TestRuntimeIatImage& testImage,
    const std::array<uint64_t, 32>& initialGprs,
    uint64_t initialFlags)
{
    VM_MICRO_EXECUTION_CONTEXT context{};
    for (size_t index = 0; index < initialGprs.size(); ++index)
        context.vregs[index] = initialGprs[index];
    context.vip = reinterpret_cast<uintptr_t>(bytecode.data());
    context.bytecodeBegin = context.vip;
    context.bytecodeEnd = context.vip + bytecode.size();
    context.reverseOpcodeMap =
        reinterpret_cast<uintptr_t>(encoding.reverse.data());
    context.registerMap = reinterpret_cast<uintptr_t>(registerMap.data());
    context.handlerSemanticToSlot =
        reinterpret_cast<uintptr_t>(config.handlerSemanticToSlot.data());
    context.imageBase = reinterpret_cast<uintptr_t>(testImage.bytes.data());
    context.metadata = reinterpret_cast<uintptr_t>(&testImage.metadata);
    context.operandCodec = encoding.codec;
    context.virtualFlags = initialFlags;
    context.architecture = static_cast<uint32_t>(config.architecture);
    return context;
}

std::string RuntimeByteWindow(
    const LoadedSynthImage& loaded,
    const VMHandlerSynthesisResult& result,
    uintptr_t address);

uint8_t CoreVariantForStrategy(
    const VMHandlerSynthesisConfig& config,
    VM_MICRO_OPCODE semantic,
    uint8_t wantedStrategy)
{
    for (uint8_t variant = 0; variant < config.variantCount; ++variant) {
        VMHandlerSemanticCodegenConfig codegen{};
        codegen.architecture = static_cast<uint32_t>(config.architecture);
        codegen.buildSeed = config.buildSeed;
        codegen.semantic = semantic;
        codegen.variant = variant;
        const auto generated = GenerateVMHandlerSemanticKernel(codegen);
        Require(generated.success,
            "无法为执行差分生成 " + std::to_string(semantic) +
            " 的 handler variant: " + generated.error);
        if (generated.semanticCoreVariantSize != 0u &&
            generated.semanticCoreStrategy == wantedStrategy) {
            return variant;
        }
    }
    throw TestFailure("执行差分未找到 semantic=" +
        std::to_string(semantic) + " strategy=" +
        std::to_string(wantedStrategy) + " 的真实业务核心变体");
}

std::vector<uint32_t> RuntimeInstructionOffsets(
    const std::vector<MicroInstruction>& program,
    const RuntimeEncoding& encoding)
{
    std::vector<uint32_t> offsets;
    offsets.reserve(program.size());
    uint32_t offset = 0;
    for (const auto& instruction : program) {
        offsets.push_back(offset);
        uint32_t size = 0;
        std::string error;
        Require(VMSchema::EncodedSize(instruction, encoding.codec, size, error),
            "执行差分无法计算微操作长度: " + error);
        Require(size <= (std::numeric_limits<uint32_t>::max)() - offset,
            "执行差分 bytecode 偏移溢出");
        offset += size;
    }
    return offsets;
}

void ExecuteOracleEquivalentProgram(
    const std::string& label,
    const std::vector<MicroInstruction>& program,
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage,
    const std::array<uint64_t, 32>& initialGprs,
    uint64_t initialFlags,
    std::vector<uint8_t>* memory = nullptr)
{
    const std::vector<uint8_t> bytecode =
        EncodeStraightLineRuntimeProgram(program, encoding);
    const std::vector<uint8_t> initialMemory = memory
        ? *memory : std::vector<uint8_t>{};

    VMMicroMachineState oracle{};
    oracle.gpr = initialGprs;
    oracle.rflags = initialFlags;
    oracle.imageBase = reinterpret_cast<uintptr_t>(testImage.bytes.data());
    VMMicroMemoryView oracleMemory{};
    if (memory) {
        oracleMemory.data = memory->data();
        oracleMemory.size = memory->size();
        oracleMemory.baseAddress = reinterpret_cast<uintptr_t>(memory->data());
    }
    VMMicroExecutionOptions options{};
    options.registerCount = 24;
    options.maxSteps = 100000;
    options.addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    std::string oracleError;
    Require(VMMicroSemanticExecutor::Execute(
            bytecode.data(), bytecode.size(), encoding.reverse.data(),
            encoding.codec, oracle, oracleMemory, options, oracleError),
        label + " 的语义 oracle 执行失败: " + oracleError);
    const std::vector<uint8_t> expectedMemory = memory
        ? *memory : std::vector<uint8_t>{};
    if (memory) *memory = initialMemory;

    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, testImage,
        initialGprs, initialFlags);
    const auto entry = reinterpret_cast<SynthEntry>(
        loaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    const uint32_t runtimeError = InvokeSynthEntry(entry, &context, &exceptionCode);
    Require(exceptionCode == 0 && runtimeError == VM_MICRO_ERR_NONE &&
        context.error == VM_MICRO_ERR_NONE,
        label + " 的合成 handler 执行失败: exception=" +
            std::to_string(exceptionCode) + " runtime=" +
            std::to_string(runtimeError) + " context=" +
            std::to_string(context.error) + " semantic=" +
            std::to_string(context.currentSemantic) + " variant=" +
            std::to_string(context.currentVariant) + " vip=" +
            std::to_string(context.vip - context.bytecodeBegin) + " address=" +
            std::to_string(gLastExceptionAddress) + " bytes=" +
            RuntimeByteWindow(loaded, result, gLastExceptionAddress));

    for (size_t index = 0; index < oracle.gpr.size(); ++index) {
        Require(context.vregs[index] == oracle.gpr[index],
            label + " vreg[" + std::to_string(index) + "] 不一致: actual=" +
            std::to_string(context.vregs[index]) + " expected=" +
            std::to_string(oracle.gpr[index]));
    }
    for (size_t index = 0; index < oracle.temporaries.size(); ++index) {
        Require(context.temps[index] == oracle.temporaries[index],
            label + " temp[" + std::to_string(index) + "] 不一致");
    }
    Require(context.valueDepth == oracle.operandStackDepth,
        label + " value stack 深度不一致");
    for (uint32_t index = 0; index < context.valueDepth; ++index) {
        Require(context.values[index] == oracle.operandStack[index],
            label + " value stack[" + std::to_string(index) + "] 不一致");
    }
    Require(context.callDepth == oracle.callDepth,
        label + " call stack 深度不一致");
    Require(context.virtualFlags == oracle.rflags,
        label + " virtualFlags 不一致: actual=" +
            std::to_string(context.virtualFlags) + " expected=" +
            std::to_string(oracle.rflags));
    Require(context.vip - context.bytecodeBegin == oracle.ip,
        label + " VIP 与 oracle IP 不一致");
    Require(context.halted == 1u && oracle.finished,
        label + " 未在顶层 RET/EXIT 边界停机");
    if (memory) Require(*memory == expectedMemory,
        label + " 的内存副作用与 oracle 不一致");
}

void RequireLazyRecordEqual(
    const VM_LAZY_FLAGS_RECORD& actual,
    const VM_LAZY_FLAGS_RECORD& expected,
    const char* recordName)
{
    Require(std::memcmp(&actual, &expected, sizeof(actual)) == 0,
        std::string(recordName) + " 与语义 oracle 不一致: actual(a=" +
            std::to_string(actual.a) + ",b=" + std::to_string(actual.b) +
            ",r=" + std::to_string(actual.result) + ",aux=" +
            std::to_string(actual.auxiliary) + ",defined=" +
            std::to_string(actual.definedMask) + ",preserve=" +
            std::to_string(actual.preserveMask) + ",op=" +
            std::to_string(actual.operation) + ",width=" +
            std::to_string(actual.width) + ",valid=" +
            std::to_string(actual.valid) + ") expected(a=" +
            std::to_string(expected.a) + ",b=" + std::to_string(expected.b) +
            ",r=" + std::to_string(expected.result) + ",aux=" +
            std::to_string(expected.auxiliary) + ",defined=" +
            std::to_string(expected.definedMask) + ",preserve=" +
            std::to_string(expected.preserveMask) + ",op=" +
            std::to_string(expected.operation) + ",width=" +
            std::to_string(expected.width) + ",valid=" +
            std::to_string(expected.valid) + ")");
}

std::string RuntimeByteWindow(
    const LoadedSynthImage& loaded,
    const VMHandlerSynthesisResult& result,
    uintptr_t address)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(loaded.Base());
    if (address < base || address >= base + result.image.size()) return "outside";
    const size_t offset = static_cast<size_t>(address - base);
    const size_t begin = offset > 12u ? offset - 12u : 0u;
    const size_t end = (std::min)(result.image.size(), offset + 16u);
    std::string bytes;
    for (size_t index = begin; index < end; ++index) {
        if (!bytes.empty()) bytes += ',';
        bytes += std::to_string(static_cast<unsigned>(loaded.Base()[index]));
    }
    return bytes;
}

void ExecuteCriticalHandlerCase(
    bool equalComparison,
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    std::array<uint8_t, 64> memory{};
    for (size_t index = 0; index < memory.size(); ++index)
        memory[index] = static_cast<uint8_t>(0xA5u ^ index);
    const std::array<uint8_t, 64> initialMemory = memory;
    constexpr size_t memoryOffset = 16;
    const uint64_t memoryAddress =
        reinterpret_cast<uintptr_t>(memory.data() + memoryOffset);
    const uint8_t width = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    std::vector<MicroInstruction> program =
        CriticalHandlerProgram(memoryAddress, equalComparison, width);
    const std::vector<uint8_t> bytecode =
        EncodeRuntimeProgram(program, encoding);

    VMMicroMachineState oracle{};
    oracle.gpr[0] = width == 8u
        ? 0x1122334455667788ULL : 0x11223388ULL;
    oracle.rflags = 0x202ULL;
    const std::array<uint64_t, 32> initialGprs = oracle.gpr;
    VMMicroMemoryView oracleMemory{};
    oracleMemory.data = memory.data();
    oracleMemory.size = memory.size();
    oracleMemory.baseAddress = reinterpret_cast<uintptr_t>(memory.data());
    VMMicroExecutionOptions options{};
    options.registerCount = 24;
    options.maxSteps = 100000;
    options.addressWidth = 8;
    std::string oracleError;
    Require(VMMicroSemanticExecutor::Execute(
            bytecode.data(), bytecode.size(), encoding.reverse.data(),
            encoding.codec, oracle, oracleMemory, options, oracleError),
        "关键 handler 程序的语义 oracle 执行失败: " + oracleError);
    const std::array<uint8_t, 64> expectedMemory = memory;
    memory = initialMemory;

    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, testImage,
        initialGprs, 0x202ULL);
    const auto entry = reinterpret_cast<SynthEntry>(
        loaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    const uint32_t runtimeError =
        InvokeSynthEntry(entry, &context, &exceptionCode);
    Require(exceptionCode == 0,
        "关键 handler 程序意外触发 native 异常: " +
            std::to_string(exceptionCode) + " address=" +
            std::to_string(gLastExceptionAddress) + " runtimeOffset=" +
            std::to_string(gLastExceptionAddress -
                reinterpret_cast<uintptr_t>(loaded.Base())) + " bytes=" +
            RuntimeByteWindow(loaded, result, gLastExceptionAddress));
    Require(runtimeError == VM_MICRO_ERR_NONE && context.error == VM_MICRO_ERR_NONE,
        "关键 handler 程序返回 runtime 错误: " +
            std::to_string(runtimeError) + "/" + std::to_string(context.error) +
            " vpCalls=" + std::to_string(gVirtualProtectCalls) +
            " vpError=" + std::to_string(gLastVirtualProtectError) +
            " flushCalls=" + std::to_string(gFlushInstructionCacheCalls) +
            " flushError=" + std::to_string(gLastFlushInstructionCacheError) +
            " semantic=" + std::to_string(context.currentSemantic) +
            " variant=" + std::to_string(context.currentVariant) +
            " decoded=" + std::to_string(context.decodedOperandCount) +
            " operands=" + std::to_string(context.decodedOperands[0]) + "," +
            std::to_string(context.decodedOperands[1]) + "," +
            std::to_string(context.decodedOperands[2]) + "," +
            std::to_string(context.decodedOperands[3]) +
            " vipOffset=" + std::to_string(
                context.vip - context.bytecodeBegin));

    for (size_t index = 0; index < oracle.gpr.size(); ++index) {
        Require(context.vregs[index] == oracle.gpr[index],
            "vreg[" + std::to_string(index) + "] 与语义 oracle 不一致: actual=" +
            std::to_string(context.vregs[index]) + ", expected=" +
            std::to_string(oracle.gpr[index]));
    }
    for (size_t index = 0; index < oracle.temporaries.size(); ++index) {
        Require(context.temps[index] == oracle.temporaries[index],
            "temp[" + std::to_string(index) + "] 与语义 oracle 不一致");
    }
    Require(memory == expectedMemory, "handler 内存副作用与语义 oracle 不一致");
    Require(context.virtualFlags == oracle.rflags,
        "全部虚拟 flags 与语义 oracle 不一致: actual=" +
        std::to_string(context.virtualFlags) + ", expected=" +
        std::to_string(oracle.rflags) + ", pendingResult=" +
        std::to_string(context.pendingFlags.result) + ", pendingWidth=" +
        std::to_string(context.pendingFlags.width) + ", pendingDefined=" +
        std::to_string(context.pendingFlags.definedMask));
    Require(context.pendingFlags.a == oracle.pendingFlags.a &&
        context.pendingFlags.b == oracle.pendingFlags.b &&
        context.pendingFlags.result == oracle.pendingFlags.result &&
        context.pendingFlags.auxiliary == oracle.pendingFlags.auxiliary &&
        context.pendingFlags.preserveMask == oracle.pendingFlags.preserveMask &&
        context.pendingFlags.operation == oracle.pendingFlags.operation &&
        context.pendingFlags.width == oracle.pendingFlags.width &&
        context.pendingFlags.definedMask == 0 && context.pendingFlags.valid == 0,
        "pendingFlags 全量消费后未保留惰性记录或未清空待求掩码");
    RequireLazyRecordEqual(context.lastAlu, oracle.lastAlu, "lastAlu");
    Require(context.valueDepth == oracle.operandStackDepth &&
        context.callDepth == oracle.callDepth,
        "handler value/call stack 深度与语义 oracle 不一致");
    Require(context.halted == 1 && context.returnStackCleanup == 0,
        "RET 未按顶层返回约定停止 direct-threaded 链");
    Require(context.vip - context.bytecodeBegin == oracle.ip &&
        context.vip == context.bytecodeEnd,
        "handler VIP 未停在 RET 后的变长字节码边界");

    const uint64_t expectedAdd = width == 8u
        ? 0x112233445566778DULL : 0x1122338DULL;
    Require(context.vregs[1] == expectedAdd &&
        context.vregs[2] == 14 && context.vregs[3] == 2,
        "ADD/UDIV_WIDE 关键终态错误");
    const uint64_t expectedSignedQuotient = width == 8u
        ? 0xFFFFFFFFFFFFFFF2ULL : 0xFFFFFFF2ULL;
    const uint64_t expectedSignedRemainder = width == 8u
        ? 0xFFFFFFFFFFFFFFFEULL : 0xFFFFFFFEULL;
    Require(context.vregs[5] == expectedSignedQuotient &&
        context.vregs[6] == expectedSignedRemainder,
        "IDIV_WIDE 128 位被除数语义错误");
    Require(context.vregs[4] == (equalComparison ? 1u : 0u),
        "惰性 flags 分支消费者选择错误");
}

void ExecuteReturnOnlyCase(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const std::vector<MicroInstruction> program = {
        Uop(VM_UOP_RET, {0}, 0),
    };
    const std::vector<uint8_t> bytecode =
        EncodeStraightLineRuntimeProgram(program, encoding);
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    const std::array<uint64_t, 32> initialGprs{};
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, testImage,
        initialGprs, 0x202ULL);
    const auto entry = reinterpret_cast<SynthEntry>(
        loaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    const uint32_t runtimeError = InvokeSynthEntry(entry, &context, &exceptionCode);
    Require(exceptionCode == 0 && runtimeError == VM_MICRO_ERR_NONE &&
        context.error == VM_MICRO_ERR_NONE && context.halted == 1,
        "RET-only handler 链执行失败: exception=" +
            std::to_string(exceptionCode) + " address=" +
            std::to_string(gLastExceptionAddress) + " runtime=" +
            std::to_string(runtimeError) + " context=" +
            std::to_string(context.error) + " halted=" +
            std::to_string(context.halted) + " offset=" +
            std::to_string(gLastExceptionAddress -
                reinterpret_cast<uintptr_t>(loaded.Base())) + " bytes=" +
            RuntimeByteWindow(loaded, result, gLastExceptionAddress));
}

void ExecuteDivideFaultCase(
    VM_MICRO_OPCODE divideOpcode,
    uint64_t high,
    uint64_t low,
    uint64_t divisor,
    uint8_t width,
    uint8_t strategy,
    bool quotientOverflow,
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const auto variant = [&](VM_MICRO_OPCODE semantic) {
        return CoreVariantForStrategy(config, semantic, strategy);
    };
    const std::vector<MicroInstruction> program = {
        Uop(VM_UOP_PUSH_IMM, {high, width}, variant(VM_UOP_PUSH_IMM)),
        Uop(VM_UOP_PUSH_IMM, {low, width}, variant(VM_UOP_PUSH_IMM)),
        Uop(VM_UOP_PUSH_IMM, {divisor, width}, variant(VM_UOP_PUSH_IMM)),
        Uop(divideOpcode, {width}, variant(divideOpcode)),
        Uop(VM_UOP_POP_VREG, {1, width, 0, 1}, variant(VM_UOP_POP_VREG)),
        Uop(VM_UOP_POP_VREG, {2, width, 0, 1}, variant(VM_UOP_POP_VREG)),
        Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),
    };
    const std::vector<uint8_t> bytecode =
        EncodeStraightLineRuntimeProgram(program, encoding);

    VMMicroMachineState oracle{};
    oracle.rflags = 0x202ULL;
    VMMicroExecutionOptions options{};
    options.registerCount = 24;
    options.maxSteps = 100;
    options.addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    VMMicroMemoryView noMemory{};
    std::string oracleError;
    Require(!VMMicroSemanticExecutor::Execute(
            bytecode.data(), bytecode.size(), encoding.reverse.data(),
            encoding.codec, oracle, noMemory, options, oracleError) &&
        oracle.fault == VMMicroFault::DivideError,
        "无效 wide divide 的语义 oracle 未产生 #DE");

    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    const std::array<uint64_t, 32> initialGprs{};
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, testImage,
        initialGprs, 0x202ULL);
    // A real #DE interrupts the handler before its mutation suffix completes.
    // Isolate every fault corpus item so one deliberately interrupted handler
    // cannot affect the next width/strategy.
    LoadedSynthImage faultLoaded;
    std::string faultLoadError;
    Require(faultLoaded.Load(result, faultLoadError),
        "wide divide 隔离 handler 映像装载失败: " + faultLoadError);
    const auto entry = reinterpret_cast<SynthEntry>(
        faultLoaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    InvokeSynthEntry(entry, &context, &exceptionCode);
    const bool expectedDivideFault =
        exceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO ||
        (quotientOverflow &&
            exceptionCode == kIntegerOverflowExceptionCode);
    Require(expectedDivideFault,
        std::string(divideOpcode == VM_UOP_UDIV_WIDE ? "UDIV" : "IDIV") +
            " width=" + std::to_string(width) + " strategy=" +
            std::to_string(strategy) + " 未传播真实 #DE，exception=" +
            std::to_string(exceptionCode) + " expected=" +
            (quotientOverflow ? "0xC0000094/0xC0000095" :
                "0xC0000094") + " address=" +
            std::to_string(gLastExceptionAddress) + " bytes=" +
            RuntimeByteWindow(
                faultLoaded, result, gLastExceptionAddress));
}

void ExecuteLazyPreservationCase(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    constexpr uint32_t logicDefined =
        VM_FLAG_CF | VM_FLAG_OF | VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_PF;
    static_assert((VM_FLAG_ARCHITECTURAL_MASK & VM_FLAG_AF) != 0,
        "lazy-preservation regression must request AF");
    const std::vector<MicroInstruction> program = {
        Uop(VM_UOP_PUSH_IMM, {0x0F, 1}, 0),
        Uop(VM_UOP_PUSH_IMM, {0x01, 1}, 1),
        Uop(VM_UOP_ADD, {1}, 2),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_ADD, 1, VM_FLAG_STATUS_MASK,
             VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 3),
        Uop(VM_UOP_DROP, {}, 0),
        // x86 masks shift counts to five bits and x64 to six.  A zero count
        // must preserve every flag from the previous pending ADD record even
        // though the static SHL descriptor normally defines status flags.
        Uop(VM_UOP_PUSH_IMM, {0x81, 1}, 1),
        Uop(VM_UOP_PUSH_IMM, {0, 1}, 2),
        Uop(VM_UOP_SHL, {1}, 3),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_SHL, 1, VM_FLAG_STATUS_MASK,
             VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 0),
        Uop(VM_UOP_DROP, {}, 1),
        Uop(VM_UOP_PUSH_IMM, {0xF0, 1}, 1),
        Uop(VM_UOP_PUSH_IMM, {0x0F, 1}, 2),
        Uop(VM_UOP_AND, {1}, 3),
        Uop(VM_UOP_FLAGS_LAZY,
            {VM_LAZY_LOGIC, 1, logicDefined,
             VM_FLAG_AF | VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF}, 0),
        Uop(VM_UOP_DROP, {}, 1),
        Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}, 2),
        Uop(VM_UOP_RET, {0}, 3),
    };
    const std::vector<uint8_t> bytecode =
        EncodeStraightLineRuntimeProgram(program, encoding);

    VMMicroMachineState oracle{};
    oracle.rflags = 0x202ULL;
    VMMicroExecutionOptions options{};
    options.registerCount = 24;
    options.maxSteps = 100;
    options.addressWidth = 8;
    VMMicroMemoryView noMemory{};
    std::string oracleError;
    Require(VMMicroSemanticExecutor::Execute(
            bytecode.data(), bytecode.size(), encoding.reverse.data(),
            encoding.codec, oracle, noMemory, options, oracleError),
        "跨惰性记录 flags oracle 执行失败: " + oracleError);

    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    const std::array<uint64_t, 32> initialGprs{};
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, testImage,
        initialGprs, 0x202ULL);
    const auto entry = reinterpret_cast<SynthEntry>(
        loaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    const uint32_t runtimeError = InvokeSynthEntry(entry, &context, &exceptionCode);
    Require(exceptionCode == 0 && runtimeError == VM_MICRO_ERR_NONE &&
        context.error == VM_MICRO_ERR_NONE,
        "跨惰性记录 flags handler 执行失败");
    Require(context.virtualFlags == oracle.rflags &&
        (context.virtualFlags & VM_FLAG_AF) != 0 &&
        (context.virtualFlags & (VM_FLAG_ZF | VM_FLAG_PF)) ==
            (VM_FLAG_ZF | VM_FLAG_PF),
        "ADD→AND 覆盖 pending 时未保留旧 AF 或新逻辑 flags 错误: actual=" +
            std::to_string(context.virtualFlags) + ", expected=" +
            std::to_string(oracle.rflags) + ", pendingOp=" +
            std::to_string(context.pendingFlags.operation) + ", pendingValid=" +
            std::to_string(context.pendingFlags.valid) + ", lastOp=" +
            std::to_string(context.lastAlu.operation) + ", lastValid=" +
            std::to_string(context.lastAlu.valid));
}

void ExecuteDataAndStackVariantMatrix(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const uint8_t addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    for (uint8_t width : kSemanticWidths) {
        if (width > addressWidth) continue;
        for (uint8_t strategy : kCoreStrategies) {
            const auto variant = [&](VM_MICRO_OPCODE semantic) {
                return CoreVariantForStrategy(config, semantic, strategy);
            };
            std::vector<uint8_t> memory(64u);
            for (size_t index = 0; index < memory.size(); ++index)
                memory[index] = static_cast<uint8_t>(0xC3u ^ index);
            const uint64_t memoryAddress = reinterpret_cast<uintptr_t>(
                memory.data() + 16u);
            const uint64_t mask = width == 8u
                ? (std::numeric_limits<uint64_t>::max)()
                : ((uint64_t{1} << (width * 8u)) - 1u);
            const uint8_t bitOffset = width == addressWidth ? 0u : 8u;
            const std::vector<MicroInstruction> program = {
                Uop(VM_UOP_PUSH_VREG, {0, width, bitOffset}, variant(VM_UOP_PUSH_VREG)),
                Uop(VM_UOP_STORE_TEMP, {0}, variant(VM_UOP_STORE_TEMP)),
                Uop(VM_UOP_LOAD_TEMP, {0}, variant(VM_UOP_LOAD_TEMP)),
                Uop(VM_UOP_DUP, {}, variant(VM_UOP_DUP)),
                Uop(VM_UOP_POP_VREG, {1, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {2, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x12u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0x34u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SWAP, {}, variant(VM_UOP_SWAP)),
                Uop(VM_UOP_POP_VREG, {3, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {4, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x11u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0x22u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0x33u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ROT, {}, variant(VM_UOP_ROT)),
                Uop(VM_UOP_POP_VREG, {5, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {6, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {7, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x55u & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),
                Uop(VM_UOP_PUSH_IMM, {memoryAddress, addressWidth}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0xA55Au & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_STORE, {width}, variant(VM_UOP_STORE)),
                Uop(VM_UOP_PUSH_IMM, {memoryAddress, addressWidth}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_LOAD, {width}, variant(VM_UOP_LOAD)),
                Uop(VM_UOP_POP_VREG, {8, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x5Au & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_POP_VREG, {9, width, bitOffset, 0}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IP, {}, variant(VM_UOP_PUSH_IP)),
                Uop(VM_UOP_POP_VREG, {10, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMAGE_BASE, {}, variant(VM_UOP_PUSH_IMAGE_BASE)),
                Uop(VM_UOP_POP_VREG, {11, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),
            };
            std::array<uint64_t, 32> initialGprs{};
            initialGprs[0] = 0x8877665544332211ULL;
            initialGprs[9] = addressWidth == 8u
                ? 0xFFEEDDCCBBAA9988ULL : 0xBBAA9988ULL;
            ExecuteOracleEquivalentProgram(
                "data/stack width=" + std::to_string(width) +
                    " strategy=" + std::to_string(strategy),
                program, config, result, loaded, encoding, testImage,
                initialGprs, 0x202ULL, &memory);
        }
    }
}

void ExecuteArithmeticVariantMatrix(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const uint8_t addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    for (uint8_t width : kSemanticWidths) {
        if (width > addressWidth) continue;
        const unsigned bits = width * 8u;
        const uint64_t mask = width == 8u
            ? (std::numeric_limits<uint64_t>::max)()
            : ((uint64_t{1} << bits) - 1u);
        const uint64_t sign = uint64_t{1} << (bits - 1u);
        for (uint8_t strategy : kCoreStrategies) {
            const auto variant = [&](VM_MICRO_OPCODE semantic) {
                return CoreVariantForStrategy(config, semantic, strategy);
            };
            std::vector<MicroInstruction> program = {
                Uop(VM_UOP_PUSH_IMM, {mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ADD_CARRY, {width}, variant(VM_UOP_ADD_CARRY)),
                Uop(VM_UOP_POP_VREG, {0, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SUB_BORROW, {width}, variant(VM_UOP_SUB_BORROW)),
                Uop(VM_UOP_POP_VREG, {1, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x0123456789ABCDEFULL & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_BSWAP, {width}, variant(VM_UOP_BSWAP)),
                Uop(VM_UOP_POP_VREG, {2, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {sign | 0x21u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {bits + 1u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SAR, {width}, variant(VM_UOP_SAR)),
                Uop(VM_UOP_POP_VREG, {3, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {sign | 0x13u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {bits + 1u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ROL, {width}, variant(VM_UOP_ROL)),
                Uop(VM_UOP_POP_VREG, {4, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {sign | 0x27u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {bits - 1u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ROR, {width}, variant(VM_UOP_ROR)),
                Uop(VM_UOP_POP_VREG, {5, width, 0, 1}, variant(VM_UOP_POP_VREG)),
            };
            if (width < addressWidth) {
                const uint8_t toWidth = static_cast<uint8_t>(width * 2u);
                program.insert(program.end(), {
                    Uop(VM_UOP_PUSH_IMM, {sign | 3u, width}, variant(VM_UOP_PUSH_IMM)),
                    Uop(VM_UOP_ZERO_EXTEND, {width, toWidth}, variant(VM_UOP_ZERO_EXTEND)),
                    Uop(VM_UOP_POP_VREG, {6, toWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                    Uop(VM_UOP_PUSH_IMM, {sign | 3u, width}, variant(VM_UOP_PUSH_IMM)),
                    Uop(VM_UOP_SIGN_EXTEND, {width, toWidth}, variant(VM_UOP_SIGN_EXTEND)),
                    Uop(VM_UOP_POP_VREG, {7, toWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                });
            }
            program.insert(program.end(), {
                Uop(VM_UOP_PUSH_IMM, {mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {2, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_UMUL_WIDE, {width}, variant(VM_UOP_UMUL_WIDE)),
                Uop(VM_UOP_POP_VREG, {9, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {8, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {sign, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {2, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SMUL_WIDE, {width}, variant(VM_UOP_SMUL_WIDE)),
                Uop(VM_UOP_POP_VREG, {11, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {10, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {2, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_UDIV_WIDE, {width}, variant(VM_UOP_UDIV_WIDE)),
                Uop(VM_UOP_POP_VREG, {13, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {12, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {(mask - 99u) & mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {7, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_IDIV_WIDE, {width}, variant(VM_UOP_IDIV_WIDE)),
                Uop(VM_UOP_POP_VREG, {15, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {14, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                // signed double-width -2^(bits) / INT_MIN == 2；专门覆盖
                // “INT_MIN 取绝对值仍为负”这条最宽 IDIV 历史漏洞。
                Uop(VM_UOP_PUSH_IMM, {mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {sign, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_IDIV_WIDE, {width}, variant(VM_UOP_IDIV_WIDE)),
                Uop(VM_UOP_POP_VREG, {17, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_POP_VREG, {16, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),
            });
            const std::array<uint64_t, 32> initialGprs{};
            ExecuteOracleEquivalentProgram(
                "arithmetic width=" + std::to_string(width) +
                    " strategy=" + std::to_string(strategy),
                program, config, result, loaded, encoding, testImage,
                initialGprs, 0x202ULL);
        }
    }
}

void ExecuteFlagsVariantMatrix(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const uint8_t addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    constexpr uint32_t preservedFlags =
        VM_FLAG_ARCHITECTURAL_MASK & ~VM_FLAG_STATUS_MASK;
    for (uint8_t width : kSemanticWidths) {
        if (width > addressWidth) continue;
        const unsigned bits = width * 8u;
        const uint64_t mask = width == 8u
            ? (std::numeric_limits<uint64_t>::max)()
            : ((uint64_t{1} << bits) - 1u);
        const uint64_t sign = uint64_t{1} << (bits - 1u);
        for (uint8_t strategy : kCoreStrategies) {
            const auto variant = [&](VM_MICRO_OPCODE semantic) {
                return CoreVariantForStrategy(config, semantic, strategy);
            };
            const std::vector<MicroInstruction> program = {
                Uop(VM_UOP_PUSH_IMM, {sign - 1u, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ADD, {width}, variant(VM_UOP_ADD)),
                Uop(VM_UOP_FLAGS_LAZY,
                    {VM_LAZY_ADD, width, VM_FLAG_STATUS_MASK, preservedFlags},
                    variant(VM_UOP_FLAGS_LAZY)),
                Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),
                Uop(VM_UOP_PUSH_CONDITION, {VM_CONDITION_O}, variant(VM_UOP_PUSH_CONDITION)),
                Uop(VM_UOP_POP_VREG, {0, 1, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_CONDITION, {VM_CONDITION_S}, variant(VM_UOP_PUSH_CONDITION)),
                Uop(VM_UOP_POP_VREG, {1, 1, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x11, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0x22, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SELECT, {VM_CONDITION_O}, variant(VM_UOP_SELECT)),
                Uop(VM_UOP_POP_VREG, {2, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0x33, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0x44, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SELECT, {VM_CONDITION_E}, variant(VM_UOP_SELECT)),
                Uop(VM_UOP_POP_VREG, {3, width, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {4, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_FLAGS_PACK_AH, {}, variant(VM_UOP_FLAGS_PACK_AH)),
                Uop(VM_UOP_POP_VREG, {5, 1, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_FLAGS_UPDATE, {VM_FLAG_UPDATE_CLEAR, VM_FLAG_CF}, variant(VM_UOP_FLAGS_UPDATE)),
                Uop(VM_UOP_FLAGS_UPDATE, {VM_FLAG_UPDATE_SET, VM_FLAG_CF}, variant(VM_UOP_FLAGS_UPDATE)),
                Uop(VM_UOP_FLAGS_UPDATE, {VM_FLAG_UPDATE_TOGGLE, VM_FLAG_PF}, variant(VM_UOP_FLAGS_UPDATE)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {6, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_AF | VM_FLAG_ZF, addressWidth}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_FLAGS_WRITE, {VM_FLAG_STATUS_MASK}, variant(VM_UOP_FLAGS_WRITE)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {7, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0xD5, 1}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_FLAGS_UNPACK_AH, {}, variant(VM_UOP_FLAGS_UNPACK_AH)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {8, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_SUB_BORROW, {width}, variant(VM_UOP_SUB_BORROW)),
                Uop(VM_UOP_FLAGS_LAZY,
                    {VM_LAZY_SBB, width, VM_FLAG_STATUS_MASK, preservedFlags},
                    variant(VM_UOP_FLAGS_LAZY)),
                Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),
                Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_FLAGS_MATERIALIZE)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {9, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_PUSH_IMM, {mask, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {0, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_PUSH_IMM, {1, width}, variant(VM_UOP_PUSH_IMM)),
                Uop(VM_UOP_ADD_CARRY, {width}, variant(VM_UOP_ADD_CARRY)),
                Uop(VM_UOP_FLAGS_LAZY,
                    {VM_LAZY_ADC, width, VM_FLAG_STATUS_MASK, preservedFlags},
                    variant(VM_UOP_FLAGS_LAZY)),
                Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),
                Uop(VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_FLAGS_MATERIALIZE)),
                Uop(VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, variant(VM_UOP_PUSH_FLAGS)),
                Uop(VM_UOP_POP_VREG, {10, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)),
                Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),
            };
            const std::array<uint64_t, 32> initialGprs{};
            ExecuteOracleEquivalentProgram(
                "flags width=" + std::to_string(width) +
                    " strategy=" + std::to_string(strategy),
                program, config, result, loaded, encoding, testImage,
                initialGprs, 0x202ULL);
        }
    }
}

void ExecuteControlFlowBoundaryMatrix(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
    const uint8_t addressWidth = config.architecture == VMHandlerArchitecture::X64
        ? 8u : 4u;
    constexpr uint32_t preservedFlags =
        VM_FLAG_ARCHITECTURAL_MASK & ~VM_FLAG_STATUS_MASK;
    for (uint8_t strategy : kCoreStrategies) {
        const auto variant = [&](VM_MICRO_OPCODE semantic) {
            return CoreVariantForStrategy(config, semantic, strategy);
        };
        std::vector<MicroInstruction> program = {
            Uop(VM_UOP_LOAD_TEMP, {0}, variant(VM_UOP_LOAD_TEMP)),             // 0
            Uop(VM_UOP_PUSH_IMM, {0, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 1
            Uop(VM_UOP_SUB, {addressWidth}, variant(VM_UOP_SUB)),              // 2
            Uop(VM_UOP_FLAGS_LAZY,
                {VM_LAZY_SUB, addressWidth, VM_FLAG_STATUS_MASK, preservedFlags},
                variant(VM_UOP_FLAGS_LAZY)),                                   // 3
            Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),                        // 4
            Uop(VM_UOP_BRANCH_IF, {VM_CONDITION_NE, 0}, variant(VM_UOP_BRANCH_IF)), // 5
            Uop(VM_UOP_PUSH_IMM, {1, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 6
            Uop(VM_UOP_STORE_TEMP, {0}, variant(VM_UOP_STORE_TEMP)),           // 7
            Uop(VM_UOP_CALL_VM, {0}, variant(VM_UOP_CALL_VM)),                 // 8
            Uop(VM_UOP_PUSH_IMM, {1, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 9
            Uop(VM_UOP_PUSH_IMM, {2, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 10
            Uop(VM_UOP_SUB, {addressWidth}, variant(VM_UOP_SUB)),              // 11
            Uop(VM_UOP_FLAGS_LAZY,
                {VM_LAZY_SUB, addressWidth, VM_FLAG_STATUS_MASK, preservedFlags},
                variant(VM_UOP_FLAGS_LAZY)),                                   // 12
            Uop(VM_UOP_DROP, {}, variant(VM_UOP_DROP)),                        // 13
            Uop(VM_UOP_BRANCH_IF, {VM_CONDITION_E, 0}, variant(VM_UOP_BRANCH_IF)), // 14
            Uop(VM_UOP_PUSH_IMM, {0x55, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 15
            Uop(VM_UOP_POP_VREG, {0, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)), // 16
            Uop(VM_UOP_BRANCH, {0}, variant(VM_UOP_BRANCH)),                   // 17
            Uop(VM_UOP_PUSH_IMM, {0x77, addressWidth}, variant(VM_UOP_PUSH_IMM)), // 18
            Uop(VM_UOP_POP_VREG, {1, addressWidth, 0, 1}, variant(VM_UOP_POP_VREG)), // 19
            Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),                         // 20
            Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),                         // 21
        };
        const std::vector<uint32_t> offsets =
            RuntimeInstructionOffsets(program, encoding);
        program[5].operands[1] = offsets[18]; // 恒假(首次)与恒真(递归)均命中。
        program[8].operands[0] = offsets[0];  // CALL 目标恰为函数首字节。
        program[14].operands[1] = offsets[0]; // 恒假分支目标也在函数首边界。
        program[17].operands[0] = offsets[21]; // 无条件分支目标恰为末条 RET。
        const std::array<uint64_t, 32> initialGprs{};
        ExecuteOracleEquivalentProgram(
            "control boundary strategy=" + std::to_string(strategy),
            program, config, result, loaded, encoding, testImage,
            initialGprs, 0x202ULL);
    }
}

#if defined(_M_X64)
extern "C" void __fastcall GateInstructionBridgeTarget(
    VM_INSTRUCTION_BRIDGE_STATE* state)
{
    state->gpr[0] ^= 0x1122334455667788ULL;
    state->gpr[15] += 0x1020304050607080ULL;
}
#endif

#if defined(_M_X64)
constexpr uint64_t kCallHostWin64Result = 0xA11CE5EED1234567ULL;
constexpr uint64_t kCallHostWin64StackMutation = 0x55AA33CC0FF00FF0ULL;
volatile uint64_t gCallHostWin64Observed[5] = {};

extern "C" __declspec(noinline) uint64_t __fastcall GateCallHostWin64Target(
    uint64_t a,
    uint64_t b,
    uint64_t c,
    uint64_t d,
    uint64_t e)
{
    gCallHostWin64Observed[0] = a;
    gCallHostWin64Observed[1] = b;
    gCallHostWin64Observed[2] = c;
    gCallHostWin64Observed[3] = d;
    gCallHostWin64Observed[4] = e;
    auto* const callerStack =
        reinterpret_cast<volatile uint64_t*>(_AddressOfReturnAddress());
    callerStack[5] = e ^ kCallHostWin64StackMutation;
    return kCallHostWin64Result;
}
#elif defined(_M_IX86)
constexpr uint32_t kCallHostX86StackMutation = 0x55AA33CCu;
volatile uint32_t gCallHostX86Observed[3] = {};

extern "C" __declspec(noinline) uint32_t __cdecl GateCallHostCdeclTarget(
    uint32_t a,
    uint32_t b)
{
    gCallHostX86Observed[0] = a;
    gCallHostX86Observed[1] = b;
    auto* const callerStack =
        reinterpret_cast<volatile uint32_t*>(_AddressOfReturnAddress());
    callerStack[1] = a ^ kCallHostX86StackMutation;
    callerStack[2] = b + 0x1020304u;
    return 0xCDEC1A11u;
}

extern "C" __declspec(noinline) uint32_t __stdcall GateCallHostStdcallTarget(
    uint32_t a,
    uint32_t b)
{
    gCallHostX86Observed[0] = a;
    gCallHostX86Observed[1] = b;
    auto* const callerStack =
        reinterpret_cast<volatile uint32_t*>(_AddressOfReturnAddress());
    callerStack[1] = a + 0x11111111u;
    callerStack[2] = b ^ kCallHostX86StackMutation;
    return 0x57DC0112u;
}

extern "C" __declspec(noinline) uint32_t __fastcall GateCallHostFastcallTarget(
    uint32_t a,
    uint32_t b,
    uint32_t stackValue)
{
    gCallHostX86Observed[0] = a;
    gCallHostX86Observed[1] = b;
    gCallHostX86Observed[2] = stackValue;
    auto* const callerStack =
        reinterpret_cast<volatile uint32_t*>(_AddressOfReturnAddress());
    callerStack[1] = stackValue ^ kCallHostX86StackMutation;
    return 0xFA57CA11u;
}

extern "C" __declspec(naked) uint32_t __cdecl GateCallHostThiscallTarget() {
    __asm {
        mov eax, dword ptr [ecx]
        mov dword ptr [gCallHostX86Observed], eax
        mov eax, dword ptr [esp + 4]
        mov dword ptr [gCallHostX86Observed + 4], eax
        xor dword ptr [esp + 4], 055AA33CCh
        mov eax, 07115CA11h
        ret 4
    }
}

extern "C" __declspec(noinline) uint32_t __stdcall GateCallHostAutoTarget(
    uint32_t a)
{
    gCallHostX86Observed[0] = a;
    auto* const callerStack =
        reinterpret_cast<volatile uint32_t*>(_AddressOfReturnAddress());
    callerStack[1] = a ^ kCallHostX86StackMutation;
    return 0xA070CA11u;
}
#endif

#if defined(_M_X64) || defined(_M_IX86)
VM_MICRO_EXECUTION_CONTEXT ExecuteCallHostOnce(
    const std::string& label,
    VM_MICRO_CALL_KIND callKind,
    uint64_t targetToken,
    VM_CALL_ABI callAbi,
    uint16_t stackArgumentBytes,
    uint8_t strategy,
    const std::array<uint64_t, 32>& initialGprs,
    uint8_t* imageBase,
    VM_METADATA_HEADER* metadata,
    uint32_t expectedError,
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& bootstrapImage)
{
    const uint8_t addressWidth =
        config.architecture == VMHandlerArchitecture::X64 ? 8u : 4u;
    const auto variant = [&](VM_MICRO_OPCODE semantic) {
        return CoreVariantForStrategy(config, semantic, strategy);
    };
    const std::vector<MicroInstruction> program = {
        Uop(VM_UOP_PUSH_IMM,
            {targetToken, addressWidth}, variant(VM_UOP_PUSH_IMM)),
        Uop(VM_UOP_CALL_HOST,
            {static_cast<uint64_t>(callKind),
             static_cast<uint64_t>(callAbi), stackArgumentBytes},
            variant(VM_UOP_CALL_HOST)),
        Uop(VM_UOP_RET, {0}, variant(VM_UOP_RET)),
    };
    const std::vector<uint8_t> bytecode =
        EncodeStraightLineRuntimeProgram(program, encoding);
    std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
    for (uint8_t index = 0; index < registerMap.size(); ++index)
        registerMap[index] = index;
    alignas(64) VM_EXTENDED_STATE extendedState{};
    CaptureCallHostExtendedState(extendedState);
    VM_MICRO_EXECUTION_CONTEXT context = MakeRuntimeContext(
        bytecode, encoding, config, registerMap, bootstrapImage,
        initialGprs, VM_FLAG_FIXED_1 | VM_FLAG_IF | VM_FLAG_CF);
    context.imageBase = reinterpret_cast<uintptr_t>(imageBase);
    context.metadata = reinterpret_cast<uintptr_t>(metadata);
    context.extendedState = reinterpret_cast<uintptr_t>(&extendedState);

    const auto entry = reinterpret_cast<SynthEntry>(
        loaded.Base() + result.contextEntryOffset);
    DWORD exceptionCode = 0;
    const uint32_t runtimeError =
        InvokeSynthEntry(entry, &context, &exceptionCode);
    Require(exceptionCode == 0 && runtimeError == expectedError &&
            context.error == expectedError,
        label + " CALL_HOST 执行边界错误: exception=" +
            std::to_string(exceptionCode) + " runtime=" +
            std::to_string(runtimeError) + " context=" +
            std::to_string(context.error) + " semantic=" +
            std::to_string(context.currentSemantic) + " variant=" +
            std::to_string(context.currentVariant) + " address=" +
            std::to_string(gLastExceptionAddress) + " bytes=" +
            RuntimeByteWindow(loaded, result, gLastExceptionAddress));
    if (expectedError == VM_MICRO_ERR_NONE) {
        Require(context.halted == 1u && context.valueDepth == 0u &&
                context.vip == context.bytecodeEnd,
            label + " CALL_HOST 成功后未在顶层 RET 精确停机");
    }
    return context;
}
#endif

void ExecuteCallHostVariantCases(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& bootstrapImage)
{
#if defined(_M_X64)
    if (config.architecture != VMHandlerArchitecture::X64) return;
    CallHostTestImage callImage(
        reinterpret_cast<uintptr_t>(&GateCallHostWin64Target));
    for (uint8_t strategy : kCoreStrategies) {
        alignas(16) std::array<uint8_t, 64> nativeStack{};
        std::array<uint64_t, 32> nativeGprs{};
        nativeGprs[4] = reinterpret_cast<uintptr_t>(nativeStack.data());
        const auto nativeContext = ExecuteCallHostOnce(
            "x64 native RVA strategy=" + std::to_string(strategy),
            VM_MICRO_CALL_NATIVE_RVA, kCallHostNativeTargetRVA,
            VM_ABI_WIN64, 0, strategy, nativeGprs, callImage.Base(),
            callImage.Metadata(), VM_MICRO_ERR_NONE, config, result,
            loaded, encoding, bootstrapImage);
        Require(nativeContext.vregs[0] == CallHostTestImage::NativeResult() &&
                nativeContext.vregs[4] == nativeGprs[4] &&
                (nativeContext.virtualFlags & VM_FLAG_CF) == 0,
            "x64 native-RVA CALL_HOST 未正确导入初始 CF、导出清零 CF，"
            "或返回值/RSP 回写错误");
        ExecuteCallHostOnce(
            "x64 rejects x86 ABI strategy=" + std::to_string(strategy),
            VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostWin64Target),
            VM_ABI_X86_CDECL, 0, strategy, nativeGprs, callImage.Base(),
            callImage.Metadata(), VM_MICRO_ERR_HANDLER_BUG, config, result,
            loaded, encoding, bootstrapImage);

        const auto runCallee = [&](VM_MICRO_CALL_KIND kind,
                                   uint64_t token,
                                   const char* kindName,
                                   uint64_t salt) {
            alignas(16) std::array<uint8_t, 64> guestStack{};
            const uint64_t stackValue = 0x5152535455565758ULL ^ salt;
            std::memcpy(guestStack.data() + 0x20,
                &stackValue, sizeof(stackValue));
            std::array<uint64_t, 32> gprs{};
            gprs[1] = 0x1111222233334444ULL ^ salt;
            gprs[2] = 0x5555666677778888ULL ^ salt;
            gprs[8] = 0x9999AAAABBBBCCCCULL ^ salt;
            gprs[9] = 0xDDDDEEEEFFFF0001ULL ^ salt;
            gprs[4] = reinterpret_cast<uintptr_t>(guestStack.data());
            for (auto& observed : gCallHostWin64Observed) observed = 0;
            const auto context = ExecuteCallHostOnce(
                std::string("x64 ") + kindName + " strategy=" +
                    std::to_string(strategy),
                kind, token, VM_ABI_WIN64, 8, strategy, gprs,
                callImage.Base(), callImage.Metadata(), VM_MICRO_ERR_NONE,
                config, result, loaded, encoding, bootstrapImage);
            uint64_t mutatedStackValue = 0;
            std::memcpy(&mutatedStackValue, guestStack.data() + 0x20,
                sizeof(mutatedStackValue));
            Require(context.vregs[0] == kCallHostWin64Result &&
                    context.vregs[4] == gprs[4] &&
                    gCallHostWin64Observed[0] == gprs[1] &&
                    gCallHostWin64Observed[1] == gprs[2] &&
                    gCallHostWin64Observed[2] == gprs[8] &&
                    gCallHostWin64Observed[3] == gprs[9] &&
                    gCallHostWin64Observed[4] == stackValue &&
                    mutatedStackValue ==
                        (stackValue ^ kCallHostWin64StackMutation),
                std::string("x64 ") + kindName +
                    " CALL_HOST 参数、返回值或栈参数回写错误 strategy=" +
                    std::to_string(strategy) + " result=" +
                    std::to_string(context.vregs[0]) + " rsp=" +
                    std::to_string(context.vregs[4]) + " args=" +
                    std::to_string(gCallHostWin64Observed[0]) + "," +
                    std::to_string(gCallHostWin64Observed[1]) + "," +
                    std::to_string(gCallHostWin64Observed[2]) + "," +
                    std::to_string(gCallHostWin64Observed[3]) + "," +
                    std::to_string(gCallHostWin64Observed[4]) + " stack=" +
                    std::to_string(mutatedStackValue));
        };
        runCallee(VM_MICRO_CALL_IMPORT_SLOT, kCallHostImportSlotRVA,
            "import slot", 0x100u + strategy);
        runCallee(VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostWin64Target),
            "indirect", 0x200u + strategy);
    }
#elif defined(_M_IX86)
    if (config.architecture != VMHandlerArchitecture::X86) return;
    CallHostTestImage callImage(
        reinterpret_cast<uintptr_t>(&GateCallHostCdeclTarget));
    struct ThiscallObject { uint32_t marker; };
    ThiscallObject thisObject{0x7150B1ECu};

    for (uint8_t strategy : kCoreStrategies) {
        const auto run = [&](const std::string& name,
                             VM_MICRO_CALL_KIND kind,
                             uint64_t token,
                             VM_CALL_ABI abi,
                             uint16_t stackBytes,
                             uint32_t firstStack,
                             uint32_t secondStack,
                             uint32_t ecxInput,
                             uint32_t edxInput,
                             uint32_t expectedCleanup,
                             uint32_t expectedReturn,
                             uint32_t expectedFirstStack,
                             uint32_t expectedSecondStack,
                             uint32_t expectedObserved0,
                             uint32_t expectedObserved1,
                             uint32_t expectedObserved2,
                             uint32_t expectedError = VM_MICRO_ERR_NONE) {
            alignas(16) std::array<uint32_t, 8> guestStack{};
            guestStack[0] = firstStack;
            guestStack[1] = secondStack;
            std::array<uint64_t, 32> gprs{};
            gprs[1] = ecxInput;
            gprs[2] = edxInput;
            gprs[4] = reinterpret_cast<uintptr_t>(guestStack.data());
            for (auto& observed : gCallHostX86Observed) observed = 0;
            const auto context = ExecuteCallHostOnce(
                name + " strategy=" + std::to_string(strategy),
                kind, token, abi, stackBytes, strategy, gprs,
                callImage.Base(), callImage.Metadata(), expectedError,
                config, result, loaded, encoding, bootstrapImage);
            Require(gCallHostX86Observed[0] == expectedObserved0 &&
                    gCallHostX86Observed[1] == expectedObserved1 &&
                    gCallHostX86Observed[2] == expectedObserved2 &&
                    guestStack[0] == expectedFirstStack &&
                    guestStack[1] == expectedSecondStack,
                name + " CALL_HOST 参数或栈参数回写错误");
            if (expectedError == VM_MICRO_ERR_NONE) {
                Require(context.vregs[0] == expectedReturn &&
                        context.vregs[4] == gprs[4] + expectedCleanup,
                    name + " CALL_HOST 返回值或虚拟 ESP 清栈错误");
            }
        };

        alignas(16) std::array<uint32_t, 4> nativeStack{};
        std::array<uint64_t, 32> nativeGprs{};
        nativeGprs[4] = reinterpret_cast<uintptr_t>(nativeStack.data());
        const auto nativeContext = ExecuteCallHostOnce(
            "x86 native RVA strategy=" + std::to_string(strategy),
            VM_MICRO_CALL_NATIVE_RVA, kCallHostNativeTargetRVA,
            VM_ABI_X86_CDECL, 0, strategy, nativeGprs, callImage.Base(),
            callImage.Metadata(), VM_MICRO_ERR_NONE, config, result,
            loaded, encoding, bootstrapImage);
        Require(nativeContext.vregs[0] == CallHostTestImage::NativeResult() &&
                nativeContext.vregs[4] == nativeGprs[4] &&
                (nativeContext.virtualFlags & VM_FLAG_CF) == 0,
            "x86 native-RVA CALL_HOST 未正确导入初始 CF、导出清零 CF，"
            "或返回值/ESP 回写错误");
        ExecuteCallHostOnce(
            "x86 rejects null target strategy=" + std::to_string(strategy),
            VM_MICRO_CALL_INDIRECT, 0, VM_ABI_X86_CDECL, 0, strategy,
            nativeGprs, callImage.Base(), callImage.Metadata(),
            VM_MICRO_ERR_HANDLER_BUG, config, result, loaded, encoding,
            bootstrapImage);

        constexpr uint32_t cdeclA = 0x10203040u;
        constexpr uint32_t cdeclB = 0x50607080u;
        run("x86 import cdecl", VM_MICRO_CALL_IMPORT_SLOT,
            kCallHostImportSlotRVA, VM_ABI_X86_CDECL, 8,
            cdeclA, cdeclB, 0, 0, 0, 0xCDEC1A11u,
            cdeclA ^ kCallHostX86StackMutation,
            cdeclB + 0x1020304u, cdeclA, cdeclB, 0);
        run("x86 indirect cdecl", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostCdeclTarget),
            VM_ABI_X86_CDECL, 8, cdeclA + strategy, cdeclB + strategy,
            0, 0, 0, 0xCDEC1A11u,
            (cdeclA + strategy) ^ kCallHostX86StackMutation,
            cdeclB + strategy + 0x1020304u,
            cdeclA + strategy, cdeclB + strategy, 0);

        constexpr uint32_t stdcallA = 0x11224488u;
        constexpr uint32_t stdcallB = 0x99AACCEEu;
        run("x86 stdcall", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostStdcallTarget),
            VM_ABI_X86_STDCALL, 8, stdcallA, stdcallB, 0, 0, 8,
            0x57DC0112u, stdcallA + 0x11111111u,
            stdcallB ^ kCallHostX86StackMutation,
            stdcallA, stdcallB, 0);

        constexpr uint32_t fastcallA = 0x13572468u;
        constexpr uint32_t fastcallB = 0x24681357u;
        constexpr uint32_t fastcallStack = 0xCAFEBABEu;
        run("x86 fastcall", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostFastcallTarget),
            VM_ABI_X86_FASTCALL, 4, fastcallStack, 0,
            fastcallA, fastcallB, 4, 0xFA57CA11u,
            fastcallStack ^ kCallHostX86StackMutation, 0,
            fastcallA, fastcallB, fastcallStack);

        constexpr uint32_t thiscallStack = 0x0BADF00Du;
        run("x86 thiscall", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostThiscallTarget),
            VM_ABI_X86_THISCALL, 4, thiscallStack, 0,
            reinterpret_cast<uintptr_t>(&thisObject), 0, 4, 0x7115CA11u,
            thiscallStack ^ kCallHostX86StackMutation, 0,
            thisObject.marker, thiscallStack, 0);

        constexpr uint32_t autoA = 0x31415926u;
        run("x86 auto partial cleanup", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostAutoTarget),
            VM_ABI_X86_AUTO, 8, autoA, 0xDEADBEEFu, 0, 0, 4,
            0xA070CA11u, autoA ^ kCallHostX86StackMutation,
            0xDEADBEEFu, autoA, 0, 0);

        // The same RET 4 target is illegal under a declared cdecl contract.
        // It must fail closed after the native effect instead of silently
        // drifting the direct-threaded handler stack.
        run("x86 cdecl cleanup mismatch", VM_MICRO_CALL_INDIRECT,
            reinterpret_cast<uintptr_t>(&GateCallHostAutoTarget),
            VM_ABI_X86_CDECL, 8, autoA, 0xDEADBEEFu, 0, 0, 0, 0,
            autoA ^ kCallHostX86StackMutation, 0xDEADBEEFu,
            autoA, 0, 0, VM_MICRO_ERR_NATIVE_BRIDGE);
    }
#else
    (void)config;
    (void)result;
    (void)loaded;
    (void)encoding;
    (void)bootstrapImage;
#endif
}

void ExecuteExternalSemanticVariantCases(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result,
    LoadedSynthImage& loaded,
    const RuntimeEncoding& encoding,
    TestRuntimeIatImage& testImage)
{
#if defined(_M_X64)
    CallHostTestImage bridgeImage(
        0, reinterpret_cast<uintptr_t>(&GateInstructionBridgeTarget));
#endif
    for (uint8_t strategy : kCoreStrategies) {
        const uint8_t int3Variant = CoreVariantForStrategy(
            config, VM_UOP_INT3, strategy);
        const std::vector<MicroInstruction> int3Program = {
            Uop(VM_UOP_INT3, {}, int3Variant),
            Uop(VM_UOP_RET, {0}, 0),
        };
        const std::vector<uint8_t> int3Bytecode =
            EncodeStraightLineRuntimeProgram(int3Program, encoding);
        std::array<uint8_t, VM_REGISTER_MAP_SIZE> registerMap{};
        for (uint8_t index = 0; index < registerMap.size(); ++index)
            registerMap[index] = index;
        const std::array<uint64_t, 32> initialGprs{};
        VM_MICRO_EXECUTION_CONTEXT int3Context = MakeRuntimeContext(
            int3Bytecode, encoding, config, registerMap, testImage,
            initialGprs, 0x202ULL);
        // INT3 deliberately interrupts the handler before its normal suffix
        // can complete.  Give every breakpoint case a fresh self-mutating
        // image so its partial decrypt state cannot poison BRIDGE_EXTENDED or
        // the other INT3 strategy.
        LoadedSynthImage int3Loaded;
        std::string int3LoadError;
        Require(int3Loaded.Load(result, int3LoadError),
            "INT3 隔离 handler 映像装载失败: " + int3LoadError);
        const auto int3Entry = reinterpret_cast<SynthEntry>(
            int3Loaded.Base() + result.contextEntryOffset);
        DWORD exceptionCode = 0;
        InvokeSynthEntry(int3Entry, &int3Context, &exceptionCode);
        Require(exceptionCode == EXCEPTION_BREAKPOINT,
            "INT3 strategy=" + std::to_string(strategy) +
            " 未产生等价 breakpoint 异常: " + std::to_string(exceptionCode));

#if defined(_M_X64)
        if (config.architecture == VMHandlerArchitecture::X64) {
            const uint8_t bridgeVariant = CoreVariantForStrategy(
                config, VM_UOP_BRIDGE_EXTENDED, strategy);
            const std::vector<MicroInstruction> bridgeProgram = {
                Uop(VM_UOP_BRIDGE_EXTENDED,
                    {kInstructionBridgeTargetRVA, 0, 0}, bridgeVariant),
                Uop(VM_UOP_RET, {0}, 0),
            };
            const std::vector<uint8_t> bridgeBytecode =
                EncodeStraightLineRuntimeProgram(bridgeProgram, encoding);
            std::array<uint64_t, 32> bridgeGprs{};
            bridgeGprs[0] = 0xFFEEDDCCBBAA9988ULL;
            bridgeGprs[15] = 0x0102030405060708ULL;
            VM_MICRO_EXECUTION_CONTEXT bridgeContext = MakeRuntimeContext(
                bridgeBytecode, encoding, config, registerMap, testImage,
                bridgeGprs, 0x202ULL);
            bridgeContext.imageBase = reinterpret_cast<uintptr_t>(
                bridgeImage.Base());
            bridgeContext.metadata = reinterpret_cast<uintptr_t>(
                bridgeImage.Metadata());
            exceptionCode = 0;
            const auto entry = reinterpret_cast<SynthEntry>(
                loaded.Base() + result.contextEntryOffset);
            const uint32_t runtimeError = InvokeSynthEntry(
                entry, &bridgeContext, &exceptionCode);
            Require(exceptionCode == 0 && runtimeError == VM_MICRO_ERR_NONE &&
                bridgeContext.error == VM_MICRO_ERR_NONE &&
                bridgeContext.vregs[0] ==
                    (bridgeGprs[0] ^ 0x1122334455667788ULL) &&
                bridgeContext.vregs[15] ==
                    bridgeGprs[15] + 0x1020304050607080ULL,
                "BRIDGE_EXTENDED strategy=" + std::to_string(strategy) +
                " 执行副作用不一致: exception=" +
                std::to_string(exceptionCode) + " runtime=" +
                std::to_string(runtimeError) + " context=" +
                std::to_string(bridgeContext.error) + " address=" +
                std::to_string(gLastExceptionAddress) + " bytes=" +
                RuntimeByteWindow(
                    loaded, result, gLastExceptionAddress));
        }
#endif
    }
}

void TestHostContextEntryExecution() {
#if defined(_M_X64)
    constexpr VMHandlerArchitecture architecture = VMHandlerArchitecture::X64;
    constexpr uint8_t seedDomain = 0xD4;
#else
    constexpr VMHandlerArchitecture architecture = VMHandlerArchitecture::X86;
    constexpr uint8_t seedDomain = 0xD3;
#endif
    const auto seed = MakeSeed(seedDomain);
    const VMHandlerSynthesisConfig config = MakeConfig(architecture, seed);
    const RuntimeEncoding encoding = MakeRuntimeEncoding(architecture, seed);
    Require(config.handlerSemanticToSlot == encoding.semanticToSlot &&
        config.handlerSlotToSemantic == encoding.slotToSemantic,
        "执行门禁的 opcode/slot build seed 映射不一致");

    VMHandlerSynthesizer synthesizer;
    const VMHandlerSynthesisResult result = synthesizer.Synthesize(config);
    ValidateOneBuild(config, result);
    LoadedSynthImage loaded;
    std::string loadError;
    Require(loaded.Load(result, loadError),
        "无法装载生成 runtime 做执行门禁: " + loadError);
    TestRuntimeIatImage testImage;

    Require(loaded.Base()[result.keyMarkerOffset - 16u] == 0,
        "首次 context-entry 前 handler decrypt state 不是 0");
#if defined(_M_IX86)
    std::cout << "[阶段] x86 RET-only 门禁\n";
    ExecuteReturnOnlyCase(config, result, loaded, encoding, testImage);
#endif
    std::cout << "[阶段] 主机架构 handler 相等分支\n";
    ExecuteCriticalHandlerCase(true, config, result, loaded, encoding, testImage);
    std::cout << "[阶段] handler 解密状态=" <<
        static_cast<unsigned>(loaded.Base()[result.keyMarkerOffset - 16u]) << '\n';
    std::cout << "[阶段] 主机架构 handler 不等分支\n";
    ExecuteCriticalHandlerCase(false, config, result, loaded, encoding, testImage);
    std::cout << "[阶段] 惰性 flags 跨记录保留\n";
    ExecuteLazyPreservationCase(config, result, loaded, encoding, testImage);
    std::cout << "[阶段] 数据/栈/内存全宽度双策略差分\n";
    ExecuteDataAndStackVariantMatrix(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] 算术/扩展/宽乘除全宽度双策略差分\n";
    ExecuteArithmeticVariantMatrix(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] FLAGS 家族全宽度/下游组合双策略差分\n";
    ExecuteFlagsVariantMatrix(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] 控制流函数首尾/恒真恒假双策略差分\n";
    ExecuteControlFlowBoundaryMatrix(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] CALL_HOST 目标解析/ABI/栈回写双策略差分\n";
    ExecuteCallHostVariantCases(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] BRIDGE_EXTENDED/INT3 外部效果双策略差分\n";
    ExecuteExternalSemanticVariantCases(
        config, result, loaded, encoding, testImage);
    std::cout << "[阶段] 宽除法全宽度/双策略真实 #DE\n";
    const uint8_t addressWidth =
        architecture == VMHandlerArchitecture::X64 ? 8u : 4u;
    for (uint8_t width : kSemanticWidths) {
        if (width > addressWidth) continue;
        const unsigned bits = width * 8u;
        const uint64_t sign = uint64_t{1} << (bits - 1u);
        for (uint8_t strategy : kCoreStrategies) {
            // Divisor zero and quotient overflow are distinct inputs but the
            // same architectural #DE boundary.  The signed overflow corpus is
            // the smallest positive quotient that no longer fits width bits.
            ExecuteDivideFaultCase(VM_UOP_UDIV_WIDE, 0, 1, 0, width,
                strategy, false, config, result, encoding, testImage);
            ExecuteDivideFaultCase(VM_UOP_UDIV_WIDE, 1, 0, 1, width,
                strategy, true, config, result, encoding, testImage);
            ExecuteDivideFaultCase(VM_UOP_IDIV_WIDE, 0, sign, 1, width,
                strategy, true, config, result, encoding, testImage);
        }
    }
}
#endif

void ValidateOneBuild(
    const VMHandlerSynthesisConfig& config,
    const VMHandlerSynthesisResult& result)
{
    Require(result.success, "handler 合成失败: " + result.error);
    std::string validationError;
    Require(
        VMHandlerSynthesizer::Validate(config, result, validationError),
        "handler 独立校验失败: " + validationError);
    Require(result.directThreaded, "产物不是 direct-threaded 分发");
    Require(result.handlerBodiesEncrypted, "handler 体未以密文存放");
    Require(!result.fixedRuntimeBlobUsed, "仍引用固定 runtime blob");
    Require(result.usesTemporaryPageWrite && result.restoresExecuteRead,
        "运行期解密未遵守临时可写并恢复 RX 的 W^X 路径");
    Require(!result.image.empty(), "合成 runtime image 为空");
    Require(result.entryOffset < result.image.size(), "入口偏移越界");
    Require(result.contextEntryOffset < result.image.size(), "context 入口偏移越界");
    Require(result.decryptorSize != 0 &&
        RangeInside(result.image.size(), result.decryptorOffset, result.decryptorSize),
        "per-build 解密器范围无效");
    Require(result.dispatchTableSize != 0 &&
        RangeInside(result.image.size(), result.dispatchTableOffset, result.dispatchTableSize),
        "分发表范围无效");
    Require(result.encryptedHandlerSize != 0 &&
        RangeInside(result.image.size(), result.encryptedHandlerOffset,
            result.encryptedHandlerSize),
        "handler 密文区范围无效");
    Require(RangeInside(result.image.size(), result.keyMarkerOffset,
            VM_RUNTIME_KEY_SHARE_SIZE),
        "key marker 范围无效");
    Require(result.opcodeMapDigest != 0, "opcode map digest 为空");
    Require(result.dispatchKeyDigest != 0, "dispatch key digest 为空");
    Require(result.microSelectionDigest != 0, "micro selection digest 为空");
    Require(result.variantSelectorDigest != 0, "per-instruction variant selector digest 为空");
    ValidateDirectTailUnwindCoverage(config, result);

    const size_t supportedSemanticCount = static_cast<size_t>(std::count_if(
        VMSchema::Opcodes().begin(), VMSchema::Opcodes().end(),
        [&](const VMOpcodeDescriptor& descriptor) {
            return config.architecture == VMHandlerArchitecture::X64
                ? descriptor.runtimeSupportedX64
                : descriptor.runtimeSupportedX86;
        }));
    const size_t expectedHandlerCount =
        supportedSemanticCount * config.variantCount;
    Require(result.handlers.size() == expectedHandlerCount,
        "未为每条微操作生成完整 K 变体");
    Require(result.dispatchEntries.size() == expectedHandlerCount,
        "dispatch entry 未覆盖每条有效 semantic 的 K 变体");
    const size_t junkSlotCount = static_cast<size_t>(std::count(
        config.handlerSlotToSemantic.begin(),
        config.handlerSlotToSemantic.end(),
        static_cast<uint8_t>(VM_HANDLER_JUNK)));
    Require(result.junkHandlers.size() == junkSlotCount * config.variantCount,
        "metadata声明的junk slot没有完整K份机器码");
    Require(result.junkDispatchEntries.size() == result.junkHandlers.size(),
        "junk handler与物理dispatch entry数量不一致");
    for (const auto& junk : result.junkHandlers) {
        Require(junk.semantic == VM_HANDLER_JUNK &&
            config.handlerSlotToSemantic[junk.slot] == VM_HANDLER_JUNK,
            "junk handler未绑定metadata junk slot");
        Require(junk.semanticComplete && junk.dispatchTailSize != 0,
            "junk handler不是可执行无副作用direct-threaded体");
        Require(junk.ciphertextBody != junk.plaintextBody,
            "junk handler以明文存放");
    }
    const uint32_t pointerSize = config.architecture == VMHandlerArchitecture::X64 ? 8u : 4u;
    const uint64_t minimumDispatchBytes =
        static_cast<uint64_t>(VM_HANDLER_TABLE_SIZE) * config.variantCount * pointerSize;
    Require(result.dispatchTableSize >= minimumDispatchBytes,
        "dispatch table 不是 slot*K 的可索引布局");

    std::map<std::tuple<uint8_t, uint8_t, uint8_t>, uint32_t> dispatchTargets;
    for (const auto& entry : result.dispatchEntries) {
        Require(entry.semantic < VM_UOP_COUNT, "dispatch entry semantic 越界");
        Require(entry.slot == config.handlerSemanticToSlot[entry.semantic],
            "dispatch entry slot 未遵循 build 映射");
        Require(entry.variant < config.variantCount, "dispatch entry variant 越界");
        Require(entry.targetOffset >= result.encryptedHandlerOffset &&
            entry.targetOffset < result.encryptedHandlerOffset + result.encryptedHandlerSize,
            "dispatch entry 未指向合成 handler 区");
        Require(dispatchTargets.emplace(
                std::make_tuple(entry.semantic, entry.slot, entry.variant),
                entry.targetOffset).second,
            "dispatch table 存在重复 semantic/slot/variant entry");
    }

    std::map<uint8_t, std::vector<const VMSynthesizedHandler*>> bySemantic;
    for (const auto& handler : result.handlers) {
        Require(handler.semantic < VM_UOP_COUNT, "handler semantic 越界");
        Require(handler.slot == config.handlerSemanticToSlot[handler.semantic],
            "handler slot 未遵循本次 build 映射");
        Require(handler.variant < config.variantCount, "handler variant 越界");
        Require(handler.plaintextBody.size() >= config.minimumJunkBytesPerHandler,
            "handler 体不足以承载约定的真实变异预算");
        Require(handler.ciphertextBody.size() == handler.plaintextBody.size(),
            "handler 密文长度改变了代码布局");
        Require(handler.ciphertextBody != handler.plaintextBody,
            "handler 体明文写入 VM section");
        Require(handler.storageSize == handler.ciphertextBody.size(),
            "handler storageSize 与密文不一致");
        Require(RangeInside(result.image.size(), handler.storageOffset, handler.storageSize),
            "handler storage 越过 image");
        Require(handler.storageOffset >= result.encryptedHandlerOffset &&
            handler.storageOffset + handler.storageSize <=
                result.encryptedHandlerOffset + result.encryptedHandlerSize,
            "handler 未完整落在密文区");
        Require(Slice(result.image, handler.storageOffset, handler.storageSize) ==
            handler.ciphertextBody, "VM section 中的 handler 密文与描述不一致");
        Require(handler.dispatchTailSize != 0 &&
            handler.dispatchTailOffset + handler.dispatchTailSize ==
                handler.plaintextBody.size(),
            "direct-threaded 解码/跳转尾不在 handler 末尾");
        Require(handler.bodyDigest != 0 && handler.dispatchTailDigest != 0,
            "handler 或分发尾 digest 为空");
        Require(handler.semanticComplete,
            "handler 只是空 barrier/包装层，没有完整微语义 lowering");
        const auto dispatch = dispatchTargets.find(std::make_tuple(
            handler.semantic, handler.slot, handler.variant));
        Require(dispatch != dispatchTargets.end(), "生成的 K handler 变体不可从 dispatch 到达");
        Require(dispatch->second == handler.storageOffset,
            "dispatch entry 未指向对应 K handler 体");
        Require(std::search(
            result.image.begin(), result.image.end(),
            handler.plaintextBody.begin(), handler.plaintextBody.end()) == result.image.end(),
            "产物中出现逐字节明文 handler 体");
        bySemantic[handler.semantic].push_back(&handler);
    }

    Require(bySemantic.size() == supportedSemanticCount,
        "handler semantic 集不完整");
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        const auto* descriptor = VMSchema::Lookup(static_cast<uint8_t>(semantic));
        const bool supported = descriptor &&
            (config.architecture == VMHandlerArchitecture::X64
                ? descriptor->runtimeSupportedX64
                : descriptor->runtimeSupportedX86);
        if (!supported) {
            Require(config.handlerSemanticToSlot[semantic] == VM_HANDLER_INVALID,
                "runtime-unsupported semantic owns a handler slot");
            Require(bySemantic.find(static_cast<uint8_t>(semantic)) == bySemantic.end(),
                "runtime-unsupported semantic was synthesized");
            continue;
        }
        const auto found = bySemantic.find(static_cast<uint8_t>(semantic));
        Require(found != bySemantic.end(), "缺失微操作 handler");
        Require(found->second.size() == config.variantCount, "单语义 K 变体数量错误");
        std::set<uint8_t> variants;
        std::set<std::vector<uint8_t>> bodies;
        std::set<std::array<uint8_t, 4>> assignments;
        std::set<uint32_t> targets;
        for (const VMSynthesizedHandler* handler : found->second) {
            variants.insert(handler->variant);
            bodies.insert(handler->plaintextBody);
            assignments.insert(handler->registerAssignment);
            targets.insert(dispatchTargets.at(std::make_tuple(
                handler->semantic, handler->slot, handler->variant)));
        }
        Require(variants.size() == config.variantCount, "K 变体编号重复");
        Require(bodies.size() == config.variantCount, "K 变体机器码并非全部不同");
        Require(assignments.size() >= 2, "K 变体未改变内部寄存器分配");
        Require(targets.size() == config.variantCount,
            "同一 semantic 的 K selector 未指向 K 个独立 handler 地址");
    }
}

void ValidatePerBuildDivergence(VMHandlerArchitecture architecture) {
    const auto seedA = MakeSeed(static_cast<uint8_t>(
        architecture == VMHandlerArchitecture::X64 ? 0x64 : 0x32));
    const auto seedB = MakeSeed(static_cast<uint8_t>(
        architecture == VMHandlerArchitecture::X64 ? 0xE4 : 0xB2));
    const VMHandlerSynthesisConfig configA = MakeConfig(architecture, seedA);
    const VMHandlerSynthesisConfig configB = MakeConfig(architecture, seedB);

    VMHandlerSynthesizer synthesizer;
    const VMHandlerSynthesisResult buildA = synthesizer.Synthesize(configA);
    const VMHandlerSynthesisResult buildB = synthesizer.Synthesize(configB);
    ValidateOneBuild(configA, buildA);
    ValidateOneBuild(configB, buildB);

    if (architecture == VMHandlerArchitecture::X64) {
        const uint64_t handlerEnd =
            static_cast<uint64_t>(buildA.encryptedHandlerOffset) +
            buildA.encryptedHandlerSize;
        const auto tailEntry = std::find_if(buildA.unwindEntries.begin(),
            buildA.unwindEntries.end(), [&](const auto& unwind) {
                return unwind.beginOffset >= buildA.encryptedHandlerOffset &&
                    static_cast<uint64_t>(unwind.beginOffset) < handlerEnd;
            });
        Require(tailEntry != buildA.unwindEntries.end(),
            "x64 负向门禁找不到 handler-tail unwind 记录");

        VMHandlerSynthesisResult missingCoverage = buildA;
        const size_t tailIndex = static_cast<size_t>(
            tailEntry - buildA.unwindEntries.begin());
        missingCoverage.unwindEntries.erase(
            missingCoverage.unwindEntries.begin() + tailIndex);
        std::string negativeError;
        Require(!VMHandlerSynthesizer::Validate(
                configA, missingCoverage, negativeError),
            "删除一条 x64 handler-tail unwind 后自校验仍然通过");

        VMHandlerSynthesisResult corruptEncoding = buildA;
        Require(RangeInside(corruptEncoding.image.size(),
                tailEntry->unwindOffset,
                static_cast<uint32_t>(kExpectedX64TailUnwindInfo.size())),
            "x64 handler-tail unwind 负向篡改范围越界");
        corruptEncoding.image[tailEntry->unwindOffset + 5u] ^= 0x01u;
        negativeError.clear();
        Require(!VMHandlerSynthesizer::Validate(
                configA, corruptEncoding, negativeError),
            "篡改 x64 handler-tail UNWIND_INFO 后自校验仍然通过");
    }

    Require(buildA.opcodeMapDigest != buildB.opcodeMapDigest,
        "两个 build 的 opcode map 相同");
    Require(buildA.dispatchKeyDigest != buildB.dispatchKeyDigest,
        "两个 build 的分发键相同");
    Require(buildA.microSelectionDigest != buildB.microSelectionDigest,
        "两个 build 的微操作选择相同");
    Require(buildA.variantSelectorDigest != buildB.variantSelectorDigest,
        "两个 build 的 per-instruction variant selector 相同");
    Require(Slice(buildA.image, buildA.decryptorOffset, buildA.decryptorSize) !=
        Slice(buildB.image, buildB.decryptorOffset, buildB.decryptorSize),
        "解密/滚动逻辑未随 build seed 变化");

    // 产物中的 handler 体就是 VM section 内的密文；跨构建二进制差异度
    // 必须测量这一实际交付区域。同时对解密后的必经执行代码另设上限，防止
    // 用加密掩盖固定语义内核，真 K 的寄存器/MBA/布局仍须发生实质变化。
    const double storedSimilarity = FourGramDiceSimilarity(
        Slice(buildA.image, buildA.encryptedHandlerOffset,
            buildA.encryptedHandlerSize),
        Slice(buildB.image, buildB.encryptedHandlerOffset,
            buildB.encryptedHandlerSize));
    Require(storedSimilarity < 0.15,
        "两次构建 VM section handler 密文 4-byte n-gram Dice 相似度未低于 15%: " +
        std::to_string(storedSimilarity));
    const double liveSimilarity = FourGramDiceSimilarity(
        CanonicalPlaintext(buildA), CanonicalPlaintext(buildB));
    Require(liveSimilarity < 0.35,
        "两次构建的必经执行 K 变体仍过度相似: " +
        std::to_string(liveSimilarity));

    // 相同显式 seed 必须可复现；任何隐藏全局随机源都会让差分门禁无法重放。
    const VMHandlerSynthesisResult replayA = synthesizer.Synthesize(configA);
    ValidateOneBuild(configA, replayA);
    Require(buildA.image == replayA.image,
        "相同 build seed 无法重放相同 handler image");
    Require(CanonicalPlaintext(buildA) == CanonicalPlaintext(replayA),
        "相同 build seed 无法重放相同 handler 体");
}

void TestSemanticBodyRejectsFixedCoreEnvelope() {
    std::array<VMHandlerSemanticCodegenResult, VM_HANDLER_VARIANT_COUNT> variants{};
    VMHandlerSemanticCodegenConfig selectedConfig{};
    bool foundBothCoreStrategies = false;

    for (uint16_t domain = 0; domain < 64u && !foundBothCoreStrategies; ++domain) {
        const auto seed = MakeSeed(static_cast<uint8_t>(0x80u + domain));
        std::set<uint8_t> coreStrategies;
        for (uint8_t variant = 0; variant < VM_HANDLER_VARIANT_COUNT; ++variant) {
            VMHandlerSemanticCodegenConfig config{};
            config.architecture = VM_ARCH_X64;
            config.buildSeed = seed;
            config.semantic = VM_UOP_NOT;
            config.variant = variant;
            variants[variant] = GenerateVMHandlerSemanticKernel(config);
            Require(variants[variant].success,
                "NOT semantic K 变体生成失败: " + variants[variant].error);
            std::string error;
            Require(ValidateVMHandlerSemanticVariantKernel(
                    config, variants[variant], error),
                "NOT semantic K 变体验证失败: " + error);
            Require(RangeInside(variants[variant].code.size(),
                    variants[variant].semanticBodyOffset,
                    variants[variant].semanticBodySize) &&
                variants[variant].semanticInputPathOffset >=
                    variants[variant].semanticBodyOffset &&
                variants[variant].semanticCoreVariantOffset >=
                    variants[variant].semanticCoreOffset &&
                variants[variant].semanticResultPathOffset +
                    variants[variant].semanticResultPathSize ==
                    variants[variant].semanticBodyOffset +
                    variants[variant].semanticBodySize,
                "semantic 输入/核心/结果证据未全部落在 semanticBody");
            coreStrategies.insert(variants[variant].semanticCoreStrategy);
        }
        if (coreStrategies.size() == 2u) {
            selectedConfig.architecture = VM_ARCH_X64;
            selectedConfig.buildSeed = seed;
            selectedConfig.semantic = VM_UOP_NOT;
            foundBothCoreStrategies = true;
        }
    }
    Require(foundBothCoreStrategies,
        "测试 seed 未产生两种 NOT 业务核心等价选型");

    std::set<std::array<uint8_t, 4>> registerAssignments;
    std::set<std::vector<uint8_t>> inputPaths;
    std::set<std::vector<uint8_t>> resultPaths;
    const VMHandlerSemanticCodegenResult* mbaVariant = nullptr;
    uint8_t mbaVariantIndex = 0;
    for (uint8_t variant = 0; variant < VM_HANDLER_VARIANT_COUNT; ++variant) {
        const auto& generated = variants[variant];
        registerAssignments.insert(generated.registerAssignment);
        inputPaths.insert(Slice(generated.code, generated.semanticInputPathOffset,
            generated.semanticInputPathSize));
        resultPaths.insert(Slice(generated.code, generated.semanticResultPathOffset,
            generated.semanticResultPathSize));
        if (generated.semanticCoreStrategy == 1u) {
            mbaVariant = &generated;
            mbaVariantIndex = variant;
        }
    }
    Require(registerAssignments.size() >= 2u &&
            inputPaths.size() == VM_HANDLER_VARIANT_COUNT &&
            resultPaths.size() == VM_HANDLER_VARIANT_COUNT,
        "K 变体未改变 semanticBody 的真实寄存器/MBA 数据路径");
    Require(mbaVariant != nullptr && mbaVariant->semanticCoreVariantSize == 3u,
        "缺少可用于固定核心负向门禁的 NOT MBA 变体");

    // 保留随机前后包络和真实输入/结果路径，只把业务核心退回固定 NOT。
    // 固定核心语义仍正确，但不再是 seed/variant 选中的 K 变体，必须拒绝。
    VMHandlerSemanticCodegenResult fixedCore = *mbaVariant;
    const std::array<uint8_t, 3> canonicalNot = {0x48, 0xF7, 0xD0};
    std::copy(canonicalNot.begin(), canonicalNot.end(),
        fixedCore.code.begin() + fixedCore.semanticCoreVariantOffset);
    selectedConfig.variant = mbaVariantIndex;
    std::string fixedCoreError;
    Require(!ValidateVMHandlerSemanticVariantKernel(
            selectedConfig, fixedCore, fixedCoreError) &&
        fixedCoreError.find("business core") != std::string::npos,
        "固定语义核心加随机包络错误通过 K 变体验证");

    VMHandlerSemanticCodegenResult outsideBody = *mbaVariant;
    outsideBody.semanticInputPathOffset = outsideBody.variantPrefixOffset;
    std::string outsideBodyError;
    Require(!ValidateVMHandlerSemanticVariantKernel(
            selectedConfig, outsideBody, outsideBodyError) &&
        outsideBodyError.find("semantic") != std::string::npos,
        "验证器错误接受 semanticBody 之外的变体证据");
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

void TestX86() { ValidatePerBuildDivergence(VMHandlerArchitecture::X86); }
void TestX64() { ValidatePerBuildDivergence(VMHandlerArchitecture::X64); }

} // namespace

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    int failures = 0;
#if defined(_M_X64) || defined(_M_IX86)
    Run("host-arch direct-threaded handler 差分执行与 #DE",
        &TestHostContextEntryExecution, failures);
#endif
    Run("x86 pack-time handler 合成与差异度", &TestX86, failures);
    Run("x64 pack-time handler 合成与差异度", &TestX64, failures);
    Run("semanticBody 真 K 变体负向门禁",
        &TestSemanticBodyRejectsFixedCoreEnvelope, failures);
    return failures == 0 ? 0 : 1;
}
