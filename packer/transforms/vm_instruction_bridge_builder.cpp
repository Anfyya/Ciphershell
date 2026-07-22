#include "vm_instruction_bridge_builder.h"

#include "../analysis/disassembler.h"
#include "../pe_parser/pe_utils.h"
#include "../vm/vm_schema.h"
#include "../../runtime/common/vm_micro_runtime_abi.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace CipherShell {
namespace {

// Returns UINT32_MAX (never a value a real caller could legitimately land on
// -- blob sizes here stay far below 4 GiB) to signal overflow/misuse.  An
// earlier version returned 0 for both "already aligned to offset 0" (the
// correct result for the very first thunk in an empty blob) and "overflow",
// which made every Build() call with at least one bridge request fail
// immediately with a false "thunk layout overflow": AlignUp(0, 16) computes
// (0 + 15) & ~15 == 0 through the normal, non-error path, and the caller's
// `if (aligned == 0)` treated that legitimate zero the same as the error
// sentinel.  See docs/zydis_encoder_pilot.md batch 16.
uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    if (!alignment || value > std::numeric_limits<uint32_t>::max() - (alignment - 1u))
        return std::numeric_limits<uint32_t>::max();
    return (value + alignment - 1u) & ~(alignment - 1u);
}

class CodeBuffer {
public:
    std::vector<uint8_t> bytes;
    void U8(uint8_t value) { bytes.push_back(value); }
    void U32(uint32_t value) {
        for (uint32_t i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void Raw(const uint8_t* data, size_t size) { bytes.insert(bytes.end(), data, data + size); }
    uint32_t Offset() const { return static_cast<uint32_t>(bytes.size()); }
};

class X64Assembler : public CodeBuffer {
public:
    void Endbr() { static constexpr uint8_t kCode[] = {0xF3, 0x0F, 0x1E, 0xFA}; Raw(kCode, sizeof(kCode)); }
    void Rex(bool width64, uint8_t reg, uint8_t base) {
        const uint8_t rex = static_cast<uint8_t>(0x40u | (width64 ? 8u : 0u) |
            (reg >= 8 ? 4u : 0u) | (base >= 8 ? 1u : 0u));
        if (rex != 0x40u) U8(rex);
    }
    void MemoryInstruction(uint8_t opcode, uint8_t regField, uint8_t base,
                           uint32_t displacement, bool width64 = true) {
        Rex(width64, regField, base);
        U8(opcode);
        U8(static_cast<uint8_t>(0x80u | ((regField & 7u) << 3u) | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void Store(uint8_t base, uint32_t displacement, uint8_t reg) {
        MemoryInstruction(0x89, reg, base, displacement);
    }
    void Load(uint8_t reg, uint8_t base, uint32_t displacement) {
        MemoryInstruction(0x8B, reg, base, displacement);
    }
    void Move(uint8_t destination, uint8_t source) {
        Rex(true, source, destination);
        U8(0x89);
        U8(static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) | (destination & 7u)));
    }
    void PushMemory(uint8_t base, uint32_t displacement) {
        Rex(false, 0, base);
        U8(0xFF);
        U8(static_cast<uint8_t>(0xB0u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PopMemory(uint8_t base, uint32_t displacement) {
        Rex(false, 0, base);
        U8(0x8F);
        U8(static_cast<uint8_t>(0x80u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void MovEax(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdx() { U8(0x31); U8(0xD2); }
    void Extended(uint8_t base, uint8_t operation, bool width64) {
        Rex(width64, 0, base);
        U8(0x0F); U8(0xAE);
        U8(static_cast<uint8_t>((operation << 3u) | (base & 7u)));
    }
    void Fxrstor(uint8_t base) { Extended(base, 1, true); }
    void Fxsave(uint8_t base) { Extended(base, 0, true); }
    void Xrstor(uint8_t base) { Extended(base, 5, true); }
    void Xsave(uint8_t base) { Extended(base, 4, true); }
    void Ret() { U8(0xC3); }
};

class X86Assembler : public CodeBuffer {
public:
    void Endbr() { static constexpr uint8_t kCode[] = {0xF3, 0x0F, 0x1E, 0xFB}; Raw(kCode, sizeof(kCode)); }
    void MemoryInstruction(uint8_t opcode, uint8_t regField, uint8_t base, uint32_t displacement) {
        U8(opcode);
        U8(static_cast<uint8_t>(0x80u | ((regField & 7u) << 3u) | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void Store(uint8_t base, uint32_t displacement, uint8_t reg) {
        MemoryInstruction(0x89, reg, base, displacement);
    }
    void Load(uint8_t reg, uint8_t base, uint32_t displacement) {
        MemoryInstruction(0x8B, reg, base, displacement);
    }
    void Move(uint8_t destination, uint8_t source) {
        U8(0x89);
        U8(static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) | (destination & 7u)));
    }
    void LoadStateFromStack() { U8(0x8B); U8(0x4C); U8(0x24); U8(0x04); }
    void PushMemory(uint8_t base, uint32_t displacement) {
        U8(0xFF); U8(static_cast<uint8_t>(0xB0u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PopMemory(uint8_t base, uint32_t displacement) {
        U8(0x8F); U8(static_cast<uint8_t>(0x80u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void MovEax(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdx() { U8(0x31); U8(0xD2); }
    void Extended(uint8_t base, uint8_t operation) {
        U8(0x0F); U8(0xAE);
        U8(static_cast<uint8_t>((operation << 3u) | (base & 7u)));
    }
    void Fxrstor(uint8_t base) { Extended(base, 1); }
    void Fxsave(uint8_t base) { Extended(base, 0); }
    void Xrstor(uint8_t base) { Extended(base, 5); }
    void Xsave(uint8_t base) { Extended(base, 4); }
    void Ret() { U8(0xC3); }
};

struct BuiltThunk {
    std::vector<uint8_t> code;
    uint32_t nativeOffset = 0;
    uint32_t unwindBeginOffset = 0;
};

BuiltThunk BuildX64Thunk(const VMBridgeRequest& request, uint8_t originalPrologSize) {
    constexpr uint8_t kRsp = 4;
    constexpr uint8_t kStateArgument = 1;
    constexpr std::array<uint8_t, 8> kNonvolatile = {3, 5, 6, 7, 12, 13, 14, 15};
    const uint8_t hidden = request.hiddenNativeRegister;
    const uint8_t extendedTemp = hidden == 10 ? 11 : 10;
    X64Assembler assembler;
    assembler.Endbr();
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Store(kStateArgument,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u),
            kNonvolatile[i]);
    }
    assembler.Store(kStateArgument,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)), kRsp);
    if (hidden != kStateArgument) assembler.Move(hidden, kStateArgument);

    assembler.Load(extendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xrstor(extendedTemp);
    } else assembler.Fxrstor(extendedTemp);

    for (uint8_t reg = 0; reg < 16; ++reg) {
        if (reg == hidden || reg == kRsp) continue;
        assembler.Load(reg, hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u));
    }
    assembler.PushMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    assembler.PopFlags();
    assembler.Load(kRsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kRsp * 8u));
    const uint32_t unwindBeginOffset = assembler.Offset();
    for (uint32_t i = 0; i <= originalPrologSize; ++i) assembler.U8(0x90);
    const uint32_t nativeOffset = assembler.Offset();
    assembler.Raw(request.instruction.rawBytes.data(), request.instruction.length);
    assembler.Store(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kRsp * 8u), kRsp);
    assembler.Load(kRsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)));
    assembler.PushFlags();
    assembler.PopMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    for (uint8_t reg = 0; reg < 16; ++reg) {
        if (reg == hidden || reg == kRsp) continue;
        assembler.Store(hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u), reg);
    }
    assembler.Load(extendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xsave(extendedTemp);
    } else assembler.Fxsave(extendedTemp);
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Load(kNonvolatile[i], hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u));
    }
    assembler.Ret();
    return {std::move(assembler.bytes), nativeOffset, unwindBeginOffset};
}

BuiltThunk BuildX86Thunk(const VMBridgeRequest& request) {
    constexpr uint8_t kEsp = 4;
    constexpr uint8_t kInitialState = 1;
    constexpr uint8_t kExtendedTemp = 6;
    constexpr std::array<uint8_t, 4> kNonvolatile = {3, 5, 6, 7};
    const uint8_t hidden = request.hiddenNativeRegister;
    X86Assembler assembler;
    assembler.Endbr();
    assembler.LoadStateFromStack();
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Store(kInitialState,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u),
            kNonvolatile[i]);
    }
    assembler.Store(kInitialState,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)), kEsp);
    if (hidden != kInitialState) assembler.Move(hidden, kInitialState);
    assembler.Load(kExtendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xrstor(kExtendedTemp);
    } else assembler.Fxrstor(kExtendedTemp);
    for (uint8_t reg = 0; reg < 8; ++reg) {
        if (reg == hidden || reg == kEsp) continue;
        assembler.Load(reg, hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u));
    }
    assembler.PushMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    assembler.PopFlags();
    assembler.Load(kEsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kEsp * 8u));
    const uint32_t nativeOffset = assembler.Offset();
    assembler.Raw(request.instruction.rawBytes.data(), request.instruction.length);
    assembler.Store(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kEsp * 8u), kEsp);
    assembler.Load(kEsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)));
    assembler.PushFlags();
    assembler.PopMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    for (uint8_t reg = 0; reg < 8; ++reg) {
        if (reg == hidden || reg == kEsp) continue;
        assembler.Store(hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u), reg);
    }
    assembler.Load(kExtendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xsave(kExtendedTemp);
    } else assembler.Fxsave(kExtendedTemp);
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Load(kNonvolatile[i], hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u));
    }
    assembler.Ret();
    return {std::move(assembler.bytes), nativeOffset, nativeOffset};
}

bool ReadSimpleUnwind(
    const CS_PE_IMAGE* image,
    const Function& function,
    const InstructionIR& instruction,
    std::vector<uint8_t>& unwind,
    uint8_t& prologSizeOut,
    std::string& error)
{
    const CS_RUNTIME_FUNCTION* runtimeFunction = nullptr;
    for (const auto& entry : image->exceptions.entries) {
        if (entry.beginAddress == function.entryAddress &&
            entry.endAddress >= function.entryAddress + function.size) {
            runtimeFunction = &entry;
            break;
        }
    }
    if (!runtimeFunction) {
        error = "bridge source function has no exact x64 runtime-function entry";
        return false;
    }
    const uint32_t offset = PEUtils::RvaToOffset(image, runtimeFunction->unwindData);
    if (offset == 0 || offset > image->rawSize || 4u > image->rawSize - offset) {
        error = "bridge source unwind header is outside the PE file";
        return false;
    }
    const uint8_t versionAndFlags = image->rawData[offset];
    const uint8_t version = versionAndFlags & 7u;
    const uint8_t flags = versionAndFlags >> 3u;
    const uint8_t prologSize = image->rawData[offset + 1u];
    const uint8_t codeCount = image->rawData[offset + 2u];
    // CapabilityChecker 已在函数级拒绝 V2；桥接重建器仍保留同样的本地防线，避免未来
    // 调用路径绕过 CapabilityChecker 后把 V2 epilog 元数据按 V1 原样复制。
    if (version < PEUtils::kParserUnwindInfoMinVersion ||
        version > PEUtils::kVmUnwindInfoMaxVersion || flags != 0u) {
        if (version == 2u) {
            error = "bridge source uses unsupported x64 unwind version 2 epilog semantics";
            return false;
        }
        error = "bridge source unwind uses handlers or chained metadata";
        return false;
    }
    if (instruction.rva < function.entryAddress ||
        instruction.rva - function.entryAddress < prologSize) {
        error = "extended-state instruction is inside the original x64 prolog";
        return false;
    }
    const size_t unwindSize = 4u + static_cast<size_t>((codeCount + 1u) & ~1u) * 2u;
    if (unwindSize > image->rawSize - offset) {
        error = "bridge source unwind codes are truncated";
        return false;
    }
    unwind.assign(image->rawData + offset, image->rawData + offset + unwindSize);
    prologSizeOut = prologSize;
    return true;
}

bool RipTarget(const InstructionIR& instruction, bool& hasTarget,
               uint32_t& targetRVA, std::string& error) {
    hasTarget = false;
    targetRVA = 0;
    for (const auto& operand : instruction.operands) {
        if (operand.type != OperandType::Memory || !operand.memory.isRipRelative) continue;
        if (hasTarget && targetRVA != operand.memory.resolvedRVA) {
            error = "bridge instruction contains inconsistent RIP-relative targets";
            return false;
        }
        hasTarget = true;
        targetRVA = operand.memory.resolvedRVA;
    }
    return true;
}

struct PendingThunk {
    size_t translationIndex = 0;
    size_t requestIndex = 0;
    uint32_t thunkOffset = 0;
    uint32_t thunkSize = 0;
    uint32_t nativeOffset = 0;
    uint32_t unwindBeginOffset = 0;
    uint32_t unwindOffset = 0;
};

} // namespace

VMInstructionBridgeBuildResult VMInstructionBridgeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<Function>& functions,
    std::vector<TranslationResult>& translations,
    const char sectionName[8],
    const char unwindSectionName[8],
    const char guardSectionName[8])
{
    VMInstructionBridgeBuildResult result{};
    if (!image || !image->isValid || functions.size() != translations.size() ||
        !sectionName || !unwindSectionName || !guardSectionName) {
        result.error = "VM_BRIDGE: invalid image, program list, or section names";
        return result;
    }
    size_t requestCount = 0;
    for (const auto& translation : translations) requestCount += translation.bridgeRequests.size();
    if (requestCount == 0) {
        result.success = result.cfgTableVerified = result.unwindVerified = true;
        return result;
    }

    std::vector<uint8_t> blob;
    std::vector<PendingThunk> pending;
    pending.reserve(requestCount);
    for (size_t functionIndex = 0; functionIndex < translations.size(); ++functionIndex) {
        auto& translation = translations[functionIndex];
        for (size_t requestIndex = 0; requestIndex < translation.bridgeRequests.size(); ++requestIndex) {
            const auto& request = translation.bridgeRequests[requestIndex];
            if (request.functionRVA != functions[functionIndex].entryAddress ||
                request.microOpIndex >= translation.instructions.size() ||
                request.hiddenNativeRegister >= (image->is64Bit ? 16u : 8u) ||
                (image->is64Bit && request.instruction.machineMode != MachineMode::X64) ||
                (!image->is64Bit && request.instruction.machineMode != MachineMode::X86)) {
                result.error = "VM_BRIDGE: request does not match its function or target architecture";
                return result;
            }
            const uint32_t aligned = AlignUp(static_cast<uint32_t>(blob.size()), 16u);
            if (aligned == std::numeric_limits<uint32_t>::max()) {
                result.error = "VM_BRIDGE: thunk layout overflow";
                return result;
            }
            blob.resize(aligned, 0x90);
            std::vector<uint8_t> unwind;
            uint8_t originalPrologSize = 0;
            if (image->is64Bit && !ReadSimpleUnwind(image, functions[functionIndex],
                    request.instruction, unwind, originalPrologSize, result.error)) {
                result.error = "VM_BRIDGE: " + result.error;
                return result;
            }
            BuiltThunk built = image->is64Bit
                ? BuildX64Thunk(request, originalPrologSize) : BuildX86Thunk(request);
            if (built.code.empty() || built.nativeOffset >= built.code.size() ||
                request.instruction.length > built.code.size() - built.nativeOffset) {
                result.error = "VM_BRIDGE: generated thunk has an invalid native instruction range";
                return result;
            }
            PendingThunk item{};
            item.translationIndex = functionIndex;
            item.requestIndex = requestIndex;
            item.thunkOffset = aligned;
            item.thunkSize = static_cast<uint32_t>(built.code.size());
            item.nativeOffset = aligned + built.nativeOffset;
            item.unwindBeginOffset = aligned + built.unwindBeginOffset;
            blob.insert(blob.end(), built.code.begin(), built.code.end());
            if (image->is64Bit) {
                item.unwindOffset = AlignUp(static_cast<uint32_t>(blob.size()), 4u);
                if (item.unwindOffset == std::numeric_limits<uint32_t>::max()) {
                    result.error = "VM_BRIDGE: unwind layout overflow";
                    return result;
                }
                blob.resize(item.unwindOffset, 0);
                blob.insert(blob.end(), unwind.begin(), unwind.end());
            }
            pending.push_back(item);
        }
    }

    PEEmitter emitter(image);
    const auto appended = emitter.AppendSection(sectionName, blob,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        result.error = "VM_BRIDGE: " + appended.error;
        return result;
    }

    Disassembler verifier;
    const uint64_t imageBase = PEUtils::ImageBase(image);
    if (!verifier.Initialize(image->is64Bit != 0, imageBase)) {
        result.error = "VM_BRIDGE: unable to initialize Zydis bridge verifier";
        return result;
    }
    std::vector<uint32_t> guardTargets;
    guardTargets.reserve(pending.size());
    for (const auto& item : pending) {
        auto& translation = translations[item.translationIndex];
        const auto& request = translation.bridgeRequests[item.requestIndex];
        bool hasRipTarget = false;
        uint32_t ripTargetRVA = 0;
        if (!RipTarget(request.instruction, hasRipTarget, ripTargetRVA, result.error)) {
            result.error = "VM_BRIDGE: " + result.error;
            return result;
        }
        if (hasRipTarget) {
            const uint64_t nextRVA = static_cast<uint64_t>(appended.rva) + item.nativeOffset +
                request.instruction.length;
            const int64_t displacement = static_cast<int64_t>(ripTargetRVA) -
                static_cast<int64_t>(nextRVA);
            if (displacement < std::numeric_limits<int32_t>::min() ||
                displacement > std::numeric_limits<int32_t>::max()) {
                result.error = "VM_BRIDGE: relocated RIP-relative target exceeds disp32";
                return result;
            }
            const uint32_t patchOffset = item.nativeOffset + request.instruction.displacementOffset;
            if (patchOffset > blob.size() || 4u > blob.size() - patchOffset) {
                result.error = "VM_BRIDGE: RIP-relative displacement patch is outside the thunk";
                return result;
            }
            const int32_t value = static_cast<int32_t>(displacement);
            std::memcpy(blob.data() + patchOffset, &value, sizeof(value));
        }

        const auto decodedInstructions = verifier.Disassemble(blob.data() + item.nativeOffset,
            request.instruction.length, appended.rva + item.nativeOffset);
        if (decodedInstructions.size() != 1 ||
            decodedInstructions.front().length != request.instruction.length ||
            decodedInstructions.front().mnemonicText != request.instruction.mnemonicText ||
            decodedInstructions.front().instructionSet != request.instruction.instructionSet) {
            result.error = "VM_BRIDGE: relocated instruction failed Zydis semantic verification";
            return result;
        }
        const InstructionIR& decoded = decodedInstructions.front();
        if (hasRipTarget) {
            bool decodedHasTarget = false;
            uint32_t decodedTarget = 0;
            if (!RipTarget(decoded, decodedHasTarget, decodedTarget, result.error) ||
                !decodedHasTarget || decodedTarget != ripTargetRVA) {
                result.error = "VM_BRIDGE: relocated RIP-relative target changed semantics";
                return result;
            }
        }

        if (request.microOpIndex >= translation.instructions.size()) {
            result.error = "VM_BRIDGE: linked micro-op index is outside translation";
            return result;
        }
        MicroInstruction& bytecode = translation.instructions[request.microOpIndex];
        if (bytecode.opcode != VM_UOP_BRIDGE_EXTENDED || bytecode.operandCount != 3) {
            result.error = "VM_BRIDGE: linked request does not reference BRIDGE_EXTENDED";
            return result;
        }
        bytecode.operands[0] = appended.rva + item.thunkOffset;
        bytecode.operands[1] |= VM_MICRO_BRIDGE_LINKED;
        std::string schemaError;
        if (!VMSchema::ValidateInstruction(bytecode, translation.registerCount, schemaError)) {
            result.error = "VM_BRIDGE: linked bytecode violates schema: " + schemaError;
            return result;
        }
        VMInstructionBridgeLink link{};
        link.functionRVA = request.functionRVA;
        link.instructionRVA = request.instruction.rva;
        link.thunkRVA = appended.rva + item.thunkOffset;
        link.thunkSize = item.thunkSize;
        link.nativeInstructionRVA = appended.rva + item.nativeOffset;
        link.nativeInstructionSize = request.instruction.length;
        link.unwindBeginRVA = appended.rva + item.unwindBeginOffset;
        link.hiddenNativeRegister = request.hiddenNativeRegister;
        link.usesAvx = request.usesAvx;
        link.usesX87 = request.usesX87;
        result.links.push_back(link);
        guardTargets.push_back(link.thunkRVA);
        if (image->is64Bit) {
            result.unwindEntries.push_back({link.unwindBeginRVA,
                link.nativeInstructionRVA + link.nativeInstructionSize,
                appended.rva + item.unwindOffset});
        }
    }

    if (!emitter.PatchBytes(appended.rva, blob, &result.error)) {
        result.error = "VM_BRIDGE: unable to commit relocated thunk section: " + result.error;
        return result;
    }
    if (image->is64Bit && (!emitter.RebuildExceptionDirectory(
            result.unwindEntries, unwindSectionName, nullptr, &result.error))) {
        result.error = "VM_BRIDGE: unable to rebuild bridge exception entries: " + result.error;
        return result;
    }
    result.unwindVerified = !image->is64Bit ||
        result.unwindEntries.size() == result.links.size();
    if (!emitter.RebuildGuardCFFunctionTable(
            guardTargets, guardSectionName, nullptr, &result.error)) {
        result.error = "VM_BRIDGE: unable to rebuild Guard CF target table: " + result.error;
        return result;
    }
    result.cfgTableVerified = !image->loadConfig.hasCFG;
    if (image->loadConfig.hasCFG) {
        std::unordered_set<uint32_t> guardSet(image->loadConfig.guardFunctionRVAs.begin(),
            image->loadConfig.guardFunctionRVAs.end());
        result.cfgTableVerified = std::all_of(guardTargets.begin(), guardTargets.end(),
            [&](uint32_t rva) { return guardSet.count(rva) != 0; });
    }
    if (!result.cfgTableVerified || !result.unwindVerified) {
        result.error = "VM_BRIDGE: CFG or unwind linkage verification failed";
        return result;
    }
    result.sectionRVA = appended.rva;
    result.sectionRawOffset = image->sections[appended.sectionIndex].PointerToRawData;
    result.sectionSize = image->sections[appended.sectionIndex].SizeOfRawData;
    result.success = true;
    return result;
}

} // namespace CipherShell
