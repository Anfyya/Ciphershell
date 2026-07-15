#include "cfg_flattener.h"

#include "../analysis/capability_checker.h"
#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace CipherShell {
namespace {

constexpr uint32_t kInvalidOffset = (std::numeric_limits<uint32_t>::max)();
constexpr uint16_t kRelocationHighLow = 3u;
constexpr uint16_t kRelocationDir64 = 10u;

uint64_t Mix64(uint64_t value) {
    value ^= value >> 30u;
    value *= 0xBF58476D1CE4E5B9ULL;
    value ^= value >> 27u;
    value *= 0x94D049BB133111EBULL;
    return value ^ (value >> 31u);
}

class SeedStream {
public:
    explicit SeedStream(uint64_t seed)
        : state_(Mix64(seed ^ 0x434647464C415435ULL)) {
        if (state_ == 0) state_ = 0x9E3779B97F4A7C15ULL;
    }

    uint64_t Next64() {
        state_ += 0x9E3779B97F4A7C15ULL;
        return Mix64(state_);
    }
    uint32_t Next32() { return static_cast<uint32_t>(Next64()); }
    uint32_t Below(uint32_t upper) {
        return upper == 0 ? 0 : static_cast<uint32_t>(Next64() % upper);
    }

private:
    uint64_t state_;
};

template <typename T>
void Shuffle(std::vector<T>& values, SeedStream& random) {
    for (size_t index = values.size(); index > 1; --index) {
        const size_t other = random.Below(static_cast<uint32_t>(index));
        std::swap(values[index - 1u], values[other]);
    }
}

uint32_t RotateLeft32(uint32_t value, uint32_t count) {
    count &= 31u;
    return count == 0 ? value :
        static_cast<uint32_t>((value << count) | (value >> (32u - count)));
}

bool OperandWrites(OperandAction action) {
    return action == OperandAction::Write || action == OperandAction::ReadWrite ||
        action == OperandAction::ConditionalWrite ||
        action == OperandAction::ConditionalReadWrite;
}

bool IsX64StackMutatingInstruction(const InstructionIR& instruction) {
    if (instruction.IsReturn()) return false;
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Push:
        case InstructionMnemonic::Pop:
        case InstructionMnemonic::PushFlags:
        case InstructionMnemonic::PopFlags:
        case InstructionMnemonic::Leave:
            return true;
        default:
            break;
    }
    for (const OperandIR& operand : instruction.operands) {
        if (operand.type == OperandType::Register &&
            operand.regInfo.registerClass == RegisterCategory::GeneralPurpose &&
            operand.regInfo.family == 4u && OperandWrites(operand.action)) {
            return true;
        }
    }
    return false;
}

bool Rel32Value(uint32_t sourceAfter, uint32_t target, int32_t& value) {
    const int64_t relative = static_cast<int64_t>(target) - sourceAfter;
    if (relative < static_cast<int64_t>((std::numeric_limits<int32_t>::min)()) ||
        relative > static_cast<int64_t>((std::numeric_limits<int32_t>::max)())) {
        return false;
    }
    value = static_cast<int32_t>(relative);
    return true;
}

uint32_t ReadU32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8u) |
        (static_cast<uint32_t>(bytes[2]) << 16u) |
        (static_cast<uint32_t>(bytes[3]) << 24u);
}

void WriteU32(std::vector<uint8_t>& bytes, uint32_t offset, uint32_t value) {
    for (uint32_t index = 0; index < 4u; ++index)
        bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8u));
}

bool RangeInside(uint32_t total, uint32_t offset, uint32_t size) {
    return offset <= total && size <= total - offset;
}

uint8_t ConditionOpcode(BranchKind kind) {
    switch (kind) {
        case BranchKind::Overflow: return 0x80;
        case BranchKind::NotOverflow: return 0x81;
        case BranchKind::Below: return 0x82;
        case BranchKind::AboveOrEqual: return 0x83;
        case BranchKind::Equal: return 0x84;
        case BranchKind::NotEqual: return 0x85;
        case BranchKind::BelowOrEqual: return 0x86;
        case BranchKind::Above: return 0x87;
        case BranchKind::Sign: return 0x88;
        case BranchKind::NotSign: return 0x89;
        case BranchKind::Parity: return 0x8A;
        case BranchKind::NotParity: return 0x8B;
        case BranchKind::Less: return 0x8C;
        case BranchKind::GreaterOrEqual: return 0x8D;
        case BranchKind::LessOrEqual: return 0x8E;
        case BranchKind::Greater: return 0x8F;
        default: return 0;
    }
}

class CodeBuffer {
public:
    struct RelativePatch {
        uint32_t fieldOffset = 0;
        size_t label = 0;
        uint32_t sourceAfter = 0;
    };
    struct DeltaPatch {
        uint32_t fieldOffset = 0;
        size_t label = 0;
        uint32_t baseOffset = 0;
    };

    size_t NewLabel() {
        labels_.push_back(kInvalidOffset);
        return labels_.size() - 1u;
    }
    bool Bind(size_t label) {
        if (label >= labels_.size() || labels_[label] != kInvalidOffset ||
            bytes.size() > (std::numeric_limits<uint32_t>::max)()) return false;
        labels_[label] = static_cast<uint32_t>(bytes.size());
        return true;
    }
    uint32_t LabelOffset(size_t label) const {
        return label < labels_.size() ? labels_[label] : kInvalidOffset;
    }
    uint32_t Offset() const { return static_cast<uint32_t>(bytes.size()); }
    void U8(uint8_t value) { bytes.push_back(value); }
    void U32(uint32_t value) {
        for (uint32_t index = 0; index < 4u; ++index)
            U8(static_cast<uint8_t>(value >> (index * 8u)));
    }
    void Raw(std::initializer_list<uint8_t> values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    void Raw(const uint8_t* values, size_t size) {
        bytes.insert(bytes.end(), values, values + size);
    }
    void Rel32(size_t label) {
        const uint32_t field = Offset();
        U32(0);
        relatives_.push_back({field, label, field + 4u});
    }
    void Delta32(size_t label, uint32_t baseOffset) {
        const uint32_t field = Offset();
        U32(0);
        deltas_.push_back({field, label, baseOffset});
    }
    bool Finalize(std::string& error) {
        for (uint32_t offset : labels_) {
            if (offset == kInvalidOffset) {
                error = "generated CFG contains an unbound label";
                return false;
            }
        }
        for (const RelativePatch& patch : relatives_) {
            int32_t value = 0;
            if (!Rel32Value(patch.sourceAfter, labels_[patch.label], value)) {
                error = "generated CFG local rel32 is out of range";
                return false;
            }
            WriteU32(bytes, patch.fieldOffset, static_cast<uint32_t>(value));
        }
        for (const DeltaPatch& patch : deltas_) {
            const int64_t value = static_cast<int64_t>(labels_[patch.label]) -
                static_cast<int64_t>(patch.baseOffset);
            if (value < static_cast<int64_t>((std::numeric_limits<int32_t>::min)()) ||
                value > static_cast<int64_t>((std::numeric_limits<int32_t>::max)())) {
                error = "generated CFG x86 address delta is out of range";
                return false;
            }
            WriteU32(bytes, patch.fieldOffset,
                static_cast<uint32_t>(static_cast<int32_t>(value)));
        }
        return true;
    }

    std::vector<uint8_t> bytes;

private:
    std::vector<uint32_t> labels_;
    std::vector<RelativePatch> relatives_;
    std::vector<DeltaPatch> deltas_;
};

struct LogicalBlock {
    const BasicBlock* block = nullptr;
    uint32_t state = 0;
    size_t label = 0;
};

struct PendingTransition {
    uint32_t callOffset = 0;
    uint32_t tokenOffset = 0;
    uint32_t state = 0;
    size_t targetLabel = 0;
};

struct PendingCase {
    uint32_t state = 0;
    size_t targetLabel = 0;
    size_t bodyLabel = 0;
    bool junk = false;
};

bool AddCodeRVA(uint32_t base, uint32_t offset, uint32_t& value) {
    if (offset > (std::numeric_limits<uint32_t>::max)() - base) return false;
    value = base + offset;
    return true;
}

bool PatchCopiedInstruction(
    CodeBuffer& code,
    uint32_t codeRVA,
    uint32_t generatedOffset,
    const InstructionIR& instruction,
    CFGFlattenedFunction& result,
    std::string& error)
{
    bool relativeImmediateSeen = false;
    for (const OperandIR& operand : instruction.operands) {
        if (operand.type == OperandType::Immediate && operand.immediateRelative)
            relativeImmediateSeen = true;
    }

    if (instruction.IsCall() && !instruction.isIndirectBranch) {
        if (!instruction.hasBranchTarget || instruction.immediateSize != 4u ||
            instruction.immediateOffset == 0u ||
            instruction.immediateOffset + instruction.immediateSize > instruction.length) {
            error = "direct CALL has no relocatable rel32 field";
            return false;
        }
        uint32_t sourceAfter = 0;
        if (!AddCodeRVA(codeRVA, generatedOffset + instruction.length, sourceAfter)) {
            error = "relocated CALL source RVA overflows";
            return false;
        }
        int32_t relative = 0;
        if (!Rel32Value(sourceAfter, instruction.branchTargetRVA, relative)) {
            error = "relocated direct CALL target is outside rel32 range";
            return false;
        }
        const uint32_t field = generatedOffset + instruction.immediateOffset;
        WriteU32(code.bytes, field, static_cast<uint32_t>(relative));
        result.codeRelocations.push_back({CFGCodeRelocationKind::RelativeCall,
            generatedOffset, field, 4u, instruction.branchTargetRVA});
    } else if (relativeImmediateSeen && !instruction.IsBranch()) {
        error = "non-control relative immediate is not supported by CFG relocation";
        return false;
    }

    uint32_t ripTarget = 0;
    uint32_t ripOperandCount = 0;
    for (const OperandIR& operand : instruction.operands) {
        if (operand.type == OperandType::Memory && operand.memory.isRipRelative) {
            ++ripOperandCount;
            ripTarget = operand.memory.resolvedRVA;
        }
    }
    if (ripOperandCount != 0u) {
        if (ripOperandCount != 1u || instruction.displacementSize != 4u ||
            instruction.displacementOffset == 0u ||
            instruction.displacementOffset + instruction.displacementSize >
                instruction.length) {
            error = "RIP-relative instruction has no unique relocatable disp32";
            return false;
        }
        uint32_t sourceAfter = 0;
        if (!AddCodeRVA(codeRVA, generatedOffset + instruction.length, sourceAfter)) {
            error = "relocated RIP-relative source RVA overflows";
            return false;
        }
        int32_t relative = 0;
        if (!Rel32Value(sourceAfter, ripTarget, relative)) {
            error = "relocated RIP-relative target is outside disp32 range";
            return false;
        }
        const uint32_t field = generatedOffset + instruction.displacementOffset;
        WriteU32(code.bytes, field, static_cast<uint32_t>(relative));
        result.codeRelocations.push_back({CFGCodeRelocationKind::RipRelativeMemory,
            generatedOffset, field, 4u, ripTarget});
    }
    return true;
}

void EmitTransition(
    CodeBuffer& code,
    size_t dispatcherLabel,
    uint32_t state,
    size_t targetLabel,
    std::vector<PendingTransition>& transitions)
{
    const uint32_t callOffset = code.Offset();
    code.U8(0xE8);
    code.Rel32(dispatcherLabel);
    const uint32_t tokenOffset = code.Offset();
    // If an exception unwinds out of the dispatcher and execution is
    // deliberately resumed at the synthetic return point, skip the literal
    // and fail closed instead of interpreting state bytes as instructions.
    code.Raw({0xEB,0x04});
    code.U32(state);
    code.Raw({0xCC,0x0F,0x0B});
    transitions.push_back({callOffset, tokenOffset, state, targetLabel});
}

void EmitDispatcherRestoreAndReturn(CodeBuffer& code, bool is64Bit) {
    if (is64Bit) {
        // R13 contains AH={SF,ZF,AF,PF,CF} and AL={OF}.  ADD AL,7F
        // reconstructs OF, SAHF restores the remaining arithmetic flags, and
        // neither instruction touches DF/IF/TF.  RAX is then restored from RBX.
        code.Raw({0x4C,0x89,0xE8,0x04,0x7F,0x9E,0x48,0x89,0xD8,
                  0x41,0x5D,0x41,0x5C,0x5B,0xC3});
    } else {
        code.Raw({0x89,0xF8,0x04,0x7F,0x9E,0x89,0xD8,
                  0x5F,0x5E,0x5B,0xC3});
    }
}

bool RuntimeFunctionEquals(
    const CS_RUNTIME_FUNCTION& left,
    const CS_RUNTIME_FUNCTION& right)
{
    return left.beginAddress == right.beginAddress &&
        left.endAddress == right.endAddress &&
        left.unwindData == right.unwindData;
}

} // namespace

CFGFlattenedFunction CFGFlattener::Generate(
    const Function& function,
    bool is64Bit,
    uint32_t codeRVA,
    const FlatteningConfig& config) const
{
    CFGFlattenedFunction result{};
    result.is64Bit = is64Bit;
    result.originalFunctionRVA = static_cast<uint32_t>(function.entryAddress);
    result.originalFunctionSize = function.size;
    result.codeRVA = codeRVA;

    if (config.buildSeed == 0u) {
        result.error = "CFG build seed is zero";
        return result;
    }
    if (!function.boundaryTrusted || function.entryAddress > 0xFFFFFFFFULL ||
        function.size < 5u || function.blocks.empty() || function.decodedBytes == 0u) {
        result.error = "CFG function has no trusted decoded boundary";
        return result;
    }
    if (function.usesSEH || function.hasExternalInteriorReference) {
        result.error = "CFG function uses SEH or has an external interior reference";
        return result;
    }
    if (is64Bit && !function.isLeaf) {
        result.error = "x64 CFG mode currently requires a leaf function for unwind closure";
        return result;
    }

    std::unordered_map<uint32_t, const BasicBlock*> byStart;
    for (const BasicBlock& block : function.blocks) {
        if (block.startAddress > 0xFFFFFFFFULL || block.instructions.empty() ||
            !byStart.emplace(static_cast<uint32_t>(block.startAddress), &block).second) {
            result.error = "CFG contains an empty, duplicate, or out-of-range basic block";
            return result;
        }
        for (const InstructionIR& instruction : block.instructions) {
            const uint64_t instructionEnd = instruction.address + instruction.length;
            const uint64_t functionEnd = function.entryAddress + function.size;
            if (instruction.length == 0u || instruction.address < function.entryAddress ||
                instructionEnd > functionEnd) {
                result.error = "CFG instruction escapes the trusted function envelope";
                return result;
            }
            if (is64Bit && IsX64StackMutatingInstruction(instruction)) {
                result.error = "x64 CFG function mutates RSP and requires unsupported unwind rewriting";
                return result;
            }
        }
        for (uint64_t successor : block.successors) {
            if (successor > 0xFFFFFFFFULL) {
                result.error = "CFG successor exceeds the PE RVA range";
                return result;
            }
        }
    }
    const auto entryFound = byStart.find(static_cast<uint32_t>(function.entryAddress));
    if (entryFound == byStart.end()) {
        result.error = "CFG entry is not a basic-block boundary";
        return result;
    }

    SeedStream random(config.buildSeed ^ function.entryAddress ^
        (is64Bit ? 0x783634434647ULL : 0x783836434647ULL));
    result.stateEncryptionKey = config.enableStateEncryption
        ? (random.Next32() | 1u) : 0u;
    const uint32_t rotation = (config.stateKeyRotation % 31u) + 1u;
    std::unordered_set<uint32_t> states;
    auto makeState = [&](uint32_t ordinal) {
        uint32_t state = ordinal + 1u;
        if (config.enableStateEncryption)
            state = RotateLeft32(state ^ result.stateEncryptionKey, rotation);
        if (config.enableStateRandomization)
            state ^= random.Next32();
        while (state == 0u || !states.insert(state).second)
            state = random.Next32() | 1u;
        return state;
    };

    CodeBuffer code;
    const size_t dispatcherLabel = code.NewLabel();
    std::vector<LogicalBlock> blocks;
    blocks.reserve(function.blocks.size());
    std::unordered_map<uint32_t, size_t> blockIndex;
    for (size_t index = 0; index < function.blocks.size(); ++index) {
        LogicalBlock logical{};
        logical.block = &function.blocks[index];
        logical.state = makeState(static_cast<uint32_t>(index));
        logical.label = code.NewLabel();
        blockIndex.emplace(static_cast<uint32_t>(logical.block->startAddress), index);
        blocks.push_back(logical);
    }

    std::vector<size_t> order(blocks.size());
    for (size_t index = 0; index < order.size(); ++index) order[index] = index;
    if (config.enableStateRandomization) Shuffle(order, random);

    const size_t entryIndex = blockIndex.at(
        static_cast<uint32_t>(function.entryAddress));
    std::vector<PendingTransition> pendingTransitions;
    result.entryOffset = code.Offset();
    EmitTransition(code, dispatcherLabel, blocks[entryIndex].state,
        blocks[entryIndex].label, pendingTransitions);

    for (size_t orderedIndex : order) {
        LogicalBlock& logical = blocks[orderedIndex];
        if (!code.Bind(logical.label)) {
            result.error = "CFG block label was bound more than once";
            return result;
        }
        CFGFlattenedBlockRecord record{};
        record.originalRVA = static_cast<uint32_t>(logical.block->startAddress);
        record.generatedOffset = code.Offset();
        record.encodedState = logical.state;

        const InstructionIR& terminal = logical.block->instructions.back();
        if (terminal.isIndirectBranch && !terminal.IsCall()) {
            result.error = "indirect non-call CFG edge cannot be flattened safely";
            return result;
        }
        const size_t copyCount = terminal.IsBranch()
            ? logical.block->instructions.size() - 1u
            : logical.block->instructions.size();
        for (size_t instructionIndex = 0; instructionIndex < copyCount;
                ++instructionIndex) {
            const InstructionIR& instruction =
                logical.block->instructions[instructionIndex];
            if (instruction.IsCall() && instruction.hasBranchTarget &&
                instruction.branchTargetRVA > function.entryAddress &&
                instruction.branchTargetRVA < function.entryAddress + function.size) {
                result.error = "direct CALL into the protected function interior is unsupported";
                return result;
            }
            const uint32_t generatedInstruction = code.Offset();
            code.Raw(instruction.rawBytes.data(), instruction.length);
            result.copiedInstructions.push_back({instruction.rva,
                generatedInstruction, instruction.length});
            if (!PatchCopiedInstruction(code, codeRVA, generatedInstruction,
                    instruction, result, result.error)) return result;
        }

        if (terminal.IsReturn()) {
            record.terminalReturn = true;
        } else if (terminal.IsConditionalBranch()) {
            record.conditional = true;
            const uint8_t condition = ConditionOpcode(terminal.branchKind);
            if (condition == 0u || !terminal.hasBranchTarget ||
                logical.block->successors.size() != 2u) {
                result.error = "conditional CFG block has no supported two-way edge";
                return result;
            }
            const auto trueFound = blockIndex.find(terminal.branchTargetRVA);
            if (trueFound == blockIndex.end()) {
                result.error = "conditional taken edge is outside the flattened function";
                return result;
            }
            uint32_t falseRVA = 0;
            for (uint64_t successor : logical.block->successors) {
                if (successor != terminal.branchTargetRVA)
                    falseRVA = static_cast<uint32_t>(successor);
            }
            const auto falseFound = blockIndex.find(falseRVA);
            if (falseRVA == 0u || falseFound == blockIndex.end()) {
                result.error = "conditional fallthrough edge is outside the flattened function";
                return result;
            }
            const size_t trueTransition = code.NewLabel();
            code.Raw({0x0F,condition});
            code.Rel32(trueTransition);
            EmitTransition(code, dispatcherLabel, blocks[falseFound->second].state,
                blocks[falseFound->second].label, pendingTransitions);
            if (!code.Bind(trueTransition)) {
                result.error = "conditional transition label was rebound";
                return result;
            }
            EmitTransition(code, dispatcherLabel, blocks[trueFound->second].state,
                blocks[trueFound->second].label, pendingTransitions);
        } else if (terminal.IsBranch()) {
            if (!terminal.hasBranchTarget || logical.block->successors.size() != 1u) {
                result.error = "unconditional CFG block has no unique direct edge";
                return result;
            }
            const auto target = blockIndex.find(terminal.branchTargetRVA);
            if (target == blockIndex.end()) {
                result.error = "unconditional edge leaves the flattened function";
                return result;
            }
            EmitTransition(code, dispatcherLabel, blocks[target->second].state,
                blocks[target->second].label, pendingTransitions);
        } else if (logical.block->successors.size() == 1u) {
            const uint32_t targetRVA =
                static_cast<uint32_t>(logical.block->successors.front());
            const auto target = blockIndex.find(targetRVA);
            if (target == blockIndex.end()) {
                result.error = "fallthrough edge leaves the flattened function";
                return result;
            }
            EmitTransition(code, dispatcherLabel, blocks[target->second].state,
                blocks[target->second].label, pendingTransitions);
        } else {
            result.error = "non-return CFG block has no unique successor";
            return result;
        }
        record.generatedSize = code.Offset() - record.generatedOffset;
        result.blocks.push_back(record);
    }

    std::vector<PendingCase> cases;
    cases.reserve(blocks.size() + config.junkCaseCount);
    for (const LogicalBlock& block : blocks)
        cases.push_back({block.state, block.label, code.NewLabel(), false});
    for (uint32_t index = 0; index < config.junkCaseCount; ++index) {
        const size_t junkLabel = code.NewLabel();
        if (!code.Bind(junkLabel)) {
            result.error = "junk block label was rebound";
            return result;
        }
        // A fake case is a real dispatcher target, but no live transition owns
        // its encoded state.  If reached through corruption it fails closed.
        code.Raw({0x66,0x90,0x0F,0x1F,0x40,0x00,0xCC,0x0F,0x0B});
        cases.push_back({makeState(static_cast<uint32_t>(blocks.size()) + index),
            junkLabel, code.NewLabel(), true});
    }
    if (config.enableDispatcherMutation) Shuffle(cases, random);

    if (!code.Bind(dispatcherLabel)) {
        result.error = "dispatcher label was rebound";
        return result;
    }
    result.dispatcherOffset = code.Offset();
    if (is64Bit) {
        // ENDBR64; push rbx/r12/r13; save RAX and arithmetic flags; load the
        // synthetic return-token pointer.  The three pushes have exact xdata.
        code.Raw({0xF3,0x0F,0x1E,0xFA,0x53,0x41,0x54,0x41,0x55,
                  0x48,0x89,0xC3,0x9F,0x0F,0x90,0xC0,0x49,0x89,0xC5,
                  0x4C,0x8B,0x64,0x24,0x18});
    } else {
        code.Raw({0xF3,0x0F,0x1E,0xFB,0x53,0x56,0x57,0x89,0xC3,
                  0x9F,0x0F,0x90,0xC0,0x89,0xC7,0x8B,0x74,0x24,0x0C});
    }
    for (const PendingCase& dispatchCase : cases) {
        if (is64Bit)
            code.Raw({0x41,0x81,0x7C,0x24,0x02});
        else
            code.Raw({0x81,0x7E,0x02});
        code.U32(dispatchCase.state);
        code.Raw({0x0F,0x84});
        code.Rel32(dispatchCase.bodyLabel);
    }
    // Unknown/corrupted state: leave the unwind-described pushes in place so
    // the trap has a valid x64 stack walk.
    code.Raw({0xCC,0x0F,0x0B});

    for (const PendingCase& dispatchCase : cases) {
        if (!code.Bind(dispatchCase.bodyLabel)) {
            result.error = "dispatcher case label was rebound";
            return result;
        }
        if (is64Bit) {
            code.Raw({0x4C,0x8D,0x25});
            code.Rel32(dispatchCase.targetLabel);
            code.Raw({0x4C,0x89,0x64,0x24,0x18});
        } else {
            const uint32_t anchor = code.Offset() + 5u;
            code.Raw({0xE8,0x00,0x00,0x00,0x00,0x5E,0x8D,0xB6});
            code.Delta32(dispatchCase.targetLabel, anchor);
            code.Raw({0x89,0x74,0x24,0x0C});
        }
        EmitDispatcherRestoreAndReturn(code, is64Bit);
    }
    result.dispatcherSize = code.Offset() - result.dispatcherOffset;

    if (!code.Finalize(result.error)) return result;
    result.code = std::move(code.bytes);

    for (const PendingTransition& transition : pendingTransitions) {
        const uint32_t target = code.LabelOffset(transition.targetLabel);
        if (target == kInvalidOffset) {
            result.error = "transition target label was not resolved";
            return result;
        }
        result.transitions.push_back({transition.callOffset, transition.tokenOffset,
            transition.state, target});
    }
    for (const PendingCase& dispatchCase : cases) {
        const uint32_t target = code.LabelOffset(dispatchCase.targetLabel);
        if (target == kInvalidOffset) {
            result.error = "dispatcher target label was not resolved";
            return result;
        }
        result.dispatchCases.push_back({dispatchCase.state, target,
            dispatchCase.junk});
    }
    if (is64Bit) {
        // UNWIND_INFO v1: ENDBR64 is followed by PUSH RBX (offset 5),
        // PUSH R12 (offset 7), PUSH R13 (offset 9).
        result.dispatcherUnwindInfo = {
            0x01,0x09,0x03,0x00,
            0x09,0xD0,0x07,0xC0,0x05,0x30,0x00,0x00
        };
    }

    result.success = true;
    std::string validationError;
    if (!ValidateGeneratedFunction(result, validationError)) {
        result.success = false;
        result.error = validationError;
    }
    return result;
}

bool CFGFlattener::ValidateGeneratedFunction(
    const CFGFlattenedFunction& function,
    std::string& error)
{
    if (!function.success || function.code.empty() || function.codeRVA == 0u ||
        function.originalFunctionRVA == 0u || function.originalFunctionSize < 5u ||
        !RangeInside(static_cast<uint32_t>(function.code.size()),
            function.entryOffset, 1u) ||
        !RangeInside(static_cast<uint32_t>(function.code.size()),
            function.dispatcherOffset, function.dispatcherSize) ||
        function.dispatcherSize == 0u || function.blocks.empty() ||
        function.dispatchCases.empty() || function.transitions.empty()) {
        error = "generated CFG descriptor is incomplete";
        return false;
    }
    if (function.is64Bit) {
        static const std::vector<uint8_t> expected = {
            0x01,0x09,0x03,0x00,
            0x09,0xD0,0x07,0xC0,0x05,0x30,0x00,0x00
        };
        if (function.dispatcherUnwindInfo != expected) {
            error = "x64 CFG dispatcher unwind metadata is not canonical";
            return false;
        }
    } else if (!function.dispatcherUnwindInfo.empty()) {
        error = "x86 CFG function unexpectedly contains x64 unwind metadata";
        return false;
    }

    std::map<uint32_t, uint32_t> liveCases;
    std::set<uint32_t> allStates;
    for (const CFGDispatchCaseRecord& dispatchCase : function.dispatchCases) {
        if (dispatchCase.encodedState == 0u ||
            dispatchCase.targetOffset >= function.code.size() ||
            !allStates.insert(dispatchCase.encodedState).second) {
            error = "CFG dispatcher contains a zero, duplicate, or out-of-range case";
            return false;
        }
        if (!dispatchCase.junk)
            liveCases.emplace(dispatchCase.encodedState, dispatchCase.targetOffset);
    }
    for (const CFGFlattenedBlockRecord& block : function.blocks) {
        const auto found = liveCases.find(block.encodedState);
        if (block.generatedSize == 0u ||
            !RangeInside(static_cast<uint32_t>(function.code.size()),
                block.generatedOffset, block.generatedSize) ||
            found == liveCases.end() || found->second != block.generatedOffset) {
            error = "CFG block is not owned by exactly one live dispatcher case";
            return false;
        }
    }
    if (liveCases.size() != function.blocks.size()) {
        error = "CFG live dispatcher cases and real block bodies are not one-to-one";
        return false;
    }

    std::set<uint32_t> transitionOffsets;
    for (const CFGTransitionRecord& transition : function.transitions) {
        if (!RangeInside(static_cast<uint32_t>(function.code.size()),
                transition.callOffset, 14u) ||
            transition.tokenOffset != transition.callOffset + 5u ||
            function.code[transition.callOffset] != 0xE8 ||
            function.code[transition.tokenOffset] != 0xEB ||
            function.code[transition.tokenOffset + 1u] != 0x04 ||
            ReadU32(function.code.data() + transition.tokenOffset + 2u) !=
                transition.encodedState ||
            function.code[transition.tokenOffset + 6u] != 0xCC ||
            function.code[transition.tokenOffset + 7u] != 0x0F ||
            function.code[transition.tokenOffset + 8u] != 0x0B ||
            !transitionOffsets.insert(transition.callOffset).second) {
            error = "CFG transition token is malformed or duplicated";
            return false;
        }
        const int32_t relative = static_cast<int32_t>(ReadU32(
            function.code.data() + transition.callOffset + 1u));
        const int64_t target = static_cast<int64_t>(transition.callOffset + 5u) + relative;
        const auto live = liveCases.find(transition.encodedState);
        if (target != function.dispatcherOffset || live == liveCases.end() ||
            live->second != transition.targetOffset) {
            error = "CFG transition does not reach its dispatcher/state target";
            return false;
        }
    }
    if (function.transitions.front().callOffset != function.entryOffset) {
        error = "CFG entry is not a real state transition";
        return false;
    }

    for (const CFGCodeRelocation& relocation : function.codeRelocations) {
        if (relocation.fieldSize != 4u ||
            !RangeInside(static_cast<uint32_t>(function.code.size()),
                relocation.fieldOffset, relocation.fieldSize)) {
            error = "CFG copied-code relocation range is invalid";
            return false;
        }
        const int32_t relative = static_cast<int32_t>(ReadU32(
            function.code.data() + relocation.fieldOffset));
        uint32_t instructionEnd = 0;
        const auto copied = std::find_if(function.copiedInstructions.begin(),
            function.copiedInstructions.end(), [&](const CFGCopiedInstructionRange& range) {
                return range.generatedOffset == relocation.instructionOffset;
            });
        if (copied == function.copiedInstructions.end() ||
            !AddCodeRVA(function.codeRVA,
                copied->generatedOffset + copied->size, instructionEnd) ||
            static_cast<int64_t>(instructionEnd) + relative != relocation.targetRVA) {
            error = "CFG copied-code relocation does not resolve to its recorded target";
            return false;
        }
    }
    return true;
}

CFGProtectionResult CFGFlattener::Protect(
    CS_PE_IMAGE* image,
    const std::vector<Function>& functions,
    const FlatteningConfig& config,
    const char codeSectionName[8],
    const char unwindSectionName[8],
    const char exceptionSectionName[8],
    const char relocationSectionName[8]) const
{
    CFGProtectionResult result{};
    if (!image || !image->isValid || !image->rawData || functions.empty() ||
        !codeSectionName || !unwindSectionName || !exceptionSectionName ||
        !relocationSectionName) {
        result.error = "CFG protection received an invalid image or empty function plan";
        return result;
    }
    result.is64Bit = image->is64Bit != 0;
    if (config.buildSeed == 0u) {
        result.error = "CFG protection build seed is zero";
        return result;
    }

    PEEmitter emitter(image);
    uint32_t predictedRVA = 0;
    if (!emitter.PredictNextSectionRVA(predictedRVA, &result.error)) return result;

    std::vector<uint8_t> section;
    CapabilityChecker capabilityChecker;
    for (const Function& function : functions) {
        std::string capabilityError;
        if (!capabilityChecker.IsFunctionCfgSafe(
                image, function, capabilityError)) {
            result.error = "CFG safety preflight failed: " + capabilityError;
            return result;
        }
        if (function.entryAddress > 0xFFFFFFFFULL) {
            result.error = "CFG function entry exceeds PE RVA range";
            return result;
        }
        if (result.is64Bit) {
            const uint32_t begin = static_cast<uint32_t>(function.entryAddress);
            const uint64_t end = static_cast<uint64_t>(begin) + function.size;
            for (const CS_RUNTIME_FUNCTION& runtimeFunction : image->exceptions.entries) {
                if (begin < runtimeFunction.endAddress &&
                    end > runtimeFunction.beginAddress) {
                    result.error = "x64 CFG function overlaps pdata and requires unsupported unwind rewriting";
                    return result;
                }
            }
        }
        while ((section.size() & 15u) != 0u) section.push_back(0x90);
        if (section.size() > (std::numeric_limits<uint32_t>::max)() - predictedRVA) {
            result.error = "CFG code section layout overflows RVA range";
            return result;
        }
        CFGProtectedFunctionRecord record{};
        record.sectionOffset = static_cast<uint32_t>(section.size());
        FlatteningConfig perFunction = config;
        perFunction.buildSeed ^= Mix64(function.entryAddress ^ record.sectionOffset);
        if (perFunction.buildSeed == 0u) perFunction.buildSeed = config.buildSeed;
        record.flattened = Generate(function, result.is64Bit,
            predictedRVA + record.sectionOffset, perFunction);
        if (!record.flattened.success) {
            result.error = "CFG generation failed at RVA 0x";
            const char hex[] = "0123456789abcdef";
            for (int shift = 28; shift >= 0; shift -= 4)
                result.error.push_back(hex[(static_cast<uint32_t>(
                    function.entryAddress) >> shift) & 0xFu]);
            result.error += ": " + record.flattened.error;
            return result;
        }
        section.insert(section.end(), record.flattened.code.begin(),
            record.flattened.code.end());
        result.functions.push_back(std::move(record));
    }
    if (section.empty()) {
        result.error = "CFG code section is empty";
        return result;
    }

    const PEAppendSectionResult codeSection = emitter.AppendSection(codeSectionName,
        section, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!codeSection.success || codeSection.rva != predictedRVA) {
        result.error = codeSection.success
            ? "CFG predicted/appended section RVA mismatch" : codeSection.error;
        return result;
    }
    result.codeSectionRVA = codeSection.rva;
    result.codeSectionRawOffset = codeSection.rawOffset;
    result.codeSectionSize = static_cast<uint32_t>(section.size());
    result.expectedCodeSection = section;

    // Every copied absolute pointer keeps its original value, but ASLR must
    // now also fix its new location.  Duplicate only relocations that actually
    // land inside copied instruction bytes.
    for (const CFGProtectedFunctionRecord& protectedFunction : result.functions) {
        for (const CFGCopiedInstructionRange& copied :
                protectedFunction.flattened.copiedInstructions) {
            for (const CS_RELOC_ENTRY& relocation : image->relocs.entries) {
                if (relocation.fullRVA < copied.originalRVA ||
                    relocation.fullRVA >=
                        static_cast<uint64_t>(copied.originalRVA) + copied.size) continue;
                const uint64_t generated =
                    static_cast<uint64_t>(protectedFunction.flattened.codeRVA) +
                    copied.generatedOffset +
                    (relocation.fullRVA - copied.originalRVA);
                if (generated > (std::numeric_limits<uint32_t>::max)()) {
                    result.error = "duplicated CFG base relocation overflows RVA range";
                    return result;
                }
                CS_RELOC_ENTRY duplicate{};
                duplicate.fullRVA = generated;
                duplicate.pageRVA = static_cast<uint32_t>(generated) & ~0xFFFu;
                duplicate.offset = static_cast<uint16_t>(generated & 0xFFFu);
                duplicate.type = relocation.type;
                result.duplicatedRelocations.push_back(duplicate);
            }
        }
    }
    std::sort(result.duplicatedRelocations.begin(),
        result.duplicatedRelocations.end(), [](const auto& left, const auto& right) {
            if (left.fullRVA != right.fullRVA) return left.fullRVA < right.fullRVA;
            return left.type < right.type;
        });
    result.duplicatedRelocations.erase(std::unique(
        result.duplicatedRelocations.begin(), result.duplicatedRelocations.end(),
        [](const auto& left, const auto& right) {
            return left.fullRVA == right.fullRVA && left.type == right.type;
        }), result.duplicatedRelocations.end());
    if (!result.duplicatedRelocations.empty() &&
        !emitter.RebuildBaseRelocationDirectory(result.duplicatedRelocations,
            relocationSectionName, nullptr, &result.error)) return result;

    if (result.is64Bit) {
        const std::vector<uint8_t>& unwind =
            result.functions.front().flattened.dispatcherUnwindInfo;
        for (const auto& function : result.functions) {
            if (function.flattened.dispatcherUnwindInfo != unwind) {
                result.error = "x64 CFG dispatchers disagree on unwind metadata";
                return result;
            }
        }
        const PEAppendSectionResult unwindSection = emitter.AppendSection(
            unwindSectionName, unwind,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
        if (!unwindSection.success) {
            result.error = unwindSection.error;
            return result;
        }
        for (const CFGProtectedFunctionRecord& function : result.functions) {
            CS_RUNTIME_FUNCTION runtimeFunction{};
            runtimeFunction.beginAddress = function.flattened.codeRVA +
                function.flattened.dispatcherOffset;
            runtimeFunction.endAddress = runtimeFunction.beginAddress +
                function.flattened.dispatcherSize;
            runtimeFunction.unwindData = unwindSection.rva;
            result.dispatcherRuntimeFunctions.push_back(runtimeFunction);
        }
        if (!emitter.RebuildExceptionDirectory(result.dispatcherRuntimeFunctions,
                exceptionSectionName, nullptr, &result.error)) return result;
    }

    std::vector<FunctionPatchTarget> patchTargets;
    patchTargets.reserve(result.functions.size());
    for (const CFGProtectedFunctionRecord& function : result.functions) {
        const uint32_t originalOffset = PEUtils::RvaToOffset(
            image, function.flattened.originalFunctionRVA);
        if (originalOffset == 0u || originalOffset > image->rawSize ||
            4u > image->rawSize - originalOffset) {
            result.error = "CFG entry patch preflight is outside file data";
            return result;
        }
        const uint8_t* original = image->rawData + originalOffset;
        const bool endbr = original[0] == 0xF3u && original[1] == 0x0Fu &&
            original[2] == 0x1Eu &&
            original[3] == (result.is64Bit ? 0xFAu : 0xFBu);
        const uint32_t patchRVA = function.flattened.originalFunctionRVA +
            (endbr ? 4u : 0u);
        uint32_t flattenedEntryRVA = 0u;
        if (!AddCodeRVA(function.flattened.codeRVA,
                function.flattened.entryOffset, flattenedEntryRVA)) {
            result.error = "CFG flattened entry RVA overflows";
            return result;
        }
        int32_t entryRelative = 0;
        if (!Rel32Value(patchRVA + 5u,
                flattenedEntryRVA, entryRelative)) {
            result.error = "CFG entry is outside the supported near-rel32 patch range";
            return result;
        }
        patchTargets.push_back({function.flattened.originalFunctionRVA,
            flattenedEntryRVA,
            function.flattened.originalFunctionSize});
    }
    FunctionTrampolinePatcher patcher;
    result.patchResults = patcher.PatchNativeFunctions(
        image, patchTargets, functions, true);
    if (result.patchResults.size() != patchTargets.size()) {
        result.error = "CFG native patcher returned an incomplete result set";
        return result;
    }
    for (const FunctionPatchResult& patch : result.patchResults) {
        if (!patch.success || patch.patchKind != FunctionPatchKind::NearRel32) {
            result.error = "CFG native patch failed: " + patch.error;
            if (patch.success)
                result.error = "CFG native patch unexpectedly used a non-rel32 entry";
            return result;
        }
    }

    result.success = true;
    if (!VerifyAppliedProtection(image, result, result.error))
        result.success = false;
    return result;
}

bool CFGFlattener::VerifyAppliedProtection(
    const CS_PE_IMAGE* image,
    const CFGProtectionResult& result,
    std::string& error)
{
    if (!image || !image->isValid || !result.success ||
        result.functions.empty() || result.expectedCodeSection.empty() ||
        result.codeSectionRVA == 0u || result.codeSectionSize !=
            result.expectedCodeSection.size() ||
        result.patchResults.size() != result.functions.size()) {
        error = "CFG protection descriptor is incomplete";
        return false;
    }
    if ((result.is64Bit &&
            result.dispatcherRuntimeFunctions.size() != result.functions.size()) ||
        (!result.is64Bit && !result.dispatcherRuntimeFunctions.empty())) {
        error = "CFG dispatcher exception-directory cardinality is inconsistent";
        return false;
    }
    const IMAGE_SECTION_HEADER* codeSection = nullptr;
    for (WORD index = 0; index < image->numSections; ++index) {
        if (PEUtils::RvaInSection(image->sections[index], result.codeSectionRVA)) {
            codeSection = &image->sections[index];
            break;
        }
    }
    if (!codeSection ||
        (codeSection->Characteristics &
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) !=
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) ||
        (codeSection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0u) {
        error = "CFG code section is not RX/W^X";
        return false;
    }
    const uint32_t codeOffset = PEUtils::RvaToOffset(image, result.codeSectionRVA);
    if (codeOffset == 0u || codeOffset > image->rawSize ||
        result.codeSectionSize > image->rawSize - codeOffset ||
        std::memcmp(image->rawData + codeOffset,
            result.expectedCodeSection.data(), result.codeSectionSize) != 0) {
        error = "CFG code section bytes differ from the verified build plan";
        return false;
    }

    for (size_t index = 0; index < result.functions.size(); ++index) {
        const CFGProtectedFunctionRecord& protectedFunction = result.functions[index];
        std::string generatedError;
        if (!ValidateGeneratedFunction(protectedFunction.flattened, generatedError)) {
            error = "CFG generated-function verification failed: " + generatedError;
            return false;
        }
        if (protectedFunction.sectionOffset > result.expectedCodeSection.size() ||
            protectedFunction.flattened.code.size() >
                result.expectedCodeSection.size() - protectedFunction.sectionOffset ||
            !std::equal(protectedFunction.flattened.code.begin(),
                protectedFunction.flattened.code.end(),
                result.expectedCodeSection.begin() +
                    protectedFunction.sectionOffset)) {
            error = "CFG function does not own its recorded code-section range";
            return false;
        }
        std::string patchError;
        if (!FunctionTrampolinePatcher::VerifyAppliedPatch(
                image, result.patchResults[index], patchError)) {
            error = "CFG entry/native-body patch verification failed: " + patchError;
            return false;
        }
        uint32_t flattenedEntryRVA = 0u;
        if (!AddCodeRVA(protectedFunction.flattened.codeRVA,
                protectedFunction.flattened.entryOffset,
                flattenedEntryRVA) ||
            result.patchResults[index].functionRVA !=
                protectedFunction.flattened.originalFunctionRVA ||
            result.patchResults[index].trampolineRVA !=
                flattenedEntryRVA ||
            result.patchResults[index].patchKind !=
                FunctionPatchKind::NearRel32) {
            error = "CFG patch target does not match its flattened entry";
            return false;
        }
    }

    for (const CS_RELOC_ENTRY& duplicate : result.duplicatedRelocations) {
        const auto found = std::find_if(image->relocs.entries.begin(),
            image->relocs.entries.end(), [&](const CS_RELOC_ENTRY& current) {
                return current.fullRVA == duplicate.fullRVA &&
                    current.type == duplicate.type;
            });
        const uint16_t expectedType = result.is64Bit
            ? kRelocationDir64 : kRelocationHighLow;
        if (duplicate.type != expectedType || found == image->relocs.entries.end()) {
            error = "CFG copied absolute operand has no matching base relocation";
            return false;
        }
    }
    for (const CS_RUNTIME_FUNCTION& runtimeFunction :
            result.dispatcherRuntimeFunctions) {
        if (!PEUtils::IsValidRuntimeFunction(image, runtimeFunction) ||
            std::find_if(image->exceptions.entries.begin(),
                image->exceptions.entries.end(), [&](const auto& current) {
                    return RuntimeFunctionEquals(current, runtimeFunction);
                }) == image->exceptions.entries.end()) {
            error = "CFG x64 dispatcher has no valid exception-directory entry";
            return false;
        }
    }
    return true;
}

} // namespace CipherShell
