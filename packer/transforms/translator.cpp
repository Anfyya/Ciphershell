#include "translator.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace CipherShell {
namespace {

uint8_t WidthBytes(uint16_t widthBits) {
    if (widthBits == 8 || widthBits == 16 || widthBits == 32 || widthBits == 64 ||
        widthBits == 128 || widthBits == 256 || widthBits == 512) {
        return static_cast<uint8_t>(widthBits / 8);
    }
    return 0;
}

bool IsImmediate(const OperandIR* operand) {
    return operand && operand->type == OperandType::Immediate;
}

bool IsRegister(const OperandIR* operand) {
    return operand && operand->type == OperandType::Register;
}

bool IsMemory(const OperandIR* operand) {
    return operand && operand->type == OperandType::Memory;
}

bool OperandWrites(OperandAction action) {
    return action == OperandAction::Write || action == OperandAction::ReadWrite ||
        action == OperandAction::ConditionalWrite ||
        action == OperandAction::ConditionalReadWrite;
}

bool IsExtendedRegisterClass(RegisterClass registerClass) {
    return registerClass == RegisterClass::Vector || registerClass == RegisterClass::X87 ||
        registerClass == RegisterClass::Mmx;
}

uint32_t AlignUpValue(uint32_t value, uint32_t alignment) {
    return alignment ? (value + alignment - 1u) & ~(alignment - 1u) : value;
}

void InitializeInstruction(BytecodeInstr& instruction) {
    std::memset(&instruction, 0, sizeof(instruction));
    instruction.dst = VM_REG_INVALID;
    instruction.src = VM_REG_INVALID;
    instruction.extra = VM_REG_INVALID;
    instruction.memBase = VM_REG_INVALID;
    instruction.memIndex = VM_REG_INVALID;
    instruction.memScale = 1;
    instruction.memoryKind = VM_MEMORY_NATIVE;
}

struct BinaryOpcodes {
    uint8_t rr;
    uint8_t rc;
    uint8_t rm;
    uint8_t mr;
};

bool OpcodesForBinary(InstructionMnemonic mnemonic, BinaryOpcodes& opcodes) {
    switch (mnemonic) {
        case InstructionMnemonic::Add: opcodes = {VM_ADD_RR, VM_ADD_RC, VM_ADD_RM, VM_ADD_MR}; return true;
        case InstructionMnemonic::Adc: opcodes = {VM_ADC_RR, VM_ADC_RC, VM_ADC_RM, VM_ADC_MR}; return true;
        case InstructionMnemonic::Sub: opcodes = {VM_SUB_RR, VM_SUB_RC, VM_SUB_RM, VM_SUB_MR}; return true;
        case InstructionMnemonic::Sbb: opcodes = {VM_SBB_RR, VM_SBB_RC, VM_SBB_RM, VM_SBB_MR}; return true;
        case InstructionMnemonic::And: opcodes = {VM_AND_RR, VM_AND_RC, VM_AND_RM, VM_AND_MR}; return true;
        case InstructionMnemonic::Or: opcodes = {VM_OR_RR, VM_OR_RC, VM_OR_RM, VM_OR_MR}; return true;
        case InstructionMnemonic::Xor: opcodes = {VM_XOR_RR, VM_XOR_RC, VM_XOR_RM, VM_XOR_MR}; return true;
        case InstructionMnemonic::Cmp: opcodes = {VM_CMP_RR, VM_CMP_RC, VM_CMP_RM, VM_CMP_MR}; return true;
        case InstructionMnemonic::Test: opcodes = {VM_TEST_RR, VM_TEST_RC, VM_TEST_RM, VM_TEST_MR}; return true;
        default: return false;
    }
}

} // namespace

Translator::Translator() = default;
Translator::~Translator() = default;

bool Translator::Initialize(const TranslationConfig& config) {
    if (config.virtualRegisterCount < 16 || config.virtualRegisterCount > 32) return false;
    m_config = config;
    m_lastFailures.clear();
    m_initialized = true;
    return true;
}

std::unordered_map<uint8_t, uint8_t> Translator::GetRegisterMap() const { return m_registerMap; }
std::unordered_map<uint8_t, uint8_t> Translator::GetOpcodeMap() const { return m_opcodeMap; }
void Translator::SetOpcodeMap(const std::unordered_map<uint8_t, uint8_t>& map) { m_opcodeMap = map; }
void Translator::SetRegisterMap(const std::unordered_map<uint8_t, uint8_t>& map) { m_registerMap = map; }
const std::vector<TranslationFailure>& Translator::GetLastFailures() const { return m_lastFailures; }

std::vector<const OperandIR*> Translator::SemanticOperands(const InstructionIR& instruction) const {
    std::vector<const OperandIR*> result;
    for (const auto& operand : instruction.operands) {
        if (operand.visibility == OperandVisibility::Explicit && operand.type != OperandType::None) {
            result.push_back(&operand);
        }
    }
    return result;
}

uint8_t Translator::MapRegisterFamily(uint8_t family) const {
    if (family >= 16) return VM_REG_INVALID;
    auto mapped = m_registerMap.find(family);
    if (mapped == m_registerMap.end() || mapped->second >= m_config.virtualRegisterCount) {
        return VM_REG_INVALID;
    }
    return mapped->second;
}

bool Translator::EncodeRegisterOperand(
    const InstructionIR& instruction,
    const OperandIR& operand,
    uint8_t& vmRegister,
    uint8_t& bitOffset,
    uint16_t& flags,
    bool destination)
{
    if (operand.type != OperandType::Register ||
        operand.regInfo.registerClass != RegisterClass::GeneralPurpose ||
        operand.regInfo.family >= 16) {
        return FailInstruction(instruction, "operand is not a supported general-purpose register");
    }
    vmRegister = MapRegisterFamily(operand.regInfo.family);
    if (vmRegister == VM_REG_INVALID) {
        return FailInstruction(instruction, "native register has no injective VM register mapping");
    }
    bitOffset = operand.regInfo.bitOffset;
    if (bitOffset != 0 && bitOffset != 8) {
        return FailInstruction(instruction, "unsupported partial-register bit offset");
    }
    if (destination && operand.regInfo.zeroExtendsOnWrite) flags |= VM_OPERAND_DST_ZERO_EXTEND;
    return true;
}

bool Translator::EncodeMemoryOperand(
    const InstructionIR& instruction,
    const OperandIR& operand,
    BytecodeInstr& output)
{
    if (operand.type != OperandType::Memory) {
        return FailInstruction(instruction, "expected memory operand");
    }
    const MemoryOperandIR& memory = operand.memory;
    if (memory.segment != RegisterId::None && memory.segment != RegisterId::DS &&
        memory.segment != RegisterId::SS) {
        return FailInstruction(instruction, "FS/GS or non-default segment memory requires a dedicated segment bridge");
    }
    output.memBase = VM_REG_INVALID;
    output.memIndex = VM_REG_INVALID;
    output.memScale = memory.hasIndex ? memory.scale : 1;
    output.memWidth = WidthBytes(memory.width ? memory.width : operand.width);
    if (output.memWidth == 0 || output.memWidth > 8) {
        return FailInstruction(instruction, "memory width is outside scalar VM range");
    }

    if (memory.isImageAddress) {
        if (memory.resolvedRVA == 0) {
            return FailInstruction(instruction, "RIP-relative memory operand has no resolved RVA");
        }
        output.memoryKind = VM_MEMORY_IMAGE_RVA;
        output.memDisp = static_cast<int64_t>(memory.resolvedRVA);
        return true;
    }

    output.memoryKind = VM_MEMORY_NATIVE;
    output.memDisp = memory.displacement;
    if (memory.hasBase) {
        if (memory.baseInfo.registerClass != RegisterClass::GeneralPurpose) {
            return FailInstruction(instruction, "memory base is not a general-purpose register");
        }
        output.memBase = MapRegisterFamily(memory.baseInfo.family);
        if (output.memBase == VM_REG_INVALID) {
            return FailInstruction(instruction, "memory base register has no VM mapping");
        }
    }
    if (memory.hasIndex) {
        if (memory.indexInfo.registerClass != RegisterClass::GeneralPurpose) {
            return FailInstruction(instruction, "memory index is not a general-purpose register");
        }
        output.memIndex = MapRegisterFamily(memory.indexInfo.family);
        if (output.memIndex == VM_REG_INVALID) {
            return FailInstruction(instruction, "memory index register has no VM mapping");
        }
    }
    if (!(output.memScale == 1 || output.memScale == 2 ||
          output.memScale == 4 || output.memScale == 8)) {
        return FailInstruction(instruction, "invalid memory index scale");
    }
    return true;
}

bool Translator::TranslateMove(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2) return FailInstruction(instruction, "MOV requires two semantic operands");
    const OperandIR& dst = *operands[0];
    const OperandIR& src = *operands[1];

    if (IsRegister(&dst) && IsRegister(&src)) {
        output.opcode = VM_MOV_RR;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset, output.flags, true) ||
            !EncodeRegisterOperand(instruction, src, output.src, output.srcBitOffset, output.flags, false)) return false;
        output.operandWidth = WidthBytes(dst.width);
    } else if (IsRegister(&dst) && IsImmediate(&src)) {
        output.opcode = VM_MOV_RC;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset, output.flags, true)) return false;
        output.operandWidth = WidthBytes(dst.width);
        output.immediate = src.immediate;
        output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
        if (src.immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
    } else if (IsRegister(&dst) && IsMemory(&src)) {
        output.opcode = VM_MOV_RM;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset, output.flags, true) ||
            !EncodeMemoryOperand(instruction, src, output)) return false;
        output.operandWidth = WidthBytes(dst.width);
        output.flags |= VM_OPERAND_SOURCE_MEMORY;
    } else if (IsMemory(&dst) && IsRegister(&src)) {
        output.opcode = VM_MOV_MR;
        if (!EncodeRegisterOperand(instruction, src, output.src, output.srcBitOffset, output.flags, false) ||
            !EncodeMemoryOperand(instruction, dst, output)) return false;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY;
    } else if (IsMemory(&dst) && IsImmediate(&src)) {
        output.opcode = VM_MOV_MC;
        if (!EncodeMemoryOperand(instruction, dst, output)) return false;
        output.immediate = src.immediate;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY | VM_OPERAND_SOURCE_IMMEDIATE;
        if (src.immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
    } else {
        return FailInstruction(instruction, "unsupported MOV operand combination");
    }
    return output.operandWidth != 0 || FailInstruction(instruction, "MOV has invalid operand width");
}

bool Translator::TranslateMoveExtend(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2 || !IsRegister(operands[0])) {
        return FailInstruction(instruction, "MOVZX/MOVSX requires register destination and one source");
    }
    const OperandIR& dst = *operands[0];
    const OperandIR& src = *operands[1];
    if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset, output.flags, true)) return false;
    output.operandWidth = WidthBytes(dst.width);
    output.aux = WidthBytes(src.width);
    if (output.operandWidth == 0 || output.aux == 0 || output.aux >= output.operandWidth) {
        return FailInstruction(instruction, "invalid extending-move widths");
    }

    const bool sign = instruction.mnemonic == InstructionMnemonic::Movsx ||
                      instruction.mnemonic == InstructionMnemonic::Movsxd;
    if (IsRegister(&src)) {
        output.opcode = static_cast<uint8_t>(instruction.mnemonic == InstructionMnemonic::Movsxd
            ? VM_MOVSXD_RR : (sign ? VM_MOVSX_RR : VM_MOVZX_RR));
        if (!EncodeRegisterOperand(instruction, src, output.src, output.srcBitOffset, output.flags, false)) return false;
    } else if (IsMemory(&src)) {
        output.opcode = static_cast<uint8_t>(instruction.mnemonic == InstructionMnemonic::Movsxd
            ? VM_MOVSXD_RM : (sign ? VM_MOVSX_RM : VM_MOVZX_RM));
        if (!EncodeMemoryOperand(instruction, src, output)) return false;
        output.flags |= VM_OPERAND_SOURCE_MEMORY;
    } else {
        return FailInstruction(instruction, "extending move source must be register or memory");
    }
    if (sign) output.flags |= VM_OPERAND_SRC_SIGNED;
    return true;
}

bool Translator::TranslateLea(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2 || !IsRegister(operands[0]) || !IsMemory(operands[1])) {
        return FailInstruction(instruction, "LEA requires register and memory operands");
    }
    output.opcode = VM_LEA;
    if (!EncodeRegisterOperand(instruction, *operands[0], output.dst, output.dstBitOffset, output.flags, true) ||
        !EncodeMemoryOperand(instruction, *operands[1], output)) return false;
    output.operandWidth = WidthBytes(operands[0]->width);
    output.memWidth = 0;
    return output.operandWidth != 0 || FailInstruction(instruction, "invalid LEA destination width");
}

bool Translator::TranslateXchg(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2) return FailInstruction(instruction, "XCHG requires two operands");
    if (IsRegister(operands[0]) && IsRegister(operands[1])) {
        output.opcode = VM_XCHG;
        if (!EncodeRegisterOperand(instruction, *operands[0], output.dst, output.dstBitOffset, output.flags, true) ||
            !EncodeRegisterOperand(instruction, *operands[1], output.src, output.srcBitOffset, output.flags, false)) return false;
        output.operandWidth = WidthBytes(operands[0]->width);
        return true;
    }
    const OperandIR* reg = IsRegister(operands[0]) ? operands[0] : operands[1];
    const OperandIR* mem = IsMemory(operands[0]) ? operands[0] : operands[1];
    if (!reg || !mem) return FailInstruction(instruction, "XCHG requires register/register or register/memory");
    output.opcode = VM_XCHG_RM;
    if (!EncodeRegisterOperand(instruction, *reg, output.dst, output.dstBitOffset, output.flags, true) ||
        !EncodeMemoryOperand(instruction, *mem, output)) return false;
    output.operandWidth = output.memWidth;
    output.flags |= VM_OPERAND_SOURCE_MEMORY;
    return true;
}

bool Translator::TranslateBinary(const InstructionIR& instruction, BytecodeInstr& output) {
    BinaryOpcodes opcodes{};
    if (!OpcodesForBinary(instruction.mnemonic, opcodes)) {
        return FailInstruction(instruction, "binary operation has no VM opcode family");
    }
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2) return FailInstruction(instruction, "binary operation requires two operands");
    const OperandIR& dst = *operands[0];
    const OperandIR& src = *operands[1];
    const bool writesDestination = instruction.mnemonic != InstructionMnemonic::Cmp &&
        instruction.mnemonic != InstructionMnemonic::Test;

    if (IsRegister(&dst) && IsRegister(&src)) {
        output.opcode = opcodes.rr;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset,
                output.flags, writesDestination) ||
            !EncodeRegisterOperand(instruction, src, output.src, output.srcBitOffset, output.flags, false)) return false;
        output.operandWidth = WidthBytes(dst.width);
    } else if (IsRegister(&dst) && IsImmediate(&src)) {
        output.opcode = opcodes.rc;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset,
                output.flags, writesDestination)) return false;
        output.operandWidth = WidthBytes(dst.width);
        output.immediate = src.immediate;
        output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
        if (src.immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
    } else if (IsRegister(&dst) && IsMemory(&src)) {
        output.opcode = opcodes.rm;
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset,
                output.flags, writesDestination) ||
            !EncodeMemoryOperand(instruction, src, output)) return false;
        output.operandWidth = WidthBytes(dst.width);
        output.flags |= VM_OPERAND_SOURCE_MEMORY;
    } else if (IsMemory(&dst) && (IsRegister(&src) || IsImmediate(&src))) {
        output.opcode = opcodes.mr;
        if (!EncodeMemoryOperand(instruction, dst, output)) return false;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY;
        if (IsRegister(&src)) {
            if (!EncodeRegisterOperand(instruction, src, output.src, output.srcBitOffset, output.flags, false)) return false;
        } else {
            output.immediate = src.immediate;
            output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
            if (src.immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
        }
    } else {
        return FailInstruction(instruction, "unsupported binary operand combination");
    }
    return output.operandWidth != 0 || FailInstruction(instruction, "binary operation has invalid width");
}

bool Translator::TranslateUnary(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 1) return FailInstruction(instruction, "unary operation requires one operand");
    const OperandIR& operand = *operands[0];
    uint8_t regOpcode = 0;
    uint8_t memOpcode = 0;
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Not: regOpcode = VM_NOT_R; memOpcode = VM_NOT_R; break;
        case InstructionMnemonic::Neg: regOpcode = VM_NEG_R; memOpcode = VM_NEG_M; break;
        case InstructionMnemonic::Inc: regOpcode = VM_INC_R; memOpcode = VM_INC_M; break;
        case InstructionMnemonic::Dec: regOpcode = VM_DEC_R; memOpcode = VM_DEC_M; break;
        default: return FailInstruction(instruction, "unsupported unary mnemonic");
    }
    if (IsRegister(&operand)) {
        output.opcode = regOpcode;
        if (!EncodeRegisterOperand(instruction, operand, output.dst, output.dstBitOffset, output.flags, true)) return false;
        output.operandWidth = WidthBytes(operand.width);
    } else if (IsMemory(&operand)) {
        output.opcode = memOpcode;
        if (!EncodeMemoryOperand(instruction, operand, output)) return false;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY;
    } else {
        return FailInstruction(instruction, "unary operand must be register or memory");
    }
    return output.operandWidth != 0 || FailInstruction(instruction, "unary operation has invalid width");
}

bool Translator::TranslateShiftRotate(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2) return FailInstruction(instruction, "shift/rotate requires destination and count");
    const OperandIR& dst = *operands[0];
    const OperandIR& count = *operands[1];
    const bool immediate = IsImmediate(&count);
    if (!immediate && !IsRegister(&count)) return FailInstruction(instruction, "shift count must be register or immediate");

    auto choose = [&](uint8_t rr, uint8_t rc, uint8_t mr, uint8_t mc) {
        output.opcode = IsMemory(&dst) ? (immediate ? mc : mr) : (immediate ? rc : rr);
    };
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Shl: case InstructionMnemonic::Sal:
            choose(VM_SHL_RR, VM_SHL_RC, VM_SHL_MR, VM_SHL_MC); break;
        case InstructionMnemonic::Shr:
            choose(VM_SHR_RR, VM_SHR_RC, VM_SHR_MR, VM_SHR_MC); break;
        case InstructionMnemonic::Sar:
            choose(VM_SAR_RR, VM_SAR_RC, VM_SAR_MR, VM_SAR_MC); break;
        case InstructionMnemonic::Rol:
            choose(VM_ROL_RR, VM_ROL_RC, VM_ROL_MR, VM_ROL_MC); break;
        case InstructionMnemonic::Ror:
            choose(VM_ROR_RR, VM_ROR_RC, VM_ROR_MR, VM_ROR_MC); break;
        default: return FailInstruction(instruction, "unsupported shift/rotate mnemonic");
    }

    if (IsRegister(&dst)) {
        if (!EncodeRegisterOperand(instruction, dst, output.dst, output.dstBitOffset, output.flags, true)) return false;
        output.operandWidth = WidthBytes(dst.width);
    } else if (IsMemory(&dst)) {
        if (!EncodeMemoryOperand(instruction, dst, output)) return false;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY;
    } else {
        return FailInstruction(instruction, "shift/rotate destination must be register or memory");
    }
    if (immediate) {
        output.immediate = count.immediate;
        output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
    } else if (!EncodeRegisterOperand(instruction, count, output.src, output.srcBitOffset, output.flags, false)) {
        return false;
    }
    return true;
}

bool Translator::TranslateMultiplyDivide(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.empty() || operands.size() > 3) {
        return FailInstruction(instruction, "multiply/divide operand count is unsupported");
    }
    if (instruction.mnemonic == InstructionMnemonic::Mul ||
        instruction.mnemonic == InstructionMnemonic::Div ||
        instruction.mnemonic == InstructionMnemonic::Idiv ||
        (instruction.mnemonic == InstructionMnemonic::Imul && operands.size() == 1)) {
        if (operands.size() != 1) return FailInstruction(instruction, "implicit-accumulator operation requires one visible operand");
        output.opcode = static_cast<uint8_t>(instruction.mnemonic == InstructionMnemonic::Mul ? VM_MUL_RR :
            (instruction.mnemonic == InstructionMnemonic::Div ? VM_DIV_RR :
             instruction.mnemonic == InstructionMnemonic::Idiv ? VM_IDIV_RR : VM_IMUL_RR));
        output.flags |= VM_OPERAND_IMPLICIT_ACCUMULATOR;
        const OperandIR& source = *operands[0];
        output.operandWidth = WidthBytes(source.width);
        if (IsRegister(&source)) {
            if (!EncodeRegisterOperand(instruction, source, output.src, output.srcBitOffset, output.flags, false)) return false;
        } else if (IsMemory(&source)) {
            if (!EncodeMemoryOperand(instruction, source, output)) return false;
            output.flags |= VM_OPERAND_SOURCE_MEMORY;
        } else return FailInstruction(instruction, "multiply/divide source must be register or memory");
        return true;
    }

    output.opcode = static_cast<uint8_t>(operands.size() == 3 ? VM_IMUL_RRC : VM_IMUL_RR);
    if (!IsRegister(operands[0]) ||
        !EncodeRegisterOperand(instruction, *operands[0], output.dst, output.dstBitOffset, output.flags, true)) return false;
    output.operandWidth = WidthBytes(operands[0]->width);
    const OperandIR* source = operands.size() == 1 ? operands[0] : operands[1];
    if (IsRegister(source)) {
        if (!EncodeRegisterOperand(instruction, *source, output.src, output.srcBitOffset, output.flags, false)) return false;
    } else if (IsMemory(source)) {
        if (!EncodeMemoryOperand(instruction, *source, output)) return false;
        output.flags |= VM_OPERAND_SOURCE_MEMORY;
    } else return FailInstruction(instruction, "IMUL source must be register or memory");
    if (operands.size() == 3) {
        if (!IsImmediate(operands[2])) return FailInstruction(instruction, "three-operand IMUL requires immediate third operand");
        output.immediate = operands[2]->immediate;
        if (operands[2]->immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
    }
    return true;
}

bool Translator::TranslateStack(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 1) return FailInstruction(instruction, "PUSH/POP requires one operand");
    const OperandIR& operand = *operands[0];
    output.operandWidth = WidthBytes(operand.width ? operand.width : instruction.stackWidth);
    if (output.operandWidth == 0) return FailInstruction(instruction, "invalid stack operand width");
    if (instruction.mnemonic == InstructionMnemonic::Push) {
        if (IsRegister(&operand)) {
            output.opcode = VM_PUSH_R;
            return EncodeRegisterOperand(instruction, operand, output.src, output.srcBitOffset, output.flags, false);
        }
        if (IsImmediate(&operand)) {
            output.opcode = VM_PUSH_C;
            output.immediate = operand.immediate;
            output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
            if (operand.immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
            return true;
        }
        if (IsMemory(&operand)) {
            output.opcode = VM_PUSH_MEM;
            output.flags |= VM_OPERAND_SOURCE_MEMORY;
            return EncodeMemoryOperand(instruction, operand, output);
        }
    } else if (instruction.mnemonic == InstructionMnemonic::Pop) {
        if (IsRegister(&operand)) {
            output.opcode = VM_POP_R;
            return EncodeRegisterOperand(instruction, operand, output.dst, output.dstBitOffset, output.flags, true);
        }
        if (IsMemory(&operand)) {
            output.opcode = VM_POP_MEM;
            output.flags |= VM_OPERAND_DEST_MEMORY;
            return EncodeMemoryOperand(instruction, operand, output);
        }
    }
    return FailInstruction(instruction, "unsupported PUSH/POP operand");
}

VM_CONDITION Translator::MapCondition(BranchKind kind) const {
    switch (kind) {
        case BranchKind::Overflow: return VM_CONDITION_O;
        case BranchKind::NotOverflow: return VM_CONDITION_NO;
        case BranchKind::Below: return VM_CONDITION_B;
        case BranchKind::AboveOrEqual: return VM_CONDITION_AE;
        case BranchKind::Equal: return VM_CONDITION_E;
        case BranchKind::NotEqual: return VM_CONDITION_NE;
        case BranchKind::BelowOrEqual: return VM_CONDITION_BE;
        case BranchKind::Above: return VM_CONDITION_A;
        case BranchKind::Sign: return VM_CONDITION_S;
        case BranchKind::NotSign: return VM_CONDITION_NS;
        case BranchKind::Parity: return VM_CONDITION_P;
        case BranchKind::NotParity: return VM_CONDITION_NP;
        case BranchKind::Less: return VM_CONDITION_L;
        case BranchKind::GreaterOrEqual: return VM_CONDITION_GE;
        case BranchKind::LessOrEqual: return VM_CONDITION_LE;
        case BranchKind::Greater: return VM_CONDITION_G;
        default: return VM_CONDITION_ALWAYS;
    }
}

uint8_t Translator::OpcodeForCondition(BranchKind kind) const {
    switch (kind) {
        case BranchKind::Overflow: return VM_JO;
        case BranchKind::NotOverflow: return VM_JNO;
        case BranchKind::Below: return VM_JB;
        case BranchKind::AboveOrEqual: return VM_JAE;
        case BranchKind::Equal: return VM_JZ;
        case BranchKind::NotEqual: return VM_JNZ;
        case BranchKind::BelowOrEqual: return VM_JBE;
        case BranchKind::Above: return VM_JA;
        case BranchKind::Sign: return VM_JS;
        case BranchKind::NotSign: return VM_JNS;
        case BranchKind::Parity: return VM_JP;
        case BranchKind::NotParity: return VM_JNP;
        case BranchKind::Less: return VM_JL;
        case BranchKind::GreaterOrEqual: return VM_JGE;
        case BranchKind::LessOrEqual: return VM_JLE;
        case BranchKind::Greater: return VM_JG;
        default: return 0;
    }
}

bool Translator::TranslateBranch(const InstructionIR& instruction, BytecodeInstr& output) {
    if (instruction.isIndirectBranch) {
        return FailInstruction(instruction,
            "indirect JMP requires a verified native-target to bytecode-boundary map");
    }
    if (!instruction.hasBranchTarget) return FailInstruction(instruction, "branch has no absolute target RVA");
    output.opcode = instruction.branchKind == BranchKind::Unconditional
        ? static_cast<uint8_t>(VM_JMP) : OpcodeForCondition(instruction.branchKind);
    if (output.opcode == 0) return FailInstruction(instruction, "branch condition has no VM mapping");
    output.condition = static_cast<uint8_t>(MapCondition(instruction.branchKind));
    output.branchTargetOffset = instruction.branchTargetRVA;
    return true;
}

bool Translator::TranslateCall(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    const auto stackBytes = m_nativeCallStackBytes.find(instruction.address);
    const uint32_t nativeStackBytes = stackBytes == m_nativeCallStackBytes.end()
        ? 0u : stackBytes->second;
    if (nativeStackBytes > VM_NATIVE_MAX_STACK_ARGUMENT_BYTES) {
        return FailInstruction(instruction, "native CALL stack arguments exceed bridge capacity");
    }
    const uint32_t abi = instruction.machineMode == MachineMode::X64
        ? static_cast<uint32_t>(VM_ABI_WIN64)
        : static_cast<uint32_t>(m_config.x86CallAbi);
    output.aux = VM_CALL_AUX_ENCODE(abi, nativeStackBytes);
    if (instruction.isIndirectBranch) {
        if (operands.size() != 1) return FailInstruction(instruction, "indirect CALL requires one target operand");
        if (IsRegister(operands[0])) {
            output.opcode = VM_CALL_INDIRECT_R;
            output.flags |= VM_OPERAND_NATIVE_BRIDGE;
            return EncodeRegisterOperand(instruction, *operands[0], output.src, output.srcBitOffset, output.flags, false);
        }
        if (IsMemory(operands[0])) {
            if (operands[0]->memory.isImageAddress &&
                m_config.importThunkRVAs.count(operands[0]->memory.resolvedRVA) != 0) {
                output.opcode = VM_CALL_IMPORT;
                output.immediate = operands[0]->memory.resolvedRVA;
                output.flags |= VM_OPERAND_TARGET_IS_IMPORT | VM_OPERAND_NATIVE_BRIDGE;
                return true;
            }
            output.opcode = VM_CALL_INDIRECT_M;
            output.flags |= VM_OPERAND_SOURCE_MEMORY | VM_OPERAND_NATIVE_BRIDGE;
            return EncodeMemoryOperand(instruction, *operands[0], output);
        }
        return FailInstruction(instruction, "indirect CALL target must be register or memory");
    }
    if (!instruction.hasBranchTarget) return FailInstruction(instruction, "direct CALL has no target RVA");
    if (instruction.branchTargetRVA >= m_functionStart && instruction.branchTargetRVA < m_functionEnd) {
        output.opcode = VM_CALL_VM;
        output.aux = 0;
        output.branchTargetOffset = instruction.branchTargetRVA;
        output.immediate = instruction.rva + instruction.length;
    } else {
        output.opcode = VM_CALL_NATIVE;
        output.immediate = instruction.branchTargetRVA;
        output.flags |= VM_OPERAND_NATIVE_BRIDGE;
    }
    return true;
}

bool Translator::TranslateRet(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() > 1) return FailInstruction(instruction, "RET has invalid operand count");
    output.opcode = VM_RET_VM;
    if (!operands.empty()) {
        if (!IsImmediate(operands[0]) || operands[0]->immediate > 0xFFFFu) {
            return FailInstruction(instruction, "RET stack cleanup is outside uint16 range");
        }
        output.aux = static_cast<uint32_t>(operands[0]->immediate);
    }
    if (instruction.machineMode == MachineMode::X64 && output.aux != 0) {
        return FailInstruction(instruction, "x64 RET with immediate stack cleanup is outside the Windows x64 ABI");
    }
    return true;
}

bool Translator::TranslateConditionalData(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    output.condition = static_cast<uint8_t>(MapCondition(instruction.branchKind));
    if (output.condition == VM_CONDITION_ALWAYS) {
        return FailInstruction(instruction, "CMOV/SET condition is not represented in IR");
    }
    if (instruction.mnemonic == InstructionMnemonic::Cmov) {
        if (operands.size() != 2 || !IsRegister(operands[0])) return FailInstruction(instruction, "CMOV requires register destination");
        if (!EncodeRegisterOperand(instruction, *operands[0], output.dst, output.dstBitOffset, output.flags, true)) return false;
        output.operandWidth = WidthBytes(operands[0]->width);
        if (IsRegister(operands[1])) {
            output.opcode = VM_CMOV_RR;
            return EncodeRegisterOperand(instruction, *operands[1], output.src, output.srcBitOffset, output.flags, false);
        }
        if (IsMemory(operands[1])) {
            output.opcode = VM_CMOV_RM;
            output.flags |= VM_OPERAND_SOURCE_MEMORY;
            return EncodeMemoryOperand(instruction, *operands[1], output);
        }
        return FailInstruction(instruction, "CMOV source must be register or memory");
    }
    if (instruction.mnemonic == InstructionMnemonic::Setcc) {
        if (operands.size() != 1) return FailInstruction(instruction, "SETcc requires one destination");
        output.operandWidth = 1;
        if (IsRegister(operands[0])) {
            output.opcode = VM_SET_R;
            return EncodeRegisterOperand(instruction, *operands[0], output.dst, output.dstBitOffset, output.flags, true);
        }
        if (IsMemory(operands[0])) {
            output.opcode = VM_SET_M;
            output.flags |= VM_OPERAND_DEST_MEMORY;
            return EncodeMemoryOperand(instruction, *operands[0], output);
        }
        return FailInstruction(instruction, "SETcc destination must be register or memory");
    }
    return FailInstruction(instruction, "unsupported conditional data instruction");
}

bool Translator::TranslateBitOperation(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2 || (!IsRegister(operands[0]) && !IsMemory(operands[0])) ||
        (!IsRegister(operands[1]) && !IsImmediate(operands[1]))) {
        return FailInstruction(instruction, "BT/BTS/BTR requires register-or-memory base and register-or-immediate index");
    }
    output.opcode = static_cast<uint8_t>(instruction.mnemonic == InstructionMnemonic::Bt ? VM_BT_RR :
        (instruction.mnemonic == InstructionMnemonic::Bts ? VM_BTS_RR : VM_BTR_RR));
    if (IsRegister(operands[0])) {
        if (!EncodeRegisterOperand(instruction, *operands[0], output.dst,
                output.dstBitOffset, output.flags,
                instruction.mnemonic != InstructionMnemonic::Bt)) return false;
        output.operandWidth = WidthBytes(operands[0]->width);
    } else {
        if (!EncodeMemoryOperand(instruction, *operands[0], output)) return false;
        output.operandWidth = output.memWidth;
        output.flags |= VM_OPERAND_DEST_MEMORY;
        if (instruction.hasLockPrefix) {
            if (instruction.mnemonic == InstructionMnemonic::Bt) {
                return FailInstruction(instruction, "LOCK prefix is invalid for BT");
            }
            output.flags |= VM_OPERAND_ATOMIC;
        }
    }
    if (IsRegister(operands[1])) {
        if (!EncodeRegisterOperand(instruction, *operands[1], output.src,
                output.srcBitOffset, output.flags, false)) return false;
    } else {
        output.immediate = operands[1]->immediate;
        output.flags |= VM_OPERAND_SOURCE_IMMEDIATE;
        if (operands[1]->immediateSigned) output.flags |= VM_OPERAND_IMMEDIATE_SIGNED;
    }
    return output.operandWidth == 2 || output.operandWidth == 4 || output.operandWidth == 8
        ? true : FailInstruction(instruction, "BT/BTS/BTR width must be 16, 32, or 64 bits");
}

bool Translator::TranslateImplicitScalar(const InstructionIR& instruction, BytecodeInstr& output) {
    const auto operands = SemanticOperands(instruction);
    const auto implicitWidth = [&]() -> uint8_t {
        uint8_t width = WidthBytes(instruction.operandWidth);
        if (width) return width;
        if (instruction.mnemonicText == "cwd" || instruction.mnemonicText == "cbw" ||
            instruction.mnemonicText == "pushf" || instruction.mnemonicText == "popf") return 2;
        if (instruction.mnemonicText == "cdq" || instruction.mnemonicText == "cwde" ||
            instruction.mnemonicText == "pushfd" || instruction.mnemonicText == "popfd") return 4;
        if (instruction.mnemonicText == "cqo" || instruction.mnemonicText == "cdqe" ||
            instruction.mnemonicText == "pushfq" || instruction.mnemonicText == "popfq") return 8;
        return instruction.machineMode == MachineMode::X64 ? 8 : 4;
    };
    switch (instruction.mnemonic) {
        case InstructionMnemonic::PushFlags:
            if (!operands.empty()) return FailInstruction(instruction, "PUSHF has explicit operands");
            output.opcode = VM_PUSHF;
            output.operandWidth = implicitWidth();
            return true;
        case InstructionMnemonic::PopFlags:
            if (!operands.empty()) return FailInstruction(instruction, "POPF has explicit operands");
            output.opcode = VM_POPF;
            output.operandWidth = implicitWidth();
            return true;
        case InstructionMnemonic::Leave:
            if (!operands.empty()) return FailInstruction(instruction, "LEAVE has explicit operands");
            output.opcode = VM_LEAVE;
            output.operandWidth = instruction.machineMode == MachineMode::X64 ? 8 : 4;
            return true;
        case InstructionMnemonic::SignExtendAccumulator:
            if (!operands.empty()) return FailInstruction(instruction, "CWD/CDQ/CQO has explicit operands");
            output.opcode = VM_SIGN_EXTEND_ACC;
            output.operandWidth = implicitWidth();
            return output.operandWidth == 2 || output.operandWidth == 4 || output.operandWidth == 8;
        case InstructionMnemonic::ExtendAccumulator:
            if (!operands.empty()) return FailInstruction(instruction, "CBW/CWDE/CDQE has explicit operands");
            output.opcode = VM_EXTEND_ACC;
            output.operandWidth = implicitWidth();
            return output.operandWidth == 2 || output.operandWidth == 4 || output.operandWidth == 8;
        case InstructionMnemonic::Clc: output.opcode = VM_CLC; break;
        case InstructionMnemonic::Stc: output.opcode = VM_STC; break;
        case InstructionMnemonic::Cmc: output.opcode = VM_CMC; break;
        case InstructionMnemonic::Lahf: output.opcode = VM_LAHF; output.operandWidth = 1; break;
        case InstructionMnemonic::Sahf: output.opcode = VM_SAHF; output.operandWidth = 1; break;
        default: return FailInstruction(instruction, "unknown implicit scalar instruction");
    }
    return operands.empty() || FailInstruction(instruction, "implicit scalar instruction has explicit operands");
}

bool Translator::TranslateInstruction(const InstructionIR& instruction, BytecodeInstr& output) {
    InitializeInstruction(output);
    if (instruction.hasLockPrefix && instruction.mnemonic != InstructionMnemonic::Xchg &&
        instruction.mnemonic != InstructionMnemonic::Bts &&
        instruction.mnemonic != InstructionMnemonic::Btr) {
        return FailInstruction(instruction,
            "LOCK-prefixed instruction has no atomic VM handler");
    }
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Nop: output.opcode = VM_NOP; return true;
        case InstructionMnemonic::Mov: return TranslateMove(instruction, output);
        case InstructionMnemonic::Movzx:
        case InstructionMnemonic::Movsx:
        case InstructionMnemonic::Movsxd: return TranslateMoveExtend(instruction, output);
        case InstructionMnemonic::Lea: return TranslateLea(instruction, output);
        case InstructionMnemonic::Xchg: return TranslateXchg(instruction, output);
        case InstructionMnemonic::Add: case InstructionMnemonic::Adc:
        case InstructionMnemonic::Sub: case InstructionMnemonic::Sbb:
        case InstructionMnemonic::And: case InstructionMnemonic::Or:
        case InstructionMnemonic::Xor: case InstructionMnemonic::Cmp:
        case InstructionMnemonic::Test: return TranslateBinary(instruction, output);
        case InstructionMnemonic::Not: case InstructionMnemonic::Neg:
        case InstructionMnemonic::Inc: case InstructionMnemonic::Dec:
            return TranslateUnary(instruction, output);
        case InstructionMnemonic::Shl: case InstructionMnemonic::Sal:
        case InstructionMnemonic::Shr: case InstructionMnemonic::Sar:
        case InstructionMnemonic::Rol: case InstructionMnemonic::Ror:
            return TranslateShiftRotate(instruction, output);
        case InstructionMnemonic::Mul: case InstructionMnemonic::Imul:
        case InstructionMnemonic::Div: case InstructionMnemonic::Idiv:
            return TranslateMultiplyDivide(instruction, output);
        case InstructionMnemonic::Push: case InstructionMnemonic::Pop:
            return TranslateStack(instruction, output);
        case InstructionMnemonic::PushFlags: case InstructionMnemonic::PopFlags:
        case InstructionMnemonic::Leave:
        case InstructionMnemonic::SignExtendAccumulator:
        case InstructionMnemonic::ExtendAccumulator:
        case InstructionMnemonic::Clc: case InstructionMnemonic::Stc:
        case InstructionMnemonic::Cmc: case InstructionMnemonic::Lahf:
        case InstructionMnemonic::Sahf:
            return TranslateImplicitScalar(instruction, output);
        case InstructionMnemonic::Bt: case InstructionMnemonic::Bts:
        case InstructionMnemonic::Btr:
            return TranslateBitOperation(instruction, output);
        case InstructionMnemonic::Bswap: {
            const auto operands = SemanticOperands(instruction);
            if (operands.size() != 1 || !IsRegister(operands[0]) ||
                !EncodeRegisterOperand(instruction, *operands[0], output.dst,
                    output.dstBitOffset, output.flags, true)) {
                return FailInstruction(instruction, "BSWAP requires one general-purpose register");
            }
            output.opcode = VM_BSWAP;
            output.operandWidth = WidthBytes(operands[0]->width);
            return output.operandWidth == 4 || output.operandWidth == 8
                ? true : FailInstruction(instruction, "BSWAP width must be 32 or 64 bits");
        }
        case InstructionMnemonic::Jmp: case InstructionMnemonic::Jo:
        case InstructionMnemonic::Jno: case InstructionMnemonic::Jb:
        case InstructionMnemonic::Jae: case InstructionMnemonic::Jz:
        case InstructionMnemonic::Jnz: case InstructionMnemonic::Jbe:
        case InstructionMnemonic::Ja: case InstructionMnemonic::Js:
        case InstructionMnemonic::Jns: case InstructionMnemonic::Jp:
        case InstructionMnemonic::Jnp: case InstructionMnemonic::Jl:
        case InstructionMnemonic::Jge: case InstructionMnemonic::Jle:
        case InstructionMnemonic::Jg: return TranslateBranch(instruction, output);
        case InstructionMnemonic::Call: return TranslateCall(instruction, output);
        case InstructionMnemonic::Ret: return TranslateRet(instruction, output);
        case InstructionMnemonic::Cmov: case InstructionMnemonic::Setcc:
            return TranslateConditionalData(instruction, output);
        case InstructionMnemonic::Simd:
            return TranslateExtendedBridge(instruction, output);
        case InstructionMnemonic::FloatingPoint:
            return TranslateExtendedBridge(instruction, output);
        default:
            return FailInstruction(instruction, "instruction mnemonic is outside production VM ISA");
    }
}

bool Translator::TranslateExtendedBridge(
    const InstructionIR& instruction,
    BytecodeInstr& output)
{
    const bool x87 = instruction.instructionSet == InstructionSetClass::X87 ||
        instruction.mnemonic == InstructionMnemonic::FloatingPoint;
    const bool avx = instruction.instructionSet == InstructionSetClass::Avx;
    if ((x87 && !m_config.enableX87Bridge) || (!x87 && !m_config.enableSimdBridge)) {
        return FailInstruction(instruction, x87
            ? "x87 native bridge is disabled by configuration"
            : "SIMD native bridge is disabled by configuration");
    }
    if (instruction.instructionSet == InstructionSetClass::Avx512 ||
        instruction.encoding == InstructionEncoding::Evex ||
        instruction.encoding == InstructionEncoding::Mvex) {
        return FailInstruction(instruction, "AVX-512/EVEX state is outside the production bridge contract");
    }
    if (instruction.instructionSet == InstructionSetClass::UnsupportedExtended ||
        instruction.encoding == InstructionEncoding::Xop ||
        instruction.encoding == InstructionEncoding::ThreeDNow) {
        return FailInstruction(instruction, "XOP/3DNow/MMX-only instruction is outside the production bridge contract");
    }
    if (instruction.hasLockPrefix || instruction.IsBranch() || instruction.IsCall() ||
        instruction.IsReturn() || instruction.length == 0 || instruction.length > instruction.rawBytes.size()) {
        return FailInstruction(instruction, "extended-state bridge received an unsafe instruction category");
    }

    std::array<bool, 16> usedGprs{};
    bool hasExtendedSemantics = x87 || avx || instruction.instructionSet == InstructionSetClass::Sse;
    bool hasRipRelativeMemory = false;
    for (const auto& operand : instruction.operands) {
        if (operand.type == OperandType::Register) {
            const RegisterClass cls = operand.regInfo.registerClass;
            hasExtendedSemantics = hasExtendedSemantics || IsExtendedRegisterClass(cls);
            if (cls == RegisterClass::GeneralPurpose && operand.regInfo.family < usedGprs.size()) {
                if ((operand.regInfo.family == 4 || operand.regInfo.family == 5) &&
                    OperandWrites(operand.action)) {
                    return FailInstruction(instruction,
                        "native extended-state bridge cannot write RSP/ESP or RBP/EBP");
                }
                usedGprs[operand.regInfo.family] = true;
            } else if (cls == RegisterClass::Mask || cls == RegisterClass::Control ||
                       cls == RegisterClass::Debug || cls == RegisterClass::Other) {
                return FailInstruction(instruction, "bridge operand uses an unsupported architectural register class");
            }
        } else if (operand.type == OperandType::Memory) {
            if (operand.memory.hasBase &&
                operand.memory.baseInfo.registerClass == RegisterClass::GeneralPurpose &&
                operand.memory.baseInfo.family < usedGprs.size()) {
                usedGprs[operand.memory.baseInfo.family] = true;
            }
            if (operand.memory.hasIndex &&
                operand.memory.indexInfo.registerClass == RegisterClass::GeneralPurpose &&
                operand.memory.indexInfo.family < usedGprs.size()) {
                usedGprs[operand.memory.indexInfo.family] = true;
            }
            hasRipRelativeMemory = hasRipRelativeMemory || operand.memory.isRipRelative;
        } else if (operand.type == OperandType::Pointer) {
            return FailInstruction(instruction, "far pointer operands are not bridgeable");
        }
    }
    if (!hasExtendedSemantics) {
        return FailInstruction(instruction, "unsupported scalar instruction cannot use the SIMD/x87 bridge");
    }
    if (hasRipRelativeMemory &&
        (instruction.displacementSize != 4 || instruction.displacementOffset > instruction.length ||
         static_cast<uint32_t>(instruction.length - instruction.displacementOffset) < 4u)) {
        return FailInstruction(instruction, "RIP-relative bridge instruction has no relocatable disp32 field");
    }

    static constexpr uint8_t kX64HiddenCandidates[] = {11, 10, 9, 8, 2, 1, 0};
    static constexpr uint8_t kX86HiddenCandidates[] = {2, 1, 0};
    const uint8_t* candidates = instruction.machineMode == MachineMode::X64
        ? kX64HiddenCandidates : kX86HiddenCandidates;
    const size_t candidateCount = instruction.machineMode == MachineMode::X64
        ? std::size(kX64HiddenCandidates) : std::size(kX86HiddenCandidates);
    uint8_t hidden = 0xFF;
    for (size_t i = 0; i < candidateCount; ++i) {
        if (!usedGprs[candidates[i]]) {
            hidden = candidates[i];
            break;
        }
    }
    if (hidden == 0xFF) {
        return FailInstruction(instruction, "bridge instruction consumes every volatile hidden-state register");
    }

    output.opcode = static_cast<uint8_t>(x87 ? VM_BRIDGE_X87 : VM_BRIDGE_SIMD);
    output.immediate = instruction.rva;
    output.flags = VM_OPERAND_NATIVE_BRIDGE;
    output.aux = hidden | (avx ? VM_BRIDGE_AUX_AVX : 0u) |
        (x87 ? VM_BRIDGE_AUX_X87 : 0u);
    return true;
}

bool Translator::FinalizeControlFlow(TranslationResult& result) {
    for (auto& instruction : result.instructions) {
        const auto* descriptor = VMSchema::Lookup(instruction.opcode);
        if (!descriptor) return false;
        if (descriptor->branch) {
            const uint32_t targetRva = instruction.branchTargetOffset;
            auto target = result.addrMap.find(targetRva);
            if (target == result.addrMap.end()) {
                TranslationFailure failure{};
                failure.address = targetRva;
                failure.mnemonic = descriptor->name;
                failure.reason = "VM branch target is not an instruction boundary in the function";
                m_lastFailures.push_back(std::move(failure));
                return false;
            }
            instruction.branchTargetOffset = target->second;
        }
    }
    return true;
}

void Translator::AnalyzeNativeCallStackArguments(const Function& function) {
    m_nativeCallStackBytes.clear();
    for (const auto& block : function.blocks) {
        uint32_t pushedBytes = 0;
        uint32_t writtenArgumentBytes = 0;
        for (const auto& instruction : block.instructions) {
            if (instruction.machineMode == MachineMode::X86 &&
                instruction.mnemonic == InstructionMnemonic::Push) {
                uint32_t width = instruction.stackWidth == 16 ? 2u : 4u;
                pushedBytes = (std::min)(
                    VM_NATIVE_MAX_STACK_ARGUMENT_BYTES + 1u, pushedBytes + width);
            }
            for (const auto& operand : instruction.operands) {
                if (operand.type != OperandType::Memory || !OperandWrites(operand.action) ||
                    !operand.memory.hasBase ||
                    operand.memory.baseInfo.registerClass != RegisterClass::GeneralPurpose ||
                    operand.memory.baseInfo.family != 4 || operand.memory.displacement < 0) continue;
                const uint32_t width = WidthBytes(
                    operand.memory.width ? operand.memory.width : operand.width);
                if (width == 0) continue;
                if (operand.memory.displacement >
                        VM_NATIVE_MAX_STACK_ARGUMENT_BYTES + 0x20u) {
                    writtenArgumentBytes = VM_NATIVE_MAX_STACK_ARGUMENT_BYTES + 1u;
                    continue;
                }
                const uint32_t displacement = static_cast<uint32_t>(operand.memory.displacement);
                if (instruction.machineMode == MachineMode::X64) {
                    if (displacement < 0x20u) continue;
                    writtenArgumentBytes = (std::max)(writtenArgumentBytes,
                        displacement - 0x20u + width);
                } else {
                    writtenArgumentBytes = (std::max)(writtenArgumentBytes,
                        displacement + width);
                }
            }
            if (instruction.IsCall()) {
                uint32_t bytes = instruction.machineMode == MachineMode::X64
                    ? AlignUpValue(writtenArgumentBytes, 8)
                    : AlignUpValue((std::max)(pushedBytes, writtenArgumentBytes), 2);
                m_nativeCallStackBytes[instruction.address] = bytes;
                pushedBytes = 0;
                writtenArgumentBytes = 0;
            } else if (instruction.IsBranch() || instruction.IsReturn()) {
                pushedBytes = 0;
                writtenArgumentBytes = 0;
            }
        }
    }
}

bool Translator::ValidateFlagDataflow(
    const Function& function,
    uint32_t& terminalReturnStackCleanup) {
    if (function.blocks.empty()) return false;
    terminalReturnStackCleanup = 0;
    bool sawTerminalReturn = false;
    std::map<uint64_t, const InstructionIR*> instructions;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            instructions[instruction.address] = &instruction;
        }
    }
    if (instructions.find(function.entryAddress) == instructions.end()) return false;

    struct FlowKey {
        uint64_t address;
        std::vector<uint64_t> returns;
        bool operator<(const FlowKey& other) const {
            if (address != other.address) return address < other.address;
            return returns < other.returns;
        }
    };
    struct FlowState {
        FlowKey key;
        uint64_t undefined;
    };
    std::vector<FlowState> worklist = {{{function.entryAddress, {}}, 0}};
    std::map<FlowKey, uint64_t> mergedStates;

    auto enqueue = [&](const FlowKey& key, uint64_t undefined) {
        auto found = mergedStates.find(key);
        if (found == mergedStates.end()) {
            mergedStates.emplace(key, undefined);
            worklist.push_back({key, undefined});
        } else {
            const uint64_t merged = found->second | undefined;
            if (merged != found->second) {
                found->second = merged;
                worklist.push_back({key, merged});
            }
        }
    };
    mergedStates.emplace(worklist.front().key, 0);

    while (!worklist.empty()) {
        FlowState state = std::move(worklist.back());
        worklist.pop_back();
        auto current = instructions.find(state.key.address);
        if (current == instructions.end()) {
            TranslationFailure failure{};
            failure.address = state.key.address;
            failure.mnemonic = "cfg";
            failure.reason = "reachable flow target is not an instruction boundary";
            m_lastFailures.push_back(std::move(failure));
            return false;
        }
        const InstructionIR& instruction = *current->second;
        uint64_t undefined = state.undefined;
        if ((instruction.flagsRead & undefined) != 0) {
            FailInstruction(instruction,
                "instruction reads flags that are undefined on a reachable predecessor path");
            return false;
        }
        undefined &= ~(instruction.flagsWritten | instruction.flagsUndefined);
        undefined |= instruction.flagsUndefined;
        const uint64_t fallthrough = instruction.address + instruction.length;

        if (instruction.IsReturn()) {
            if (!state.key.returns.empty()) {
                FlowKey returned = state.key;
                returned.address = returned.returns.back();
                returned.returns.pop_back();
                enqueue(returned, undefined);
            } else {
                const auto operands = SemanticOperands(instruction);
                uint32_t cleanup = 0;
                if (operands.size() > 1 ||
                    (!operands.empty() &&
                        (operands[0]->type != OperandType::Immediate ||
                         operands[0]->immediate > 0xFFFFu))) {
                    FailInstruction(instruction, "terminal RET has an invalid stack cleanup operand");
                    return false;
                }
                if (!operands.empty()) cleanup = static_cast<uint32_t>(operands[0]->immediate);
                if (instruction.machineMode == MachineMode::X64 && cleanup != 0) {
                    FailInstruction(instruction,
                        "x64 terminal RET uses callee stack cleanup outside the Windows x64 ABI");
                    return false;
                }
                if (!sawTerminalReturn) {
                    terminalReturnStackCleanup = cleanup;
                    sawTerminalReturn = true;
                } else if (terminalReturnStackCleanup != cleanup) {
                    FailInstruction(instruction,
                        "reachable terminal RET paths use inconsistent stack cleanup values");
                    return false;
                }
            }
        } else if (instruction.IsCall()) {
            FlowKey called = state.key;
            if (!instruction.isIndirectBranch && instruction.hasBranchTarget &&
                instructions.find(instruction.branchTargetRVA) != instructions.end()) {
                if (called.returns.size() >= VM_MAX_INTERNAL_CALL_DEPTH) {
                    FailInstruction(instruction, "internal CALL depth exceeds runtime bound");
                    return false;
                }
                called.returns.push_back(fallthrough);
                called.address = instruction.branchTargetRVA;
            } else {
                called.address = fallthrough;
            }
            enqueue(called, undefined);
        } else if (instruction.IsBranch()) {
            if (instruction.isIndirectBranch || !instruction.hasBranchTarget) {
                FailInstruction(instruction, "indirect or unresolved branch is not statically verifiable");
                return false;
            }
            FlowKey branch = state.key;
            branch.address = instruction.branchTargetRVA;
            enqueue(branch, undefined);
            if (instruction.IsConditionalBranch()) {
                FlowKey next = state.key;
                next.address = fallthrough;
                enqueue(next, undefined);
            }
        } else {
            FlowKey next = state.key;
            next.address = fallthrough;
            enqueue(next, undefined);
        }
        if (mergedStates.size() > 1000000u) {
            FailInstruction(instruction, "flag dataflow state space exceeds verification bound");
            return false;
        }
    }
    if (!sawTerminalReturn) {
        TranslationFailure failure{};
        failure.address = function.entryAddress;
        failure.mnemonic = "ret";
        failure.reason = "function has no reachable terminal RET";
        m_lastFailures.push_back(std::move(failure));
        return false;
    }
    return true;
}

TranslationResult Translator::TranslateFunction(const Function& function) {
    TranslationResult result{};
    result.registerCount = m_config.virtualRegisterCount;
    m_lastFailures.clear();
    if (!m_initialized || function.blocks.empty() || function.size == 0) {
        result.failures = m_lastFailures;
        return result;
    }
    m_functionStart = function.entryAddress;
    m_functionEnd = function.entryAddress + function.size;
    AnalyzeNativeCallStackArguments(function);
    if (!ValidateFlagDataflow(function, result.returnStackCleanup)) {
        result.failures = m_lastFailures;
        return result;
    }

    std::vector<const InstructionIR*> ordered;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) ordered.push_back(&instruction);
    }
    std::sort(ordered.begin(), ordered.end(), [](const InstructionIR* lhs, const InstructionIR* rhs) {
        return lhs->address < rhs->address;
    });
    ordered.erase(std::unique(ordered.begin(), ordered.end(), [](const InstructionIR* lhs, const InstructionIR* rhs) {
        return lhs->address == rhs->address;
    }), ordered.end());

    for (const InstructionIR* instruction : ordered) {
        if (!instruction || instruction->length == 0) {
            result.failures = m_lastFailures;
            return result;
        }
        BytecodeInstr bytecodeInstruction{};
        if (!TranslateInstruction(*instruction, bytecodeInstruction)) {
            result.failures = m_lastFailures;
            return result;
        }
        std::string schemaReason;
        const bool bridge = bytecodeInstruction.opcode == VM_BRIDGE_SIMD ||
            bytecodeInstruction.opcode == VM_BRIDGE_X87;
        if (!bridge && !VMSchema::ValidateInstruction(
                bytecodeInstruction, m_config.virtualRegisterCount, schemaReason)) {
            FailInstruction(*instruction, "schema validation failed: " + schemaReason);
            result.failures = m_lastFailures;
            return result;
        }
        const uint32_t offset = static_cast<uint32_t>(result.instructions.size() * VMSchema::InstructionSize());
        result.addrMap[instruction->address] = offset;
        result.instructions.push_back(bytecodeInstruction);
        if (bridge) {
            VMBridgeRequest request{};
            request.instructionIndex = static_cast<uint32_t>(result.instructions.size() - 1u);
            request.functionRVA = static_cast<uint32_t>(function.entryAddress);
            request.instruction = *instruction;
            request.hiddenNativeRegister = static_cast<uint8_t>(bytecodeInstruction.aux &
                VM_BRIDGE_AUX_HIDDEN_REGISTER_MASK);
            request.usesAvx = (bytecodeInstruction.aux & VM_BRIDGE_AUX_AVX) != 0;
            request.usesX87 = (bytecodeInstruction.aux & VM_BRIDGE_AUX_X87) != 0;
            result.usesSimd = result.usesSimd || !request.usesX87;
            result.usesAvx = result.usesAvx || request.usesAvx;
            result.usesX87 = result.usesX87 || request.usesX87;
            result.bridgeRequests.push_back(std::move(request));
        }
    }

    if (!FinalizeControlFlow(result)) {
        result.failures = m_lastFailures;
        return result;
    }
    result.totalSize = static_cast<uint32_t>(result.instructions.size() * VMSchema::InstructionSize());
    result.success = !result.instructions.empty();
    result.failures = m_lastFailures;
    return result;
}

TranslationResult Translator::TranslateBlock(const BasicBlock& block, uint32_t) {
    Function function{};
    function.entryAddress = block.startAddress;
    function.size = static_cast<uint32_t>(block.endAddress - block.startAddress);
    function.blocks.push_back(block);
    return TranslateFunction(function);
}

std::vector<uint8_t> Translator::GenerateBytecode(const TranslationResult& result) {
    if (!result.success) return {};
    std::vector<uint8_t> bytecode;
    bytecode.reserve(result.instructions.size() * VMSchema::InstructionSize());
    for (const auto& instruction : result.instructions) {
        std::string reason;
        if (!VMSchema::ValidateInstruction(instruction, m_config.virtualRegisterCount, reason)) return {};
        VMSchema::Encode(instruction, m_opcodeMap, bytecode);
    }
    return bytecode.size() == result.instructions.size() * VMSchema::InstructionSize()
        ? bytecode : std::vector<uint8_t>{};
}

std::string Translator::FormatInstructionBytes(const InstructionIR& instruction) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t i = 0; i < instruction.length && i < instruction.rawBytes.size(); ++i) {
        if (i) oss << ' ';
        oss << std::setw(2) << static_cast<unsigned>(instruction.rawBytes[i]);
    }
    return oss.str();
}

bool Translator::FailInstruction(const InstructionIR& instruction, const std::string& reason) {
    TranslationFailure failure{};
    failure.address = instruction.address;
    failure.mnemonic = instruction.mnemonicText.empty()
        ? InstructionMnemonicName(instruction.mnemonic) : instruction.mnemonicText;
    failure.bytes = FormatInstructionBytes(instruction);
    failure.reason = reason;
    m_lastFailures.push_back(std::move(failure));
    return false;
}

} // namespace CipherShell
