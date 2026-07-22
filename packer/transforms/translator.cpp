#include "translator.h"
#include "../differential/vm_native_differential_protocol.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>

namespace CipherShell {
namespace {

uint8_t WidthBytes(uint16_t widthBits) {
    switch (widthBits) {
        case 8: return 1;
        case 16: return 2;
        case 32: return 4;
        case 64: return 8;
        default: return 0;
    }
}

bool IsRegister(const OperandIR* operand) {
    return operand && operand->type == OperandType::Register;
}

bool IsImmediate(const OperandIR* operand) {
    return operand && operand->type == OperandType::Immediate;
}

bool IsMemory(const OperandIR* operand) {
    return operand && operand->type == OperandType::Memory;
}

std::vector<const OperandIR*> SemanticOperandsForInstruction(
    const InstructionIR& instruction)
{
    std::vector<const OperandIR*> operands;
    const bool isShiftRotate =
        instruction.mnemonic == InstructionMnemonic::Shl ||
        instruction.mnemonic == InstructionMnemonic::Sal ||
        instruction.mnemonic == InstructionMnemonic::Shr ||
        instruction.mnemonic == InstructionMnemonic::Sar ||
        instruction.mnemonic == InstructionMnemonic::Rol ||
        instruction.mnemonic == InstructionMnemonic::Ror;
    const bool hasMoffsMemory = instruction.mnemonic == InstructionMnemonic::Mov &&
        std::any_of(instruction.operands.begin(), instruction.operands.end(),
            [](const OperandIR& operand) {
                return operand.visibility == OperandVisibility::Explicit &&
                    operand.type == OperandType::Memory &&
                    !operand.memory.hasBase && !operand.memory.hasIndex &&
                    operand.memory.hasDisplacement;
            });
    for (const auto& operand : instruction.operands) {
        const bool implicitMoffsAccumulator = hasMoffsMemory &&
            operand.visibility == OperandVisibility::Implicit &&
            operand.type == OperandType::Register &&
            operand.regInfo.registerClass == RegisterCategory::GeneralPurpose &&
            operand.regInfo.family == 0u;
        // Zydis represents the architectural CL source of D2/D3 and the
        // implicit one of D0/D1 as hidden operands.  They are nevertheless
        // real semantic inputs and must reach both translation and the
        // concrete path oracle.
        const bool implicitShiftCount = isShiftRotate &&
            operand.visibility == OperandVisibility::Implicit &&
            (operand.type == OperandType::Register ||
                operand.type == OperandType::Immediate) &&
            operand.action == OperandAction::Read;
        if ((operand.visibility == OperandVisibility::Explicit ||
                implicitMoffsAccumulator || implicitShiftCount) &&
            operand.type != OperandType::None) {
            operands.push_back(&operand);
        }
    }
    return operands;
}

bool OperandWrites(OperandAction action) {
    return action == OperandAction::Write || action == OperandAction::ReadWrite ||
        action == OperandAction::ConditionalWrite ||
        action == OperandAction::ConditionalReadWrite;
}

bool IsExtendedRegisterClass(RegisterCategory cls) {
    return cls == RegisterCategory::Vector || cls == RegisterCategory::X87 ||
        cls == RegisterCategory::Mmx;
}

uint64_t Mix64(uint64_t value) {
    value += 0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27u)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31u);
}

uint64_t WidthMask(uint8_t width) {
    return width == 8u ? UINT64_MAX : ((1ULL << (width * 8u)) - 1ULL);
}

uint8_t AddressWidth(const InstructionIR& instruction) {
    const uint8_t decodedWidth = WidthBytes(instruction.addressWidth);
    return decodedWidth != 0 ? decodedWidth :
        (instruction.machineMode == MachineMode::X64 ? 8u : 4u);
}

uint8_t StackPointerWidth(const InstructionIR& instruction) {
    const uint8_t decodedWidth = WidthBytes(instruction.stackWidth);
    return decodedWidth != 0 ? decodedWidth :
        (instruction.machineMode == MachineMode::X64 ? 8u : 4u);
}

uint8_t ImplicitWidth(const InstructionIR& instruction) {
    const uint8_t explicitWidth = WidthBytes(instruction.operandWidth);
    if (explicitWidth != 0) return explicitWidth;
    const std::string& name = instruction.mnemonicText;
    if (name == "cbw" || name == "cwd" || name == "pushf" || name == "popf") return 2;
    if (name == "cwde" || name == "cdq" || name == "pushfd" || name == "popfd") return 4;
    if (name == "cdqe" || name == "cqo" || name == "pushfq" || name == "popfq") return 8;
    return instruction.machineMode == MachineMode::X64 ? 8u : 4u;
}

uint32_t DefinedFlagsFor(InstructionMnemonic mnemonic) {
    switch (mnemonic) {
        case InstructionMnemonic::And:
        case InstructionMnemonic::Or:
        case InstructionMnemonic::Xor:
        case InstructionMnemonic::Test:
            return VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF;
        case InstructionMnemonic::Bt:
        case InstructionMnemonic::Bts:
        case InstructionMnemonic::Btr:
            return VM_FLAG_CF;
        case InstructionMnemonic::Rol:
        case InstructionMnemonic::Ror:
            return VM_FLAG_CF | VM_FLAG_OF;
        case InstructionMnemonic::Shl:
        case InstructionMnemonic::Sal:
        case InstructionMnemonic::Shr:
        case InstructionMnemonic::Sar:
            return VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF;
        case InstructionMnemonic::Mul:
        case InstructionMnemonic::Imul:
            return VM_FLAG_CF | VM_FLAG_OF;
        default:
            return VM_FLAG_STATUS_MASK;
    }
}

VM_LAZY_FLAG_KIND LazyKindFor(InstructionMnemonic mnemonic) {
    switch (mnemonic) {
        case InstructionMnemonic::Add: return VM_LAZY_ADD;
        case InstructionMnemonic::Adc: return VM_LAZY_ADC;
        case InstructionMnemonic::Sub:
        case InstructionMnemonic::Cmp: return VM_LAZY_SUB;
        case InstructionMnemonic::Sbb: return VM_LAZY_SBB;
        case InstructionMnemonic::And:
        case InstructionMnemonic::Or:
        case InstructionMnemonic::Xor:
        case InstructionMnemonic::Test: return VM_LAZY_LOGIC;
        case InstructionMnemonic::Neg: return VM_LAZY_NEG;
        case InstructionMnemonic::Inc: return VM_LAZY_INC;
        case InstructionMnemonic::Dec: return VM_LAZY_DEC;
        case InstructionMnemonic::Shl:
        case InstructionMnemonic::Sal: return VM_LAZY_SHL;
        case InstructionMnemonic::Shr: return VM_LAZY_SHR;
        case InstructionMnemonic::Sar: return VM_LAZY_SAR;
        case InstructionMnemonic::Rol: return VM_LAZY_ROL;
        case InstructionMnemonic::Ror: return VM_LAZY_ROR;
        case InstructionMnemonic::Mul: return VM_LAZY_MUL;
        case InstructionMnemonic::Imul: return VM_LAZY_IMUL;
        case InstructionMnemonic::Bt:
        case InstructionMnemonic::Bts:
        case InstructionMnemonic::Btr: return VM_LAZY_BIT_TEST;
        default: return VM_LAZY_NONE;
    }
}

} // namespace

Translator::Translator() = default;
Translator::~Translator() = default;

bool Translator::Initialize(const TranslationConfig& config) {
    if (config.virtualRegisterCount < 16 || config.virtualRegisterCount > 32 ||
        config.handlerVariantCount == 0 ||
        config.handlerVariantCount > VM_MICRO_MAX_HANDLER_VARIANTS ||
        config.heavyMinimumRatio < VM_MICRO_HEAVY_MIN_RATIO) {
        m_initialized = false;
        return false;
    }
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
    return SemanticOperandsForInstruction(instruction);
}

uint8_t Translator::MapRegisterFamily(uint8_t family) const {
    if (family >= 16) return VM_REG_INVALID;
    const auto found = m_registerMap.find(family);
    if (found == m_registerMap.end() || found->second >= m_config.virtualRegisterCount) {
        return VM_REG_INVALID;
    }
    return found->second;
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

void Translator::Emit(
    TranslationResult& result,
    VM_MICRO_OPCODE opcode,
    std::initializer_list<uint64_t> operands,
    uint32_t sourceRva)
{
    MicroInstruction micro{};
    micro.opcode = opcode;
    micro.operandCount = static_cast<uint8_t>(operands.size());
    micro.sourceRva = sourceRva;
    size_t index = 0;
    for (uint64_t operand : operands) micro.operands[index++] = operand;
    const uint64_t selection = Mix64(m_config.buildSeed ^
        (static_cast<uint64_t>(m_currentFunctionRva) << 32u) ^
        (static_cast<uint64_t>(sourceRva) << 1u) ^
        (static_cast<uint64_t>(result.instructions.size()) * 0xD6E8FEB86659FD93ULL) ^
        static_cast<uint64_t>(opcode));
    micro.handlerVariant = static_cast<uint8_t>(selection % m_config.handlerVariantCount);
    result.instructions.push_back(micro);

    uint64_t digest = result.microSelectionDigest == 0 ?
        (0xCBF29CE484222325ULL ^ m_config.buildSeed) : result.microSelectionDigest;
    digest ^= static_cast<uint8_t>(opcode);
    digest *= 0x100000001B3ULL;
    digest ^= micro.handlerVariant;
    digest *= 0x100000001B3ULL;
    for (uint64_t operand : operands) {
        digest ^= Mix64(operand);
        digest *= 0x100000001B3ULL;
    }
    result.microSelectionDigest = digest;
}

void Translator::EmitHeavyPrefix(
    const InstructionIR& instruction,
    TranslationResult& result)
{
    const unsigned groups = m_config.density == VMMicroDensity::Heavy ? 2u : 0u;
    for (unsigned group = 0; group < groups; ++group) {
        const uint64_t choice = Mix64(m_config.buildSeed ^ instruction.address ^
            (static_cast<uint64_t>(group) << 48u));
        const uint8_t temp = static_cast<uint8_t>(24u + (choice % 8u));
        if ((choice & 1u) != 0) {
            const uint8_t family = static_cast<uint8_t>((choice >> 8u) & 0x0Fu);
            Emit(result, VM_UOP_PUSH_VREG,
                {MapRegisterFamily(family), AddressWidth(instruction), 0}, instruction.rva);
        } else {
            Emit(result, VM_UOP_PUSH_IMM,
                {Mix64(choice), AddressWidth(instruction)}, instruction.rva);
        }
        Emit(result, VM_UOP_STORE_TEMP, {temp}, instruction.rva);
        Emit(result, VM_UOP_LOAD_TEMP, {temp}, instruction.rva);
        Emit(result, VM_UOP_DROP, {}, instruction.rva);
    }
}

bool Translator::EmitRegisterRead(
    const InstructionIR& instruction,
    uint8_t family,
    uint8_t width,
    uint8_t bitOffset,
    TranslationResult& result)
{
    const uint8_t reg = MapRegisterFamily(family);
    if (reg == VM_REG_INVALID || width == 0 || width > 8 ||
        bitOffset + width * 8u > 64u) {
        return FailInstruction(instruction, "general-purpose register read cannot be represented in micro ISA");
    }
    Emit(result, VM_UOP_PUSH_VREG, {reg, width, bitOffset}, instruction.rva);
    return true;
}

bool Translator::EmitRegisterWrite(
    const InstructionIR& instruction,
    uint8_t family,
    uint8_t width,
    uint8_t bitOffset,
    bool zeroExtend,
    TranslationResult& result)
{
    const uint8_t reg = MapRegisterFamily(family);
    if (reg == VM_REG_INVALID || width == 0 || width > 8 ||
        bitOffset + width * 8u > 64u) {
        return FailInstruction(instruction, "general-purpose register write cannot be represented in micro ISA");
    }
    Emit(result, VM_UOP_POP_VREG, {reg, width, bitOffset, zeroExtend ? 1u : 0u}, instruction.rva);
    return true;
}

bool Translator::EmitAddress(
    const InstructionIR& instruction,
    const OperandIR& operand,
    TranslationResult& result)
{
    if (operand.type != OperandType::Memory) {
        return FailInstruction(instruction, "address lowering received a non-memory operand");
    }
    const MemoryOperandIR& memory = operand.memory;
    if (memory.segment != RegisterId::None && memory.segment != RegisterId::DS &&
        memory.segment != RegisterId::SS) {
        return FailInstruction(instruction, "FS/GS and non-default segments have no micro address semantic");
    }
    const uint8_t addressWidth = AddressWidth(instruction);
    if (memory.isImageAddress || memory.isRipRelative) {
        Emit(result, VM_UOP_PUSH_IMAGE_BASE, {}, instruction.rva);
        Emit(result, VM_UOP_PUSH_IMM, {memory.resolvedRVA, addressWidth}, instruction.rva);
        Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
        return true;
    }

    if (memory.hasBase) {
        if (memory.baseInfo.registerClass != RegisterCategory::GeneralPurpose ||
            !EmitRegisterRead(instruction, memory.baseInfo.family, addressWidth, 0, result)) {
            return FailInstruction(instruction, "memory base is not a mapped general-purpose register");
        }
    } else {
        Emit(result, VM_UOP_PUSH_IMM, {0, addressWidth}, instruction.rva);
    }

    if (memory.hasIndex) {
        if (memory.indexInfo.registerClass != RegisterCategory::GeneralPurpose ||
            !(memory.scale == 1 || memory.scale == 2 || memory.scale == 4 || memory.scale == 8) ||
            !EmitRegisterRead(instruction, memory.indexInfo.family, addressWidth, 0, result)) {
            return FailInstruction(instruction, "memory index/scale is not representable in micro ISA");
        }
        const uint64_t choice = Mix64(m_config.buildSeed ^ instruction.address ^ memory.scale);
        if (memory.scale != 1) {
            if ((choice & 1u) == 0) {
                Emit(result, VM_UOP_PUSH_IMM, {memory.scale, addressWidth}, instruction.rva);
                Emit(result, VM_UOP_MUL, {addressWidth}, instruction.rva);
            } else {
                unsigned doublings = memory.scale == 2 ? 1u : (memory.scale == 4 ? 2u : 3u);
                for (unsigned i = 0; i < doublings; ++i) {
                    Emit(result, VM_UOP_DUP, {}, instruction.rva);
                    Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
                }
            }
        }
        Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
    }
    if (memory.hasDisplacement && memory.displacement != 0) {
        Emit(result, VM_UOP_PUSH_IMM,
            {static_cast<uint64_t>(memory.displacement) & WidthMask(addressWidth), addressWidth},
            instruction.rva);
        Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
    }
    return true;
}

bool Translator::EmitRead(
    const InstructionIR& instruction,
    const OperandIR& operand,
    TranslationResult& result,
    uint8_t forcedWidth)
{
    const uint8_t width = forcedWidth != 0 ? forcedWidth : WidthBytes(operand.width);
    if (width == 0 || width > 8) {
        return FailInstruction(instruction, "scalar operand width is outside micro ISA");
    }
    if (operand.type == OperandType::Register) {
        if (operand.regInfo.registerClass != RegisterCategory::GeneralPurpose) {
            return FailInstruction(instruction, "non-GPR scalar read is not micro-lowerable");
        }
        return EmitRegisterRead(instruction, operand.regInfo.family, width,
            operand.regInfo.bitOffset, result);
    }
    if (operand.type == OperandType::Immediate) {
        if (operand.immediateIsImageAddress) {
            const uint8_t addressWidth = AddressWidth(instruction);
            if (!instruction.hasImageRelocation ||
                !instruction.imageRelocationSupported ||
                width != addressWidth) {
                return FailInstruction(instruction,
                    "relocated image immediate has no exact pointer-width VM semantic");
            }
            Emit(result, VM_UOP_PUSH_IMAGE_BASE, {}, instruction.rva);
            Emit(result, VM_UOP_PUSH_IMM,
                {operand.immediateResolvedRVA, addressWidth}, instruction.rva);
            Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
            return true;
        }
        Emit(result, VM_UOP_PUSH_IMM, {operand.immediate, width}, instruction.rva);
        return true;
    }
    if (operand.type == OperandType::Memory) {
        if (!EmitAddress(instruction, operand, result)) return false;
        Emit(result, VM_UOP_LOAD, {width}, instruction.rva);
        return true;
    }
    return FailInstruction(instruction, "unsupported scalar source operand");
}

bool Translator::EmitWrite(
    const InstructionIR& instruction,
    const OperandIR& operand,
    TranslationResult& result,
    uint8_t forcedWidth,
    uint8_t temp)
{
    const uint8_t width = forcedWidth != 0 ? forcedWidth : WidthBytes(operand.width);
    if (width == 0 || width > 8) {
        return FailInstruction(instruction, "scalar destination width is outside micro ISA");
    }
    if (operand.type == OperandType::Register) {
        if (operand.regInfo.registerClass != RegisterCategory::GeneralPurpose) {
            return FailInstruction(instruction, "non-GPR scalar write is not micro-lowerable");
        }
        return EmitRegisterWrite(instruction, operand.regInfo.family, width,
            operand.regInfo.bitOffset, operand.regInfo.zeroExtendsOnWrite, result);
    }
    if (operand.type == OperandType::Memory) {
        Emit(result, VM_UOP_STORE_TEMP, {temp}, instruction.rva);
        if (!EmitAddress(instruction, operand, result)) return false;
        Emit(result, VM_UOP_LOAD_TEMP, {temp}, instruction.rva);
        Emit(result, VM_UOP_STORE, {width}, instruction.rva);
        return true;
    }
    return FailInstruction(instruction, "unsupported scalar destination operand");
}

bool Translator::LowerMove(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (instruction.mnemonic == InstructionMnemonic::Lea) {
        if (operands.size() != 2 || !IsRegister(operands[0]) || !IsMemory(operands[1])) {
            return FailInstruction(instruction, "LEA requires GPR destination and memory address expression");
        }
        return EmitAddress(instruction, *operands[1], result) &&
            EmitWrite(instruction, *operands[0], result, AddressWidth(instruction));
    }
    if (instruction.mnemonic == InstructionMnemonic::Xchg) {
        if (instruction.hasLockPrefix || operands.size() != 2 ||
            (!IsRegister(operands[0]) && !IsMemory(operands[0])) ||
            (!IsRegister(operands[1]) && !IsMemory(operands[1])) ||
            IsMemory(operands[0]) || IsMemory(operands[1])) {
            return FailInstruction(instruction,
                "memory XCHG is implicitly atomic and has no synthesized micro atomic contract");
        }
        const uint8_t width = WidthBytes(operands[0]->width);
        if (!EmitRead(instruction, *operands[0], result, width)) return false;
        Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
        if (!EmitRead(instruction, *operands[1], result, width)) return false;
        Emit(result, VM_UOP_STORE_TEMP, {1}, instruction.rva);
        Emit(result, VM_UOP_LOAD_TEMP, {1}, instruction.rva);
        if (!EmitWrite(instruction, *operands[0], result, width, 2)) return false;
        Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
        return EmitWrite(instruction, *operands[1], result, width, 2);
    }
    if (operands.size() != 2 ||
        (!IsRegister(operands[0]) && !IsMemory(operands[0])) ||
        (!IsRegister(operands[1]) && !IsImmediate(operands[1]) && !IsMemory(operands[1])) ||
        (IsMemory(operands[0]) && IsMemory(operands[1]))) {
        return FailInstruction(instruction, "MOV operands are outside scalar micro contract");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    return EmitRead(instruction, *operands[1], result, width) &&
        EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerMoveExtend(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 2 || !IsRegister(operands[0]) ||
        (!IsRegister(operands[1]) && !IsMemory(operands[1]))) {
        return FailInstruction(instruction, "MOVZX/MOVSX requires GPR destination and scalar source");
    }
    const uint8_t sourceWidth = WidthBytes(operands[1]->width);
    const uint8_t destinationWidth = WidthBytes(operands[0]->width);
    if (sourceWidth == 0 || destinationWidth == 0 || sourceWidth >= destinationWidth) {
        return FailInstruction(instruction, "move-extension widths are invalid");
    }
    if (!EmitRead(instruction, *operands[1], result, sourceWidth)) return false;
    Emit(result, instruction.mnemonic == InstructionMnemonic::Movzx ?
        VM_UOP_ZERO_EXTEND : VM_UOP_SIGN_EXTEND,
        {sourceWidth, destinationWidth}, instruction.rva);
    return EmitWrite(instruction, *operands[0], result, destinationWidth);
}

bool Translator::LowerBinary(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (instruction.hasLockPrefix || operands.size() != 2 ||
        (!IsRegister(operands[0]) && !IsMemory(operands[0])) ||
        (!IsRegister(operands[1]) && !IsImmediate(operands[1]) && !IsMemory(operands[1])) ||
        (IsMemory(operands[0]) && IsMemory(operands[1]))) {
        return FailInstruction(instruction, "binary instruction is not a non-atomic scalar pair");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    if (!EmitRead(instruction, *operands[0], result, width) ||
        !EmitRead(instruction, *operands[1], result, width)) return false;

    VM_MICRO_OPCODE opcode = VM_UOP_TRAP;
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Add: opcode = VM_UOP_ADD; break;
        case InstructionMnemonic::Adc: opcode = VM_UOP_ADD_CARRY; break;
        case InstructionMnemonic::Sub:
        case InstructionMnemonic::Cmp: opcode = VM_UOP_SUB; break;
        case InstructionMnemonic::Sbb: opcode = VM_UOP_SUB_BORROW; break;
        case InstructionMnemonic::And:
        case InstructionMnemonic::Test: opcode = VM_UOP_AND; break;
        case InstructionMnemonic::Or: opcode = VM_UOP_OR; break;
        case InstructionMnemonic::Xor: opcode = VM_UOP_XOR; break;
        default: return FailInstruction(instruction, "binary mnemonic has no micro ALU semantic");
    }
    if (opcode == VM_UOP_ADD_CARRY || opcode == VM_UOP_SUB_BORROW) {
        Emit(result, VM_UOP_FLAGS_MATERIALIZE, {VM_FLAG_CF}, instruction.rva);
        Emit(result, VM_UOP_PUSH_FLAGS, {VM_FLAG_CF}, instruction.rva);
    }
    Emit(result, opcode, {width}, instruction.rva);
    const VM_LAZY_FLAG_KIND lazy = LazyKindFor(instruction.mnemonic);
    Emit(result, VM_UOP_FLAGS_LAZY,
        {static_cast<uint64_t>(lazy), width, DefinedFlagsFor(instruction.mnemonic), 0}, instruction.rva);
    if (instruction.mnemonic == InstructionMnemonic::Cmp ||
        instruction.mnemonic == InstructionMnemonic::Test) {
        Emit(result, VM_UOP_DROP, {}, instruction.rva);
        return true;
    }
    return EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerUnary(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (instruction.hasLockPrefix || operands.size() != 1 ||
        (!IsRegister(operands[0]) && !IsMemory(operands[0]))) {
        return FailInstruction(instruction, "unary instruction is not a non-atomic scalar destination");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    if (!EmitRead(instruction, *operands[0], result, width)) return false;
    if (instruction.mnemonic == InstructionMnemonic::Not) {
        Emit(result, VM_UOP_NOT, {width}, instruction.rva);
    } else if (instruction.mnemonic == InstructionMnemonic::Neg) {
        Emit(result, VM_UOP_NEG, {width}, instruction.rva);
        Emit(result, VM_UOP_FLAGS_LAZY,
            {VM_LAZY_NEG, width, VM_FLAG_STATUS_MASK, 0}, instruction.rva);
    } else {
        Emit(result, VM_UOP_PUSH_IMM, {1, width}, instruction.rva);
        const bool increment = instruction.mnemonic == InstructionMnemonic::Inc;
        Emit(result, increment ? VM_UOP_ADD : VM_UOP_SUB, {width}, instruction.rva);
        Emit(result, VM_UOP_FLAGS_LAZY,
            {static_cast<uint64_t>(increment ? VM_LAZY_INC : VM_LAZY_DEC), width,
             VM_FLAG_PF | VM_FLAG_AF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF,
             VM_FLAG_CF}, instruction.rva);
    }
    return EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerShiftRotate(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (instruction.hasLockPrefix || operands.size() != 2 ||
        (!IsRegister(operands[0]) && !IsMemory(operands[0])) ||
        (!IsRegister(operands[1]) && !IsImmediate(operands[1]))) {
        return FailInstruction(instruction, "shift/rotate requires scalar destination and register/immediate count");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    if (!EmitRead(instruction, *operands[0], result, width) ||
        !EmitRead(instruction, *operands[1], result, 1)) return false;
    VM_MICRO_OPCODE opcode = VM_UOP_TRAP;
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Shl:
        case InstructionMnemonic::Sal: opcode = VM_UOP_SHL; break;
        case InstructionMnemonic::Shr: opcode = VM_UOP_SHR; break;
        case InstructionMnemonic::Sar: opcode = VM_UOP_SAR; break;
        case InstructionMnemonic::Rol: opcode = VM_UOP_ROL; break;
        case InstructionMnemonic::Ror: opcode = VM_UOP_ROR; break;
        default: break;
    }
    if (opcode == VM_UOP_TRAP) return FailInstruction(instruction, "shift/rotate has no micro semantic");
    Emit(result, opcode, {width}, instruction.rva);
    Emit(result, VM_UOP_FLAGS_LAZY,
        {static_cast<uint64_t>(LazyKindFor(instruction.mnemonic)), width,
         DefinedFlagsFor(instruction.mnemonic), 0}, instruction.rva);
    return EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerMultiplyDivide(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (operands.empty() || operands.size() > 3 || instruction.hasLockPrefix) {
        return FailInstruction(instruction, "multiply/divide operand form is outside micro ISA");
    }
    const bool implicit = instruction.mnemonic == InstructionMnemonic::Mul ||
        instruction.mnemonic == InstructionMnemonic::Div ||
        instruction.mnemonic == InstructionMnemonic::Idiv ||
        (instruction.mnemonic == InstructionMnemonic::Imul && operands.size() == 1);
    if (implicit) {
        if (operands.size() != 1 || (!IsRegister(operands[0]) && !IsMemory(operands[0]))) {
            return FailInstruction(instruction, "implicit multiply/divide requires one scalar source");
        }
        const uint8_t width = WidthBytes(operands[0]->width);
        if (width == 0) return FailInstruction(instruction, "implicit multiply/divide width is invalid");
        if (instruction.mnemonic == InstructionMnemonic::Mul ||
            instruction.mnemonic == InstructionMnemonic::Imul) {
            if (!EmitRegisterRead(instruction, 0, width, 0, result) ||
                !EmitRead(instruction, *operands[0], result, width)) return false;
            Emit(result, instruction.mnemonic == InstructionMnemonic::Mul ?
                VM_UOP_UMUL_WIDE : VM_UOP_SMUL_WIDE, {width}, instruction.rva);
            Emit(result, VM_UOP_FLAGS_LAZY,
                {static_cast<uint64_t>(instruction.mnemonic == InstructionMnemonic::Mul ?
                    VM_LAZY_MUL : VM_LAZY_IMUL),
                 width, VM_FLAG_CF | VM_FLAG_OF, 0}, instruction.rva);
            Emit(result, VM_UOP_STORE_TEMP, {1}, instruction.rva);
            Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
            Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
            if (!EmitRegisterWrite(instruction, 0, width, 0, width == 4u, result)) return false;
            Emit(result, VM_UOP_LOAD_TEMP, {1}, instruction.rva);
            return EmitRegisterWrite(instruction, width == 1 ? 0 : 2,
                width, width == 1 ? 8u : 0u, width == 4u, result);
        }
        if (!EmitRegisterRead(instruction, width == 1 ? 0 : 2,
                width, width == 1 ? 8u : 0u, result) ||
            !EmitRegisterRead(instruction, 0, width, 0, result) ||
            !EmitRead(instruction, *operands[0], result, width)) return false;
        Emit(result, instruction.mnemonic == InstructionMnemonic::Div ?
            VM_UOP_UDIV_WIDE : VM_UOP_IDIV_WIDE, {width}, instruction.rva);
        Emit(result, VM_UOP_STORE_TEMP, {1}, instruction.rva);
        Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
        Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
        if (!EmitRegisterWrite(instruction, 0, width, 0, width == 4u, result)) return false;
        Emit(result, VM_UOP_LOAD_TEMP, {1}, instruction.rva);
        return EmitRegisterWrite(instruction, width == 1 ? 0 : 2,
            width, width == 1 ? 8u : 0u, width == 4u, result);
    }

    if (instruction.mnemonic != InstructionMnemonic::Imul ||
        (operands.size() != 2 && operands.size() != 3) || !IsRegister(operands[0])) {
        return FailInstruction(instruction, "explicit multiply must be two/three-operand IMUL");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    const OperandIR* lhs = operands.size() == 2 ? operands[0] : operands[1];
    const OperandIR* rhs = operands.size() == 2 ? operands[1] : operands[2];
    if (!EmitRead(instruction, *lhs, result, width) ||
        !EmitRead(instruction, *rhs, result, width)) return false;
    Emit(result, VM_UOP_SMUL_WIDE, {width}, instruction.rva);
    Emit(result, VM_UOP_FLAGS_LAZY,
        {VM_LAZY_IMUL, width, VM_FLAG_CF | VM_FLAG_OF, 0}, instruction.rva);
    Emit(result, VM_UOP_STORE_TEMP, {1}, instruction.rva);
    return EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerStack(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() != 1) return FailInstruction(instruction, "PUSH/POP requires one scalar operand");
    const uint8_t stackWidth = WidthBytes(instruction.operandWidth) != 0 ?
        WidthBytes(instruction.operandWidth) :
        (WidthBytes(operands[0]->width) != 0 ? WidthBytes(operands[0]->width) : AddressWidth(instruction));
    const uint8_t addressWidth = StackPointerWidth(instruction);
    if (instruction.mnemonic == InstructionMnemonic::Push) {
        if (!EmitRead(instruction, *operands[0], result, stackWidth)) return false;
        Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
        if (!EmitRegisterRead(instruction, 4, addressWidth, 0, result)) return false;
        Emit(result, VM_UOP_PUSH_IMM, {stackWidth, addressWidth}, instruction.rva);
        Emit(result, VM_UOP_SUB, {addressWidth}, instruction.rva);
        Emit(result, VM_UOP_DUP, {}, instruction.rva);
        if (!EmitRegisterWrite(instruction, 4, addressWidth, 0, false, result)) return false;
        Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
        Emit(result, VM_UOP_STORE, {stackWidth}, instruction.rva);
        return true;
    }
    if (instruction.mnemonic == InstructionMnemonic::Pop) {
        if (!IsRegister(operands[0]) && !IsMemory(operands[0])) {
            return FailInstruction(instruction, "POP destination must be register or memory");
        }
        if (!EmitRegisterRead(instruction, 4, addressWidth, 0, result)) return false;
        Emit(result, VM_UOP_DUP, {}, instruction.rva);
        Emit(result, VM_UOP_LOAD, {stackWidth}, instruction.rva);
        Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
        Emit(result, VM_UOP_PUSH_IMM, {stackWidth, addressWidth}, instruction.rva);
        Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
        if (!EmitRegisterWrite(instruction, 4, addressWidth, 0, false, result)) return false;
        Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
        return EmitWrite(instruction, *operands[0], result, stackWidth, 1);
    }
    return FailInstruction(instruction, "stack mnemonic is not PUSH/POP");
}

bool Translator::LowerBranch(const InstructionIR& instruction, TranslationResult& result) {
    if (instruction.isIndirectBranch || !instruction.hasBranchTarget) {
        return FailInstruction(instruction, "branch target is not a statically verified VM boundary");
    }
    if (instruction.branchKind == BranchKind::Unconditional) {
        Emit(result, VM_UOP_BRANCH, {0}, instruction.rva);
        m_branchFixups.push_back({result.instructions.size() - 1u, 0, instruction.branchTargetRVA});
        return true;
    }
    const VM_CONDITION condition = MapCondition(instruction.branchKind);
    if (condition == VM_CONDITION_ALWAYS) {
        return FailInstruction(instruction, "conditional branch has no VM condition mapping");
    }
    Emit(result, VM_UOP_BRANCH_IF, {static_cast<uint64_t>(condition), 0}, instruction.rva);
    m_branchFixups.push_back({result.instructions.size() - 1u, 1, instruction.branchTargetRVA});
    return true;
}

bool Translator::LowerCall(const InstructionIR& instruction, TranslationResult& result) {
    if (instruction.isIndirectBranch || !instruction.hasBranchTarget) {
        return FailInstruction(instruction, "indirect/unresolved CALL has no provable VM target");
    }
    if (instruction.branchTargetRVA < m_functionStart || instruction.branchTargetRVA >= m_functionEnd) {
        return FailInstruction(instruction, "external native CALL ABI is not statically recoverable");
    }
    Emit(result, VM_UOP_CALL_VM, {0}, instruction.rva);
    m_branchFixups.push_back({result.instructions.size() - 1u, 0, instruction.branchTargetRVA});
    return true;
}

bool Translator::LowerRet(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (operands.size() > 1 || (!operands.empty() &&
        (!IsImmediate(operands[0]) || operands[0]->immediate > 0xFFFFu))) {
        return FailInstruction(instruction, "RET cleanup operand is invalid");
    }
    const uint64_t cleanup = operands.empty() ? 0 : operands[0]->immediate;
    if (instruction.machineMode == MachineMode::X64 && cleanup != 0) {
        return FailInstruction(instruction, "x64 RET immediate violates Windows x64 ABI");
    }
    // This is part of production bytecode, not differential-only
    // instrumentation. The native return bridge restores virtualFlags to the
    // architectural frame, so every pending lazy flag must be committed before
    // RET. Per-corpus verification masks only the bits undefined on the actual
    // native path; all defined bits therefore remain byte-for-byte checked.
    Emit(result, VM_UOP_FLAGS_MATERIALIZE,
        {VM_FLAG_ARCHITECTURAL_MASK}, instruction.rva);
    Emit(result, VM_UOP_RET, {cleanup}, instruction.rva);
    return true;
}

bool Translator::LowerConditionalData(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    const VM_CONDITION condition = MapCondition(instruction.branchKind);
    if (condition == VM_CONDITION_ALWAYS) {
        return FailInstruction(instruction, "conditional data instruction lacks condition mapping");
    }
    if (instruction.mnemonic == InstructionMnemonic::Cmov) {
        if (operands.size() != 2 || !IsRegister(operands[0]) ||
            (!IsRegister(operands[1]) && !IsMemory(operands[1]))) {
            return FailInstruction(instruction, "CMOV requires GPR destination and scalar source");
        }
        const uint8_t width = WidthBytes(operands[0]->width);
        if (!EmitRead(instruction, *operands[0], result, width) ||
            !EmitRead(instruction, *operands[1], result, width)) return false;
        Emit(result, VM_UOP_SELECT, {static_cast<uint64_t>(condition)}, instruction.rva);
        return EmitWrite(instruction, *operands[0], result, width);
    }
    if (instruction.mnemonic == InstructionMnemonic::Setcc) {
        if (operands.size() != 1 || (!IsRegister(operands[0]) && !IsMemory(operands[0]))) {
            return FailInstruction(instruction, "SETcc requires byte register/memory destination");
        }
        Emit(result, VM_UOP_PUSH_CONDITION, {static_cast<uint64_t>(condition)}, instruction.rva);
        return EmitWrite(instruction, *operands[0], result, 1);
    }
    return FailInstruction(instruction, "conditional data mnemonic is unsupported");
}

bool Translator::LowerBitOperation(const InstructionIR& instruction, TranslationResult& result) {
    const auto operands = SemanticOperands(instruction);
    if (instruction.hasLockPrefix || operands.size() != 2 || !IsRegister(operands[0]) ||
        (!IsRegister(operands[1]) && !IsImmediate(operands[1]))) {
        return FailInstruction(instruction,
            "only non-atomic register BT/BTS/BTR has bounded micro bit-index semantics");
    }
    const uint8_t width = WidthBytes(operands[0]->width);
    if (width != 2 && width != 4 && width != 8) {
        return FailInstruction(instruction, "BT/BTS/BTR width must be 16/32/64 bits");
    }
    if (!EmitRead(instruction, *operands[0], result, width) ||
        !EmitRead(instruction, *operands[1], result, width)) return false;
    VM_MICRO_OPCODE opcode = instruction.mnemonic == InstructionMnemonic::Bt ? VM_UOP_BIT_TEST :
        (instruction.mnemonic == InstructionMnemonic::Bts ? VM_UOP_BIT_SET : VM_UOP_BIT_RESET);
    Emit(result, opcode, {width}, instruction.rva);
    Emit(result, VM_UOP_FLAGS_LAZY,
        {VM_LAZY_BIT_TEST, width, VM_FLAG_CF, 0}, instruction.rva);
    if (instruction.mnemonic == InstructionMnemonic::Bt) {
        Emit(result, VM_UOP_DROP, {}, instruction.rva);
        return true;
    }
    return EmitWrite(instruction, *operands[0], result, width);
}

bool Translator::LowerImplicitScalar(const InstructionIR& instruction, TranslationResult& result) {
    if (!SemanticOperands(instruction).empty()) {
        return FailInstruction(instruction, "implicit scalar instruction unexpectedly has visible operands");
    }
    const uint8_t width = ImplicitWidth(instruction);
    const uint8_t addressWidth = StackPointerWidth(instruction);
    switch (instruction.mnemonic) {
        case InstructionMnemonic::PushFlags:
            Emit(result, VM_UOP_PUSH_FLAGS, {VM_FLAG_ARCHITECTURAL_MASK}, instruction.rva);
            if (width >= 4u) {
                Emit(result, VM_UOP_PUSH_IMM,
                    {~static_cast<uint64_t>(VM_FLAG_PUSH_CLEARED_MASK), width},
                    instruction.rva);
                Emit(result, VM_UOP_AND, {width}, instruction.rva);
            }
            Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
            if (!EmitRegisterRead(instruction, 4, addressWidth, 0, result)) return false;
            Emit(result, VM_UOP_PUSH_IMM, {width, addressWidth}, instruction.rva);
            Emit(result, VM_UOP_SUB, {addressWidth}, instruction.rva);
            Emit(result, VM_UOP_DUP, {}, instruction.rva);
            if (!EmitRegisterWrite(instruction, 4, addressWidth, 0, false, result)) return false;
            Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
            Emit(result, VM_UOP_STORE, {width}, instruction.rva);
            return true;
        case InstructionMnemonic::PopFlags:
            return FailInstruction(instruction,
                "POPF/POPFD/POPFQ privilege, trap, and RF semantics are not losslessly virtualized");
        case InstructionMnemonic::Leave:
            if (!EmitRegisterRead(instruction, 5, addressWidth, 0, result) ||
                !EmitRegisterWrite(instruction, 4, addressWidth, 0, false, result) ||
                !EmitRegisterRead(instruction, 4, addressWidth, 0, result)) return false;
            Emit(result, VM_UOP_DUP, {}, instruction.rva);
            Emit(result, VM_UOP_LOAD, {addressWidth}, instruction.rva);
            Emit(result, VM_UOP_STORE_TEMP, {0}, instruction.rva);
            Emit(result, VM_UOP_PUSH_IMM, {addressWidth, addressWidth}, instruction.rva);
            Emit(result, VM_UOP_ADD, {addressWidth}, instruction.rva);
            if (!EmitRegisterWrite(instruction, 4, addressWidth, 0, false, result)) return false;
            Emit(result, VM_UOP_LOAD_TEMP, {0}, instruction.rva);
            return EmitRegisterWrite(instruction, 5, addressWidth, 0, false, result);
        case InstructionMnemonic::SignExtendAccumulator:
            if (!EmitRegisterRead(instruction, 0, width, 0, result)) return false;
            Emit(result, VM_UOP_PUSH_IMM, {width * 8u - 1u, 1}, instruction.rva);
            Emit(result, VM_UOP_SAR, {width}, instruction.rva);
            return EmitRegisterWrite(instruction, 2, width, 0, width == 4u, result);
        case InstructionMnemonic::ExtendAccumulator: {
            const uint8_t sourceWidth = width / 2u;
            if (sourceWidth == 0 || !EmitRegisterRead(instruction, 0, sourceWidth, 0, result)) return false;
            Emit(result, VM_UOP_SIGN_EXTEND, {sourceWidth, width}, instruction.rva);
            return EmitRegisterWrite(instruction, 0, width, 0, width == 4u, result);
        }
        case InstructionMnemonic::Clc:
        case InstructionMnemonic::Stc:
        case InstructionMnemonic::Cmc:
            Emit(result, VM_UOP_FLAGS_UPDATE,
                {static_cast<uint64_t>(instruction.mnemonic == InstructionMnemonic::Clc ?
                    VM_FLAG_UPDATE_CLEAR : (instruction.mnemonic == InstructionMnemonic::Stc ?
                    VM_FLAG_UPDATE_SET : VM_FLAG_UPDATE_TOGGLE)),
                 VM_FLAG_CF}, instruction.rva);
            return true;
        case InstructionMnemonic::Lahf:
            Emit(result, VM_UOP_FLAGS_PACK_AH, {}, instruction.rva);
            return EmitRegisterWrite(instruction, 0, 1, 8, false, result);
        case InstructionMnemonic::Sahf:
            if (!EmitRegisterRead(instruction, 0, 1, 8, result)) return false;
            Emit(result, VM_UOP_FLAGS_UNPACK_AH, {}, instruction.rva);
            return true;
        default:
            return FailInstruction(instruction, "implicit scalar instruction has no micro lowering");
    }
}

uint8_t Translator::SelectBridgeHiddenRegister(const InstructionIR& instruction) {
    std::array<bool, 16> used{};
    for (const auto& operand : instruction.operands) {
        if (operand.type == OperandType::Register) {
            if (operand.regInfo.registerClass == RegisterCategory::GeneralPurpose && operand.regInfo.family < 16) {
                used[operand.regInfo.family] = true;
            }
        } else if (operand.type == OperandType::Memory) {
            if (operand.memory.hasBase && operand.memory.baseInfo.family < 16) used[operand.memory.baseInfo.family] = true;
            if (operand.memory.hasIndex && operand.memory.indexInfo.family < 16) used[operand.memory.indexInfo.family] = true;
        }
    }
    static constexpr uint8_t x64Candidates[] = {11, 10, 9, 8, 2, 1, 0};
    static constexpr uint8_t x86Candidates[] = {2, 1, 0};
    const uint8_t* candidates = instruction.machineMode == MachineMode::X64 ? x64Candidates : x86Candidates;
    const size_t count = instruction.machineMode == MachineMode::X64 ?
        std::size(x64Candidates) : std::size(x86Candidates);
    for (size_t i = 0; i < count; ++i) if (!used[candidates[i]]) return candidates[i];
    return 0xFF;
}

bool Translator::LowerExtendedBridge(const InstructionIR& instruction, TranslationResult& result) {
    const bool x87 = instruction.instructionSet == InstructionSetClass::X87 ||
        instruction.mnemonic == InstructionMnemonic::FloatingPoint;
    const bool avx = instruction.instructionSet == InstructionSetClass::Avx;
    if ((x87 && !m_config.enableX87Bridge) || (!x87 && !m_config.enableSimdBridge)) {
        return FailInstruction(instruction, x87 ?
            "x87 bridge disabled" : "SIMD bridge disabled");
    }
    if (instruction.flagsRead != 0 || instruction.flagsWritten != 0 ||
        instruction.flagsUndefined != 0) {
        return FailInstruction(instruction,
            "extended native bridge reads or writes flags; flag state must stay inside VM");
    }
    if (instruction.instructionSet == InstructionSetClass::Avx512 ||
        instruction.encoding == InstructionEncoding::Evex ||
        instruction.encoding == InstructionEncoding::Mvex ||
        instruction.instructionSet == InstructionSetClass::UnsupportedExtended ||
        instruction.encoding == InstructionEncoding::Xop ||
        instruction.encoding == InstructionEncoding::ThreeDNow ||
        instruction.hasLockPrefix || instruction.IsBranch() || instruction.IsCall() ||
        instruction.IsReturn() || instruction.length == 0 ||
        instruction.length > instruction.rawBytes.size()) {
        return FailInstruction(instruction, "extended instruction is outside safe bridge contract");
    }
    bool hasExtended = x87 || avx || instruction.instructionSet == InstructionSetClass::Sse;
    for (const auto& operand : instruction.operands) {
        if (operand.type == OperandType::Register) {
            hasExtended = hasExtended || IsExtendedRegisterClass(operand.regInfo.registerClass);
            if (operand.regInfo.registerClass == RegisterCategory::GeneralPurpose && operand.regInfo.family < 16 &&
                (operand.regInfo.family == 4 || operand.regInfo.family == 5) && OperandWrites(operand.action)) {
                return FailInstruction(instruction, "bridge cannot write stack/frame pointer");
            }
        } else if (operand.type == OperandType::Pointer) {
            return FailInstruction(instruction, "far pointer is not bridgeable");
        }
    }
    if (!hasExtended) return FailInstruction(instruction, "bridge contains no extended-state semantics");
    const uint8_t hidden = SelectBridgeHiddenRegister(instruction);
    if (hidden == 0xFF) return FailInstruction(instruction, "bridge has no hidden state register");

    const uint32_t index = static_cast<uint32_t>(result.instructions.size());
    const uint32_t aux = hidden | (avx ? VM_MICRO_BRIDGE_AVX : 0u) |
        (x87 ? VM_MICRO_BRIDGE_X87 : 0u);
    Emit(result, VM_UOP_BRIDGE_EXTENDED, {0, aux, instruction.rva}, instruction.rva);
    VMBridgeRequest request{};
    request.microOpIndex = index;
    request.functionRVA = m_currentFunctionRva;
    request.instruction = instruction;
    request.hiddenNativeRegister = hidden;
    request.usesAvx = avx;
    request.usesX87 = x87;
    result.bridgeRequests.push_back(std::move(request));
    result.usesSimd = result.usesSimd || !x87;
    result.usesAvx = result.usesAvx || avx;
    result.usesX87 = result.usesX87 || x87;
    return true;
}

bool Translator::LowerInstruction(const InstructionIR& instruction, TranslationResult& result) {
    EmitHeavyPrefix(instruction, result);
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Nop:
            if (m_config.density == VMMicroDensity::Light) {
                Emit(result, VM_UOP_PUSH_IMM, {Mix64(m_config.buildSeed ^ instruction.address), 1}, instruction.rva);
                Emit(result, VM_UOP_STORE_TEMP, {31}, instruction.rva);
                Emit(result, VM_UOP_LOAD_TEMP, {31}, instruction.rva);
                Emit(result, VM_UOP_DROP, {}, instruction.rva);
            }
            return true;
        case InstructionMnemonic::Mov:
        case InstructionMnemonic::Lea:
        case InstructionMnemonic::Xchg: return LowerMove(instruction, result);
        case InstructionMnemonic::Movzx:
        case InstructionMnemonic::Movsx:
        case InstructionMnemonic::Movsxd: return LowerMoveExtend(instruction, result);
        case InstructionMnemonic::Add: case InstructionMnemonic::Adc:
        case InstructionMnemonic::Sub: case InstructionMnemonic::Sbb:
        case InstructionMnemonic::And: case InstructionMnemonic::Or:
        case InstructionMnemonic::Xor: case InstructionMnemonic::Cmp:
        case InstructionMnemonic::Test: return LowerBinary(instruction, result);
        case InstructionMnemonic::Not: case InstructionMnemonic::Neg:
        case InstructionMnemonic::Inc: case InstructionMnemonic::Dec:
        case InstructionMnemonic::Bswap:
            if (instruction.mnemonic == InstructionMnemonic::Bswap) {
                const auto operands = SemanticOperands(instruction);
                if (operands.size() != 1 || !IsRegister(operands[0])) return FailInstruction(instruction, "BSWAP requires GPR");
                const uint8_t width = WidthBytes(operands[0]->width);
                if ((width != 4 && width != 8) || !EmitRead(instruction, *operands[0], result, width)) return false;
                Emit(result, VM_UOP_BSWAP, {width}, instruction.rva);
                return EmitWrite(instruction, *operands[0], result, width);
            }
            return LowerUnary(instruction, result);
        case InstructionMnemonic::Shl: case InstructionMnemonic::Sal:
        case InstructionMnemonic::Shr: case InstructionMnemonic::Sar:
        case InstructionMnemonic::Rol: case InstructionMnemonic::Ror:
            return LowerShiftRotate(instruction, result);
        case InstructionMnemonic::Mul: case InstructionMnemonic::Imul:
        case InstructionMnemonic::Div: case InstructionMnemonic::Idiv:
            return LowerMultiplyDivide(instruction, result);
        case InstructionMnemonic::Push: case InstructionMnemonic::Pop:
            return LowerStack(instruction, result);
        case InstructionMnemonic::PushFlags: case InstructionMnemonic::PopFlags:
        case InstructionMnemonic::Leave:
        case InstructionMnemonic::SignExtendAccumulator:
        case InstructionMnemonic::ExtendAccumulator:
        case InstructionMnemonic::Clc: case InstructionMnemonic::Stc:
        case InstructionMnemonic::Cmc: case InstructionMnemonic::Lahf:
        case InstructionMnemonic::Sahf: return LowerImplicitScalar(instruction, result);
        case InstructionMnemonic::Bt: case InstructionMnemonic::Bts:
        case InstructionMnemonic::Btr: return LowerBitOperation(instruction, result);
        case InstructionMnemonic::Jmp: case InstructionMnemonic::Jo:
        case InstructionMnemonic::Jno: case InstructionMnemonic::Jb:
        case InstructionMnemonic::Jae: case InstructionMnemonic::Jz:
        case InstructionMnemonic::Jnz: case InstructionMnemonic::Jbe:
        case InstructionMnemonic::Ja: case InstructionMnemonic::Js:
        case InstructionMnemonic::Jns: case InstructionMnemonic::Jp:
        case InstructionMnemonic::Jnp: case InstructionMnemonic::Jl:
        case InstructionMnemonic::Jge: case InstructionMnemonic::Jle:
        case InstructionMnemonic::Jg: return LowerBranch(instruction, result);
        case InstructionMnemonic::Call: return LowerCall(instruction, result);
        case InstructionMnemonic::Ret: return LowerRet(instruction, result);
        case InstructionMnemonic::Cmov: case InstructionMnemonic::Setcc:
            return LowerConditionalData(instruction, result);
        case InstructionMnemonic::Simd:
        case InstructionMnemonic::FloatingPoint:
            return LowerExtendedBridge(instruction, result);
        case InstructionMnemonic::Int3:
            // Both encodings (0xCC and CD 03) decode to the same mnemonic;
            // VM_UOP_INT3 has no operands and no stack effect (VMSchema:
            // Special/0/0), and its synthesized handler executes a real
            // trap inline (see EmitBusinessCoreVariant's VM_UOP_INT3 case in
            // vm_handler_semantic_codegen.cpp) rather than simulating one.
            //
            // AnalyzeFunctionRange (disassembler.cpp) treats any Interrupt-
            // category instruction as a function boundary exactly like RET
            // or an indirect branch and never decodes anything past it, so
            // this is always the function's final instruction. VM_UOP_INT3
            // itself is schema-non-terminal (descriptor.terminal == false,
            // to keep VMSchema::ValidateStream's fallthrough/reachability
            // rules the same as every other opcode), so synthesize the same
            // "materialize lazy flags, then return" terminal LowerRet emits
            // for a real RET immediately after it -- this both gives the
            // bytecode stream a real terminal to reach and defines what
            // happens if the hardware trap is ever survived/resumed rather
            // than ending the process. Matches the INT3-then-RET shape this
            // opcode's own tests already rely on (see
            // ExecuteExternalSemanticVariantCases in
            // test_vm_handler_synthesis.cpp).
            Emit(result, VM_UOP_INT3, {}, instruction.rva);
            Emit(result, VM_UOP_FLAGS_MATERIALIZE,
                {VM_FLAG_ARCHITECTURAL_MASK}, instruction.rva);
            Emit(result, VM_UOP_RET, {0}, instruction.rva);
            return true;
        default:
            return FailInstruction(instruction, "instruction has no production micro-op lowering");
    }
}

bool Translator::FinalizeProgram(TranslationResult& result) {
    result.microOffsets.clear();
    result.microOffsets.reserve(result.instructions.size());
    uint32_t offset = 0;
    for (const auto& instruction : result.instructions) {
        result.microOffsets.push_back(offset);
        uint32_t encodedSize = 0;
        std::string reason;
        if (!VMSchema::EncodedSize(instruction, result.operandCodec, encodedSize, reason) ||
            encodedSize > std::numeric_limits<uint32_t>::max() - offset) {
            return false;
        }
        offset += encodedSize;
    }
    for (auto& address : result.addrMap) {
        if (address.second >= result.microOffsets.size()) return false;
        address.second = result.microOffsets[address.second];
    }
    for (const auto& fixup : m_branchFixups) {
        if (fixup.microOpIndex >= result.instructions.size()) return false;
        const auto target = result.addrMap.find(fixup.targetRva);
        if (target == result.addrMap.end()) return false;
        result.instructions[fixup.microOpIndex].operands[fixup.operandIndex] = target->second;
    }
    result.totalSize = offset;
    result.microOpCount = static_cast<uint32_t>(result.instructions.size());
    result.microOpRatio = result.nativeInstructionCount == 0 ? 0.0 :
        static_cast<double>(result.microOpCount) /
        static_cast<double>(result.nativeInstructionCount);
    if (result.density == VMMicroDensity::Heavy &&
        result.microOpRatio < static_cast<double>(m_config.heavyMinimumRatio)) {
        return false;
    }
    result.bytecode = GenerateBytecode(result);
    return !result.bytecode.empty() && result.bytecode.size() == result.totalSize;
}

bool Translator::ValidateFlagDataflow(
    const Function& function,
    uint32_t& terminalReturnStackCleanup,
    uint64_t& observableRflagsMask)
{
    if (function.blocks.empty()) return false;
    terminalReturnStackCleanup = 0;
    observableRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
    bool sawTerminalReturn = false;
    uint64_t terminalUndefined = 0;
    std::map<uint64_t, const InstructionIR*> instructions;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) instructions[instruction.address] = &instruction;
    }
    if (instructions.find(function.entryAddress) == instructions.end()) return false;
    struct FlowKey {
        uint64_t address;
        std::vector<uint64_t> returns;
        bool operator<(const FlowKey& other) const {
            return address != other.address ? address < other.address : returns < other.returns;
        }
    };
    struct FlowState {
        FlowKey key;
        uint64_t mayUndefined;
        uint64_t mustUndefined;
    };
    struct FlowLattice {
        uint64_t mayUndefined;
        uint64_t mustUndefined;
    };
    std::vector<FlowState> worklist = {
        {{function.entryAddress, {}}, 0, 0}};
    std::map<FlowKey, FlowLattice> merged;
    merged.emplace(worklist.front().key, FlowLattice{0, 0});
    auto enqueue = [&](const FlowKey& key, uint64_t mayUndefined,
                       uint64_t mustUndefined) {
        auto found = merged.find(key);
        if (found == merged.end()) {
            merged.emplace(key, FlowLattice{mayUndefined, mustUndefined});
            worklist.push_back({key, mayUndefined, mustUndefined});
        } else {
            const uint64_t mergedMay =
                found->second.mayUndefined | mayUndefined;
            const uint64_t mergedMust =
                found->second.mustUndefined & mustUndefined;
            if (mergedMay != found->second.mayUndefined ||
                mergedMust != found->second.mustUndefined) {
                found->second = {mergedMay, mergedMust};
                worklist.push_back({key, mergedMay, mergedMust});
            }
        }
    };
    while (!worklist.empty()) {
        FlowState state = std::move(worklist.back());
        worklist.pop_back();
        const auto found = instructions.find(state.key.address);
        if (found == instructions.end()) return false;
        const InstructionIR& instruction = *found->second;
        uint64_t mayUndefined = state.mayUndefined;
        uint64_t mustUndefined = state.mustUndefined;
        if ((instruction.flagsRead & mayUndefined) != 0) {
            return FailInstruction(instruction, "instruction reads flags undefined on a reachable path");
        }
        const bool isShift =
            instruction.mnemonic == InstructionMnemonic::Shl ||
            instruction.mnemonic == InstructionMnemonic::Sal ||
            instruction.mnemonic == InstructionMnemonic::Shr ||
            instruction.mnemonic == InstructionMnemonic::Sar;
        const bool isRotate =
            instruction.mnemonic == InstructionMnemonic::Rol ||
            instruction.mnemonic == InstructionMnemonic::Ror;
        if (isShift || isRotate) {
            const auto operands = SemanticOperands(instruction);
            if (operands.size() != 2u) {
                return FailInstruction(instruction,
                    "shift/rotate flag dataflow lacks its count operand");
            }
            const uint8_t width = WidthBytes(operands[0]->width);
            if (width != 1u && width != 2u && width != 4u && width != 8u) {
                return FailInstruction(instruction,
                    "shift/rotate flag dataflow has an invalid width");
            }
            const uint64_t nonStatusWritten =
                instruction.flagsWritten & ~static_cast<uint64_t>(VM_FLAG_STATUS_MASK);
            const uint64_t nonStatusUndefined =
                instruction.flagsUndefined & ~static_cast<uint64_t>(VM_FLAG_STATUS_MASK);
            mayUndefined &= ~(nonStatusWritten | nonStatusUndefined);
            mayUndefined |= nonStatusUndefined;
            mustUndefined &= ~(nonStatusWritten | nonStatusUndefined);
            mustUndefined |= nonStatusUndefined;

            if (IsImmediate(operands[1])) {
                const unsigned bits = width * 8u;
                const unsigned countMask = width == 8u ? 63u : 31u;
                const unsigned count = static_cast<unsigned>(
                    operands[1]->immediate) & countMask;
                if (count != 0u) {
                    uint64_t written = 0;
                    uint64_t undefined = 0;
                    if (isShift) {
                        written = VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF;
                        undefined = VM_FLAG_AF;
                        if (count < bits) written |= VM_FLAG_CF;
                        else undefined |= VM_FLAG_CF;
                    } else {
                        written = VM_FLAG_CF;
                    }
                    if (count == 1u) written |= VM_FLAG_OF;
                    else undefined |= VM_FLAG_OF;
                    mayUndefined &= ~(written | undefined);
                    mayUndefined |= undefined;
                    mustUndefined &= ~(written | undefined);
                    mustUndefined |= undefined;
                }
            } else if (IsRegister(operands[1])) {
                // CL can select every masked count at run time.  A zero count
                // preserves incoming flags, while non-zero counts define some
                // flags and can leave others undefined.  Keep incoming
                // may-undefined state for conditionally defined bits and add
                // every bit that is undefined for at least one possible count.
                if (isShift) {
                    if (width < 4u) mayUndefined |= VM_FLAG_CF;
                    mayUndefined |= VM_FLAG_AF | VM_FLAG_OF;
                    mustUndefined &= ~(static_cast<uint64_t>(VM_FLAG_CF) |
                        VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF);
                } else {
                    mayUndefined |= VM_FLAG_OF;
                    mustUndefined &= ~(static_cast<uint64_t>(VM_FLAG_CF) |
                        VM_FLAG_OF);
                }
            } else {
                return FailInstruction(instruction,
                    "shift/rotate flag dataflow count is not scalar");
            }
        } else {
            mayUndefined &= ~(instruction.flagsWritten | instruction.flagsUndefined);
            mayUndefined |= instruction.flagsUndefined;
            mustUndefined &= ~(instruction.flagsWritten | instruction.flagsUndefined);
            mustUndefined |= instruction.flagsUndefined;
        }
        const uint64_t fallthrough = instruction.address + instruction.length;
        if (instruction.IsReturn()) {
            if (!state.key.returns.empty()) {
                FlowKey next = state.key;
                next.address = next.returns.back();
                next.returns.pop_back();
                enqueue(next, mayUndefined, mustUndefined);
            } else {
                const auto operands = SemanticOperands(instruction);
                uint32_t cleanup = 0;
                if (operands.size() > 1 || (!operands.empty() &&
                    (!IsImmediate(operands[0]) || operands[0]->immediate > 0xFFFFu))) {
                    return FailInstruction(instruction, "terminal RET cleanup is invalid");
                }
                if (!operands.empty()) cleanup = static_cast<uint32_t>(operands[0]->immediate);
                // Keep a conservative function-wide mask for metadata and
                // identity. The model/native gates additionally execute the
                // oracle for each concrete corpus case, so a flag defined on
                // that actual path is still compared even when another path
                // leaves it undefined.
                terminalUndefined |=
                    mayUndefined & VM_FLAG_ARCHITECTURAL_MASK;
                if (!sawTerminalReturn) {
                    terminalReturnStackCleanup = cleanup;
                    sawTerminalReturn = true;
                } else if (terminalReturnStackCleanup != cleanup) {
                    return FailInstruction(instruction, "terminal RET paths use inconsistent cleanup");
                }
            }
        } else if (instruction.IsInterrupt()) {
            // AnalyzeFunctionRange (disassembler.cpp) already treats any
            // Interrupt-category instruction (INT3/INT n) as a function
            // boundary exactly like RET or an indirect branch: it
            // deliberately never decodes anything past a real trap, since it
            // cannot know what follows one. So this is always the last
            // decoded instruction on its path -- mirror that here as an
            // alternate terminal, with 0 cleanup (INT3 has no cleanup
            // operand and its VM_UOP_INT3 handler never touches the guest
            // stack).
            //
            // Reaching it from inside a virtualized internal CALL is
            // different from RET, though: the real hardware trap bypasses
            // that internal call-stack bookkeeping entirely rather than
            // "returning" through it, so there is no provable resumption
            // point to enqueue. Fail closed instead of guessing.
            if (!state.key.returns.empty()) {
                return FailInstruction(instruction,
                    "INT3 inside a virtualized internal CALL has no provable termination path");
            }
            terminalUndefined |= mayUndefined & VM_FLAG_ARCHITECTURAL_MASK;
            if (!sawTerminalReturn) {
                terminalReturnStackCleanup = 0;
                sawTerminalReturn = true;
            } else if (terminalReturnStackCleanup != 0) {
                return FailInstruction(instruction, "terminal RET paths use inconsistent cleanup");
            }
        } else if (instruction.IsCall()) {
            FlowKey next = state.key;
            if (!instruction.isIndirectBranch && instruction.hasBranchTarget &&
                instructions.find(instruction.branchTargetRVA) != instructions.end()) {
                if (next.returns.size() >= VM_MAX_INTERNAL_CALL_DEPTH) {
                    return FailInstruction(instruction, "internal CALL depth exceeds VM bound");
                }
                next.returns.push_back(fallthrough);
                next.address = instruction.branchTargetRVA;
            } else next.address = fallthrough;
            enqueue(next, mayUndefined, mustUndefined);
        } else if (instruction.IsBranch()) {
            if (instruction.isIndirectBranch || !instruction.hasBranchTarget) {
                return FailInstruction(instruction, "branch is not statically resolved");
            }
            FlowKey branch = state.key;
            branch.address = instruction.branchTargetRVA;
            enqueue(branch, mayUndefined, mustUndefined);
            if (instruction.IsConditionalBranch()) {
                FlowKey next = state.key;
                next.address = fallthrough;
                enqueue(next, mayUndefined, mustUndefined);
            }
        } else {
            FlowKey next = state.key;
            next.address = fallthrough;
            enqueue(next, mayUndefined, mustUndefined);
        }
        if (merged.size() > 1000000u) return FailInstruction(instruction, "flag CFG state bound exceeded");
    }
    if (sawTerminalReturn) {
        observableRflagsMask = static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK) &
            ~terminalUndefined;
    }
    return sawTerminalReturn;
}

TranslationResult Translator::TranslateFunction(const Function& function) {
    TranslationResult result{};
    result.registerCount = m_config.virtualRegisterCount;
    result.density = m_config.density;
    m_lastFailures.clear();
    m_branchFixups.clear();
    if (!m_initialized || function.blocks.empty() || function.size == 0 ||
        m_opcodeMap.empty() || m_registerMap.size() < 16) {
        result.failures = m_lastFailures;
        return result;
    }
    std::array<bool, 32> usedRegisters{};
    for (uint8_t family = 0; family < 16; ++family) {
        const uint8_t mapped = MapRegisterFamily(family);
        if (mapped == VM_REG_INVALID || usedRegisters[mapped]) {
            TranslationFailure failure{};
            failure.address = function.entryAddress;
            failure.mnemonic = "register_map";
            failure.reason = "native-to-virtual register map is missing or non-injective";
            m_lastFailures.push_back(std::move(failure));
            result.failures = m_lastFailures;
            return result;
        }
        usedRegisters[mapped] = true;
    }
    bool modeKnown = false;
    MachineMode functionMode = MachineMode::X86;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (!modeKnown) {
                functionMode = instruction.machineMode;
                modeKnown = true;
            } else if (functionMode != instruction.machineMode) {
                TranslationFailure failure{};
                failure.address = instruction.address;
                failure.mnemonic = "machine_mode";
                failure.reason = "function mixes x86 and x64 instruction modes";
                m_lastFailures.push_back(std::move(failure));
                result.failures = m_lastFailures;
                return result;
            }
        }
    }
    if (!modeKnown) {
        result.failures = m_lastFailures;
        return result;
    }
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool runtimeSupported = functionMode == MachineMode::X64
            ? descriptor.runtimeSupportedX64
            : descriptor.runtimeSupportedX86;
        if (descriptor.opcode == VM_UOP_TRAP || !runtimeSupported) continue;
        if (m_opcodeMap.find(static_cast<uint8_t>(descriptor.opcode)) == m_opcodeMap.end()) {
            TranslationFailure failure{};
            failure.address = function.entryAddress;
            failure.mnemonic = descriptor.name;
            failure.reason = "micro semantic has no per-build opcode map entry";
            m_lastFailures.push_back(std::move(failure));
            result.failures = m_lastFailures;
            return result;
        }
    }

    m_functionStart = function.entryAddress;
    m_functionEnd = function.entryAddress + function.size;
    m_currentFunctionRva = static_cast<uint32_t>(function.entryAddress);
    result.operandCodec = VMSchema::DeriveOperandCodec(m_config.buildSeed, m_currentFunctionRva);
    if (!ValidateFlagDataflow(function, result.returnStackCleanup,
            result.observableRflagsMask)) {
        result.failures = m_lastFailures;
        return result;
    }
    std::vector<const InstructionIR*> ordered;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) ordered.push_back(&instruction);
    }
    std::sort(ordered.begin(), ordered.end(), [](const InstructionIR* a, const InstructionIR* b) {
        return a->address < b->address;
    });
    ordered.erase(std::unique(ordered.begin(), ordered.end(), [](const InstructionIR* a, const InstructionIR* b) {
        return a->address == b->address;
    }), ordered.end());
    result.nativeInstructionCount = static_cast<uint32_t>(ordered.size());
    for (const InstructionIR* instruction : ordered) {
        if (!instruction || instruction->length == 0 ||
            result.instructions.size() > std::numeric_limits<uint32_t>::max()) {
            result.failures = m_lastFailures;
            return result;
        }
        const uint32_t firstMicro = static_cast<uint32_t>(result.instructions.size());
        result.addrMap[instruction->address] = firstMicro;
        result.addrMap[instruction->rva] = firstMicro;
        if (!LowerInstruction(*instruction, result)) {
            result.failures = m_lastFailures;
            return result;
        }
    }
    if (!FinalizeProgram(result)) {
        TranslationFailure failure{};
        failure.address = function.entryAddress;
        failure.mnemonic = "micro_finalize";
        failure.reason = "variable-length layout, branch boundary, codec, or heavy-ratio gate failed";
        m_lastFailures.push_back(std::move(failure));
        result.failures = m_lastFailures;
        return result;
    }
    result.success = true;
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
    if (result.instructions.empty()) return {};
    std::vector<uint8_t> bytecode;
    bytecode.reserve(result.totalSize);
    for (const auto& instruction : result.instructions) {
        std::string reason;
        if (!VMSchema::ValidateInstruction(instruction, result.registerCount, reason) ||
            !VMSchema::Encode(instruction, m_opcodeMap, result.operandCodec, bytecode, reason)) {
            return {};
        }
    }
    std::array<uint8_t, 256> reverse{};
    reverse.fill(0xFFu);
    for (const auto& mapping : m_opcodeMap) {
        if (reverse[mapping.second] != 0xFFu) return {};
        reverse[mapping.second] = mapping.first;
    }
    const auto validation = VMSchema::ValidateStream(bytecode.data(), bytecode.size(),
        reverse.data(), result.operandCodec, result.registerCount);
    return validation.success ? bytecode : std::vector<uint8_t>{};
}

namespace {

enum class OracleFault : uint8_t { None, DivideError, Unsupported, Memory, ControlFlow, Breakpoint };

struct OracleState {
    std::array<uint64_t, 16> gpr{};
    std::array<uint64_t, VM_MAX_INTERNAL_CALL_DEPTH> callStack{};
    uint32_t callDepth = 0;
    uint64_t rflags = 0;
    uint64_t undefinedRflagsMask = 0;
    uint64_t ip = 0;
    bool finished = false;
    OracleFault fault = OracleFault::None;
};

uint64_t NextCorpusValue(uint64_t& state) {
    state ^= state << 13u;
    state ^= state >> 7u;
    state ^= state << 17u;
    return state;
}

uint64_t OracleTruncate(uint64_t value, uint8_t width) {
    return value & WidthMask(width);
}

uint64_t OracleSignExtend(uint64_t value, uint8_t width) {
    const uint64_t sign = 1ULL << (width * 8u - 1u);
    value &= WidthMask(width);
    return (value ^ sign) - sign;
}

bool OracleParity(uint8_t value) {
    value ^= static_cast<uint8_t>(value >> 4u);
    value &= 0x0Fu;
    return ((0x6996u >> value) & 1u) == 0u;
}

void OracleSetFlag(uint64_t& flags, uint32_t flag, bool set) {
    if (set) flags |= flag;
    else flags &= ~static_cast<uint64_t>(flag);
}

void OracleResultFlags(uint64_t& flags, uint64_t result, uint8_t width) {
    result &= WidthMask(width);
    OracleSetFlag(flags, VM_FLAG_ZF, result == 0);
    OracleSetFlag(flags, VM_FLAG_SF, (result & (1ULL << (width * 8u - 1u))) != 0);
    OracleSetFlag(flags, VM_FLAG_PF, OracleParity(static_cast<uint8_t>(result)));
}

uint64_t OracleAddSub(
    OracleState& state,
    uint64_t a,
    uint64_t b,
    uint8_t width,
    bool subtract,
    bool carry)
{
    const uint64_t mask = WidthMask(width);
    const uint64_t sign = 1ULL << (width * 8u - 1u);
    a &= mask;
    b &= mask;
    const uint64_t carryValue = carry ? 1u : 0u;
    const uint64_t result = subtract ?
        ((a - b - carryValue) & mask) : ((a + b + carryValue) & mask);
    const bool cf = subtract ?
        (a < b || (carry && a == b)) :
        (result < a || (carry && result == a));
    OracleSetFlag(state.rflags, VM_FLAG_CF, cf);
    OracleSetFlag(state.rflags, VM_FLAG_OF, subtract ?
        (((a ^ b) & (a ^ result) & sign) != 0) :
        ((~(a ^ b) & (a ^ result) & sign) != 0));
    OracleSetFlag(state.rflags, VM_FLAG_AF, ((a ^ b ^ result) & 0x10u) != 0);
    OracleResultFlags(state.rflags, result, width);
    return result;
}

bool OracleCondition(uint64_t flags, VM_CONDITION condition) {
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
        case VM_CONDITION_LE: return zf || sf != of;
        case VM_CONDITION_G: return !zf && sf == of;
        default: return false;
    }
}

bool OracleMapCondition(BranchKind kind, VM_CONDITION& condition) {
    switch (kind) {
        case BranchKind::Overflow: condition = VM_CONDITION_O; return true;
        case BranchKind::NotOverflow: condition = VM_CONDITION_NO; return true;
        case BranchKind::Below: condition = VM_CONDITION_B; return true;
        case BranchKind::AboveOrEqual: condition = VM_CONDITION_AE; return true;
        case BranchKind::Equal: condition = VM_CONDITION_E; return true;
        case BranchKind::NotEqual: condition = VM_CONDITION_NE; return true;
        case BranchKind::BelowOrEqual: condition = VM_CONDITION_BE; return true;
        case BranchKind::Above: condition = VM_CONDITION_A; return true;
        case BranchKind::Sign: condition = VM_CONDITION_S; return true;
        case BranchKind::NotSign: condition = VM_CONDITION_NS; return true;
        case BranchKind::Parity: condition = VM_CONDITION_P; return true;
        case BranchKind::NotParity: condition = VM_CONDITION_NP; return true;
        case BranchKind::Less: condition = VM_CONDITION_L; return true;
        case BranchKind::GreaterOrEqual: condition = VM_CONDITION_GE; return true;
        case BranchKind::LessOrEqual: condition = VM_CONDITION_LE; return true;
        case BranchKind::Greater: condition = VM_CONDITION_G; return true;
        default: return false;
    }
}

bool OracleMemoryRange(
    uint64_t address,
    uint8_t width,
    uint64_t memoryBase,
    const std::vector<uint8_t>& memory,
    size_t& offset)
{
    if (address < memoryBase) return false;
    const uint64_t relative = address - memoryBase;
    if (relative > memory.size() || width > memory.size() - static_cast<size_t>(relative)) return false;
    offset = static_cast<size_t>(relative);
    return true;
}

bool OracleAddress(
    const InstructionIR& instruction,
    const OperandIR& operand,
    const OracleState& state,
    uint64_t imageBase,
    uint64_t& address)
{
    if (operand.type != OperandType::Memory) return false;
    const auto& memory = operand.memory;
    if (memory.segment != RegisterId::None && memory.segment != RegisterId::DS &&
        memory.segment != RegisterId::SS) return false;
    if (memory.isImageAddress || memory.isRipRelative) {
        const uint64_t untruncated = imageBase + memory.resolvedRVA;
        if (untruncated < imageBase) return false;
        address = OracleTruncate(untruncated, AddressWidth(instruction));
        return true;
    }
    uint64_t value = 0;
    if (memory.hasBase) {
        if (memory.baseInfo.registerClass != RegisterCategory::GeneralPurpose ||
            memory.baseInfo.family >= state.gpr.size()) return false;
        value = state.gpr[memory.baseInfo.family];
    }
    if (memory.hasIndex) {
        if (memory.indexInfo.registerClass != RegisterCategory::GeneralPurpose ||
            memory.indexInfo.family >= state.gpr.size() ||
            !(memory.scale == 1 || memory.scale == 2 || memory.scale == 4 || memory.scale == 8)) return false;
        value += state.gpr[memory.indexInfo.family] * memory.scale;
    }
    value += static_cast<uint64_t>(memory.displacement);
    address = OracleTruncate(value, AddressWidth(instruction));
    return true;
}

bool OracleReadOperand(
    const InstructionIR& instruction,
    const OperandIR& operand,
    uint8_t width,
    const OracleState& state,
    uint64_t imageBase,
    uint64_t memoryBase,
    const std::vector<uint8_t>& memory,
    uint64_t& value)
{
    if (operand.type == OperandType::Register &&
        operand.regInfo.registerClass == RegisterCategory::GeneralPurpose &&
        operand.regInfo.family < state.gpr.size()) {
        value = OracleTruncate(state.gpr[operand.regInfo.family] >>
            operand.regInfo.bitOffset, width);
        return true;
    }
    if (operand.type == OperandType::Immediate) {
        if (operand.immediateIsImageAddress) {
            const uint64_t relocated = imageBase + operand.immediateResolvedRVA;
            if (relocated < imageBase || width != AddressWidth(instruction)) return false;
            value = OracleTruncate(relocated, width);
        } else {
            value = OracleTruncate(operand.immediate, width);
        }
        return true;
    }
    if (operand.type == OperandType::Memory) {
        uint64_t address = 0;
        size_t offset = 0;
        if (!OracleAddress(instruction, operand, state, imageBase, address) ||
            !OracleMemoryRange(address, width, memoryBase, memory, offset)) return false;
        value = 0;
        for (uint8_t i = 0; i < width; ++i) {
            value |= static_cast<uint64_t>(memory[offset + i]) << (i * 8u);
        }
        return true;
    }
    return false;
}

bool OracleWriteOperand(
    const InstructionIR& instruction,
    const OperandIR& operand,
    uint8_t width,
    uint64_t value,
    OracleState& state,
    uint64_t imageBase,
    uint64_t memoryBase,
    std::vector<uint8_t>& memory)
{
    value = OracleTruncate(value, width);
    if (operand.type == OperandType::Register &&
        operand.regInfo.registerClass == RegisterCategory::GeneralPurpose &&
        operand.regInfo.family < state.gpr.size()) {
        uint64_t& target = state.gpr[operand.regInfo.family];
        if (operand.regInfo.zeroExtendsOnWrite) target = value;
        else {
            const uint64_t shiftedMask = WidthMask(width) << operand.regInfo.bitOffset;
            target = (target & ~shiftedMask) | (value << operand.regInfo.bitOffset);
        }
        return true;
    }
    if (operand.type == OperandType::Memory) {
        uint64_t address = 0;
        size_t offset = 0;
        if (!OracleAddress(instruction, operand, state, imageBase, address) ||
            !OracleMemoryRange(address, width, memoryBase, memory, offset)) return false;
        for (uint8_t i = 0; i < width; ++i) {
            memory[offset + i] = static_cast<uint8_t>(value >> (i * 8u));
        }
        return true;
    }
    return false;
}

void OracleMultiply64(uint64_t a, uint64_t b, bool signedMultiply,
    uint64_t& low, uint64_t& high)
{
    const uint64_t a0 = static_cast<uint32_t>(a), a1 = a >> 32u;
    const uint64_t b0 = static_cast<uint32_t>(b), b1 = b >> 32u;
    const uint64_t p00 = a0 * b0, p01 = a0 * b1;
    const uint64_t p10 = a1 * b0, p11 = a1 * b1;
    const uint64_t carry = (p00 >> 32u) + static_cast<uint32_t>(p01) +
        static_cast<uint32_t>(p10);
    low = (carry << 32u) | static_cast<uint32_t>(p00);
    high = p11 + (p01 >> 32u) + (p10 >> 32u) + (carry >> 32u);
    if (signedMultiply) {
        if ((a >> 63u) != 0) high -= b;
        if ((b >> 63u) != 0) high -= a;
    }
}

bool OracleUnsignedDivide128(uint64_t high, uint64_t low, uint64_t divisor,
    uint64_t& quotient, uint64_t& remainder)
{
    if (divisor == 0 || high >= divisor) return false;
    quotient = 0;
    remainder = high;
    for (int bit = 63; bit >= 0; --bit) {
        const bool carry = (remainder >> 63u) != 0;
        remainder = (remainder << 1u) | ((low >> bit) & 1u);
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= 1ULL << bit;
        }
    }
    return true;
}

bool OracleSignedDivide128(uint64_t high, uint64_t low, uint64_t divisor,
    uint64_t& quotient, uint64_t& remainder)
{
    if (divisor == 0) return false;
    const bool dividendNegative = (high >> 63u) != 0;
    const bool divisorNegative = (divisor >> 63u) != 0;
    if (dividendNegative) {
        low = ~low + 1u;
        high = ~high + (low == 0 ? 1u : 0u);
    }
    const uint64_t divisorMagnitude = divisorNegative ? ~divisor + 1u : divisor;
    uint64_t quotientMagnitude = 0, remainderMagnitude = 0;
    if (!OracleUnsignedDivide128(high, low, divisorMagnitude,
            quotientMagnitude, remainderMagnitude)) return false;
    const bool negative = dividendNegative != divisorNegative;
    if ((!negative && quotientMagnitude > INT64_MAX) ||
        (negative && quotientMagnitude > (1ULL << 63u))) return false;
    quotient = negative ? ~quotientMagnitude + 1u : quotientMagnitude;
    remainder = dividendNegative ? ~remainderMagnitude + 1u : remainderMagnitude;
    return true;
}

bool PrepareOracleMemoryRegisters(
    const Function& function,
    OracleState& state,
    uint64_t memoryBase,
    uint32_t memorySize,
    uint32_t imageSize,
    std::string& error)
{
    if (imageSize == 0 || imageSize >= memorySize ||
        memorySize - imageSize < 0x200u) {
        error = "oracle corpus does not contain separate image and stack/scratch regions";
        return false;
    }
    const uint64_t tailBegin = memoryBase + imageSize;
    const uint64_t tailEnd = memoryBase + memorySize;
    const uint64_t scratchEnd = tailBegin + (memorySize - imageSize) / 2u;
    const uint64_t scratchCenter = tailBegin + (scratchEnd - tailBegin) / 2u;
    const uint64_t stackCenter = scratchEnd + (tailEnd - scratchEnd) / 2u;
    state.gpr[4] = stackCenter;
    bool isX64 = false;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            isX64 = isX64 || instruction.machineMode == MachineMode::X64;
            if (instruction.mnemonic == InstructionMnemonic::Leave) {
                state.gpr[5] = stackCenter;
            }
            for (const auto& operand : instruction.operands) {
                if (operand.type != OperandType::Memory) continue;
                const uint8_t width = WidthBytes(operand.memory.width ?
                    operand.memory.width : operand.width);
                if (width == 0 || (operand.memory.isImageAddress || operand.memory.isRipRelative ?
                    operand.memory.resolvedRVA > imageSize - width : false)) {
                    error = "oracle memory operand escapes bounded corpus image";
                    return false;
                }
                if (operand.memory.isImageAddress || operand.memory.isRipRelative) {
                    continue;
                }
                if (operand.memory.hasIndex) {
                    if (operand.memory.indexInfo.family >= 16) {
                        error = "oracle memory index is not a GPR";
                        return false;
                    }
                    if (AddressWidth(instruction) == 4u) {
                        state.gpr[operand.memory.indexInfo.family] &= 0xFFFFFFFF00000000ULL;
                    } else {
                        state.gpr[operand.memory.indexInfo.family] = 0;
                    }
                }
                if (operand.memory.hasBase) {
                    if (operand.memory.baseInfo.family >= 16) {
                        error = "oracle memory base is not a GPR";
                        return false;
                    }
                    const int64_t displacement = operand.memory.displacement;
                    const uint8_t family = operand.memory.baseInfo.family;
                    const bool stackBase = family == 4u || family == 5u;
                    const uint64_t regionBegin = stackBase ? scratchEnd : tailBegin;
                    const uint64_t regionEnd = stackBase ? tailEnd : scratchEnd;
                    const uint64_t selectedCenter = stackBase
                        ? stackCenter : scratchCenter;
                    if ((displacement < 0 &&
                            static_cast<uint64_t>(-(displacement + 1)) + 1u >
                                selectedCenter - regionBegin) ||
                        (displacement >= 0 &&
                            static_cast<uint64_t>(displacement) >
                                regionEnd - selectedCenter) ||
                        (displacement >= 0
                            ? selectedCenter + static_cast<uint64_t>(displacement)
                            : selectedCenter -
                                (static_cast<uint64_t>(-(displacement + 1)) + 1u)) >
                                regionEnd - width) {
                        error = "oracle memory displacement escapes its isolated scratch/stack region";
                        return false;
                    }
                    if (AddressWidth(instruction) == 4u) {
                        state.gpr[operand.memory.baseInfo.family] =
                            (state.gpr[operand.memory.baseInfo.family] & 0xFFFFFFFF00000000ULL) |
                            static_cast<uint32_t>(selectedCenter);
                    } else {
                        state.gpr[operand.memory.baseInfo.family] = selectedCenter;
                    }
                } else if (!operand.memory.isImageAddress && !operand.memory.isRipRelative) {
                    const uint64_t absolute = static_cast<uint64_t>(operand.memory.displacement);
                    if (absolute < memoryBase || absolute > memoryBase + memorySize - width) {
                        error = "oracle absolute memory operand escapes corpus";
                        return false;
                    }
                }
            }
        }
    }
    // Model a real function-entry stack.  Win64 enters at RSP == 8 (mod 16)
    // because the caller aligns before CALL; x86 keeps at least DWORD
    // alignment.  Re-apply this after memory-base preparation because an
    // explicit [rsp+disp] operand may have moved SP to the corpus center.
    if (isX64) {
        state.gpr[4] = (state.gpr[4] & ~0xFULL) + 8u;
    } else {
        state.gpr[4] &= ~0x3ULL;
    }
    return true;
}

bool ExecuteOracle(
    const Function& function,
    OracleState& state,
    uint64_t imageBase,
    uint64_t memoryBase,
    std::vector<uint8_t>& memory,
    uint32_t maxSteps,
    std::string& error)
{
    std::unordered_map<uint64_t, const InstructionIR*> byAddress;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            byAddress[instruction.address] = &instruction;
            byAddress[instruction.rva] = &instruction;
        }
    }
    state.ip = function.entryAddress;
    for (uint32_t step = 0; step < maxSteps && !state.finished; ++step) {
        const auto found = byAddress.find(state.ip);
        if (found == byAddress.end()) {
            state.fault = OracleFault::ControlFlow;
            error = "oracle control flow left a decoded instruction boundary";
            return false;
        }
        const InstructionIR& instruction = *found->second;
        const uint64_t fallthrough = instruction.address + instruction.length;
        const std::vector<const OperandIR*> operands =
            SemanticOperandsForInstruction(instruction);
        auto read = [&](const OperandIR& operand, uint8_t width, uint64_t& value) {
            return OracleReadOperand(instruction, operand, width, state, imageBase,
                memoryBase, memory, value);
        };
        auto write = [&](const OperandIR& operand, uint8_t width, uint64_t value) {
            return OracleWriteOperand(instruction, operand, width, value, state,
                imageBase, memoryBase, memory);
        };
        auto readReg = [&](uint8_t family, uint8_t width, uint8_t bitOffset) {
            return OracleTruncate(state.gpr[family] >> bitOffset, width);
        };
        auto writeReg = [&](uint8_t family, uint8_t width, uint8_t bitOffset,
                            uint64_t value) {
            value = OracleTruncate(value, width);
            if (width == 4u && bitOffset == 0u) {
                state.gpr[family] = value;
            } else {
                const uint64_t mask = WidthMask(width) << bitOffset;
                state.gpr[family] = (state.gpr[family] & ~mask) |
                    (value << bitOffset);
            }
        };
        uint64_t a = 0, b = 0, result = 0;
        // Most instructions have count-independent flag effects and can use
        // the disassembler's conservative metadata verbatim.  Shift/rotate
        // instructions refine these masks below from the concrete masked
        // count: x86 leaves every flag unchanged for count zero, defines OF
        // only for count one, and makes OF undefined for larger counts.
        uint64_t concreteFlagsWritten = instruction.flagsWritten;
        uint64_t concreteFlagsUndefined = instruction.flagsUndefined;
        bool advance = true;
        switch (instruction.mnemonic) {
            case InstructionMnemonic::Nop: break;
            case InstructionMnemonic::Mov:
                if (operands.size() != 2 || !read(*operands[1], WidthBytes(operands[0]->width), a) ||
                    !write(*operands[0], WidthBytes(operands[0]->width), a)) goto unsupported;
                break;
            case InstructionMnemonic::Movzx:
            case InstructionMnemonic::Movsx:
            case InstructionMnemonic::Movsxd: {
                if (operands.size() != 2) goto unsupported;
                const uint8_t sourceWidth = WidthBytes(operands[1]->width);
                const uint8_t destinationWidth = WidthBytes(operands[0]->width);
                if (!read(*operands[1], sourceWidth, a)) goto memory_fault;
                result = instruction.mnemonic == InstructionMnemonic::Movzx ?
                    OracleTruncate(a, sourceWidth) : OracleSignExtend(a, sourceWidth);
                if (!write(*operands[0], destinationWidth, result)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Lea:
                if (operands.size() != 2 || !OracleAddress(instruction, *operands[1], state,
                        imageBase, a) || !write(*operands[0], AddressWidth(instruction), a)) goto unsupported;
                break;
            case InstructionMnemonic::Xchg: {
                if (operands.size() != 2) goto unsupported;
                const uint8_t width = WidthBytes(operands[0]->width);
                if (!read(*operands[0], width, a) || !read(*operands[1], width, b) ||
                    !write(*operands[0], width, b) || !write(*operands[1], width, a)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Add: case InstructionMnemonic::Adc:
            case InstructionMnemonic::Sub: case InstructionMnemonic::Sbb:
            case InstructionMnemonic::And: case InstructionMnemonic::Or:
            case InstructionMnemonic::Xor: case InstructionMnemonic::Cmp:
            case InstructionMnemonic::Test: {
                if (operands.size() != 2) goto unsupported;
                const uint8_t width = WidthBytes(operands[0]->width);
                if (!read(*operands[0], width, a) || !read(*operands[1], width, b)) goto memory_fault;
                const bool carry = (state.rflags & VM_FLAG_CF) != 0;
                if (instruction.mnemonic == InstructionMnemonic::Add ||
                    instruction.mnemonic == InstructionMnemonic::Adc) {
                    result = OracleAddSub(state, a, b, width, false,
                        instruction.mnemonic == InstructionMnemonic::Adc && carry);
                } else if (instruction.mnemonic == InstructionMnemonic::Sub ||
                           instruction.mnemonic == InstructionMnemonic::Sbb ||
                           instruction.mnemonic == InstructionMnemonic::Cmp) {
                    result = OracleAddSub(state, a, b, width, true,
                        instruction.mnemonic == InstructionMnemonic::Sbb && carry);
                } else {
                    result = instruction.mnemonic == InstructionMnemonic::And ||
                        instruction.mnemonic == InstructionMnemonic::Test ? (a & b) :
                        (instruction.mnemonic == InstructionMnemonic::Or ? (a | b) : (a ^ b));
                    result &= WidthMask(width);
                    OracleSetFlag(state.rflags, VM_FLAG_CF, false);
                    OracleSetFlag(state.rflags, VM_FLAG_OF, false);
                    OracleResultFlags(state.rflags, result, width);
                }
                if (instruction.mnemonic != InstructionMnemonic::Cmp &&
                    instruction.mnemonic != InstructionMnemonic::Test &&
                    !write(*operands[0], width, result)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Not: case InstructionMnemonic::Neg:
            case InstructionMnemonic::Inc: case InstructionMnemonic::Dec: {
                if (operands.size() != 1) goto unsupported;
                const uint8_t width = WidthBytes(operands[0]->width);
                if (!read(*operands[0], width, a)) goto memory_fault;
                if (instruction.mnemonic == InstructionMnemonic::Not) result = ~a;
                else if (instruction.mnemonic == InstructionMnemonic::Neg) {
                    result = OracleAddSub(state, 0, a, width, true, false);
                } else {
                    const bool oldCarry = (state.rflags & VM_FLAG_CF) != 0;
                    result = OracleAddSub(state, a, 1, width,
                        instruction.mnemonic == InstructionMnemonic::Dec, false);
                    OracleSetFlag(state.rflags, VM_FLAG_CF, oldCarry);
                }
                if (!write(*operands[0], width, result)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Shl: case InstructionMnemonic::Sal:
            case InstructionMnemonic::Shr: case InstructionMnemonic::Sar:
            case InstructionMnemonic::Rol: case InstructionMnemonic::Ror: {
                if (operands.size() != 2) goto unsupported;
                const uint8_t width = WidthBytes(operands[0]->width);
                if (!read(*operands[0], width, a) || !read(*operands[1], 1, b)) goto memory_fault;
                const unsigned bits = width * 8u;
                const unsigned count = static_cast<unsigned>(b) & (width == 8 ? 63u : 31u);
                if (count == 0) {
                    result = a;
                    concreteFlagsWritten = 0;
                    concreteFlagsUndefined = 0;
                }
                else if (instruction.mnemonic == InstructionMnemonic::Shl ||
                         instruction.mnemonic == InstructionMnemonic::Sal) {
                    concreteFlagsWritten = VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF;
                    concreteFlagsUndefined = VM_FLAG_AF;
                    if (count < bits) concreteFlagsWritten |= VM_FLAG_CF;
                    else concreteFlagsUndefined |= VM_FLAG_CF;
                    if (count == 1u) concreteFlagsWritten |= VM_FLAG_OF;
                    else concreteFlagsUndefined |= VM_FLAG_OF;
                    result = OracleTruncate(a << count, width);
                    OracleSetFlag(state.rflags, VM_FLAG_CF,
                        count < bits && ((a >> (bits - count)) & 1u) != 0);
                    if (count == 1) OracleSetFlag(state.rflags, VM_FLAG_OF,
                        ((result & (1ULL << (bits - 1u))) != 0) != ((state.rflags & VM_FLAG_CF) != 0));
                    else OracleSetFlag(state.rflags, VM_FLAG_OF, false);
                    OracleResultFlags(state.rflags, result, width);
                } else if (instruction.mnemonic == InstructionMnemonic::Shr ||
                           instruction.mnemonic == InstructionMnemonic::Sar) {
                    concreteFlagsWritten = VM_FLAG_PF | VM_FLAG_ZF | VM_FLAG_SF;
                    concreteFlagsUndefined = VM_FLAG_AF;
                    if (count < bits) concreteFlagsWritten |= VM_FLAG_CF;
                    else concreteFlagsUndefined |= VM_FLAG_CF;
                    if (count == 1u) concreteFlagsWritten |= VM_FLAG_OF;
                    else concreteFlagsUndefined |= VM_FLAG_OF;
                    OracleSetFlag(state.rflags, VM_FLAG_CF,
                        count < bits && ((a >> (count - 1u)) & 1u) != 0);
                    result = instruction.mnemonic == InstructionMnemonic::Shr ?
                        OracleTruncate(a, width) >> count :
                        static_cast<uint64_t>(static_cast<int64_t>(OracleSignExtend(a, width)) >> count);
                    result = OracleTruncate(result, width);
                    if (count == 1 && instruction.mnemonic == InstructionMnemonic::Shr) {
                        OracleSetFlag(state.rflags, VM_FLAG_OF, (a & (1ULL << (bits - 1u))) != 0);
                    } else OracleSetFlag(state.rflags, VM_FLAG_OF, false);
                    OracleResultFlags(state.rflags, result, width);
                } else {
                    const unsigned effective = count % bits;
                    concreteFlagsWritten = VM_FLAG_CF;
                    concreteFlagsUndefined = 0;
                    if (count == 1u) concreteFlagsWritten |= VM_FLAG_OF;
                    else concreteFlagsUndefined |= VM_FLAG_OF;
                    if (effective == 0) {
                        result = a;
                    } else if (instruction.mnemonic == InstructionMnemonic::Rol) {
                        result = OracleTruncate((a << effective) |
                            (OracleTruncate(a, width) >> (bits - effective)), width);
                        OracleSetFlag(state.rflags, VM_FLAG_CF, (result & 1u) != 0);
                        OracleSetFlag(state.rflags, VM_FLAG_OF, effective == 1u ?
                            (((result & (1ULL << (bits - 1u))) != 0) !=
                             ((state.rflags & VM_FLAG_CF) != 0)) : false);
                    } else {
                        result = OracleTruncate((OracleTruncate(a, width) >> effective) |
                            (a << (bits - effective)), width);
                        OracleSetFlag(state.rflags, VM_FLAG_CF,
                            (result & (1ULL << (bits - 1u))) != 0);
                        OracleSetFlag(state.rflags, VM_FLAG_OF, effective == 1u ?
                            (((result & (1ULL << (bits - 1u))) != 0) !=
                             ((result & (1ULL << (bits - 2u))) != 0)) : false);
                    }
                    // A non-zero masked count that happens to rotate by a
                    // complete operand width still updates CF.  Only the
                    // destination value is unchanged in that case.
                    if (effective == 0) {
                        if (instruction.mnemonic == InstructionMnemonic::Rol) {
                            OracleSetFlag(state.rflags, VM_FLAG_CF,
                                (result & 1u) != 0);
                        } else {
                            OracleSetFlag(state.rflags, VM_FLAG_CF,
                                (result & (1ULL << (bits - 1u))) != 0);
                        }
                    }
                }
                if (!write(*operands[0], width, result)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Bswap:
                if (operands.size() != 1) goto unsupported;
                {
                    const uint8_t width = WidthBytes(operands[0]->width);
                    if (!read(*operands[0], width, a)) goto memory_fault;
                    result = 0;
                    for (uint8_t i = 0; i < width; ++i) result |=
                        ((a >> (i * 8u)) & 0xFFu) << ((width - 1u - i) * 8u);
                    if (!write(*operands[0], width, result)) goto memory_fault;
                }
                break;
            case InstructionMnemonic::Bt: case InstructionMnemonic::Bts:
            case InstructionMnemonic::Btr:
                if (operands.size() != 2 || !IsRegister(operands[0])) goto unsupported;
                {
                    const uint8_t width = WidthBytes(operands[0]->width);
                    if (!read(*operands[0], width, a) || !read(*operands[1], width, b)) goto memory_fault;
                    const unsigned bit = static_cast<unsigned>(b % (width * 8u));
                    OracleSetFlag(state.rflags, VM_FLAG_CF, ((a >> bit) & 1u) != 0);
                    result = a;
                    if (instruction.mnemonic == InstructionMnemonic::Bts) result |= 1ULL << bit;
                    if (instruction.mnemonic == InstructionMnemonic::Btr) result &= ~(1ULL << bit);
                    if (instruction.mnemonic != InstructionMnemonic::Bt &&
                        !write(*operands[0], width, result)) goto memory_fault;
                }
                break;
            case InstructionMnemonic::Cmov:
                if (operands.size() != 2) goto unsupported;
                {
                    VM_CONDITION condition = VM_CONDITION_ALWAYS;
                    if (!OracleMapCondition(instruction.branchKind, condition)) goto unsupported;
                    if (!read(*operands[1], WidthBytes(operands[0]->width), a)) goto memory_fault;
                    if (OracleCondition(state.rflags, condition)) {
                        if (!write(*operands[0], WidthBytes(operands[0]->width), a)) goto memory_fault;
                    } else if (instruction.machineMode == MachineMode::X64 &&
                               WidthBytes(operands[0]->width) == 4u &&
                               IsRegister(operands[0])) {
                        // Intel CMOVcc r32 clears DEST[63:32] even when the
                        // condition is false; the low 32 bits remain intact.
                        state.gpr[operands[0]->regInfo.family] &= 0xFFFFFFFFULL;
                    }
                }
                break;
            case InstructionMnemonic::Setcc:
                if (operands.size() != 1) goto unsupported;
                {
                    VM_CONDITION condition = VM_CONDITION_ALWAYS;
                    if (!OracleMapCondition(instruction.branchKind, condition)) goto unsupported;
                    if (!write(*operands[0], 1, OracleCondition(state.rflags, condition) ? 1 : 0)) goto memory_fault;
                }
                break;
            case InstructionMnemonic::Jmp:
            case InstructionMnemonic::Jo: case InstructionMnemonic::Jno:
            case InstructionMnemonic::Jb: case InstructionMnemonic::Jae:
            case InstructionMnemonic::Jz: case InstructionMnemonic::Jnz:
            case InstructionMnemonic::Jbe: case InstructionMnemonic::Ja:
            case InstructionMnemonic::Js: case InstructionMnemonic::Jns:
            case InstructionMnemonic::Jp: case InstructionMnemonic::Jnp:
            case InstructionMnemonic::Jl: case InstructionMnemonic::Jge:
            case InstructionMnemonic::Jle: case InstructionMnemonic::Jg: {
                if (instruction.isIndirectBranch || !instruction.hasBranchTarget) goto unsupported;
                bool taken = instruction.mnemonic == InstructionMnemonic::Jmp;
                if (!taken) {
                    VM_CONDITION condition = VM_CONDITION_ALWAYS;
                    if (!OracleMapCondition(instruction.branchKind, condition)) goto unsupported;
                    taken = OracleCondition(state.rflags, condition);
                }
                if (taken) { state.ip = instruction.branchTargetRVA; advance = false; }
                break;
            }
            case InstructionMnemonic::Call:
                if (instruction.isIndirectBranch || !instruction.hasBranchTarget ||
                    byAddress.find(instruction.branchTargetRVA) == byAddress.end() ||
                    state.callDepth >= state.callStack.size()) goto unsupported;
                state.callStack[state.callDepth++] = fallthrough;
                state.ip = instruction.branchTargetRVA;
                advance = false;
                break;
            case InstructionMnemonic::Ret:
                if (state.callDepth != 0) state.ip = state.callStack[--state.callDepth];
                else state.finished = true;
                advance = false;
                break;
            case InstructionMnemonic::Mul:
            case InstructionMnemonic::Imul:
            case InstructionMnemonic::Div:
            case InstructionMnemonic::Idiv: {
                const bool implicit = instruction.mnemonic == InstructionMnemonic::Mul ||
                    instruction.mnemonic == InstructionMnemonic::Div ||
                    instruction.mnemonic == InstructionMnemonic::Idiv ||
                    (instruction.mnemonic == InstructionMnemonic::Imul && operands.size() == 1u);
                if (implicit) {
                    if (operands.size() != 1u) goto unsupported;
                    const uint8_t width = WidthBytes(operands[0]->width);
                    if (width == 0 || !read(*operands[0], width, b)) goto memory_fault;
                    if (instruction.mnemonic == InstructionMnemonic::Mul ||
                        instruction.mnemonic == InstructionMnemonic::Imul) {
                        a = readReg(0, width, 0);
                        uint64_t low = 0, high = 0;
                        if (width < 8u) {
                            const uint64_t product = instruction.mnemonic == InstructionMnemonic::Mul ?
                                OracleTruncate(a, width) * OracleTruncate(b, width) :
                                static_cast<uint64_t>(
                                    static_cast<int64_t>(OracleSignExtend(a, width)) *
                                    static_cast<int64_t>(OracleSignExtend(b, width)));
                            low = OracleTruncate(product, width);
                            high = OracleTruncate(product >> (width * 8u), width);
                        } else {
                            OracleMultiply64(a, b,
                                instruction.mnemonic == InstructionMnemonic::Imul,
                                low, high);
                        }
                        const uint64_t expectedHigh = instruction.mnemonic == InstructionMnemonic::Mul ?
                            0u : ((low & (1ULL << (width * 8u - 1u))) ? WidthMask(width) : 0u);
                        const bool overflow = high != expectedHigh;
                        OracleSetFlag(state.rflags, VM_FLAG_CF, overflow);
                        OracleSetFlag(state.rflags, VM_FLAG_OF, overflow);
                        writeReg(0, width, 0, low);
                        writeReg(width == 1u ? 0u : 2u, width,
                            width == 1u ? 8u : 0u, high);
                    } else {
                        const uint64_t high = readReg(width == 1u ? 0u : 2u,
                            width, width == 1u ? 8u : 0u);
                        const uint64_t low = readReg(0, width, 0);
                        uint64_t quotient = 0, remainder = 0;
                        bool valid = false;
                        if (width < 8u) {
                            const unsigned bits = width * 8u;
                            const uint64_t combined = (high << bits) | low;
                            const uint64_t divisor = OracleTruncate(b, width);
                            if (instruction.mnemonic == InstructionMnemonic::Div) {
                                valid = divisor != 0;
                                if (valid) {
                                    quotient = combined / divisor;
                                    remainder = combined % divisor;
                                    valid = quotient <= WidthMask(width);
                                }
                            } else {
                                const unsigned combinedBits = bits * 2u;
                                const uint64_t sign = 1ULL << (combinedBits - 1u);
                                const int64_t dividend = static_cast<int64_t>((combined ^ sign) - sign);
                                const int64_t divisorSigned = static_cast<int64_t>(OracleSignExtend(divisor, width));
                                valid = divisorSigned != 0 &&
                                    !(dividend == INT64_MIN && divisorSigned == -1);
                                if (valid) {
                                    const int64_t signedQuotient = dividend / divisorSigned;
                                    const int64_t signedRemainder = dividend % divisorSigned;
                                    const int64_t minimum = -(1LL << (bits - 1u));
                                    const int64_t maximum = (1LL << (bits - 1u)) - 1;
                                    valid = signedQuotient >= minimum && signedQuotient <= maximum;
                                    quotient = OracleTruncate(static_cast<uint64_t>(signedQuotient), width);
                                    remainder = OracleTruncate(static_cast<uint64_t>(signedRemainder), width);
                                }
                            }
                        } else if (instruction.mnemonic == InstructionMnemonic::Div) {
                            valid = OracleUnsignedDivide128(high, low, b, quotient, remainder);
                        } else {
                            valid = OracleSignedDivide128(high, low, b, quotient, remainder);
                        }
                        if (!valid) goto divide_fault;
                        writeReg(0, width, 0, quotient);
                        writeReg(width == 1u ? 0u : 2u, width,
                            width == 1u ? 8u : 0u, remainder);
                    }
                    break;
                }
                if (instruction.mnemonic != InstructionMnemonic::Imul ||
                    (operands.size() != 2u && operands.size() != 3u)) goto unsupported;
                const uint8_t width = WidthBytes(operands[0]->width);
                const OperandIR* lhs = operands.size() == 2u ? operands[0] : operands[1];
                const OperandIR* rhs = operands.size() == 2u ? operands[1] : operands[2];
                if (!read(*lhs, width, a) || !read(*rhs, width, b)) goto memory_fault;
                uint64_t low = 0, high = 0;
                if (width < 8u) {
                    const uint64_t product = static_cast<uint64_t>(
                        static_cast<int64_t>(OracleSignExtend(a, width)) *
                        static_cast<int64_t>(OracleSignExtend(b, width)));
                    low = OracleTruncate(product, width);
                    high = OracleTruncate(product >> (width * 8u), width);
                } else {
                    OracleMultiply64(a, b, true, low, high);
                }
                const uint64_t expectedHigh = (low & (1ULL << (width * 8u - 1u))) ?
                    WidthMask(width) : 0u;
                OracleSetFlag(state.rflags, VM_FLAG_CF, high != expectedHigh);
                OracleSetFlag(state.rflags, VM_FLAG_OF, high != expectedHigh);
                if (!write(*operands[0], width, low)) goto memory_fault;
                break;
            }
            case InstructionMnemonic::Push:
            case InstructionMnemonic::Pop: {
                if (operands.size() != 1u) goto unsupported;
                const uint8_t stackWidth = WidthBytes(instruction.operandWidth) != 0 ?
                    WidthBytes(instruction.operandWidth) :
                    (WidthBytes(operands[0]->width) != 0 ?
                        WidthBytes(operands[0]->width) : AddressWidth(instruction));
                const uint8_t addressWidth = StackPointerWidth(instruction);
                if (instruction.mnemonic == InstructionMnemonic::Push) {
                    if (!read(*operands[0], stackWidth, a)) goto memory_fault;
                    state.gpr[4] = OracleTruncate(state.gpr[4] - stackWidth, addressWidth);
                    size_t offset = 0;
                    if (!OracleMemoryRange(state.gpr[4], stackWidth,
                            memoryBase, memory, offset)) goto memory_fault;
                    for (uint8_t i = 0; i < stackWidth; ++i) {
                        memory[offset + i] = static_cast<uint8_t>(a >> (i * 8u));
                    }
                } else {
                    size_t offset = 0;
                    if (!OracleMemoryRange(state.gpr[4], stackWidth,
                            memoryBase, memory, offset)) goto memory_fault;
                    a = 0;
                    for (uint8_t i = 0; i < stackWidth; ++i) {
                        a |= static_cast<uint64_t>(memory[offset + i]) << (i * 8u);
                    }
                    state.gpr[4] = OracleTruncate(state.gpr[4] + stackWidth, addressWidth);
                    if (!write(*operands[0], stackWidth, a)) goto memory_fault;
                }
                break;
            }
            case InstructionMnemonic::PushFlags:
            case InstructionMnemonic::PopFlags: {
                const uint8_t width = ImplicitWidth(instruction);
                const uint8_t addressWidth = StackPointerWidth(instruction);
                if (instruction.mnemonic == InstructionMnemonic::PushFlags) {
                    state.gpr[4] = OracleTruncate(state.gpr[4] - width, addressWidth);
                    size_t offset = 0;
                    if (!OracleMemoryRange(state.gpr[4], width,
                            memoryBase, memory, offset)) goto memory_fault;
                    const uint64_t pushedFlags = width >= 4u
                        ? state.rflags & ~static_cast<uint64_t>(VM_FLAG_PUSH_CLEARED_MASK)
                        : state.rflags;
                    for (uint8_t i = 0; i < width; ++i) {
                        memory[offset + i] = static_cast<uint8_t>(pushedFlags >> (i * 8u));
                    }
                } else {
                    size_t offset = 0;
                    if (!OracleMemoryRange(state.gpr[4], width,
                            memoryBase, memory, offset)) goto memory_fault;
                    a = 0;
                    for (uint8_t i = 0; i < width; ++i) {
                        a |= static_cast<uint64_t>(memory[offset + i]) << (i * 8u);
                    }
                    state.gpr[4] = OracleTruncate(state.gpr[4] + width, addressWidth);
                    state.rflags = (state.rflags & ~static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK)) |
                        (a & VM_FLAG_ARCHITECTURAL_MASK);
                }
                break;
            }
            case InstructionMnemonic::Leave: {
                const uint8_t addressWidth = StackPointerWidth(instruction);
                state.gpr[4] = OracleTruncate(state.gpr[5], addressWidth);
                size_t offset = 0;
                if (!OracleMemoryRange(state.gpr[4], addressWidth,
                        memoryBase, memory, offset)) goto memory_fault;
                a = 0;
                for (uint8_t i = 0; i < addressWidth; ++i) {
                    a |= static_cast<uint64_t>(memory[offset + i]) << (i * 8u);
                }
                state.gpr[4] = OracleTruncate(state.gpr[4] + addressWidth, addressWidth);
                writeReg(5, addressWidth, 0, a);
                break;
            }
            case InstructionMnemonic::SignExtendAccumulator: {
                const uint8_t width = ImplicitWidth(instruction);
                a = readReg(0, width, 0);
                writeReg(2, width, 0,
                    (a & (1ULL << (width * 8u - 1u))) ? WidthMask(width) : 0u);
                break;
            }
            case InstructionMnemonic::ExtendAccumulator: {
                const uint8_t width = ImplicitWidth(instruction);
                const uint8_t sourceWidth = width / 2u;
                writeReg(0, width, 0, OracleSignExtend(readReg(0, sourceWidth, 0), sourceWidth));
                break;
            }
            case InstructionMnemonic::Clc:
                state.rflags &= ~static_cast<uint64_t>(VM_FLAG_CF);
                break;
            case InstructionMnemonic::Stc:
                state.rflags |= VM_FLAG_CF;
                break;
            case InstructionMnemonic::Cmc:
                state.rflags ^= VM_FLAG_CF;
                break;
            case InstructionMnemonic::Lahf:
                result = 0x02u |
                    ((state.rflags & VM_FLAG_SF) ? 0x80u : 0u) |
                    ((state.rflags & VM_FLAG_ZF) ? 0x40u : 0u) |
                    ((state.rflags & VM_FLAG_AF) ? 0x10u : 0u) |
                    ((state.rflags & VM_FLAG_PF) ? 0x04u : 0u) |
                    ((state.rflags & VM_FLAG_CF) ? 0x01u : 0u);
                writeReg(0, 1, 8, result);
                break;
            case InstructionMnemonic::Sahf: {
                const uint64_t packed = readReg(0, 1, 8);
                const uint64_t mask = VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF |
                    VM_FLAG_PF | VM_FLAG_CF;
                result = ((packed & 0x80u) ? VM_FLAG_SF : 0u) |
                    ((packed & 0x40u) ? VM_FLAG_ZF : 0u) |
                    ((packed & 0x10u) ? VM_FLAG_AF : 0u) |
                    ((packed & 0x04u) ? VM_FLAG_PF : 0u) |
                    ((packed & 0x01u) ? VM_FLAG_CF : 0u);
                state.rflags = (state.rflags & ~mask) | result;
                break;
            }
            case InstructionMnemonic::Int3:
                // This from-scratch software x86 interpreter has no concept
                // of a real hardware trap; it can only report that a real
                // CPU would fault here (mirroring the DivideError case
                // below), not what happens after -- that is exactly what
                // the native differential path this oracle feeds proves
                // instead, against the real synthesized handler and real
                // hardware.
                state.fault = OracleFault::Breakpoint;
                error = "IR model reached INT3";
                return false;
            default:
                goto unsupported;
        }
        state.undefinedRflagsMask &=
            ~(concreteFlagsWritten | concreteFlagsUndefined);
        state.undefinedRflagsMask |= concreteFlagsUndefined;
        if (advance) state.ip = fallthrough;
        continue;
memory_fault:
        state.fault = OracleFault::Memory;
        error = "IR model memory access escaped the bounded corpus";
        return false;
divide_fault:
        state.fault = OracleFault::DivideError;
        error = "IR model produced #DE";
        return false;
unsupported:
        state.fault = OracleFault::Unsupported;
        error = "IR model cannot safely model instruction at RVA " +
            std::to_string(instruction.rva);
        return false;
    }
    if (!state.finished) {
        state.fault = OracleFault::ControlFlow;
        error = "IR model exceeded the execution step bound";
        return false;
    }
    return true;
}

} // namespace

VMIRModelPreflightResult VMIRModelPreflightVerifier::Verify(
    const Function& function,
    const TranslationResult& translation,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    const VMIRModelPreflightConfig& config)
{
    VMIRModelPreflightResult result{};
    result.vmGroupId = config.vmGroupId;
    if (!translation.success || translation.bytecode.empty() || config.corpusCount == 0 ||
        config.memorySize < 0x1000u || registerMap.size() < 16) {
        result.error = "IR model preflight received incomplete translation/configuration";
        return result;
    }
    std::array<uint8_t, 256> reverse{};
    reverse.fill(0xFFu);
    for (const auto& item : opcodeMap) {
        if (reverse[item.second] != 0xFFu) {
            result.error = "IR model preflight opcode map is not injective";
            return result;
        }
        reverse[item.second] = item.first;
    }
    std::array<bool, 32> mappedSlots{};
    for (uint8_t family = 0; family < 16; ++family) {
        const auto mapped = registerMap.find(family);
        if (mapped == registerMap.end() || mapped->second >= translation.registerCount ||
            mappedSlots[mapped->second]) {
            result.error = "IR model preflight register map is missing or non-injective";
            return result;
        }
        mappedSlots[mapped->second] = true;
    }

    uint64_t corpusMemoryBase = 0x0000000110000000ULL;
    bool usesAddress16 = false;
    bool usesAddress32 = false;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            for (const auto& operand : instruction.operands) {
                if (operand.type != OperandType::Memory) continue;
                usesAddress16 = usesAddress16 || AddressWidth(instruction) == 2u;
                usesAddress32 = usesAddress32 || AddressWidth(instruction) == 4u;
            }
        }
    }
    if (usesAddress16) {
        if (config.memorySize < 0x10000u) {
            result.error = "16-bit addressing IR model corpus requires the full 64 KiB space";
            return result;
        }
        corpusMemoryBase = 0;
    } else if (usesAddress32) {
        corpusMemoryBase = 0x0000000010000000ULL;
    }
    uint64_t random = config.corpusSeed ^ function.entryAddress ^ translation.microSelectionDigest;
    for (uint32_t corpusIndex = 0; corpusIndex < config.corpusCount; ++corpusIndex) {
        OracleState oracle{};
        for (uint64_t& value : oracle.gpr) value = NextCorpusValue(random);
        oracle.rflags = NextCorpusValue(random) | 0x02u;
        std::string oracleError;
        const uint32_t imageSize = config.imageSize != 0
            ? config.imageSize : config.memorySize / 2u;
        if (!PrepareOracleMemoryRegisters(function, oracle, corpusMemoryBase,
                config.memorySize, imageSize, oracleError)) {
            result.failingCase = corpusIndex;
            result.error = oracleError;
            return result;
        }
        std::vector<uint8_t> oracleMemory(config.memorySize);
        for (uint8_t& byte : oracleMemory) byte = static_cast<uint8_t>(NextCorpusValue(random));
        std::vector<uint8_t> microMemory = oracleMemory;

        VMMicroMachineState micro{};
        for (uint64_t& value : micro.gpr) value = NextCorpusValue(random);
        for (uint8_t family = 0; family < 16; ++family) {
            micro.gpr[registerMap.at(family)] = oracle.gpr[family];
        }
        micro.rflags = oracle.rflags;
        micro.imageBase = corpusMemoryBase;
        VMMicroExecutionOptions options{};
        options.registerCount = translation.registerCount;
        options.maxSteps = config.maxSteps;
        options.addressWidth = function.blocks.front().instructions.front().machineMode ==
            MachineMode::X64 ? 8u : 4u;

        const bool oracleOk = ExecuteOracle(function, oracle, corpusMemoryBase, corpusMemoryBase,
            oracleMemory, config.maxSteps, oracleError);
        VMMicroMemoryView view{microMemory.data(), microMemory.size(), corpusMemoryBase};
        std::string microError;
        const bool microOk = VMMicroSemanticExecutor::Execute(translation.bytecode.data(),
            translation.bytecode.size(), reverse.data(), translation.operandCodec,
            micro, view, options, microError);
        const bool equivalentDivideFault = !oracleOk && !microOk &&
            oracle.fault == OracleFault::DivideError &&
            micro.fault == VMMicroFault::DivideError;
        if ((!oracleOk || !microOk) && !equivalentDivideFault) {
            result.failingCase = corpusIndex;
            result.error = !oracleOk ? "IR model fail-closed: " + oracleError :
                "micro semantic executor mismatch/fault: " + microError;
            return result;
        }
        if (equivalentDivideFault) {
            VMMicroSemanticExecutor::MaterializeFlags(micro, VM_FLAG_ARCHITECTURAL_MASK);
        }
        for (uint8_t family = 0; family < 16; ++family) {
            if (oracle.gpr[family] != micro.gpr[registerMap.at(family)]) {
                result.failingCase = corpusIndex;
                result.error = "IR model preflight GPR mismatch at family " +
                    std::to_string(family);
                return result;
            }
        }
        const uint64_t caseObservableRflagsMask =
            static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK) &
            ~oracle.undefinedRflagsMask;
        if (((oracle.rflags ^ micro.rflags) &
                caseObservableRflagsMask) != 0u) {
            result.failingCase = corpusIndex;
            result.error = "IR model preflight observable RFLAGS mismatch";
            return result;
        }
        if (oracleMemory != microMemory) {
            result.failingCase = corpusIndex;
            result.error = "IR model preflight memory side-effect mismatch";
            return result;
        }
        if (micro.operandStackDepth != 0 ||
            (!equivalentDivideFault && (!micro.finished || micro.fault != VMMicroFault::None))) {
            result.failingCase = corpusIndex;
            result.error = "micro execution did not terminate with a closed operand stack";
            return result;
        }
        ++result.casesExecuted;
    }
    result.success = result.casesExecuted == config.corpusCount;
    return result;
}

namespace {

uint64_t DifferentialIdentityBytes(
    uint64_t identity,
    const void* data,
    size_t size)
{
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        identity = Mix64(identity ^
            (static_cast<uint64_t>(bytes[index]) +
             (static_cast<uint64_t>(index) << 8u)));
    }
    return identity;
}

template <typename T>
uint64_t DifferentialIdentityValue(uint64_t identity, const T& value) {
    return DifferentialIdentityBytes(identity, &value, sizeof(value));
}

VMNativeDifferentialArchitecture NativeDifferentialArchitecture(
    const Function& function)
{
    VMNativeDifferentialArchitecture architecture =
        VMNativeDifferentialArchitecture::Unknown;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            const auto current = instruction.machineMode == MachineMode::X64
                ? VMNativeDifferentialArchitecture::X64
                : (instruction.machineMode == MachineMode::X86
                    ? VMNativeDifferentialArchitecture::X86
                    : VMNativeDifferentialArchitecture::Unknown);
            if (current == VMNativeDifferentialArchitecture::Unknown) return current;
            if (architecture == VMNativeDifferentialArchitecture::Unknown) {
                architecture = current;
            } else if (architecture != current) {
                return VMNativeDifferentialArchitecture::Unknown;
            }
        }
    }
    return architecture;
}

uint64_t NativeDifferentialInputIdentity(
    const VMNativeDifferentialCaseRequest& request)
{
    uint64_t identity = 0x4E41544956454341ULL; /* NATIV ECA domain */
    identity = DifferentialIdentityValue(identity, request.corpusIndex);
    identity = DifferentialIdentityValue(identity, request.architecture);
    identity = DifferentialIdentityValue(identity, request.functionRVA);
    identity = DifferentialIdentityValue(identity, request.translationIdentity);
    identity = DifferentialIdentityValue(identity, request.handlerImageDigest);
    identity = DifferentialIdentityValue(identity, request.memoryBase);
    identity = DifferentialIdentityValue(identity, request.timeoutMilliseconds);
    identity = DifferentialIdentityBytes(identity, request.initialGpr.data(),
        request.initialGpr.size() * sizeof(request.initialGpr[0]));
    identity = DifferentialIdentityValue(identity, request.initialRflags);
    return DifferentialIdentityBytes(identity, request.initialMemory.data(),
        request.initialMemory.size());
}

bool PrepareNativeDifferentialAddressSpace(
    const Function& function,
    uint32_t memorySize,
    uint32_t imageSize,
    std::array<uint64_t, 16>& gpr,
    uint64_t& memoryBase,
    std::string& error)
{
    bool usesAddress16 = false;
    bool usesAddress32 = false;
    bool isX86 = false;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            isX86 = isX86 || instruction.machineMode == MachineMode::X86;
            for (const auto& operand : instruction.operands) {
                if (operand.type != OperandType::Memory) continue;
                usesAddress16 = usesAddress16 || AddressWidth(instruction) == 2u;
                usesAddress32 = usesAddress32 || AddressWidth(instruction) == 4u;
            }
        }
    }
    memoryBase = usesAddress16 ? 0u :
        ((usesAddress32 || isX86)
            ? 0x0000000020000000ULL : 0x0000000110000000ULL);
    if (usesAddress16 && memorySize < 0x10000u) {
        error = "native differential 16-bit addressing requires the full 64 KiB corpus";
        return false;
    }
    OracleState preparation{};
    preparation.gpr = gpr;
    if (!PrepareOracleMemoryRegisters(
            function, preparation, memoryBase, memorySize, imageSize, error)) {
        return false;
    }
    gpr = preparation.gpr;
    return true;
}

bool IsCompleteArchitecturalSnapshot(
    const VMNativeDifferentialSnapshot& snapshot,
    uint32_t memorySize)
{
    return snapshot.validRflagsMask ==
            static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK) &&
        snapshot.memory.size() == memorySize;
}

} // namespace

uint64_t VMNativeDifferentialVerifier::ComputeTranslationIdentity(
    const Function& function,
    const TranslationResult& translation,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap)
{
    uint64_t identity = 0x564D4E4154495645ULL; /* VMNATIVE */
    identity = DifferentialIdentityValue(identity, function.entryAddress);
    identity = DifferentialIdentityValue(identity, function.size);
    identity = DifferentialIdentityValue(identity, translation.registerCount);
    identity = DifferentialIdentityValue(identity, translation.observableRflagsMask);
    identity = DifferentialIdentityValue(identity, translation.microSelectionDigest);
    identity = DifferentialIdentityBytes(identity, &translation.operandCodec,
        sizeof(translation.operandCodec));
    identity = DifferentialIdentityBytes(identity, translation.bytecode.data(),
        translation.bytecode.size());
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            identity = DifferentialIdentityValue(identity, instruction.rva);
            identity = DifferentialIdentityValue(identity, instruction.length);
            identity = DifferentialIdentityBytes(identity, instruction.rawBytes.data(),
                instruction.length);
            identity = DifferentialIdentityValue(identity, instruction.hasImageRelocation);
            identity = DifferentialIdentityValue(identity, instruction.imageRelocationSupported);
            identity = DifferentialIdentityValue(identity, instruction.imageRelocationOffset);
            identity = DifferentialIdentityValue(identity, instruction.imageRelocationSize);
            identity = DifferentialIdentityValue(identity, instruction.imageRelocationTargetRVA);
        }
    }
    for (uint32_t semantic = 0; semantic < 256u; ++semantic) {
        const auto found = opcodeMap.find(static_cast<uint8_t>(semantic));
        const uint8_t encoded = found == opcodeMap.end() ? 0xFFu : found->second;
        identity = DifferentialIdentityValue(identity, encoded);
    }
    for (uint32_t family = 0; family < 32u; ++family) {
        const auto found = registerMap.find(static_cast<uint8_t>(family));
        const uint8_t slot = found == registerMap.end() ? 0xFFu : found->second;
        identity = DifferentialIdentityValue(identity, slot);
    }
    return identity;
}

VMNativeDifferentialResult VMNativeDifferentialVerifier::Verify(
    const Function& function,
    const TranslationResult& translation,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    const VMNativeDifferentialConfig& config)
{
    VMNativeDifferentialResult result{};
    result.vmGroupId = config.vmGroupId;
    if (!translation.success || translation.bytecode.empty() ||
        function.blocks.empty() || config.corpusCount == 0u ||
        config.memorySize < 0x1000u ||
        config.memorySize > VM_NATIVE_DIFFERENTIAL_MAX_MEMORY_SIZE ||
        config.timeoutMilliseconds == 0u) {
        result.error = "native differential gate received incomplete translation/configuration";
        return result;
    }
    const uint64_t architecturalFlags = VM_FLAG_ARCHITECTURAL_MASK;
    const uint64_t mandatoryPreservedFlags =
        architecturalFlags & ~static_cast<uint64_t>(VM_FLAG_STATUS_MASK);
    if ((translation.observableRflagsMask & ~architecturalFlags) != 0u ||
        (translation.observableRflagsMask & mandatoryPreservedFlags) !=
            mandatoryPreservedFlags) {
        result.error = "native differential observable RFLAGS mask is invalid or incomplete";
        return result;
    }
    if (translation.usesSimd || translation.usesAvx || translation.usesX87) {
        result.error = "native differential extended processor-state evidence is unavailable";
        return result;
    }
    if (!function.boundaryTrusted || function.size == 0u ||
        function.decodedBytes != function.size ||
        translation.nativeInstructionCount == 0u ||
        translation.microOpCount == 0u) {
        result.error = "native differential function/translation coverage is incomplete";
        return result;
    }
    for (const auto& block : function.blocks) {
        if (block.instructions.empty()) {
            result.error = "native differential function contains an empty basic block";
            return result;
        }
        for (const auto& instruction : block.instructions) {
            if (instruction.length == 0u ||
                instruction.length > instruction.rawBytes.size()) {
                result.error = "native differential function contains incomplete raw instruction bytes";
                return result;
            }
        }
    }
    if (!config.evidenceProvider) {
        result.error = "isolated native differential evidence provider is unavailable";
        return result;
    }
    if (config.expectedHandlerImageDigest == 0u) {
        result.error = "synthesized handler image identity is unavailable";
        return result;
    }
    const VMNativeDifferentialArchitecture architecture =
        NativeDifferentialArchitecture(function);
    if (architecture == VMNativeDifferentialArchitecture::Unknown) {
        result.error = "native differential architecture is missing or mixed";
        return result;
    }
    if (registerMap.size() < 16u || opcodeMap.empty()) {
        result.error = "native differential opcode/register maps are incomplete";
        return result;
    }
    std::array<bool, 256> opcodeSlots{};
    for (const auto& mapping : opcodeMap) {
        if (opcodeSlots[mapping.second]) {
            result.error = "native differential opcode map is not injective";
            return result;
        }
        opcodeSlots[mapping.second] = true;
    }
    std::array<bool, 32> registerSlots{};
    for (uint8_t family = 0; family < 16u; ++family) {
        const auto mapped = registerMap.find(family);
        if (mapped == registerMap.end() ||
            mapped->second >= translation.registerCount ||
            registerSlots[mapped->second]) {
            result.error = "native differential register map is missing or non-injective";
            return result;
        }
        registerSlots[mapped->second] = true;
    }

    const uint64_t translationIdentity = ComputeTranslationIdentity(
        function, translation, opcodeMap, registerMap);
    uint64_t random = config.corpusSeed ^ function.entryAddress ^ translationIdentity;
    for (uint32_t corpusIndex = 0; corpusIndex < config.corpusCount; ++corpusIndex) {
        result.failingCase = corpusIndex;
        VMNativeDifferentialCaseRequest request{};
        request.corpusIndex = corpusIndex;
        request.architecture = architecture;
        request.functionRVA = function.entryAddress;
        request.translationIdentity = translationIdentity;
        request.handlerImageDigest = config.expectedHandlerImageDigest;
        request.timeoutMilliseconds = config.timeoutMilliseconds;
        for (uint64_t& value : request.initialGpr) {
            value = NextCorpusValue(random);
        }
        const uint32_t imageSize = config.imageSize != 0
            ? config.imageSize : config.memorySize / 2u;
        if (!PrepareNativeDifferentialAddressSpace(function, config.memorySize,
                imageSize,
                request.initialGpr, request.memoryBase, result.error)) {
            return result;
        }
        /*
         * The evidence worker executes at CPL3. IF cannot be cleared there,
         * while TF/AC would turn the verifier harness itself into a trap/alignment
         * source. Both Win32 and Win64 ABIs require DF=0 at function boundaries,
         * so randomize the arithmetic bits plus ID and bind both executions to
         * that real ABI/user-mode state.
         */
        request.initialRflags = VM_FLAG_FIXED_1 | VM_FLAG_IF |
            (NextCorpusValue(random) & static_cast<uint64_t>(
                VM_FLAG_STATUS_MASK | VM_FLAG_ID));
        request.initialMemory.resize(config.memorySize);
        for (uint8_t& byte : request.initialMemory) {
            byte = static_cast<uint8_t>(NextCorpusValue(random));
        }
        OracleState pathOracle{};
        pathOracle.gpr = request.initialGpr;
        pathOracle.rflags = request.initialRflags;
        std::vector<uint8_t> pathMemory = request.initialMemory;
        std::string pathError;
        const bool pathCompleted = ExecuteOracle(function, pathOracle,
            request.memoryBase, request.memoryBase, pathMemory, 1000000u,
            pathError);
        const bool expectedDivideFault = !pathCompleted &&
            pathOracle.fault == OracleFault::DivideError &&
            config.expectDivideFault;
        const bool expectedBreakpointFault = !pathCompleted &&
            pathOracle.fault == OracleFault::Breakpoint &&
            config.expectBreakpointFault;
        if (!pathCompleted && !expectedDivideFault && !expectedBreakpointFault) {
            result.error = "native differential path-mask oracle failed closed";
            if (!pathError.empty()) result.error += ": " + pathError;
            return result;
        }
        const uint64_t caseObservableRflagsMask =
            static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK) &
            ~pathOracle.undefinedRflagsMask;
        request.inputIdentity = NativeDifferentialInputIdentity(request);

        VMNativeDifferentialCaseEvidence evidence{};
        std::string providerError;
        if (!config.evidenceProvider->ExecuteCase(function, translation,
                opcodeMap, registerMap, request, evidence, providerError)) {
            result.error = "native differential provider failed closed";
            if (!providerError.empty()) result.error += ": " + providerError;
            return result;
        }
        if (evidence.corpusIndex != request.corpusIndex ||
            evidence.architecture != request.architecture ||
            evidence.functionRVA != request.functionRVA ||
            evidence.translationIdentity != request.translationIdentity ||
            evidence.handlerImageDigest != request.handlerImageDigest ||
            evidence.inputIdentity != request.inputIdentity) {
            result.error = "native differential evidence is not bound to the requested case";
            return result;
        }
        if (!evidence.isolatedWorker || !evidence.timeoutEnforced) {
            result.error = "native differential evidence lacks isolation or deadline enforcement";
            return result;
        }
        if (evidence.timedOut) {
            result.error = "native differential worker timed out";
            return result;
        }
        if (!evidence.nativeCpuExecuted || evidence.nativeInstructionCount == 0u) {
            result.error = "native differential evidence contains no actual CPU execution";
            return result;
        }
        if (!evidence.synthesizedHandlersExecuted ||
            evidence.handlerInstructionCount == 0u) {
            result.error = "native differential evidence contains no synthesized handler execution";
            return result;
        }
        const bool nativeRaisedFault = evidence.nativeFaulted ||
            evidence.nativeExceptionCode != 0u;
        const bool vmRaisedFault = evidence.vmFaulted ||
            evidence.vmFault != VMMicroFault::None;
        if ((config.expectDivideFault || config.expectBreakpointFault) &&
            (nativeRaisedFault || vmRaisedFault)) {
            // The x86/x64 #DE vector is a single hardware fault for both the
            // divisor=0 and quotient-overflow sub-cases, but Windows' SEH
            // translation reports them under two different NTSTATUS codes:
            // STATUS_INTEGER_DIVIDE_BY_ZERO (0xC0000094) and
            // STATUS_INTEGER_OVERFLOW (0xC0000095). The synthesized handler's
            // own divideFailure path does not distinguish the two either (both
            // set VM_MICRO_ERR_DIVIDE), so either native code is a match.
            constexpr uint32_t kDivideByZeroExceptionCode = 0xC0000094u;
            constexpr uint32_t kIntegerOverflowExceptionCode = 0xC0000095u;
            // STATUS_BREAKPOINT: real #BP from VM_UOP_INT3's inline 0xCC/
            // CD 03 (see EmitBusinessCoreVariant), classified as
            // VMMicroFault::ExplicitTrap by the evidence provider.
            constexpr uint32_t kBreakpointExceptionCode = 0x80000003u;
            const bool classificationOk = config.expectDivideFault
                ? (nativeRaisedFault && vmRaisedFault &&
                   (evidence.nativeExceptionCode == kDivideByZeroExceptionCode ||
                    evidence.nativeExceptionCode == kIntegerOverflowExceptionCode) &&
                   evidence.vmFault == VMMicroFault::DivideError)
                : (nativeRaisedFault && vmRaisedFault &&
                   evidence.nativeExceptionCode == kBreakpointExceptionCode &&
                   evidence.vmFault == VMMicroFault::ExplicitTrap);
            if (!classificationOk) {
                result.error = "native differential divide/breakpoint-fault evidence does not "
                    "match on both sides (native=" +
                    std::to_string(evidence.nativeExceptionCode) + " faulted=" +
                    std::to_string(nativeRaisedFault) + ", vm fault=" +
                    std::to_string(static_cast<int>(evidence.vmFault)) + " faulted=" +
                    std::to_string(vmRaisedFault) + ")";
                return result;
            }
            // Equivalence, not just classification: both test families place
            // the faulting instruction as the function's very first
            // instruction, so neither side may show any register/flag
            // change from the pristine corpus input at the instant of the
            // fault -- proving the fault is architecturally transparent
            // rather than merely "eventually reported the right code".
            // evidence.*FaultGpr is already architecture-width-masked (see
            // the worker harness/provider), so the pristine input must be
            // masked the same way before comparing on x86 -- otherwise every
            // case fails spuriously on the upper 32 bits of a 64-bit random
            // corpus value that the real 32-bit CPU/VM never even had.
            const uint64_t gprCompareMask = architecture == VMNativeDifferentialArchitecture::X64
                ? (std::numeric_limits<uint64_t>::max)() : 0xFFFFFFFFULL;
            for (uint8_t family = 0; family < 16; ++family) {
                const uint64_t expectedGpr = request.initialGpr[family] & gprCompareMask;
                if (evidence.nativeFaultGpr[family] != expectedGpr ||
                    evidence.vmFaultGpr[family] != expectedGpr) {
                    result.error = "native differential fault-time register state diverged "
                        "from the pristine input (family=" + std::to_string(family) +
                        " native=" + std::to_string(evidence.nativeFaultGpr[family]) +
                        " vm=" + std::to_string(evidence.vmFaultGpr[family]) +
                        " initial=" + std::to_string(expectedGpr) + ")";
                    return result;
                }
            }
            // RF (Resume Flag) is excluded: real hardware sets it
            // automatically in the CONTEXT/trap frame whenever any
            // fault-class exception is delivered, purely as a "don't
            // re-trigger an instruction breakpoint on resume" artifact of
            // fault delivery itself -- it says nothing about whether the
            // guest's own architectural state was disturbed, and the VM's
            // software-tracked virtualFlags never models it (see
            // VM_FLAG_PUSH_CLEARED_MASK in vm_isa.h for the same exclusion
            // elsewhere). Comparing it here would fail every real hardware
            // fault regardless of correctness.
            constexpr uint64_t kFaultRflagsMask =
                static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK) & ~static_cast<uint64_t>(VM_FLAG_RF);
            const uint64_t expectedFaultRflags = request.initialRflags & kFaultRflagsMask;
            if ((evidence.nativeFaultRflags & kFaultRflagsMask) != expectedFaultRflags ||
                (evidence.vmFaultRflags & kFaultRflagsMask) != expectedFaultRflags) {
                result.error = "native differential fault-time RFLAGS diverged from the "
                    "pristine input (native=" + std::to_string(evidence.nativeFaultRflags) +
                    " vm=" + std::to_string(evidence.vmFaultRflags) + " initial=" +
                    std::to_string(expectedFaultRflags) + ")";
                return result;
            }
            // Same first-instruction property lets the native fault EIP be
            // pinned exactly: the faulting instruction (including any
            // prefix bytes) is always the corpus's first byte, so the
            // exception address is a fixed, corpus-independent offset from
            // that start -- 0 for DIV/IDIV and for the one-byte 0xCC INT3;
            // measured (not textbook-assumed) behavior for the two-byte
            // "CD 03" INT n form is that Windows' vector-3 trap handler
            // still reports (instruction-end - 1), i.e. offset 1, because it
            // does not distinguish which encoding triggered vector 3.
            // config.expectedNativeFaultOffset tells us which this corpus
            // expects.
            if (evidence.nativeFaultOffset != config.expectedNativeFaultOffset) {
                result.error = "native differential fault EIP is not where this encoding's "
                    "architectural rule requires (nativeFaultOffset=" +
                    std::to_string(evidence.nativeFaultOffset) + " expected=" +
                    std::to_string(config.expectedNativeFaultOffset) + ")";
                return result;
            }
            ++result.casesVerified;
            continue;
        }
        if (nativeRaisedFault || vmRaisedFault) {
            result.error = "native differential corpus raised an exception or VM fault";
            return result;
        }
        if (!IsCompleteArchitecturalSnapshot(evidence.nativeState, config.memorySize) ||
            !IsCompleteArchitecturalSnapshot(evidence.vmState, config.memorySize)) {
            result.error = "native differential evidence lacks complete flags or memory snapshots";
            return result;
        }
        // The native half must use a real CALL/RET pair.  Its captured SP is
        // therefore one return-address slot (plus x86 RET imm16 cleanup) above
        // the logical function-body SP retained by the VM.  Validate that
        // relationship exactly instead of either comparing unlike states or
        // ignoring SP balance.
        const uint64_t pointerSize =
            architecture == VMNativeDifferentialArchitecture::X64 ? 8u : 4u;
        const uint64_t stackMask =
            architecture == VMNativeDifferentialArchitecture::X64
                ? (std::numeric_limits<uint64_t>::max)() : 0xFFFFFFFFULL;
        const uint64_t expectedNativeSp =
            (evidence.vmState.gpr[4] + pointerSize +
                translation.returnStackCleanup) & stackMask;
        const uint64_t nativeSp = evidence.nativeState.gpr[4] & stackMask;
        if (nativeSp != expectedNativeSp) {
            std::ostringstream detail;
            detail << "native differential stack-balance mismatch"
                   << " native_sp=0x" << std::hex << nativeSp
                   << " vm_logical_sp=0x" << evidence.vmState.gpr[4]
                   << " expected_native_sp=0x" << expectedNativeSp
                   << " return_cleanup=0x" << translation.returnStackCleanup;
            result.error = detail.str();
            return result;
        }
        for (uint8_t family = 0; family < 16u; ++family) {
            if (family == 4u) continue;
            if (evidence.nativeState.gpr[family] == evidence.vmState.gpr[family]) {
                continue;
            }
            std::ostringstream detail;
            detail << "native differential complete GPR mismatch"
                   << " family=" << std::dec << static_cast<unsigned>(family)
                   << " native=0x" << std::hex << evidence.nativeState.gpr[family]
                   << " vm=0x" << evidence.vmState.gpr[family]
                   << " initial=0x" << request.initialGpr[family];
            result.error = detail.str();
            return result;
        }
        const uint64_t architecturalMask = caseObservableRflagsMask;
        if (((evidence.nativeState.rflags ^ evidence.vmState.rflags) &
                architecturalMask) != 0u) {
            std::ostringstream detail;
            detail << "native differential observable architectural RFLAGS mismatch"
                   << " native=0x" << std::hex << evidence.nativeState.rflags
                   << " vm=0x" << evidence.vmState.rflags
                   << " xor=0x" << ((evidence.nativeState.rflags ^
                        evidence.vmState.rflags) & architecturalMask)
                   << " mask=0x" << architecturalMask;
            result.error = detail.str();
            return result;
        }
        if (evidence.nativeState.memory != evidence.vmState.memory) {
            const auto mismatch = std::mismatch(
                evidence.nativeState.memory.begin(), evidence.nativeState.memory.end(),
                evidence.vmState.memory.begin());
            std::ostringstream detail;
            detail << "native differential memory side-effect mismatch";
            if (mismatch.first != evidence.nativeState.memory.end()) {
                const size_t offset = static_cast<size_t>(
                    mismatch.first - evidence.nativeState.memory.begin());
                detail << " offset=0x" << std::hex << offset
                       << " native=0x" << static_cast<unsigned>(*mismatch.first)
                       << " vm=0x" << static_cast<unsigned>(*mismatch.second);
            }
            result.error = detail.str();
            return result;
        }
        ++result.casesVerified;
    }
    result.success = result.casesVerified == config.corpusCount;
    result.nativeCpuEvidenceVerified = result.success;
    result.synthesizedHandlerEvidenceVerified = result.success;
    return result;
}

std::string Translator::FormatInstructionBytes(const InstructionIR& instruction) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (uint8_t i = 0; i < instruction.length && i < instruction.rawBytes.size(); ++i) {
        if (i != 0) stream << ' ';
        stream << std::setw(2) << static_cast<unsigned>(instruction.rawBytes[i]);
    }
    return stream.str();
}

bool Translator::FailInstruction(const InstructionIR& instruction, const std::string& reason) {
    TranslationFailure failure{};
    failure.address = instruction.address;
    failure.mnemonic = instruction.mnemonicText.empty() ?
        InstructionMnemonicName(instruction.mnemonic) : instruction.mnemonicText;
    failure.bytes = FormatInstructionBytes(instruction);
    failure.reason = reason;
    m_lastFailures.push_back(std::move(failure));
    return false;
}

} // namespace CipherShell
