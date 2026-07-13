#include "disassembler.h"

#include <Zydis/Zydis.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace CipherShell {
namespace {

OperandAction MapOperandAction(ZydisOperandActions actions) {
    const bool read = (actions & (ZYDIS_OPERAND_ACTION_READ | ZYDIS_OPERAND_ACTION_CONDREAD)) != 0;
    const bool write = (actions & (ZYDIS_OPERAND_ACTION_WRITE | ZYDIS_OPERAND_ACTION_CONDWRITE)) != 0;
    const bool conditionalRead = (actions & ZYDIS_OPERAND_ACTION_CONDREAD) != 0;
    const bool conditionalWrite = (actions & ZYDIS_OPERAND_ACTION_CONDWRITE) != 0;
    if (conditionalRead && conditionalWrite) return OperandAction::ConditionalReadWrite;
    if (conditionalRead && write) return OperandAction::ConditionalReadWrite;
    if (read && conditionalWrite) return OperandAction::ConditionalReadWrite;
    if (conditionalRead) return OperandAction::ConditionalRead;
    if (conditionalWrite) return OperandAction::ConditionalWrite;
    if (read && write) return OperandAction::ReadWrite;
    if (read) return OperandAction::Read;
    if (write) return OperandAction::Write;
    return OperandAction::None;
}

OperandVisibility MapVisibility(ZydisOperandVisibility visibility) {
    switch (visibility) {
        case ZYDIS_OPERAND_VISIBILITY_IMPLICIT: return OperandVisibility::Implicit;
        case ZYDIS_OPERAND_VISIBILITY_HIDDEN: return OperandVisibility::Hidden;
        default: return OperandVisibility::Explicit;
    }
}

RegisterId MapRegisterId(ZydisRegister reg) {
    if (reg >= ZYDIS_REGISTER_NONE && reg <= ZYDIS_REGISTER_R15) {
        return static_cast<RegisterId>(static_cast<uint16_t>(reg));
    }
    switch (reg) {
        case ZYDIS_REGISTER_IP: return RegisterId::IP;
        case ZYDIS_REGISTER_EIP: return RegisterId::EIP;
        case ZYDIS_REGISTER_RIP: return RegisterId::RIP;
        case ZYDIS_REGISTER_FLAGS: return RegisterId::FLAGS;
        case ZYDIS_REGISTER_EFLAGS: return RegisterId::EFLAGS;
        case ZYDIS_REGISTER_RFLAGS: return RegisterId::RFLAGS;
        case ZYDIS_REGISTER_ES: return RegisterId::ES;
        case ZYDIS_REGISTER_CS: return RegisterId::CS;
        case ZYDIS_REGISTER_SS: return RegisterId::SS;
        case ZYDIS_REGISTER_DS: return RegisterId::DS;
        case ZYDIS_REGISTER_FS: return RegisterId::FS;
        case ZYDIS_REGISTER_GS: return RegisterId::GS;
        default: break;
    }
    if (reg >= ZYDIS_REGISTER_ST0 && reg <= ZYDIS_REGISTER_ST7) {
        return static_cast<RegisterId>(static_cast<uint16_t>(RegisterId::ST0) +
            static_cast<uint16_t>(reg - ZYDIS_REGISTER_ST0));
    }
    if (reg >= ZYDIS_REGISTER_MM0 && reg <= ZYDIS_REGISTER_MM7) {
        return static_cast<RegisterId>(static_cast<uint16_t>(RegisterId::MM0) +
            static_cast<uint16_t>(reg - ZYDIS_REGISTER_MM0));
    }
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) return RegisterId::XMM0;
    if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) return RegisterId::YMM0;
    if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) return RegisterId::ZMM0;
    if (reg >= ZYDIS_REGISTER_K0 && reg <= ZYDIS_REGISTER_K7) return RegisterId::K0;
    if (reg >= ZYDIS_REGISTER_CR0 && reg <= ZYDIS_REGISTER_CR15) return RegisterId::CR0;
    if (reg >= ZYDIS_REGISTER_DR0 && reg <= ZYDIS_REGISTER_DR15) return RegisterId::DR0;
    return reg == ZYDIS_REGISTER_NONE ? RegisterId::None : RegisterId::Other;
}

RegisterInfo MapRegisterInfo(ZydisRegister reg) {
    RegisterInfo info = DescribeRegister(MapRegisterId(reg));
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_XMM0);
    } else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_YMM0);
    } else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_ZMM0);
    } else if (reg >= ZYDIS_REGISTER_K0 && reg <= ZYDIS_REGISTER_K7) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_K0);
    } else if (reg >= ZYDIS_REGISTER_CR0 && reg <= ZYDIS_REGISTER_CR15) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_CR0);
    } else if (reg >= ZYDIS_REGISTER_DR0 && reg <= ZYDIS_REGISTER_DR15) {
        info.index = static_cast<uint8_t>(reg - ZYDIS_REGISTER_DR0);
    }
    return info;
}

InstructionEncoding MapEncoding(ZydisInstructionEncoding encoding) {
    switch (encoding) {
        case ZYDIS_INSTRUCTION_ENCODING_LEGACY: return InstructionEncoding::Legacy;
        case ZYDIS_INSTRUCTION_ENCODING_VEX: return InstructionEncoding::Vex;
        case ZYDIS_INSTRUCTION_ENCODING_EVEX: return InstructionEncoding::Evex;
        case ZYDIS_INSTRUCTION_ENCODING_XOP: return InstructionEncoding::Xop;
        case ZYDIS_INSTRUCTION_ENCODING_MVEX: return InstructionEncoding::Mvex;
        case ZYDIS_INSTRUCTION_ENCODING_3DNOW: return InstructionEncoding::ThreeDNow;
        default: return InstructionEncoding::Invalid;
    }
}

InstructionSetClass ClassifyInstructionSet(const ZydisDecodedInstruction& decoded) {
    if (decoded.meta.isa_ext == ZYDIS_ISA_EXT_X87) return InstructionSetClass::X87;
    if (decoded.encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX ||
        decoded.encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX ||
        decoded.meta.isa_ext == ZYDIS_ISA_EXT_AVX512EVEX ||
        decoded.meta.isa_ext == ZYDIS_ISA_EXT_AVX512VEX) {
        return InstructionSetClass::Avx512;
    }
    switch (decoded.meta.isa_ext) {
        case ZYDIS_ISA_EXT_AVX: case ZYDIS_ISA_EXT_AVX2:
        case ZYDIS_ISA_EXT_AVX2GATHER: case ZYDIS_ISA_EXT_AVXAES:
        case ZYDIS_ISA_EXT_AVX_IFMA: case ZYDIS_ISA_EXT_AVX_NE_CONVERT:
        case ZYDIS_ISA_EXT_AVX_VNNI: case ZYDIS_ISA_EXT_AVX_VNNI_INT16:
        case ZYDIS_ISA_EXT_AVX_VNNI_INT8: case ZYDIS_ISA_EXT_F16C:
        case ZYDIS_ISA_EXT_FMA: case ZYDIS_ISA_EXT_VAES:
        case ZYDIS_ISA_EXT_VPCLMULQDQ:
            return InstructionSetClass::Avx;
        case ZYDIS_ISA_EXT_SSE: case ZYDIS_ISA_EXT_SSE2:
        case ZYDIS_ISA_EXT_SSE3: case ZYDIS_ISA_EXT_SSE4:
        case ZYDIS_ISA_EXT_SSE4A: case ZYDIS_ISA_EXT_SSSE3:
        case ZYDIS_ISA_EXT_AES: case ZYDIS_ISA_EXT_PCLMULQDQ:
        case ZYDIS_ISA_EXT_SHA: case ZYDIS_ISA_EXT_SHA512:
            return InstructionSetClass::Sse;
        case ZYDIS_ISA_EXT_AMD3DNOW: case ZYDIS_ISA_EXT_AMD3DNOW_PREFETCH:
        case ZYDIS_ISA_EXT_FMA4: case ZYDIS_ISA_EXT_MMX:
        case ZYDIS_ISA_EXT_XOP:
            return InstructionSetClass::UnsupportedExtended;
        default:
            break;
    }
    return InstructionSetClass::Scalar;
}

BranchKind MapConditionMnemonic(ZydisMnemonic mnemonic) {
    switch (mnemonic) {
        case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_CMOVO: case ZYDIS_MNEMONIC_SETO:
            return BranchKind::Overflow;
        case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_CMOVNO: case ZYDIS_MNEMONIC_SETNO:
            return BranchKind::NotOverflow;
        case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_CMOVB: case ZYDIS_MNEMONIC_SETB:
            return BranchKind::Below;
        case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_SETNB:
            return BranchKind::AboveOrEqual;
        case ZYDIS_MNEMONIC_JZ: case ZYDIS_MNEMONIC_CMOVZ: case ZYDIS_MNEMONIC_SETZ:
            return BranchKind::Equal;
        case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_CMOVNZ: case ZYDIS_MNEMONIC_SETNZ:
            return BranchKind::NotEqual;
        case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_SETBE:
            return BranchKind::BelowOrEqual;
        case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_CMOVNBE: case ZYDIS_MNEMONIC_SETNBE:
            return BranchKind::Above;
        case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_CMOVS: case ZYDIS_MNEMONIC_SETS:
            return BranchKind::Sign;
        case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_SETNS:
            return BranchKind::NotSign;
        case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_CMOVP: case ZYDIS_MNEMONIC_SETP:
            return BranchKind::Parity;
        case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_SETNP:
            return BranchKind::NotParity;
        case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_CMOVL: case ZYDIS_MNEMONIC_SETL:
            return BranchKind::Less;
        case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_SETNL:
            return BranchKind::GreaterOrEqual;
        case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_SETLE:
            return BranchKind::LessOrEqual;
        case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_CMOVNLE: case ZYDIS_MNEMONIC_SETNLE:
            return BranchKind::Greater;
        default: return BranchKind::None;
    }
}

InstructionMnemonic MapMnemonic(ZydisMnemonic mnemonic, ZydisInstructionCategory category) {
    switch (mnemonic) {
        case ZYDIS_MNEMONIC_NOP: return InstructionMnemonic::Nop;
        case ZYDIS_MNEMONIC_MOV: return InstructionMnemonic::Mov;
        case ZYDIS_MNEMONIC_MOVZX: return InstructionMnemonic::Movzx;
        case ZYDIS_MNEMONIC_MOVSX: return InstructionMnemonic::Movsx;
        case ZYDIS_MNEMONIC_MOVSXD: return InstructionMnemonic::Movsxd;
        case ZYDIS_MNEMONIC_LEA: return InstructionMnemonic::Lea;
        case ZYDIS_MNEMONIC_XCHG: return InstructionMnemonic::Xchg;
        case ZYDIS_MNEMONIC_ADD: return InstructionMnemonic::Add;
        case ZYDIS_MNEMONIC_ADC: return InstructionMnemonic::Adc;
        case ZYDIS_MNEMONIC_SUB: return InstructionMnemonic::Sub;
        case ZYDIS_MNEMONIC_SBB: return InstructionMnemonic::Sbb;
        case ZYDIS_MNEMONIC_AND: return InstructionMnemonic::And;
        case ZYDIS_MNEMONIC_OR: return InstructionMnemonic::Or;
        case ZYDIS_MNEMONIC_XOR: return InstructionMnemonic::Xor;
        case ZYDIS_MNEMONIC_NOT: return InstructionMnemonic::Not;
        case ZYDIS_MNEMONIC_NEG: return InstructionMnemonic::Neg;
        case ZYDIS_MNEMONIC_INC: return InstructionMnemonic::Inc;
        case ZYDIS_MNEMONIC_DEC: return InstructionMnemonic::Dec;
        case ZYDIS_MNEMONIC_SHL: return InstructionMnemonic::Shl;
        case ZYDIS_MNEMONIC_SHR: return InstructionMnemonic::Shr;
        case ZYDIS_MNEMONIC_SAR: return InstructionMnemonic::Sar;
        case ZYDIS_MNEMONIC_ROL: return InstructionMnemonic::Rol;
        case ZYDIS_MNEMONIC_ROR: return InstructionMnemonic::Ror;
        case ZYDIS_MNEMONIC_MUL: return InstructionMnemonic::Mul;
        case ZYDIS_MNEMONIC_IMUL: return InstructionMnemonic::Imul;
        case ZYDIS_MNEMONIC_DIV: return InstructionMnemonic::Div;
        case ZYDIS_MNEMONIC_IDIV: return InstructionMnemonic::Idiv;
        case ZYDIS_MNEMONIC_CMP: return InstructionMnemonic::Cmp;
        case ZYDIS_MNEMONIC_TEST: return InstructionMnemonic::Test;
        case ZYDIS_MNEMONIC_PUSH: return InstructionMnemonic::Push;
        case ZYDIS_MNEMONIC_POP: return InstructionMnemonic::Pop;
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ:
            return InstructionMnemonic::PushFlags;
        case ZYDIS_MNEMONIC_POPF: case ZYDIS_MNEMONIC_POPFD: case ZYDIS_MNEMONIC_POPFQ:
            return InstructionMnemonic::PopFlags;
        case ZYDIS_MNEMONIC_LEAVE: return InstructionMnemonic::Leave;
        case ZYDIS_MNEMONIC_CWD: case ZYDIS_MNEMONIC_CDQ: case ZYDIS_MNEMONIC_CQO:
            return InstructionMnemonic::SignExtendAccumulator;
        case ZYDIS_MNEMONIC_CBW: case ZYDIS_MNEMONIC_CWDE: case ZYDIS_MNEMONIC_CDQE:
            return InstructionMnemonic::ExtendAccumulator;
        case ZYDIS_MNEMONIC_BT: return InstructionMnemonic::Bt;
        case ZYDIS_MNEMONIC_BTS: return InstructionMnemonic::Bts;
        case ZYDIS_MNEMONIC_BTR: return InstructionMnemonic::Btr;
        case ZYDIS_MNEMONIC_BSWAP: return InstructionMnemonic::Bswap;
        case ZYDIS_MNEMONIC_CLC: return InstructionMnemonic::Clc;
        case ZYDIS_MNEMONIC_STC: return InstructionMnemonic::Stc;
        case ZYDIS_MNEMONIC_CMC: return InstructionMnemonic::Cmc;
        case ZYDIS_MNEMONIC_LAHF: return InstructionMnemonic::Lahf;
        case ZYDIS_MNEMONIC_SAHF: return InstructionMnemonic::Sahf;
        case ZYDIS_MNEMONIC_ENDBR32: case ZYDIS_MNEMONIC_ENDBR64:
            return InstructionMnemonic::Nop;
        case ZYDIS_MNEMONIC_JMP: return InstructionMnemonic::Jmp;
        case ZYDIS_MNEMONIC_CALL: return InstructionMnemonic::Call;
        case ZYDIS_MNEMONIC_RET: return InstructionMnemonic::Ret;
        case ZYDIS_MNEMONIC_INT3: return InstructionMnemonic::Int3;
        default: break;
    }
    switch (category) {
        case ZYDIS_CATEGORY_COND_BR: {
            switch (MapConditionMnemonic(mnemonic)) {
                case BranchKind::Overflow: return InstructionMnemonic::Jo;
                case BranchKind::NotOverflow: return InstructionMnemonic::Jno;
                case BranchKind::Below: return InstructionMnemonic::Jb;
                case BranchKind::AboveOrEqual: return InstructionMnemonic::Jae;
                case BranchKind::Equal: return InstructionMnemonic::Jz;
                case BranchKind::NotEqual: return InstructionMnemonic::Jnz;
                case BranchKind::BelowOrEqual: return InstructionMnemonic::Jbe;
                case BranchKind::Above: return InstructionMnemonic::Ja;
                case BranchKind::Sign: return InstructionMnemonic::Js;
                case BranchKind::NotSign: return InstructionMnemonic::Jns;
                case BranchKind::Parity: return InstructionMnemonic::Jp;
                case BranchKind::NotParity: return InstructionMnemonic::Jnp;
                case BranchKind::Less: return InstructionMnemonic::Jl;
                case BranchKind::GreaterOrEqual: return InstructionMnemonic::Jge;
                case BranchKind::LessOrEqual: return InstructionMnemonic::Jle;
                case BranchKind::Greater: return InstructionMnemonic::Jg;
                default: return InstructionMnemonic::Unsupported;
            }
        }
        case ZYDIS_CATEGORY_CMOV: return InstructionMnemonic::Cmov;
        case ZYDIS_CATEGORY_SETCC: return InstructionMnemonic::Setcc;
        case ZYDIS_CATEGORY_X87_ALU: case ZYDIS_CATEGORY_FCMOV:
            return InstructionMnemonic::FloatingPoint;
        case ZYDIS_CATEGORY_SSE: case ZYDIS_CATEGORY_AVX: case ZYDIS_CATEGORY_AVX2:
        case ZYDIS_CATEGORY_AVX512: case ZYDIS_CATEGORY_MMX: case ZYDIS_CATEGORY_VEX:
            return InstructionMnemonic::Simd;
        default: return InstructionMnemonic::Unsupported;
    }
}

InstructionCategory MapCategory(const ZydisDecodedInstruction& decoded, InstructionMnemonic mnemonic) {
    switch (decoded.meta.category) {
        case ZYDIS_CATEGORY_CALL: return InstructionCategory::Call;
        case ZYDIS_CATEGORY_RET: return InstructionCategory::Return;
        case ZYDIS_CATEGORY_COND_BR: return InstructionCategory::ConditionalBranch;
        case ZYDIS_CATEGORY_UNCOND_BR: return InstructionCategory::UnconditionalBranch;
        case ZYDIS_CATEGORY_PUSH: case ZYDIS_CATEGORY_POP: return InstructionCategory::Stack;
        case ZYDIS_CATEGORY_CMOV: return InstructionCategory::ConditionalMove;
        case ZYDIS_CATEGORY_SETCC: return InstructionCategory::SetCondition;
        case ZYDIS_CATEGORY_INTERRUPT: return InstructionCategory::Interrupt;
        case ZYDIS_CATEGORY_X87_ALU: case ZYDIS_CATEGORY_FCMOV: return InstructionCategory::FloatingPoint;
        case ZYDIS_CATEGORY_SSE: case ZYDIS_CATEGORY_AVX: case ZYDIS_CATEGORY_AVX2:
        case ZYDIS_CATEGORY_AVX512: case ZYDIS_CATEGORY_MMX: case ZYDIS_CATEGORY_VEX:
            return InstructionCategory::Simd;
        case ZYDIS_CATEGORY_SYSTEM: case ZYDIS_CATEGORY_SYSCALL: case ZYDIS_CATEGORY_SYSRET:
            return InstructionCategory::System;
        default: break;
    }
    switch (mnemonic) {
        case InstructionMnemonic::Mov: case InstructionMnemonic::Movzx:
        case InstructionMnemonic::Movsx: case InstructionMnemonic::Movsxd:
        case InstructionMnemonic::Lea: case InstructionMnemonic::Xchg:
        case InstructionMnemonic::ExtendAccumulator: case InstructionMnemonic::Bswap:
        case InstructionMnemonic::Lahf: case InstructionMnemonic::Sahf:
            return InstructionCategory::DataTransfer;
        case InstructionMnemonic::Add: case InstructionMnemonic::Adc:
        case InstructionMnemonic::Sub: case InstructionMnemonic::Sbb:
        case InstructionMnemonic::Neg: case InstructionMnemonic::Inc:
        case InstructionMnemonic::Dec: case InstructionMnemonic::Mul:
        case InstructionMnemonic::Imul: case InstructionMnemonic::Div:
        case InstructionMnemonic::Idiv:
        case InstructionMnemonic::SignExtendAccumulator:
            return InstructionCategory::Arithmetic;
        case InstructionMnemonic::And: case InstructionMnemonic::Or:
        case InstructionMnemonic::Xor: case InstructionMnemonic::Not:
            return InstructionCategory::Logical;
        case InstructionMnemonic::Shl: case InstructionMnemonic::Sal:
        case InstructionMnemonic::Shr: case InstructionMnemonic::Sar:
        case InstructionMnemonic::Rol: case InstructionMnemonic::Ror:
            return InstructionCategory::ShiftRotate;
        case InstructionMnemonic::Cmp: case InstructionMnemonic::Test:
            return InstructionCategory::Compare;
        case InstructionMnemonic::Bt: case InstructionMnemonic::Bts:
        case InstructionMnemonic::Btr: return InstructionCategory::Logical;
        case InstructionMnemonic::PushFlags: case InstructionMnemonic::PopFlags:
        case InstructionMnemonic::Leave: return InstructionCategory::Stack;
        case InstructionMnemonic::Clc: case InstructionMnemonic::Stc:
        case InstructionMnemonic::Cmc: case InstructionMnemonic::Nop:
            return InstructionCategory::Other;
        default: return InstructionCategory::Other;
    }
}

BranchKind DetermineBranchKind(const ZydisDecodedInstruction& decoded) {
    if (decoded.meta.category == ZYDIS_CATEGORY_CALL) return BranchKind::Call;
    if (decoded.meta.category == ZYDIS_CATEGORY_RET) return BranchKind::Return;
    if (decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR) return BranchKind::Unconditional;
    return MapConditionMnemonic(decoded.mnemonic);
}

bool IsIndirectControlFlow(const ZydisDecodedInstruction& decoded,
                           const ZydisDecodedOperand* operands) {
    if (decoded.meta.category != ZYDIS_CATEGORY_CALL &&
        decoded.meta.category != ZYDIS_CATEGORY_UNCOND_BR &&
        decoded.meta.category != ZYDIS_CATEGORY_COND_BR) {
        return false;
    }
    for (uint8_t i = 0; i < decoded.operand_count_visible; ++i) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER ||
            operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            return true;
        }
    }
    return false;
}

} // namespace

Disassembler::Disassembler()
    : m_initialized(false), m_is64Bit(false), m_imageBase(0) {}

Disassembler::~Disassembler() = default;

bool Disassembler::Initialize(bool is64Bit, uint64_t imageBase) {
    m_is64Bit = is64Bit;
    m_imageBase = imageBase;
    m_lastError.clear();
    m_initialized = true;
    return true;
}

void Disassembler::SetError(uint64_t address, const std::string& reason) {
    std::ostringstream oss;
    oss << "Zydis decode failed at RVA 0x" << std::hex << address << ": " << reason;
    m_lastError = oss.str();
}

const std::string& Disassembler::GetLastError() const { return m_lastError; }
bool Disassembler::HasError() const { return !m_lastError.empty(); }

bool Disassembler::MeasureInstructionSpan(
    const uint8_t* code,
    uint32_t availableSize,
    uint64_t baseAddress,
    uint32_t minimumSize,
    uint32_t& span)
{
    span = 0;
    m_lastError.clear();
    if (!m_initialized || !code || minimumSize == 0 || minimumSize > availableSize) {
        SetError(baseAddress, "invalid instruction-span request");
        return false;
    }
    while (span < minimumSize) {
        InstructionIR instruction{};
        if (!DecodeInstruction(code + span, availableSize - span,
                baseAddress + span, instruction)) return false;
        if (instruction.length == 0 || instruction.length > availableSize - span) {
            SetError(baseAddress + span, "decoded instruction exceeds overwrite range");
            return false;
        }
        span += instruction.length;
    }
    return true;
}

bool Disassembler::DecodeInstruction(
    const uint8_t* code,
    uint32_t size,
    uint64_t address,
    InstructionIR& out)
{
    if (!m_initialized || !code || size == 0) {
        SetError(address, "invalid decoder input");
        return false;
    }

    ZydisDecoder decoder;
    const ZydisMachineMode mode = m_is64Bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    const ZydisStackWidth stackWidth = m_is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stackWidth))) {
        SetError(address, "ZydisDecoderInit returned failure");
        return false;
    }

    ZydisDecodedInstruction decoded{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    const ZyanStatus status = ZydisDecoderDecodeFull(
        &decoder, code, static_cast<ZyanUSize>(size), &decoded, operands);
    if (!ZYAN_SUCCESS(status) || decoded.length == 0 || decoded.length > out.rawBytes.size()) {
        std::ostringstream reason;
        reason << "status=0x" << std::hex << static_cast<uint32_t>(status);
        SetError(address, reason.str());
        return false;
    }

    out = InstructionIR{};
    out.address = address;
    if (address > std::numeric_limits<uint32_t>::max()) {
        SetError(address, "instruction address is outside PE RVA range");
        return false;
    }
    out.rva = static_cast<uint32_t>(address);
    const uint64_t runtimeAddress = m_imageBase ? m_imageBase + address : address;
    out.length = decoded.length;
    std::memcpy(out.rawBytes.data(), code, decoded.length);
    out.machineMode = m_is64Bit ? MachineMode::X64 : MachineMode::X86;
    out.encoding = MapEncoding(decoded.encoding);
    out.instructionSet = ClassifyInstructionSet(decoded);
    out.addressWidth = decoded.address_width;
    out.operandWidth = decoded.operand_width;
    out.stackWidth = decoded.stack_width;
    out.displacementOffset = decoded.raw.disp.offset;
    out.displacementSize = static_cast<uint8_t>(decoded.raw.disp.size / 8u);
    out.mnemonic = MapMnemonic(decoded.mnemonic, decoded.meta.category);
    if (out.mnemonic == InstructionMnemonic::Unsupported) {
        if (out.instructionSet == InstructionSetClass::X87) {
            out.mnemonic = InstructionMnemonic::FloatingPoint;
        } else if (out.instructionSet == InstructionSetClass::Sse ||
                   out.instructionSet == InstructionSetClass::Avx ||
                   out.instructionSet == InstructionSetClass::Avx512) {
            out.mnemonic = InstructionMnemonic::Simd;
        }
    }
    out.category = MapCategory(decoded, out.mnemonic);
    out.branchKind = DetermineBranchKind(decoded);
    out.isIndirectBranch = IsIndirectControlFlow(decoded, operands);
    out.hasLockPrefix = (decoded.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
    if (out.isIndirectBranch) out.branchKind = BranchKind::Indirect;

    const char* mnemonicText = ZydisMnemonicGetString(decoded.mnemonic);
    out.mnemonicText = mnemonicText ? mnemonicText : "invalid";

    if (decoded.cpu_flags) {
        out.flagsRead = decoded.cpu_flags->tested;
        out.flagsWritten = decoded.cpu_flags->modified |
            decoded.cpu_flags->set_0 | decoded.cpu_flags->set_1;
        out.flagsUndefined = decoded.cpu_flags->undefined;
    }

    out.operands.reserve(decoded.operand_count);
    for (uint8_t i = 0; i < decoded.operand_count; ++i) {
        const ZydisDecodedOperand& source = operands[i];
        OperandIR operand{};
        operand.action = MapOperandAction(source.actions);
        operand.visibility = MapVisibility(source.visibility);
        operand.width = source.size;
        switch (source.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                operand.type = OperandType::Register;
                operand.reg = MapRegisterId(source.reg.value);
                operand.regInfo = MapRegisterInfo(source.reg.value);
                break;
            case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
                operand.type = OperandType::Immediate;
                operand.immediateSigned = source.imm.is_signed != 0;
                operand.immediateRelative = source.imm.is_relative != 0;
                operand.immediate = source.imm.is_signed
                    ? static_cast<uint64_t>(source.imm.value.s)
                    : source.imm.value.u;
                if (operand.immediateRelative &&
                    (out.IsBranch() || out.IsCall())) {
                    ZyanU64 absolute = 0;
                    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &decoded, &source, runtimeAddress, &absolute))) {
                        SetError(address, "relative control-flow target cannot be resolved to a PE RVA");
                        return false;
                    }
                    const uint64_t targetRVA = m_imageBase ? absolute - m_imageBase : absolute;
                    if ((m_imageBase && absolute < m_imageBase) ||
                        targetRVA > std::numeric_limits<uint32_t>::max()) {
                        SetError(address, "relative control-flow target is outside the PE RVA range");
                        return false;
                    }
                    out.hasBranchTarget = true;
                    out.branchTargetRVA = static_cast<uint32_t>(targetRVA);
                    out.branchTargetVA = absolute;
                }
                break;
            }
            case ZYDIS_OPERAND_TYPE_MEMORY: {
                operand.type = OperandType::Memory;
                operand.memory.segment = MapRegisterId(source.mem.segment);
                operand.memory.base = MapRegisterId(source.mem.base);
                operand.memory.index = MapRegisterId(source.mem.index);
                operand.memory.baseInfo = MapRegisterInfo(source.mem.base);
                operand.memory.indexInfo = MapRegisterInfo(source.mem.index);
                operand.memory.scale = source.mem.scale ? source.mem.scale : 1;
                operand.memory.displacement = source.mem.disp.value;
                operand.memory.width = source.size;
                operand.memory.hasBase = source.mem.base != ZYDIS_REGISTER_NONE;
                operand.memory.hasIndex = source.mem.index != ZYDIS_REGISTER_NONE;
                operand.memory.hasDisplacement = source.mem.disp.has_displacement != 0;
                operand.memory.isRipRelative = source.mem.base == ZYDIS_REGISTER_RIP ||
                    source.mem.base == ZYDIS_REGISTER_EIP;
                if (operand.memory.isRipRelative) {
                    ZyanU64 absolute = 0;
                    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &decoded, &source, runtimeAddress, &absolute))) {
                        SetError(address, "RIP-relative memory target cannot be resolved to a PE RVA");
                        return false;
                    }
                    const uint64_t targetRVA = m_imageBase ? absolute - m_imageBase : absolute;
                    if ((m_imageBase && absolute < m_imageBase) ||
                        targetRVA > std::numeric_limits<uint32_t>::max()) {
                        SetError(address, "RIP-relative memory target is outside the PE RVA range");
                        return false;
                    }
                    operand.memory.resolvedRVA = static_cast<uint32_t>(targetRVA);
                    operand.memory.resolvedVA = absolute;
                    operand.memory.isImageAddress = true;
                } else if (!operand.memory.hasBase && !operand.memory.hasIndex &&
                           operand.memory.hasDisplacement && m_imageBase) {
                    const uint64_t absolute = static_cast<uint32_t>(source.mem.disp.value);
                    if (absolute >= m_imageBase && absolute - m_imageBase <=
                            std::numeric_limits<uint32_t>::max()) {
                        operand.memory.resolvedRVA = static_cast<uint32_t>(absolute - m_imageBase);
                        operand.memory.resolvedVA = absolute;
                        operand.memory.isImageAddress = true;
                    }
                }
                break;
            }
            case ZYDIS_OPERAND_TYPE_POINTER:
                operand.type = OperandType::Pointer;
                operand.immediate = (static_cast<uint64_t>(source.ptr.segment) << 32) | source.ptr.offset;
                break;
            default:
                operand.type = OperandType::None;
                break;
        }
        out.operands.push_back(operand);
    }

    ZydisFormatter formatter;
    if (ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        char text[256]{};
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
                &formatter, &decoded, operands, decoded.operand_count_visible,
                text, sizeof(text), address, nullptr))) {
            const std::string formatted(text);
            const size_t space = formatted.find(' ');
            out.formattedOperands = space == std::string::npos ? std::string() : formatted.substr(space + 1);
        }
    }
    return true;
}

std::vector<InstructionIR> Disassembler::Disassemble(
    const uint8_t* code,
    uint32_t size,
    uint64_t baseAddress)
{
    std::vector<InstructionIR> result;
    m_lastError.clear();
    if (!m_initialized || !code || size == 0) {
        SetError(baseAddress, "decoder is not initialized or buffer is empty");
        return result;
    }

    uint32_t offset = 0;
    while (offset < size) {
        InstructionIR instruction{};
        if (!DecodeInstruction(code + offset, size - offset, baseAddress + offset, instruction)) {
            result.clear();
            return result;
        }
        result.push_back(std::move(instruction));
        offset += result.back().length;
    }
    return result;
}

std::vector<BasicBlock> Disassembler::BuildBasicBlocks(
    const std::vector<InstructionIR>& instructions)
{
    std::vector<BasicBlock> blocks;
    if (instructions.empty()) return blocks;

    std::unordered_set<uint64_t> instructionBoundaries;
    std::unordered_set<uint64_t> blockStarts;
    for (const auto& instruction : instructions) instructionBoundaries.insert(instruction.address);
    blockStarts.insert(instructions.front().address);
    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& instruction = instructions[i];
        if (instruction.hasBranchTarget &&
            instructionBoundaries.count(instruction.branchTargetRVA) != 0) {
            blockStarts.insert(instruction.branchTargetRVA);
        }
        if ((instruction.IsBranch() || instruction.IsReturn()) && i + 1 < instructions.size()) {
            blockStarts.insert(instructions[i + 1].address);
        }
    }

    BasicBlock current{};
    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& instruction = instructions[i];
        if (!current.instructions.empty() && blockStarts.count(instruction.address) != 0) {
            current.endAddress = current.instructions.back().address + current.instructions.back().length;
            current.instructionCount = static_cast<uint32_t>(current.instructions.size());
            blocks.push_back(std::move(current));
            current = BasicBlock{};
        }
        if (current.instructions.empty()) current.startAddress = instruction.address;
        current.instructions.push_back(instruction);
        if (instruction.IsBranch() || instruction.IsReturn()) {
            current.endAddress = instruction.address + instruction.length;
            current.instructionCount = static_cast<uint32_t>(current.instructions.size());
            blocks.push_back(std::move(current));
            current = BasicBlock{};
        }
    }
    if (!current.instructions.empty()) {
        current.endAddress = current.instructions.back().address + current.instructions.back().length;
        current.instructionCount = static_cast<uint32_t>(current.instructions.size());
        blocks.push_back(std::move(current));
    }

    std::unordered_map<uint64_t, size_t> byStart;
    for (size_t i = 0; i < blocks.size(); ++i) byStart.emplace(blocks[i].startAddress, i);
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i].instructions.empty()) continue;
        const InstructionIR& last = blocks[i].instructions.back();
        auto addSuccessor = [&](uint64_t address) {
            auto found = byStart.find(address);
            if (found == byStart.end()) return;
            if (std::find(blocks[i].successors.begin(), blocks[i].successors.end(), address) ==
                blocks[i].successors.end()) {
                blocks[i].successors.push_back(address);
                blocks[found->second].predecessors.push_back(blocks[i].startAddress);
            }
        };
        if (last.hasBranchTarget) addSuccessor(last.branchTargetRVA);
        if (!last.IsReturn() &&
            (!last.IsBranch() || last.IsConditionalBranch()) && i + 1 < blocks.size()) {
            addSuccessor(blocks[i + 1].startAddress);
        }
    }
    return blocks;
}

std::vector<Function> Disassembler::DetectFunctions(
    const std::vector<BasicBlock>& blocks,
    const uint8_t*,
    uint32_t)
{
    std::vector<Function> functions;
    if (blocks.empty()) return functions;

    Function current{};
    current.entryAddress = blocks.front().startAddress;
    for (const auto& block : blocks) {
        if (current.blocks.empty()) current.entryAddress = block.startAddress;
        current.blocks.push_back(block);
        for (const auto& instruction : block.instructions) {
            if (instruction.IsCall()) current.isLeaf = false;
        }
        if (!block.instructions.empty() && block.instructions.back().IsReturn()) {
            const uint64_t end = block.endAddress;
            if (end < current.entryAddress || end - current.entryAddress > std::numeric_limits<uint32_t>::max()) {
                m_lastError = "function range exceeds PE RVA limits";
                return {};
            }
            current.size = static_cast<uint32_t>(end - current.entryAddress);
            functions.push_back(std::move(current));
            current = Function{};
        }
    }
    if (!current.blocks.empty()) {
        const uint64_t end = current.blocks.back().endAddress;
        if (end >= current.entryAddress && end - current.entryAddress <= std::numeric_limits<uint32_t>::max()) {
            current.size = static_cast<uint32_t>(end - current.entryAddress);
            functions.push_back(std::move(current));
        }
    }
    return functions;
}

std::string Disassembler::FormatInstruction(const InstructionIR& instruction) const {
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << instruction.rva << ": "
        << instruction.mnemonicText;
    if (!instruction.formattedOperands.empty()) oss << ' ' << instruction.formattedOperands;
    return oss.str();
}

std::vector<Function> Disassembler::AnalyzeCode(
    const uint8_t* code,
    uint32_t size,
    uint64_t baseAddress,
    bool is64Bit)
{
    if (!Initialize(is64Bit, m_imageBase)) return {};
    const auto instructions = Disassemble(code, size, baseAddress);
    if (instructions.empty()) return {};
    const auto blocks = BuildBasicBlocks(instructions);
    return DetectFunctions(blocks, code, size);
}

bool Disassembler::AnalyzeFunctionRange(
    const uint8_t* code,
    uint32_t availableSize,
    uint64_t functionRVA,
    uint32_t trustedSize,
    bool is64Bit,
    Function& function)
{
    function = Function{};
    m_lastError.clear();
    if (!code || availableSize == 0 || trustedSize > availableSize ||
        functionRVA > std::numeric_limits<uint32_t>::max() ||
        !Initialize(is64Bit, m_imageBase)) {
        SetError(functionRVA, "invalid function-range analysis request");
        return false;
    }
    const uint32_t rangeSize = trustedSize ? trustedSize : availableSize;
    std::vector<uint8_t> ownership(rangeSize, 0);
    std::vector<uint32_t> worklist(1, 0);
    std::unordered_map<uint32_t, InstructionIR> decoded;
    bool hasTerminal = false;

    while (!worklist.empty()) {
        uint32_t offset = worklist.back();
        worklist.pop_back();
        if (offset >= rangeSize) {
            SetError(functionRVA + offset, "control-flow target is outside the function range");
            return false;
        }
        while (offset < rangeSize) {
            if (decoded.find(offset) != decoded.end()) break;
            if (ownership[offset] != 0) {
                SetError(functionRVA + offset, "control-flow target enters the middle of an instruction");
                return false;
            }
            InstructionIR instruction{};
            if (!DecodeInstruction(code + offset, rangeSize - offset,
                    functionRVA + offset, instruction)) return false;
            if (instruction.length == 0 || instruction.length > rangeSize - offset) {
                SetError(functionRVA + offset, "instruction exceeds the trusted function range");
                return false;
            }
            for (uint32_t byte = offset; byte < offset + instruction.length; ++byte) {
                if (ownership[byte] != 0) {
                    SetError(functionRVA + offset, "recursive decode produced overlapping instructions");
                    return false;
                }
                ownership[byte] = 1;
            }
            decoded.emplace(offset, instruction);
            const uint32_t fallthrough = offset + instruction.length;

            if (instruction.IsReturn()) {
                hasTerminal = true;
                break;
            }
            if (instruction.IsBranch()) {
                if (instruction.isIndirectBranch) {
                    hasTerminal = true;
                    break;
                }
                if (!instruction.hasBranchTarget || instruction.branchTargetRVA < functionRVA ||
                    instruction.branchTargetRVA >= functionRVA + rangeSize) {
                    if (trustedSize == 0 && !instruction.IsConditionalBranch() &&
                        instruction.hasBranchTarget) {
                        // An unbounded recursive-descent candidate may end in a
                        // direct tail jump to another known/adjacent function.
                        hasTerminal = true;
                        break;
                    }
                    SetError(instruction.address, "direct branch exits the trusted function range");
                    return false;
                }
                const uint32_t targetOffset = static_cast<uint32_t>(
                    instruction.branchTargetRVA - functionRVA);
                worklist.push_back(targetOffset);
                if (!instruction.IsConditionalBranch()) break;
            }
            if (fallthrough >= rangeSize) {
                SetError(instruction.address, "reachable function path falls off its trusted range");
                return false;
            }
            offset = fallthrough;
        }
    }

    if (decoded.empty() || !hasTerminal) {
        SetError(functionRVA, "function has no reachable terminal instruction");
        return false;
    }
    std::vector<InstructionIR> instructions;
    instructions.reserve(decoded.size());
    uint32_t maximumEnd = 0;
    uint32_t decodedBytes = 0;
    for (auto& item : decoded) {
        maximumEnd = (std::max)(maximumEnd, item.first + item.second.length);
        decodedBytes += item.second.length;
        instructions.push_back(std::move(item.second));
    }
    std::sort(instructions.begin(), instructions.end(), [](const auto& left, const auto& right) {
        return left.address < right.address;
    });
    std::unordered_set<uint64_t> boundaries;
    for (const auto& instruction : instructions) boundaries.insert(instruction.address);
    for (const auto& instruction : instructions) {
        if (instruction.hasBranchTarget && !instruction.IsCall() &&
            boundaries.count(instruction.branchTargetRVA) == 0) {
            SetError(instruction.address, "branch target is not a decoded instruction boundary");
            return false;
        }
    }

    function.entryAddress = functionRVA;
    function.size = trustedSize ? trustedSize : maximumEnd;
    function.blocks = BuildBasicBlocks(instructions);
    function.boundaryTrusted = trustedSize != 0;
    function.decodedBytes = decodedBytes;
    function.isLeaf = true;
    for (const auto& instruction : instructions) {
        if (instruction.IsCall()) function.isLeaf = false;
    }
    return !function.blocks.empty();
}

} // namespace CipherShell
