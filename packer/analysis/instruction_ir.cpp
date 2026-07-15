#include "instruction_ir.h"

namespace CipherShell {

bool InstructionIR::IsBranch() const {
    return category == InstructionCategory::UnconditionalBranch ||
           category == InstructionCategory::ConditionalBranch;
}

bool InstructionIR::IsConditionalBranch() const {
    return category == InstructionCategory::ConditionalBranch;
}

bool InstructionIR::IsCall() const { return category == InstructionCategory::Call; }
bool InstructionIR::IsReturn() const { return category == InstructionCategory::Return; }
bool InstructionIR::IsNop() const { return mnemonic == InstructionMnemonic::Nop; }
bool InstructionIR::IsInterrupt() const { return category == InstructionCategory::Interrupt; }

namespace {
RegisterInfo Gpr(RegisterId id, uint8_t family, uint16_t width, uint8_t bitOffset = 0,
                 bool zeroExtend = false, bool highByte = false) {
    RegisterInfo info{};
    info.id = id;
    info.registerClass = RegisterCategory::GeneralPurpose;
    info.family = family;
    info.index = family;
    info.width = width;
    info.bitOffset = bitOffset;
    info.zeroExtendsOnWrite = zeroExtend;
    info.highByte = highByte;
    return info;
}
}

RegisterInfo DescribeRegister(RegisterId id) {
    const uint16_t v = static_cast<uint16_t>(id);
    const uint16_t al = static_cast<uint16_t>(RegisterId::AL);
    const uint16_t ah = static_cast<uint16_t>(RegisterId::AH);
    const uint16_t spl = static_cast<uint16_t>(RegisterId::SPL);
    const uint16_t ax = static_cast<uint16_t>(RegisterId::AX);
    const uint16_t eax = static_cast<uint16_t>(RegisterId::EAX);
    const uint16_t rax = static_cast<uint16_t>(RegisterId::RAX);

    if (v >= al && v <= static_cast<uint16_t>(RegisterId::BL)) {
        return Gpr(id, static_cast<uint8_t>(v - al), 8);
    }
    if (v >= ah && v <= static_cast<uint16_t>(RegisterId::BH)) {
        return Gpr(id, static_cast<uint8_t>(v - ah), 8, 8, false, true);
    }
    if (v >= spl && v <= static_cast<uint16_t>(RegisterId::R15B)) {
        return Gpr(id, static_cast<uint8_t>(4 + v - spl), 8);
    }
    if (v >= ax && v <= static_cast<uint16_t>(RegisterId::R15W)) {
        return Gpr(id, static_cast<uint8_t>(v - ax), 16);
    }
    if (v >= eax && v <= static_cast<uint16_t>(RegisterId::R15D)) {
        return Gpr(id, static_cast<uint8_t>(v - eax), 32, 0, true);
    }
    if (v >= rax && v <= static_cast<uint16_t>(RegisterId::R15)) {
        return Gpr(id, static_cast<uint8_t>(v - rax), 64);
    }

    RegisterInfo info{};
    info.id = id;
    switch (id) {
        case RegisterId::IP: info.registerClass = RegisterCategory::InstructionPointer; info.width = 16; break;
        case RegisterId::EIP: info.registerClass = RegisterCategory::InstructionPointer; info.width = 32; break;
        case RegisterId::RIP: info.registerClass = RegisterCategory::InstructionPointer; info.width = 64; break;
        case RegisterId::FLAGS: info.registerClass = RegisterCategory::Flags; info.width = 16; break;
        case RegisterId::EFLAGS: info.registerClass = RegisterCategory::Flags; info.width = 32; break;
        case RegisterId::RFLAGS: info.registerClass = RegisterCategory::Flags; info.width = 64; break;
        case RegisterId::ES: case RegisterId::CS: case RegisterId::SS:
        case RegisterId::DS: case RegisterId::FS: case RegisterId::GS:
            info.registerClass = RegisterCategory::Segment; info.width = 16; break;
        case RegisterId::ST0: case RegisterId::ST1: case RegisterId::ST2: case RegisterId::ST3:
        case RegisterId::ST4: case RegisterId::ST5: case RegisterId::ST6: case RegisterId::ST7:
            info.registerClass = RegisterCategory::X87;
            info.index = static_cast<uint8_t>(v - static_cast<uint16_t>(RegisterId::ST0));
            info.width = 80;
            break;
        case RegisterId::MM0: case RegisterId::MM1: case RegisterId::MM2: case RegisterId::MM3:
        case RegisterId::MM4: case RegisterId::MM5: case RegisterId::MM6: case RegisterId::MM7:
            info.registerClass = RegisterCategory::Mmx;
            info.index = static_cast<uint8_t>(v - static_cast<uint16_t>(RegisterId::MM0));
            info.width = 64;
            break;
        case RegisterId::XMM0: info.registerClass = RegisterCategory::Vector; info.width = 128; break;
        case RegisterId::YMM0: info.registerClass = RegisterCategory::Vector; info.width = 256; break;
        case RegisterId::ZMM0: info.registerClass = RegisterCategory::Vector; info.width = 512; break;
        case RegisterId::K0: info.registerClass = RegisterCategory::Mask; info.width = 64; break;
        case RegisterId::CR0: info.registerClass = RegisterCategory::Control; break;
        case RegisterId::DR0: info.registerClass = RegisterCategory::Debug; break;
        case RegisterId::Other: info.registerClass = RegisterCategory::Other; break;
        default: break;
    }
    return info;
}

const char* InstructionMnemonicName(InstructionMnemonic mnemonic) {
    switch (mnemonic) {
        case InstructionMnemonic::Nop: return "nop";
        case InstructionMnemonic::Mov: return "mov";
        case InstructionMnemonic::Movzx: return "movzx";
        case InstructionMnemonic::Movsx: return "movsx";
        case InstructionMnemonic::Movsxd: return "movsxd";
        case InstructionMnemonic::Lea: return "lea";
        case InstructionMnemonic::Xchg: return "xchg";
        case InstructionMnemonic::Add: return "add";
        case InstructionMnemonic::Adc: return "adc";
        case InstructionMnemonic::Sub: return "sub";
        case InstructionMnemonic::Sbb: return "sbb";
        case InstructionMnemonic::And: return "and";
        case InstructionMnemonic::Or: return "or";
        case InstructionMnemonic::Xor: return "xor";
        case InstructionMnemonic::Not: return "not";
        case InstructionMnemonic::Neg: return "neg";
        case InstructionMnemonic::Inc: return "inc";
        case InstructionMnemonic::Dec: return "dec";
        case InstructionMnemonic::Shl: return "shl";
        case InstructionMnemonic::Sal: return "sal";
        case InstructionMnemonic::Shr: return "shr";
        case InstructionMnemonic::Sar: return "sar";
        case InstructionMnemonic::Rol: return "rol";
        case InstructionMnemonic::Ror: return "ror";
        case InstructionMnemonic::Mul: return "mul";
        case InstructionMnemonic::Imul: return "imul";
        case InstructionMnemonic::Div: return "div";
        case InstructionMnemonic::Idiv: return "idiv";
        case InstructionMnemonic::Cmp: return "cmp";
        case InstructionMnemonic::Test: return "test";
        case InstructionMnemonic::Push: return "push";
        case InstructionMnemonic::Pop: return "pop";
        case InstructionMnemonic::PushFlags: return "pushf";
        case InstructionMnemonic::PopFlags: return "popf";
        case InstructionMnemonic::Leave: return "leave";
        case InstructionMnemonic::SignExtendAccumulator: return "cwd/cdq/cqo";
        case InstructionMnemonic::ExtendAccumulator: return "cbw/cwde/cdqe";
        case InstructionMnemonic::Bt: return "bt";
        case InstructionMnemonic::Bts: return "bts";
        case InstructionMnemonic::Btr: return "btr";
        case InstructionMnemonic::Bswap: return "bswap";
        case InstructionMnemonic::Clc: return "clc";
        case InstructionMnemonic::Stc: return "stc";
        case InstructionMnemonic::Cmc: return "cmc";
        case InstructionMnemonic::Lahf: return "lahf";
        case InstructionMnemonic::Sahf: return "sahf";
        case InstructionMnemonic::Jmp: return "jmp";
        case InstructionMnemonic::Call: return "call";
        case InstructionMnemonic::Ret: return "ret";
        case InstructionMnemonic::Cmov: return "cmovcc";
        case InstructionMnemonic::Setcc: return "setcc";
        case InstructionMnemonic::Int3: return "int3";
        case InstructionMnemonic::Simd: return "simd";
        case InstructionMnemonic::FloatingPoint: return "x87";
        case InstructionMnemonic::Unsupported: return "unsupported";
        default: return "invalid";
    }
}

} // namespace CipherShell
