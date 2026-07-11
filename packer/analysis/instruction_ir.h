#ifndef CS_INSTRUCTION_IR_H
#define CS_INSTRUCTION_IR_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

enum class MachineMode : uint8_t {
    X86,
    X64
};

enum class InstructionEncoding : uint8_t {
    Legacy,
    Vex,
    Evex,
    Xop,
    Mvex,
    ThreeDNow,
    Invalid
};

enum class InstructionSetClass : uint8_t {
    Scalar,
    Sse,
    Avx,
    Avx512,
    X87,
    UnsupportedExtended
};

enum class OperandType : uint8_t {
    None,
    Register,
    Immediate,
    Memory,
    Pointer
};

enum class OperandAction : uint8_t {
    None,
    Read,
    Write,
    ReadWrite,
    ConditionalRead,
    ConditionalWrite,
    ConditionalReadWrite
};

enum class OperandVisibility : uint8_t {
    Explicit,
    Implicit,
    Hidden
};

enum class RegisterClass : uint8_t {
    None,
    GeneralPurpose,
    InstructionPointer,
    Flags,
    Segment,
    X87,
    Mmx,
    Vector,
    Mask,
    Control,
    Debug,
    Other
};

enum class RegisterId : uint16_t {
    None,
    AL, CL, DL, BL, AH, CH, DH, BH,
    SPL, BPL, SIL, DIL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    AX, CX, DX, BX, SP, BP, SI, DI,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    IP, EIP, RIP,
    FLAGS, EFLAGS, RFLAGS,
    ES, CS, SS, DS, FS, GS,
    ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7,
    MM0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
    XMM0, YMM0, ZMM0,
    K0,
    CR0,
    DR0,
    Other,
    Invalid = 0xFFFF
};

struct RegisterInfo {
    RegisterId id = RegisterId::None;
    RegisterClass registerClass = RegisterClass::None;
    uint8_t family = 0xFF;
    uint8_t index = 0xFF;
    uint16_t width = 0;
    uint8_t bitOffset = 0;
    bool zeroExtendsOnWrite = false;
    bool highByte = false;
};

enum class InstructionMnemonic : uint16_t {
    Invalid,
    Nop,
    Mov,
    Movzx,
    Movsx,
    Movsxd,
    Lea,
    Xchg,
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Not,
    Neg,
    Inc,
    Dec,
    Shl,
    Sal,
    Shr,
    Sar,
    Rol,
    Ror,
    Mul,
    Imul,
    Div,
    Idiv,
    Cmp,
    Test,
    Push,
    Pop,
    PushFlags,
    PopFlags,
    Leave,
    SignExtendAccumulator,
    ExtendAccumulator,
    Bt,
    Bts,
    Btr,
    Bswap,
    Clc,
    Stc,
    Cmc,
    Lahf,
    Sahf,
    Jmp,
    Jo,
    Jno,
    Jb,
    Jae,
    Jz,
    Jnz,
    Jbe,
    Ja,
    Js,
    Jns,
    Jp,
    Jnp,
    Jl,
    Jge,
    Jle,
    Jg,
    Call,
    Ret,
    Cmov,
    Setcc,
    Int3,
    Simd,
    FloatingPoint,
    Unsupported
};

enum class InstructionCategory : uint8_t {
    Invalid,
    DataTransfer,
    Arithmetic,
    Logical,
    ShiftRotate,
    Compare,
    Stack,
    UnconditionalBranch,
    ConditionalBranch,
    Call,
    Return,
    ConditionalMove,
    SetCondition,
    Simd,
    FloatingPoint,
    Interrupt,
    System,
    Other
};

enum class BranchKind : uint8_t {
    None,
    Unconditional,
    Call,
    Return,
    Overflow,
    NotOverflow,
    Below,
    AboveOrEqual,
    Equal,
    NotEqual,
    BelowOrEqual,
    Above,
    Sign,
    NotSign,
    Parity,
    NotParity,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
    Indirect
};

struct MemoryOperandIR {
    RegisterId segment = RegisterId::None;
    RegisterId base = RegisterId::None;
    RegisterId index = RegisterId::None;
    RegisterInfo baseInfo{};
    RegisterInfo indexInfo{};
    uint8_t scale = 1;
    int64_t displacement = 0;
    uint16_t width = 0;
    bool hasBase = false;
    bool hasIndex = false;
    bool hasDisplacement = false;
    bool isRipRelative = false;
    bool isImageAddress = false;
    uint64_t resolvedVA = 0;
    uint32_t resolvedRVA = 0;
};

struct OperandIR {
    OperandType type = OperandType::None;
    OperandAction action = OperandAction::None;
    OperandVisibility visibility = OperandVisibility::Explicit;
    uint16_t width = 0;
    RegisterId reg = RegisterId::None;
    RegisterInfo regInfo{};
    uint64_t immediate = 0;
    bool immediateSigned = false;
    bool immediateRelative = false;
    MemoryOperandIR memory{};
};

struct InstructionIR {
    uint64_t address = 0;
    uint32_t rva = 0;
    uint8_t length = 0;
    std::array<uint8_t, 15> rawBytes{};
    InstructionMnemonic mnemonic = InstructionMnemonic::Invalid;
    InstructionCategory category = InstructionCategory::Invalid;
    MachineMode machineMode = MachineMode::X64;
    InstructionEncoding encoding = InstructionEncoding::Invalid;
    InstructionSetClass instructionSet = InstructionSetClass::Scalar;
    uint16_t operandWidth = 0;
    uint16_t stackWidth = 0;
    uint8_t displacementOffset = 0;
    uint8_t displacementSize = 0;
    std::vector<OperandIR> operands;

    BranchKind branchKind = BranchKind::None;
    bool hasBranchTarget = false;
    uint64_t branchTargetVA = 0;
    uint32_t branchTargetRVA = 0;
    bool isIndirectBranch = false;
    bool hasLockPrefix = false;

    uint64_t flagsRead = 0;
    uint64_t flagsWritten = 0;
    uint64_t flagsUndefined = 0;

    std::string mnemonicText;
    std::string formattedOperands;

    bool IsBranch() const;
    bool IsConditionalBranch() const;
    bool IsCall() const;
    bool IsReturn() const;
    bool IsNop() const;
    bool IsInterrupt() const;
};

struct BasicBlock {
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    uint32_t instructionCount = 0;
    std::vector<InstructionIR> instructions;
    std::vector<uint64_t> successors;
    std::vector<uint64_t> predecessors;
    bool isFunctionEntry = false;
    bool isLoopHeader = false;
    bool isHotspot = false;
    uint32_t protectionLevel = 0;
};

struct Function {
    uint64_t entryAddress = 0;
    uint32_t size = 0;
    std::string name;
    std::string discoverySource;
    std::vector<BasicBlock> blocks;
    bool isLeaf = true;
    bool isRecursive = false;
    bool usesSEH = false;
    bool boundaryTrusted = false;
    bool hasExternalInteriorReference = false;
    uint32_t decodedBytes = 0;
    uint32_t assignedLevel = 0;
};

using Instruction = InstructionIR;

RegisterInfo DescribeRegister(RegisterId id);
const char* InstructionMnemonicName(InstructionMnemonic mnemonic);

} // namespace CipherShell

#endif // CS_INSTRUCTION_IR_H
