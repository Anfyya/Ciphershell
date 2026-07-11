#ifndef CS_TRANSLATOR_H
#define CS_TRANSLATOR_H

#include "../analysis/disassembler.h"
#include "../vm/vm_schema.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace CipherShell {

static constexpr uint8_t VM_REG_INVALID = VM_REGISTER_INVALID;

struct TranslationFailure {
    uint64_t address = 0;
    std::string mnemonic;
    std::string bytes;
    std::string reason;
};

struct VMBridgeRequest {
    uint32_t instructionIndex = 0;
    uint32_t functionRVA = 0;
    InstructionIR instruction{};
    uint8_t hiddenNativeRegister = 0xFF;
    bool usesAvx = false;
    bool usesX87 = false;
};

struct TranslationResult {
    std::vector<BytecodeInstr> instructions;
    std::vector<uint8_t> bytecode;
    std::unordered_map<uint64_t, uint32_t> addrMap;
    uint32_t totalSize = 0;
    uint32_t registerCount = 0;
    uint32_t returnStackCleanup = 0;
    bool usesSimd = false;
    bool usesAvx = false;
    bool usesX87 = false;
    bool success = false;
    std::vector<VMBridgeRequest> bridgeRequests;
    std::vector<TranslationFailure> failures;
};

struct TranslationConfig {
    uint32_t virtualRegisterCount = 32;
    bool enableSimdBridge = true;
    bool enableX87Bridge = true;
    VM_CALL_ABI x86CallAbi = VM_ABI_X86_AUTO;
    std::unordered_set<uint32_t> importThunkRVAs;
};

class Translator {
public:
    Translator();
    ~Translator();

    bool Initialize(const TranslationConfig& config);

    TranslationResult TranslateFunction(const Function& function);
    TranslationResult TranslateBlock(const BasicBlock& block, uint32_t baseOffset);

    std::vector<uint8_t> GenerateBytecode(const TranslationResult& result);

    std::unordered_map<uint8_t, uint8_t> GetRegisterMap() const;
    std::unordered_map<uint8_t, uint8_t> GetOpcodeMap() const;
    void SetOpcodeMap(const std::unordered_map<uint8_t, uint8_t>& opcodeMap);
    void SetRegisterMap(const std::unordered_map<uint8_t, uint8_t>& registerMap);
    const std::vector<TranslationFailure>& GetLastFailures() const;

private:
    bool TranslateInstruction(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateMove(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateMoveExtend(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateLea(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateXchg(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateBinary(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateUnary(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateShiftRotate(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateMultiplyDivide(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateStack(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateBranch(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateCall(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateRet(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateConditionalData(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateBitOperation(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateImplicitScalar(const InstructionIR& instruction, BytecodeInstr& output);
    bool TranslateExtendedBridge(const InstructionIR& instruction, BytecodeInstr& output);

    std::vector<const OperandIR*> SemanticOperands(const InstructionIR& instruction) const;
    bool EncodeRegisterOperand(
        const InstructionIR& instruction,
        const OperandIR& operand,
        uint8_t& vmRegister,
        uint8_t& bitOffset,
        uint16_t& flags,
        bool destination);
    bool EncodeMemoryOperand(
        const InstructionIR& instruction,
        const OperandIR& operand,
        BytecodeInstr& output);
    uint8_t MapRegisterFamily(uint8_t family) const;
    VM_CONDITION MapCondition(BranchKind branchKind) const;
    uint8_t OpcodeForCondition(BranchKind branchKind) const;

    bool FinalizeControlFlow(TranslationResult& result);
    bool ValidateFlagDataflow(const Function& function, uint32_t& terminalReturnStackCleanup);
    bool FailInstruction(const InstructionIR& instruction, const std::string& reason);
    static std::string FormatInstructionBytes(const InstructionIR& instruction);

    TranslationConfig m_config{};
    std::unordered_map<uint8_t, uint8_t> m_registerMap;
    std::unordered_map<uint8_t, uint8_t> m_opcodeMap;
    std::vector<TranslationFailure> m_lastFailures;
    uint64_t m_functionStart = 0;
    uint64_t m_functionEnd = 0;
    bool m_initialized = false;
};

} // namespace CipherShell

#endif // CS_TRANSLATOR_H
