#ifndef CS_TRANSLATOR_H
#define CS_TRANSLATOR_H

#include "../analysis/disassembler.h"
#include "../../stub/vm/vm_context.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

enum class X86Register : uint8_t {
    EAX = 0, ECX = 1, EDX = 2, EBX = 3,
    ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    R8  = 8, R9  = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    UNKNOWN = 0xFF
};

static constexpr uint8_t VM_REG_INVALID = 0xFF;

struct BytecodeInstr {
    uint8_t     opcode;
    uint8_t     regDst;
    uint8_t     regSrc;
    uint8_t     regExtra;
    uint8_t     scale;
    uint8_t     memBaseReg;
    uint8_t     memIndexReg;
    uint8_t     memScale;
    uint8_t     memWidth;
    uint8_t     memoryKind;
    bool        isRipRelative;
    int64_t     memDisp;
    uint64_t    immediate;
    uint32_t    jumpTarget;
    bool        isJump;
    bool        needsRelocation;
};

struct TranslationFailure {
    uint64_t    address;
    std::string mnemonic;
    std::string bytes;
    std::string reason;
};

struct TranslationResult {
    std::vector<BytecodeInstr>  instructions;
    std::vector<uint8_t>        bytecode;
    std::unordered_map<uint64_t, uint32_t> addrMap;
    uint32_t                    totalSize;
    uint32_t                    registerCount;
    bool                        success;
    std::vector<TranslationFailure> failures;
};

struct TranslationConfig {
    uint32_t    virtualRegisterCount;
    bool        enableRegisterRemapping;
    bool        enableOpcodeRandomization;
    bool        enableInstructionMerging;
    bool        enableJunkInsertion;
    uint32_t    junkRatio;

    TranslationConfig() :
        virtualRegisterCount(24),
        enableRegisterRemapping(true),
        enableOpcodeRandomization(true),
        enableInstructionMerging(false),
        enableJunkInsertion(true),
        junkRatio(10) {}
};

class Translator {
public:
    Translator();
    ~Translator();

    bool Initialize(const TranslationConfig& config);

    TranslationResult TranslateFunction(const Function& func);
    TranslationResult TranslateBlock(const BasicBlock& block, uint32_t baseOffset);

    std::vector<uint8_t> GenerateBytecode(
        const TranslationResult& result,
        const uint8_t* key,
        const uint8_t* nonce
    );

    std::unordered_map<uint8_t, uint8_t> GetRegisterMap() const;
    std::unordered_map<uint8_t, uint8_t> GetOpcodeMap() const;
    void SetOpcodeMap(const std::unordered_map<uint8_t, uint8_t>& opcodeMap);
    void SetRegisterMap(const std::unordered_map<uint8_t, uint8_t>& registerMap);
    std::unordered_map<uint8_t, uint8_t> GenerateOpcodeMap();
    const std::vector<TranslationFailure>& GetLastFailures() const;

private:
    bool TranslateInstruction(const Instruction& instr, BytecodeInstr& outInstr);

    bool TranslateMov(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateAdd(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateSub(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateCmp(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateAnd(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateOr(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateTest(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateLea(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslatePush(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslatePop(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateJump(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateCall(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateRet(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateNop(const Instruction& instr, BytecodeInstr& outInstr);

    uint8_t MapRegister(uint8_t x86Reg);

    void EncodeInstruction(const BytecodeInstr& instr, std::vector<uint8_t>& bytecode);
    void EncodeOpcode(uint8_t opcode, std::vector<uint8_t>& bytecode);
    void EncodeRegister(uint8_t reg, std::vector<uint8_t>& bytecode);
    void EncodeImmediate32(uint32_t imm, std::vector<uint8_t>& bytecode);
    void EncodeImmediate64(uint64_t imm, std::vector<uint8_t>& bytecode);
    void EncryptBytecode(std::vector<uint8_t>& bytecode, const uint8_t* key, const uint8_t* nonce);

    BytecodeInstr GenerateJunkInstruction();

    bool FailInstruction(const Instruction& instr, const std::string& reason);
    uint8_t GetOpcodeForInstruction(const std::string& mnemonic);
    bool IsJumpInstruction(const std::string& mnemonic);
    uint32_t CalculateEncodedSize(const BytecodeInstr& instr);

    TranslationConfig m_config;
    std::unordered_map<uint8_t, uint8_t> m_registerMap;
    std::unordered_map<uint8_t, uint8_t> m_opcodeMap;
    std::vector<TranslationFailure> m_lastFailures;
    uint32_t m_nextVirtualReg;
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_TRANSLATOR_H
