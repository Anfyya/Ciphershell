/**
 * CipherShell x86/x64 → Mirage Bytecode 转译器
 * 将原生指令翻译为 VM 字节码
 */

#ifndef CS_TRANSLATOR_H
#define CS_TRANSLATOR_H

#include "../analysis/disassembler.h"
#include "../../stub/vm/vm_context.h"
#include <cstdint>
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// 寄存器映射
// ============================================================================

// x86 寄存器 → 虚拟寄存器映射
enum class X86Register : uint8_t {
    EAX = 0, ECX = 1, EDX = 2, EBX = 3,
    ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    R8  = 8, R9  = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    UNKNOWN = 0xFF
};

// ============================================================================
// 字节码指令
// ============================================================================

struct BytecodeInstr {
    uint8_t     opcode;             // VM opcode
    uint8_t     regDst;             // 目标寄存器
    uint8_t     regSrc;             // 源寄存器
    uint8_t     regExtra;           // 额外寄存器
    uint64_t    immediate;          // 立即数
    uint32_t    jumpTarget;         // 跳转目标（bytecode偏移）
    bool        isJump;             // 是否跳转指令
    bool        needsRelocation;    // 需要重定位
};

// ============================================================================
// 翻译结果
// ============================================================================

struct TranslationResult {
    std::vector<BytecodeInstr>  instructions;      // 字节码指令
    std::vector<uint8_t>        bytecode;           // 最终字节码流
    std::unordered_map<uint64_t, uint32_t> addrMap; // 原始地址 → bytecode偏移映射
    uint32_t                    totalSize;          // 字节码总大小
    uint32_t                    registerCount;      // 使用的寄存器数
};

// ============================================================================
// 翻译配置
// ============================================================================

struct TranslationConfig {
    uint32_t    virtualRegisterCount;   // 虚拟寄存器数量
    bool        enableRegisterRemapping;// 寄存器重映射
    bool        enableOpcodeRandomization;// Opcode 随机化
    bool        enableInstructionMerging;// 指令合并
    bool        enableJunkInsertion;     // 插入垃圾指令
    uint32_t    junkRatio;              // 垃圾指令比例

    TranslationConfig() :
        virtualRegisterCount(24),
        enableRegisterRemapping(true),
        enableOpcodeRandomization(true),
        enableInstructionMerging(false),
        enableJunkInsertion(true),
        junkRatio(10) {}
};

// ============================================================================
// 转译器类
// ============================================================================

class Translator {
public:
    Translator();
    ~Translator();

    /**
     * 初始化转译器
     * @param config 翻译配置
     * @return 是否成功
     */
    bool Initialize(const TranslationConfig& config);

    /**
     * 翻译函数
     * @param func 函数信息
     * @return 翻译结果
     */
    TranslationResult TranslateFunction(const Function& func);

    /**
     * 翻译基本块
     * @param block 基本块
     * @param baseOffset 字节码基偏移
     * @return 翻译结果
     */
    TranslationResult TranslateBlock(const BasicBlock& block, uint32_t baseOffset);

    /**
     * 生成最终字节码
     * @param result 翻译结果
     * @param key 加密密钥
     * @param nonce nonce
     * @return 加密后的字节码
     */
    std::vector<uint8_t> GenerateBytecode(
        const TranslationResult& result,
        const uint8_t* key,
        const uint8_t* nonce
    );

    /**
     * 获取寄存器映射
     * @return 寄存器映射表
     */
    std::unordered_map<uint8_t, uint8_t> GetRegisterMap() const;

    /**
     * 生成 Opcode 映射表
     * @return Opcode 映射
     */
    std::unordered_map<uint8_t, uint8_t> GenerateOpcodeMap();

private:
    // 指令翻译
    bool TranslateInstruction(const Instruction& instr, BytecodeInstr& outInstr);

    // 特定指令翻译
    bool TranslateMov(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateAdd(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateSub(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateCmp(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslatePush(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslatePop(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateJump(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateCall(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateRet(const Instruction& instr, BytecodeInstr& outInstr);
    bool TranslateNop(const Instruction& instr, BytecodeInstr& outInstr);

    // 寄存器映射
    uint8_t MapRegister(uint8_t x86Reg);

    // 字节码编码
    void EncodeInstruction(const BytecodeInstr& instr, std::vector<uint8_t>& bytecode);
    void EncodeOpcode(uint8_t opcode, std::vector<uint8_t>& bytecode);
    void EncodeRegister(uint8_t reg, std::vector<uint8_t>& bytecode);
    void EncodeImmediate32(uint32_t imm, std::vector<uint8_t>& bytecode);
    void EncodeImmediate64(uint64_t imm, std::vector<uint8_t>& bytecode);

    // 字节码加密
    void EncryptBytecode(std::vector<uint8_t>& bytecode, const uint8_t* key, const uint8_t* nonce);

    // 垃圾指令生成
    BytecodeInstr GenerateJunkInstruction();

    // 辅助函数
    uint8_t GetOpcodeForInstruction(const std::string& mnemonic);
    bool IsJumpInstruction(const std::string& mnemonic);

    // BUG 1 修复：计算指令编码后的实际字节长度（用于两遍偏移量计算）
    uint32_t CalculateEncodedSize(const BytecodeInstr& instr);

    // 成员变量
    TranslationConfig m_config;
    std::unordered_map<uint8_t, uint8_t> m_registerMap;  // x86 reg -> VM reg
    std::unordered_map<uint8_t, uint8_t> m_opcodeMap;    // standard op -> randomized op
    uint32_t m_nextVirtualReg;
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_TRANSLATOR_H
