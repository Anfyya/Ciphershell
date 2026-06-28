/**
 * CipherShell 反汇编引擎
 * 封装 Zydis 库，提供统一的反汇编接口
 */

#ifndef CS_DISASSEMBLER_H
#define CS_DISASSEMBLER_H

#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace CipherShell {

// ============================================================================
// 指令信息
// ============================================================================

struct Instruction {
    uint64_t    address;            // 指令地址（RVA）
    uint32_t    length;             // 指令长度
    uint8_t     bytes[15];          // 原始字节（最大 15 字节）
    std::string mnemonic;           // 助记符
    std::string operands;           // 操作数字符串
    
    // 分类
    bool        isBranch;           // 是否分支指令
    bool        isCall;             // 是否调用指令
    bool        isReturn;           // 是否返回指令
    bool        isNop;              // 是否 NOP
    bool        isInterrupt;        // 是否中断指令
    
    // 分支目标
    bool        hasTarget;          // 是否有目标地址
    uint64_t    targetAddress;      // 目标地址
    bool        isConditional;      // 是否条件分支
    bool        isIndirect;         // 是否间接跳转
    
    // 操作数信息
    int         operandCount;       // 操作数数量
    uint8_t     regRead[4];         // 读取的寄存器
    uint8_t     regWrite[4];        // 写入的寄存器
    bool        readsMemory;        // 是否读内存
    bool        writesMemory;       // 是否写内存
};

// ============================================================================
// 基本块
// ============================================================================

struct BasicBlock {
    uint64_t    startAddress;       // 起始地址
    uint64_t    endAddress;         // 结束地址
    uint32_t    instructionCount;   // 指令数量
    std::vector<Instruction> instructions;
    
    // 控制流边
    std::vector<uint64_t> successors;       // 后继块地址
    std::vector<uint64_t> predecessors;     // 前驱块地址
    
    // 标记
    bool        isFunctionEntry;    // 是否函数入口
    bool        isLoopHeader;       // 是否循环头
    bool        isHotspot;          // 是否热点
    uint32_t    protectionLevel;    // 分配的保护等级
};

// ============================================================================
// 函数信息
// ============================================================================

struct Function {
    uint64_t    entryAddress;       // 入口地址
    uint32_t    size;               // 函数大小
    std::string name;               // 函数名（如果有符号）
    std::vector<BasicBlock> blocks; // 基本块列表
    
    // 属性
    bool        isLeaf;             // 是否叶子函数
    bool        isRecursive;        // 是否递归
    bool        usesSEH;            // 是否使用 SEH
    uint32_t    assignedLevel;      // 分配的保护等级
};

// ============================================================================
// 反汇编配置
// ============================================================================

struct DisasmConfig {
    bool        linearSweep;        // 线性扫描模式
    bool        recursiveDescent;   // 递归下降模式
    bool        followCalls;        // 跟踪调用
    bool        detectFunctions;    // 自动检测函数
    uint32_t    maxInstructions;    // 最大指令数
    uint64_t    startAddress;       // 起始地址
    uint64_t    endAddress;         // 结束地址

    DisasmConfig() :
        linearSweep(false),
        recursiveDescent(true),
        followCalls(false),
        detectFunctions(true),
        maxInstructions(100000),
        startAddress(0),
        endAddress(0) {}
};

// ============================================================================
// 反汇编器类
// ============================================================================

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    /**
     * 初始化反汇编器
     * @param is64Bit 是否 64 位模式
     * @return 是否成功
     */
    bool Initialize(bool is64Bit);

    /**
     * 反汇编代码块
     * @param code 代码数据
     * @param size 代码大小
     * @param baseAddress 基地址
     * @return 指令列表
     */
    std::vector<Instruction> Disassemble(
        const uint8_t* code,
        uint32_t size,
        uint64_t baseAddress
    );

    /**
     * 构建基本块
     * @param instructions 指令列表
     * @return 基本块列表
     */
    std::vector<BasicBlock> BuildBasicBlocks(
        const std::vector<Instruction>& instructions
    );

    /**
     * 识别函数
     * @param blocks 基本块列表
     * @param codeData 代码数据
     * @param codeSize 代码大小
     * @return 函数列表
     */
    std::vector<Function> DetectFunctions(
        const std::vector<BasicBlock>& blocks,
        const uint8_t* codeData,
        uint32_t codeSize
    );

    /**
     * 获取指令字符串
     * @param instr 指令
     * @return 格式化的字符串
     */
    std::string FormatInstruction(const Instruction& instr);

    /**
     * 分析代码段，识别函数
     * @param code 代码数据
     * @param size 代码大小
     * @param baseAddress 基地址
     * @param is64Bit 是否 64 位
     * @return 函数列表
     */
    std::vector<Function> AnalyzeCode(const uint8_t* code, uint32_t size, uint64_t baseAddress, bool is64Bit);

private:
    // 内部反汇编
    bool DecodeInstruction(const uint8_t* code, uint32_t size, uint64_t address, Instruction& instr);
    
    // 分支分析
    bool AnalyzeBranch(Instruction& instr);
    bool IsConditionalBranch(uint8_t opcode);
    bool IsUnconditionalJump(uint8_t opcode);
    bool IsCall(uint8_t opcode);
    bool IsReturn(uint8_t opcode);
    
    // 辅助函数
    bool IsPrologue(const uint8_t* code, uint32_t size);
    bool IsEpilogue(const uint8_t* code, uint32_t size);
    uint32_t GetInstructionLength(const uint8_t* code, uint32_t maxSize);

    // 成员变量
    bool m_initialized;
    bool m_is64Bit;
};

} // namespace CipherShell

#endif // CS_DISASSEMBLER_H
