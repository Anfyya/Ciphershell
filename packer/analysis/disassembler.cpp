/**
 * CipherShell 反汇编引擎 - 实现
 * 简化的 x86/x64 反汇编器（不依赖 Zydis）
 */

#include "disassembler.h"
#include <cstring>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// x86 指令长度表（简化版）
// ============================================================================

// 单字节指令长度
static const int SINGLE_BYTE_LENGTHS[256] = {
    // 0x00-0x0F
    2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 0,
    // 0x10-0x1F
    2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1,
    // 0x20-0x2F
    2, 2, 2, 2, 1, 1, 0, 1, 2, 2, 2, 2, 1, 1, 0, 1,
    // 0x30-0x3F
    2, 2, 2, 2, 1, 1, 0, 1, 2, 2, 2, 2, 1, 1, 0, 1,
    // 0x40-0x4F (inc/dec registers in 32-bit, REX prefix in 64-bit)
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    // 0x50-0x5F (push/pop registers)
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    // 0x60-0x6F
    0, 0, 2, 2, 0, 0, 0, 0, 5, 5, 2, 2, 0, 0, 0, 0,
    // 0x70-0x7F (conditional jumps)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    // 0x80-0x8F
    0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    // 0x90-0x9F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
    // 0xA0-0xAF
    5, 5, 5, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    // 0xB0-0xBF (mov imm to reg)
    2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 5, 5,
    // 0xC0-0xCF
    0, 0, 3, 1, 0, 0, 0, 0, 0, 1, 3, 1, 0, 5, 0, 1,
    // 0xD0-0xDF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0xE0-0xEF
    2, 2, 2, 2, 1, 1, 1, 1, 5, 5, 0, 2, 1, 1, 1, 1,
    // 0xF0-0xFF
    0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0
};

// ============================================================================
// 构造/析构
// ============================================================================

Disassembler::Disassembler() 
    : m_initialized(false)
    , m_is64Bit(false)
{
}

Disassembler::~Disassembler() {}

// ============================================================================
// 公共接口
// ============================================================================

bool Disassembler::Initialize(bool is64Bit) {
    m_is64Bit = is64Bit;
    m_initialized = true;
    return true;
}

std::vector<Instruction> Disassembler::Disassemble(
    const uint8_t* code,
    uint32_t size,
    uint64_t baseAddress)
{
    std::vector<Instruction> result;

    if (!m_initialized || !code || size == 0) {
        return result;
    }

    uint64_t address = baseAddress;
    uint32_t offset = 0;

    while (offset < size) {
        Instruction instr;
        memset(&instr, 0, sizeof(instr));

        if (!DecodeInstruction(code + offset, size - offset, address, instr)) {
            // 无法解码，跳过这个字节
            offset++;
            address++;
            continue;
        }

        instr.address = address;
        instr.length = GetInstructionLength(code + offset, size - offset);
        if (instr.length == 0) instr.length = 1;  // 最小 1 字节

        memcpy(instr.bytes, code + offset, std::min((uint32_t)15, instr.length));

        // 分析分支
        AnalyzeBranch(instr);

        result.push_back(instr);

        offset += instr.length;
        address += instr.length;
    }

    return result;
}

std::vector<BasicBlock> Disassembler::BuildBasicBlocks(
    const std::vector<Instruction>& instructions)
{
    std::vector<BasicBlock> blocks;

    if (instructions.empty()) {
        return blocks;
    }

    // 收集所有分支目标
    std::vector<uint64_t> branchTargets;
    for (const auto& instr : instructions) {
        if (instr.hasTarget) {
            branchTargets.push_back(instr.targetAddress);
        }
    }

    // 排序并去重
    std::sort(branchTargets.begin(), branchTargets.end());
    branchTargets.erase(std::unique(branchTargets.begin(), branchTargets.end()), branchTargets.end());

    // 构建基本块
    BasicBlock currentBlock;
    currentBlock.startAddress = instructions[0].address;
    currentBlock.instructionCount = 0;

    for (size_t i = 0; i < instructions.size(); i++) {
        const auto& instr = instructions[i];

        // 检查是否需要开始新块
        bool newBlock = false;

        // 如果当前地址是分支目标，开始新块
        if (std::find(branchTargets.begin(), branchTargets.end(), instr.address) != branchTargets.end()) {
            newBlock = true;
        }

        // 如果前一条指令是分支，开始新块
        if (i > 0 && (instructions[i-1].isBranch || instructions[i-1].isCall || instructions[i-1].isReturn)) {
            newBlock = true;
        }

        if (newBlock && currentBlock.instructionCount > 0) {
            currentBlock.endAddress = instructions[i-1].address + instructions[i-1].length;
            blocks.push_back(currentBlock);
            currentBlock = BasicBlock();
            currentBlock.startAddress = instr.address;
            currentBlock.instructionCount = 0;
        }

        currentBlock.instructions.push_back(instr);
        currentBlock.instructionCount++;

        // 如果是分支指令，结束当前块
        if (instr.isBranch || instr.isReturn) {
            currentBlock.endAddress = instr.address + instr.length;
            blocks.push_back(currentBlock);
            currentBlock = BasicBlock();
            if (i + 1 < instructions.size()) {
                currentBlock.startAddress = instructions[i+1].address;
            }
            currentBlock.instructionCount = 0;
        }
    }

    // 处理最后一个块
    if (currentBlock.instructionCount > 0) {
        if (!instructions.empty()) {
            currentBlock.endAddress = instructions.back().address + instructions.back().length;
        }
        blocks.push_back(currentBlock);
    }

    // 建立前后驱关系
    for (size_t i = 0; i < blocks.size(); i++) {
        // 查找后继
        for (const auto& instr : blocks[i].instructions) {
            if (instr.hasTarget) {
                // 查找目标块
                for (size_t j = 0; j < blocks.size(); j++) {
                    if (blocks[j].startAddress == instr.targetAddress) {
                        blocks[i].successors.push_back(instr.targetAddress);
                        blocks[j].predecessors.push_back(blocks[i].startAddress);
                        break;
                    }
                }
            }
        }

        // 如果不是分支指令，下一个块是后继
        if (!blocks[i].instructions.empty()) {
            const auto& lastInstr = blocks[i].instructions.back();
            if (!lastInstr.isBranch && !lastInstr.isReturn && i + 1 < blocks.size()) {
                blocks[i].successors.push_back(blocks[i+1].startAddress);
                blocks[i+1].predecessors.push_back(blocks[i].startAddress);
            }
        }
    }

    return blocks;
}

std::vector<Function> Disassembler::DetectFunctions(
    const std::vector<BasicBlock>& blocks,
    const uint8_t* codeData,
    uint32_t codeSize)
{
    std::vector<Function> functions;

    if (!m_initialized || blocks.empty()) {
        return functions;
    }

    // 检测函数入口（通过 prologue 模式）
    for (const auto& block : blocks) {
        bool isEntry = false;

        // 查找对应代码
        uint32_t offset = (uint32_t)(block.startAddress - blocks[0].startAddress);
        if (offset < codeSize) {
            isEntry = IsPrologue(codeData + offset, codeSize - offset);
        }

        // 或者是被调用的目标
        if (!isEntry) {
            for (const auto& otherBlock : blocks) {
                for (const auto& instr : otherBlock.instructions) {
                    if (instr.isCall && instr.targetAddress == block.startAddress) {
                        isEntry = true;
                        break;
                    }
                }
                if (isEntry) break;
            }
        }

        if (isEntry) {
            Function func;
            func.entryAddress = block.startAddress;
            func.size = 0;
            func.isLeaf = true;
            func.isRecursive = false;
            func.usesSEH = false;
            func.assignedLevel = 1;

            // 收集函数内的所有块
            // 简化实现：只添加入口块
            func.blocks.push_back(block);
            func.size = block.endAddress - block.startAddress;

            // 检查是否是叶子函数
            for (const auto& instr : block.instructions) {
                if (instr.isCall) {
                    func.isLeaf = false;
                    break;
                }
            }

            functions.push_back(func);
        }
    }

    return functions;
}

std::string Disassembler::FormatInstruction(const Instruction& instr) {
    // 简化的指令格式化
    char buffer[256];
    
    if (!instr.mnemonic.empty()) {
        if (!instr.operands.empty()) {
            snprintf(buffer, sizeof(buffer), "%08llx: %-8s %s", 
                     instr.address, instr.mnemonic.c_str(), instr.operands.c_str());
        } else {
            snprintf(buffer, sizeof(buffer), "%08llx: %s", 
                     instr.address, instr.mnemonic.c_str());
        }
    } else {
        snprintf(buffer, sizeof(buffer), "%08llx: db %02X", 
                 instr.address, instr.bytes[0]);
    }

    return std::string(buffer);
}

// ============================================================================
// 内部实现
// ============================================================================

bool Disassembler::DecodeInstruction(const uint8_t* code, uint32_t size, uint64_t address, Instruction& instr) {
    if (size == 0) return false;

    uint8_t opcode = code[0];
    instr.length = 1;

    // 简化的指令解码
    switch (opcode) {
        // NOP
        case 0x90:
            instr.mnemonic = "nop";
            instr.isNop = true;
            break;

        // INT3
        case 0xCC:
            instr.mnemonic = "int3";
            instr.isInterrupt = true;
            break;

        // RET
        case 0xC3:
            instr.mnemonic = "ret";
            instr.isReturn = true;
            break;

        // RET imm16
        case 0xC2:
            if (size >= 3) {
                instr.mnemonic = "ret";
                instr.length = 3;
                instr.isReturn = true;
            }
            break;

        // JMP rel8
        case 0xEB:
            if (size >= 2) {
                instr.mnemonic = "jmp";
                instr.isBranch = true;
                instr.isConditional = false;
                instr.hasTarget = true;
                int8_t rel = (int8_t)code[1];
                instr.targetAddress = address + 2 + rel;
                instr.length = 2;
            }
            break;

        // JMP rel32
        case 0xE9:
            if (size >= 5) {
                instr.mnemonic = "jmp";
                instr.isBranch = true;
                instr.isConditional = false;
                instr.hasTarget = true;
                int32_t rel = *(int32_t*)(code + 1);
                instr.targetAddress = address + 5 + rel;
                instr.length = 5;
            }
            break;

        // CALL rel32
        case 0xE8:
            if (size >= 5) {
                instr.mnemonic = "call";
                instr.isCall = true;
                instr.hasTarget = true;
                int32_t rel = *(int32_t*)(code + 1);
                instr.targetAddress = address + 5 + rel;
                instr.length = 5;
            }
            break;

        // PUSH reg (0x50-0x57)
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            instr.mnemonic = "push";
            break;

        // POP reg (0x58-0x5F)
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            instr.mnemonic = "pop";
            break;

        // MOV reg, imm32 (0xB8-0xBF)
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            if (size >= 5) {
                instr.mnemonic = "mov";
                instr.length = 5;
            }
            break;

        // PUSH imm32
        case 0x68:
            if (size >= 5) {
                instr.mnemonic = "push";
                instr.length = 5;
            }
            break;

        // 条件跳转 (0x70-0x7F)
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            if (size >= 2) {
                const char* condNames[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jg"
                };
                instr.mnemonic = condNames[opcode - 0x70];
                instr.isBranch = true;
                instr.isConditional = true;
                instr.hasTarget = true;
                int8_t rel = (int8_t)code[1];
                instr.targetAddress = address + 2 + rel;
                instr.length = 2;
            }
            break;

        // 默认处理
        default:
            instr.mnemonic = "???";
            instr.length = 1;
            break;
    }

    return true;
}

bool Disassembler::AnalyzeBranch(Instruction& instr) {
    // 已在 DecodeInstruction 中分析
    return true;
}

bool Disassembler::IsConditionalBranch(uint8_t opcode) {
    return (opcode >= 0x70 && opcode <= 0x7F);
}

bool Disassembler::IsUnconditionalJump(uint8_t opcode) {
    return (opcode == 0xEB || opcode == 0xE9);
}

bool Disassembler::IsCall(uint8_t opcode) {
    return (opcode == 0xE8);
}

bool Disassembler::IsReturn(uint8_t opcode) {
    return (opcode == 0xC3 || opcode == 0xC2);
}

bool Disassembler::IsPrologue(const uint8_t* code, uint32_t size) {
    if (size < 3) return false;

    // 常见的函数序言模式
    // push ebp; mov ebp, esp
    if (code[0] == 0x55 && code[1] == 0x89 && code[2] == 0xE5) return true;
    
    // push ebp; mov ebp, esp; sub esp, imm8
    if (size >= 4 && code[0] == 0x55 && code[1] == 0x89 && code[2] == 0xE5 && code[3] == 0x83) return true;

    // sub rsp, imm8 (x64)
    if (m_is64Bit && code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC) return true;

    return false;
}

bool Disassembler::IsEpilogue(const uint8_t* code, uint32_t size) {
    if (size < 2) return false;

    // pop ebp; ret
    if (code[0] == 0x5D && code[1] == 0xC3) return true;

    // leave; ret
    if (code[0] == 0xC9 && code[1] == 0xC3) return true;

    return false;
}

uint32_t Disassembler::GetInstructionLength(const uint8_t* code, uint32_t maxSize) {
    if (maxSize == 0) return 0;

    // 简化的指令长度计算
    uint8_t opcode = code[0];
    
    // 特殊指令
    switch (opcode) {
        case 0xC2: return 3;  // ret imm16
        case 0x68: return 5;  // push imm32
        case 0xE8: return 5;  // call rel32
        case 0xE9: return 5;  // jmp rel32
        case 0xEB: return 2;  // jmp rel8
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            return 5;  // mov reg, imm32
    }

    // 条件跳转
    if (opcode >= 0x70 && opcode <= 0x7F) return 2;

    // 使用查找表
    int len = SINGLE_BYTE_LENGTHS[opcode];
    return (len > 0) ? len : 1;
}


// ============================================================================
// AnalyzeCode — 分析代码段，识别函数
// ============================================================================

std::vector<Function> Disassembler::AnalyzeCode(
    const uint8_t* code, uint32_t size, uint64_t baseAddress, bool is64Bit)
{
    Initialize(is64Bit);
    std::vector<Function> functions;

    // 反汇编所有指令
    auto instructions = Disassemble(code, size, baseAddress);
    if (instructions.empty()) return functions;

    // 简单的函数识别：按 RET 指令分割
    Function currentFunc;
    currentFunc.entryAddress = baseAddress;
    currentFunc.size = 0;
    currentFunc.isLeaf = true;
    currentFunc.isRecursive = false;
    currentFunc.usesSEH = false;
    currentFunc.assignedLevel = 0;

    BasicBlock currentBlock;
    currentBlock.startAddress = baseAddress;
    currentBlock.endAddress = baseAddress;
    currentBlock.instructionCount = 0;

    for (const auto& instr : instructions) {
        currentBlock.instructions.push_back(instr);
        currentBlock.instructionCount++;
        currentBlock.endAddress = instr.address + instr.length;

        if (instr.isCall) {
            currentFunc.isLeaf = false;
        }

        // 在分支或返回处切割基本块
        if (instr.isBranch || instr.isReturn) {
            currentFunc.blocks.push_back(currentBlock);

            if (instr.isReturn) {
                // 结束当前函数
                currentFunc.size = (uint32_t)(currentBlock.endAddress - currentFunc.entryAddress);
                if (!currentFunc.blocks.empty()) {
                    functions.push_back(currentFunc);
                }

                // 开始新函数
                currentFunc = Function();
                currentFunc.entryAddress = instr.address + instr.length;
                currentFunc.size = 0;
                currentFunc.isLeaf = true;
                currentFunc.isRecursive = false;
                currentFunc.usesSEH = false;
                currentFunc.assignedLevel = 0;
            }

            // 开始新基本块
            currentBlock = BasicBlock();
            currentBlock.startAddress = instr.address + instr.length;
            currentBlock.endAddress = currentBlock.startAddress;
            currentBlock.instructionCount = 0;
        }
    }

    // 处理剩余块
    if (currentBlock.instructionCount > 0) {
        currentFunc.blocks.push_back(currentBlock);
    }
    if (!currentFunc.blocks.empty()) {
        currentFunc.size = (uint32_t)(currentBlock.endAddress - currentFunc.entryAddress);
        functions.push_back(currentFunc);
    }

    // ========================================================================
    // 后处理：为每个函数的基本块计算后继信息
    // ========================================================================
    for (auto& func : functions) {
        for (size_t bi = 0; bi < func.blocks.size(); bi++) {
            auto& blk = func.blocks[bi];
            if (blk.instructions.empty()) continue;

            const auto& lastInstr = blk.instructions.back();

            if (lastInstr.isReturn) {
                // 返回：无后继
                continue;
            }

            if (lastInstr.isBranch && !lastInstr.isConditional) {
                // 无条件跳转：后继 = 目标地址
                blk.successors.push_back(lastInstr.targetAddress);
            } else if (lastInstr.isBranch && lastInstr.isConditional) {
                // 条件跳转：两个后继（fallthrough + target）
                blk.successors.push_back(lastInstr.address + lastInstr.length); // fallthrough
                blk.successors.push_back(lastInstr.targetAddress);               // target
            } else {
                // 一般指令（含 call）：后继 = 下一块的起始地址（fallthrough）
                if (bi + 1 < func.blocks.size()) {
                    blk.successors.push_back(func.blocks[bi + 1].startAddress);
                }
            }
        }
    }

    return functions;
}

} // namespace CipherShell
