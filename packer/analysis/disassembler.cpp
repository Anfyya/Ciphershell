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

static uint32_t ConsumeModRMBytes(const uint8_t* code, uint32_t size, uint32_t pos) {
    if (pos >= size) return 0;
    uint8_t modrm = code[pos++];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm = modrm & 7;
    if (mod != 3 && rm == 4) {
        if (pos >= size) return 0;
        uint8_t sib = code[pos++];
        uint8_t base = sib & 7;
        if (mod == 0 && base == 5) {
            if (pos + 4 > size) return 0;
            pos += 4;
        }
    } else if (mod == 0 && rm == 5) {
        if (pos + 4 > size) return 0;
        pos += 4;
    }
    if (mod == 1) {
        if (pos + 1 > size) return 0;
        pos += 1;
    } else if (mod == 2) {
        if (pos + 4 > size) return 0;
        pos += 4;
    }
    return pos;
}
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
        // BUG 2 修复：Instruction 包含 std::string 成员，不能用 memset 清零，
        // 否则会破坏 string 的内部状态。使用值初始化代替。
        Instruction instr{};

        if (!DecodeInstruction(code + offset, size - offset, address, instr)) {
            // 无法解码，跳过这个字节
            offset++;
            address++;
            continue;
        }

        instr.address = address;
        // BUG 1 修复：GetInstructionLength 与 DecodeInstruction 各自独立解码指令长度，
        // 可能返回不同结果。直接使用 DecodeInstruction 已经计算好的 length。
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
            func.size = static_cast<uint32_t>((std::min)(block.endAddress - block.startAddress, static_cast<uint64_t>(UINT32_MAX)));

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
                     static_cast<unsigned long long>(instr.address), instr.mnemonic.c_str(), instr.operands.c_str());
        } else {
            snprintf(buffer, sizeof(buffer), "%08llx: %s", 
                     static_cast<unsigned long long>(instr.address), instr.mnemonic.c_str());
        }
    } else {
        snprintf(buffer, sizeof(buffer), "%08llx: db %02X", 
                 static_cast<unsigned long long>(instr.address), instr.bytes[0]);
    }

    return std::string(buffer);
}

// ============================================================================
// 内部实现
// ============================================================================

bool Disassembler::DecodeInstruction(const uint8_t* code, uint32_t size, uint64_t address, Instruction& instr) {
    if (size == 0) return false;

    uint32_t pos = 0;

    // 统一消费常见前缀；长度计算必须包含前缀，否则下游 CFG/VM 会错位。
    uint8_t rex = 0;
    bool operand16 = false;
    while (pos < size) {
        uint8_t p = code[pos];
        if (p == 0x66) { operand16 = true; pos++; continue; }
        if (p == 0x67 || p == 0xF2 || p == 0xF3) { pos++; continue; }
        if (m_is64Bit && (p & 0xF0) == 0x40) { rex = p; pos++; continue; }
        break;
    }
    if (pos >= size) {
        instr.length = pos;
        return true;
    }

    uint8_t opcode = code[pos];
    pos++;

    // BUG 4 修复：处理 0x0F 双字节操作码（如条件跳转 0F 80-0F 8F、MOVZX 0F B6 等）
    if (opcode == 0x0F) {
        if (pos >= size) {
            instr.length = pos;
            instr.mnemonic = "???";
            return true;
        }
        uint8_t opcode2 = code[pos];
        pos++;

        // 0F 80 - 0F 8F: 条件跳转 rel32（近跳转）
        if (opcode2 >= 0x80 && opcode2 <= 0x8F) {
            if (pos + 4 <= size) {
                const char* condNames[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jg"
                };
                instr.mnemonic = condNames[opcode2 - 0x80];
                instr.isBranch = true;
                instr.isConditional = true;
                instr.hasTarget = true;
                int32_t rel = *(int32_t*)(code + pos);
                pos += 4;
                instr.targetAddress = address + pos + rel;
                instr.length = pos;
                return true;
            }
        }
        // 0F B6: MOVZX r32, r/m8
        // 0F B7: MOVZX r32, r/m16
        // 0F BE: MOVSX r32, r/m8
        // 0F BF: MOVSX r32, r/m16
        else if (opcode2 == 0xB6 || opcode2 == 0xB7 || opcode2 == 0xBE || opcode2 == 0xBF) {
            if (pos < size) {
                uint8_t modrm = code[pos];
                pos++;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 5) pos += 4;       // disp32
                else if (mod == 0 && rm == 4) {           // SIB
                    pos++;
                }
                else if (mod == 1) {
                    if (rm == 4) pos++;  // SIB
                    pos++;               // disp8
                }
                else if (mod == 2) {
                    if (rm == 4) pos++;  // SIB
                    pos += 4;            // disp32
                }
                instr.mnemonic = (opcode2 == 0xB6 || opcode2 == 0xB7) ? "movzx" : "movsx";
                instr.length = pos;
                return true;
            }
        }
        // 0F 94 - 0F 9F: SETcc r/m8
        else if (opcode2 >= 0x90 && opcode2 <= 0x9F) {
            if (pos < size) {
                pos++;  // ModR/M 字节
                instr.mnemonic = "setcc";
                instr.length = pos;
                return true;
            }
        }
        // 0F AF: IMUL r, r/m
        else if (opcode2 == 0xAF) {
            if (pos < size) {
                uint8_t modrm = code[pos];
                pos++;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 5) pos += 4;
                else if (mod == 0 && rm == 4) pos++;
                else if (mod == 1) { if (rm == 4) pos++; pos++; }
                else if (mod == 2) { if (rm == 4) pos++; pos += 4; }
                instr.mnemonic = "imul";
                instr.length = pos;
                return true;
            }
        }
        // 其他 0F 开头的双字节操作码：默认 2 字节 + 可能的 ModR/M
        else {
            // 保守处理：假设带 ModR/M
            if (pos < size) {
                uint8_t modrm = code[pos];
                pos++;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 5) pos += 4;
                else if (mod == 0 && rm == 4) pos++;
                else if (mod == 1) { if (rm == 4) pos++; pos++; }
                else if (mod == 2) { if (rm == 4) pos++; pos += 4; }
            }
            instr.mnemonic = "???";
            instr.length = pos;
            return true;
        }

        instr.mnemonic = "???";
        instr.length = pos;
        return true;
    }

    // 如果有 REX.W 前缀，调整 MOV reg, imm 的长度（imm64 而非 imm32）
    bool rexW = (rex & 0x08) != 0;

    instr.length = pos;  // 至少包含前缀 + 操作码

    // 简化的指令解码
    // 注意：pos 已经包含了 REX prefix 的偏移（pos = rex ? 2 : 1）
    switch (opcode) {
        // NOP
        case 0x90:
            instr.mnemonic = "nop";
            instr.isNop = true;
            // instr.length = pos (已设置)
            break;

        // Common ModR/M register, memory and ALU instructions
        case 0x8B: case 0x89: case 0x8A: case 0x88: case 0x8D:
        case 0x03: case 0x01: case 0x2B: case 0x29: case 0x3B: case 0x39:
        case 0x21: case 0x23: case 0x09: case 0x0B:
        case 0x31: case 0x33: case 0x85: case 0x84:
        {
            uint32_t end = ConsumeModRMBytes(code, size, pos);
            if (end == 0) break;
            switch (opcode) {
                case 0x8B: case 0x89: case 0x8A: case 0x88: instr.mnemonic = "mov"; break;
                case 0x8D: instr.mnemonic = "lea"; break;
                case 0x03: case 0x01: instr.mnemonic = "add"; break;
                case 0x2B: case 0x29: instr.mnemonic = "sub"; break;
                case 0x3B: case 0x39: instr.mnemonic = "cmp"; break;
                case 0x21: case 0x23: instr.mnemonic = "and"; break;
                case 0x09: case 0x0B: instr.mnemonic = "or"; break;
                case 0x31: case 0x33: instr.mnemonic = "xor"; break;
                case 0x84: case 0x85: instr.mnemonic = "test"; break;
            }
            uint8_t mod = (code[pos] >> 6) & 3;
            instr.readsMemory = (mod != 3) && (opcode != 0x89 && opcode != 0x88);
            instr.writesMemory = (mod != 3) && (opcode == 0x89 || opcode == 0x88);
            instr.length = end;
            break;
        }

        case 0x83: case 0x81:
        {
            uint32_t end = ConsumeModRMBytes(code, size, pos);
            if (end == 0) break;
            uint8_t ext = (code[pos] >> 3) & 7;
            uint32_t immSize = (opcode == 0x83) ? 1 : 4;
            if (end + immSize > size) break;
            switch (ext) {
                case 0: instr.mnemonic = "add"; break;
                case 4: instr.mnemonic = "and"; break;
                case 5: instr.mnemonic = "sub"; break;
                case 6: instr.mnemonic = "xor"; break;
                case 7: instr.mnemonic = "cmp"; break;
                default: instr.mnemonic = "???"; break;
            }
            instr.length = end + immSize;
            break;
        }
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
            if (pos + 2 <= size) {
                instr.mnemonic = "ret";
                instr.length = pos + 2;  // 操作码 + 2字节立即数
                instr.isReturn = true;
            }
            break;

        // JMP rel8
        case 0xEB:
            if (pos + 1 <= size) {
                instr.mnemonic = "jmp";
                instr.isBranch = true;
                instr.isConditional = false;
                instr.hasTarget = true;
                int8_t rel = (int8_t)code[pos];
                instr.length = pos + 1;
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        // JMP rel32
        case 0xE9:
            if (pos + 4 <= size) {
                instr.mnemonic = "jmp";
                instr.isBranch = true;
                instr.isConditional = false;
                instr.hasTarget = true;
                int32_t rel = *(int32_t*)(code + pos);
                instr.length = pos + 4;
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        // CALL rel32
        case 0xE8:
            if (pos + 4 <= size) {
                instr.mnemonic = "call";
                instr.isCall = true;
                instr.hasTarget = true;
                int32_t rel = *(int32_t*)(code + pos);
                instr.length = pos + 4;
                instr.targetAddress = address + instr.length + rel;
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

        // MOV reg, imm32/imm64 (0xB8-0xBF)
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        {
            // BUG 3 修复：REX.W 时立即数为 8 字节（imm64），否则 4 字节
            uint32_t immSize = (rexW) ? 8 : 4;
            if (pos + immSize <= size) {
                instr.mnemonic = "mov";
                instr.length = pos + immSize;
            }
            break;
        }

        // PUSH imm32
        case 0x68:
            if (pos + 4 <= size) {
                instr.mnemonic = "push";
                instr.length = pos + 4;
            }
            break;

        // PUSH imm8
        case 0x6A:
            if (pos + 1 <= size) {
                instr.mnemonic = "push";
                instr.length = pos + 1;
            }
            break;

                // FF /2 call r/m, /4 jmp r/m, /6 push r/m
        case 0xFF:
        {
            uint32_t end = ConsumeModRMBytes(code, size, pos);
            if (end == 0) break;
            uint8_t ext = (code[pos] >> 3) & 7;
            if (ext == 2) { instr.mnemonic = "call"; instr.isCall = true; instr.isIndirect = true; }
            else if (ext == 4) { instr.mnemonic = "jmp"; instr.isBranch = true; instr.isIndirect = true; }
            else if (ext == 6) { instr.mnemonic = "push"; }
            else { instr.mnemonic = "???"; }
            instr.length = end;
            break;
        }

        // 条件跳转 (0x70-0x7F)
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            if (pos + 1 <= size) {
                const char* condNames[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jg"
                };
                instr.mnemonic = condNames[opcode - 0x70];
                instr.isBranch = true;
                instr.isConditional = true;
                instr.hasTarget = true;
                int8_t rel = (int8_t)code[pos];
                instr.length = pos + 1;
                instr.targetAddress = address + instr.length + rel;
            }
            break;

        // 默认处理
        default:
            instr.mnemonic = "???";
            // instr.length = pos (已设置)
            break;
    }

    return true;
}

bool Disassembler::AnalyzeBranch(Instruction& instr) {
    // 已在 DecodeInstruction 中分析
    return true;
}

bool Disassembler::IsConditionalBranch(uint8_t opcode) {
    // 短条件跳转 0x70-0x7F; 近条件跳转需要双字节 0x0F 80-8F，在此只检查单字节
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

    // BUG 1 修复：统一使用 DecodeInstruction 计算长度，
    // 避免两套独立解码逻辑返回不同结果。
    Instruction tempInstr{};
    if (DecodeInstruction(code, maxSize, 0, tempInstr)) {
        return tempInstr.length > 0 ? tempInstr.length : 1;
    }
    return 1;
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

    // ============================================================================================
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

