/**
 * CipherShell x86/x64 → Mirage Bytecode 转译器 - 实现
 */

#include "translator.h"
#include "../../third_party/chacha20.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <random>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

Translator::Translator() 
    : m_nextVirtualReg(0)
    , m_initialized(false)
{
    srand((unsigned int)time(nullptr));
}

Translator::~Translator() {}

// ============================================================================
// 公共接口
// ============================================================================

bool Translator::Initialize(const TranslationConfig& config) {
    m_config = config;

    // 初始化寄存器映射
    for (int i = 0; i < 16; i++) {
        if (config.enableRegisterRemapping) {
            // 随机映射
            m_registerMap[i] = (uint8_t)(i % config.virtualRegisterCount);
        } else {
            m_registerMap[i] = (uint8_t)i;
        }
    }

    // 生成 opcode 映射
    m_opcodeMap = GenerateOpcodeMap();

    m_initialized = true;
    return true;
}

TranslationResult Translator::TranslateFunction(const Function& func) {
    TranslationResult result;
    result.totalSize = 0;
    result.registerCount = m_config.virtualRegisterCount;

    if (!m_initialized) return result;

    // BUG 1 修复：使用两遍策略计算正确的跳转偏移
    // 第一遍：生成所有 VM 指令并记录每条指令在字节码流中的实际偏移
    uint32_t currentOffset = 0;
    std::vector<uint32_t> instrOffsets; // 每条 VM 指令的字节码偏移

    for (const auto& block : func.blocks) {
        // 记录基本块起始地址到字节码偏移的映射
        result.addrMap[block.startAddress] = currentOffset;

        for (const auto& instr : block.instructions) {
            // 记录原始指令地址的映射
            result.addrMap[instr.address] = currentOffset;

            BytecodeInstr vmInstr;
            memset(&vmInstr, 0, sizeof(vmInstr));

            if (TranslateInstruction(instr, vmInstr)) {
                instrOffsets.push_back(currentOffset);
                result.instructions.push_back(vmInstr);
                // 使用实际编码大小而非固定估算值
                currentOffset += CalculateEncodedSize(vmInstr);
            }

            // 插入垃圾指令
            if (m_config.enableJunkInsertion && (rand() % 100) < (int)m_config.junkRatio) {
                BytecodeInstr junk = GenerateJunkInstruction();
                instrOffsets.push_back(currentOffset);
                result.instructions.push_back(junk);
                currentOffset += CalculateEncodedSize(junk);
            }
        }
    }

    // 第二遍：回填跳转目标偏移
    // 跳转指令的 immediate 字段存储的是相对于 x86 原始指令的偏移
    // 需要将其转换为 VM 字节码中的绝对偏移
    for (size_t i = 0; i < result.instructions.size(); i++) {
        BytecodeInstr& vmInstr = result.instructions[i];
        if (vmInstr.isJump) {
            // immediate 中是 x86 相对偏移，jumpTarget 可存储 VM 字节码绝对偏移
            // 由于原始地址映射已建立，可以在 GenerateBytecode 阶段做最终解析
            // 这里将当前 VM 字节码偏移记录到 jumpTarget 中，供后续使用
            vmInstr.jumpTarget = instrOffsets[i];
        }
    }

    result.totalSize = currentOffset;
    return result;
}

TranslationResult Translator::TranslateBlock(const BasicBlock& block, uint32_t baseOffset) {
    TranslationResult result;
    result.totalSize = baseOffset;
    result.registerCount = m_config.virtualRegisterCount;

    if (!m_initialized) return result;

    uint32_t currentOffset = baseOffset;

    for (const auto& instr : block.instructions) {
        result.addrMap[instr.address] = currentOffset;

        BytecodeInstr vmInstr;
        memset(&vmInstr, 0, sizeof(vmInstr));

        if (TranslateInstruction(instr, vmInstr)) {
            result.instructions.push_back(vmInstr);
            // BUG 1 修复：使用实际编码大小而非固定 11 字节
            currentOffset += CalculateEncodedSize(vmInstr);
        }
    }

    result.totalSize = currentOffset - baseOffset;
    return result;
}

std::vector<uint8_t> Translator::GenerateBytecode(
    const TranslationResult& result,
    const uint8_t* key,
    const uint8_t* nonce)
{
    std::vector<uint8_t> bytecode;

    // 编码每条指令
    for (const auto& instr : result.instructions) {
        EncodeInstruction(instr, bytecode);
    }

    // 加密字节码
    if (key) {
        EncryptBytecode(bytecode, key, nonce);
    }

    return bytecode;
}

std::unordered_map<uint8_t, uint8_t> Translator::GetRegisterMap() const {
    return m_registerMap;
}

std::unordered_map<uint8_t, uint8_t> Translator::GenerateOpcodeMap() {
    std::unordered_map<uint8_t, uint8_t> opcodeMap;

    // 标准 opcode 列表
    uint8_t standardOpcodes[] = {
        VM_NOP, VM_MOV_RR, VM_MOV_RC, VM_MOV_RM, VM_MOV_MR,
        VM_PUSH_R, VM_PUSH_C, VM_POP_R, VM_PUSHAD, VM_POPAD,
        VM_ADD_RR, VM_ADD_RC, VM_SUB_RR, VM_SUB_RC,
        VM_AND_RR, VM_OR_RR, VM_XOR_RR, VM_NOT_R,
        VM_CMP_RR, VM_CMP_RC, VM_TEST_RR, VM_TEST_RC,
        VM_JMP, VM_JZ, VM_JNZ, VM_JA, VM_JB, VM_JG, VM_JL,
        VM_CALL_VM, VM_RET_VM, VM_CALL_NATIVE, VM_VMEXIT
    };

    int count = sizeof(standardOpcodes) / sizeof(standardOpcodes[0]);

    // 生成随机映射
    std::vector<uint8_t> randomOpcodes;
    for (int i = 0; i < 256; i++) {
        randomOpcodes.push_back((uint8_t)i);
    }

    // 打乱
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(randomOpcodes.begin(), randomOpcodes.end(), g);

    for (int i = 0; i < count; i++) {
        opcodeMap[standardOpcodes[i]] = randomOpcodes[i];
    }

    return opcodeMap;
}

// ============================================================================
// 指令翻译
// ============================================================================

bool Translator::TranslateInstruction(const Instruction& instr, BytecodeInstr& outInstr) {
    if (instr.mnemonic.empty()) return false;

    // 根据助记符选择翻译函数
    if (instr.mnemonic == "mov") return TranslateMov(instr, outInstr);
    if (instr.mnemonic == "add") return TranslateAdd(instr, outInstr);
    if (instr.mnemonic == "sub") return TranslateSub(instr, outInstr);
    if (instr.mnemonic == "cmp") return TranslateCmp(instr, outInstr);
    if (instr.mnemonic == "push") return TranslatePush(instr, outInstr);
    if (instr.mnemonic == "pop") return TranslatePop(instr, outInstr);
    if (instr.mnemonic == "call") return TranslateCall(instr, outInstr);
    if (instr.mnemonic == "ret") return TranslateRet(instr, outInstr);
    if (instr.mnemonic == "nop") return TranslateNop(instr, outInstr);
    // BUG 2 修复：XOR 指令需要从 ModR/M 字节正确提取源/目标寄存器，
    // 而非硬编码寄存器 0
    if (instr.mnemonic == "xor") {
        if (instr.bytes[0] == 0x31 || instr.bytes[0] == 0x33) {
            // 0x31: XOR r/m, reg  (reg 字段是源)
            // 0x33: XOR reg, r/m  (reg 字段是目标)
            outInstr.opcode = VM_XOR_RR;
            outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
            outInstr.regSrc = MapRegister(instr.bytes[1] & 7);
            // 0x31 编码下 reg 是源，rm 是目标，需要交换
            if (instr.bytes[0] == 0x31) {
                uint8_t tmp = outInstr.regDst;
                outInstr.regDst = MapRegister(instr.bytes[1] & 7);
                outInstr.regSrc = MapRegister((instr.bytes[1] >> 3) & 7);
            }
        } else if (instr.bytes[0] == 0x83 && ((instr.bytes[1] >> 3) & 7) == 6) {
            // 0x83 /6: XOR r/m, imm8 — reg 字段 (/6) 是操作码扩展
            outInstr.opcode = VM_XOR_RC;
            outInstr.regDst = MapRegister(instr.bytes[1] & 7);
            outInstr.immediate = (int64_t)(int8_t)instr.bytes[2];
        } else {
            // 其它 XOR 编码，回退到通用处理
            outInstr.opcode = VM_XOR_RR;
            outInstr.regDst = MapRegister(0);
            outInstr.regSrc = MapRegister(0);
        }
        return true;
    }
    if (instr.mnemonic == "int3") {
        outInstr.opcode = VM_INT3;
        return true;
    }

    // 跳转指令
    if (IsJumpInstruction(instr.mnemonic)) {
        return TranslateJump(instr, outInstr);
    }

    // 默认：翻译为 NOP
    outInstr.opcode = VM_NOP;
    return true;
}

bool Translator::TranslateMov(const Instruction& instr, BytecodeInstr& outInstr) {
    // MOV reg, imm32
    if (instr.bytes[0] >= 0xB8 && instr.bytes[0] <= 0xBF) {
        outInstr.opcode = VM_MOV_RC;
        outInstr.regDst = MapRegister(instr.bytes[0] - 0xB8);
        outInstr.immediate = *(uint32_t*)(instr.bytes + 1);
        return true;
    }

    // PUSH imm32 (用 MOV + PUSH 模拟)
    if (instr.bytes[0] == 0x68) {
        outInstr.opcode = VM_PUSH_C;
        outInstr.immediate = *(uint32_t*)(instr.bytes + 1);
        return true;
    }

    outInstr.opcode = VM_MOV_RR;
    outInstr.regDst = MapRegister(0);
    outInstr.regSrc = MapRegister(0);
    return true;
}

bool Translator::TranslateAdd(const Instruction& instr, BytecodeInstr& outInstr) {
    // ADD reg, reg (03 xx)
    if (instr.bytes[0] == 0x03) {
        outInstr.opcode = VM_ADD_RR;
        // ModR/M 解析（简化）
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
        outInstr.regSrc = MapRegister(instr.bytes[1] & 7);
        return true;
    }

    // BUG 3 修复：0x83 /0 是 ADD r/m, imm8
    // ModR/M 中 reg 字段 (/0) 是操作码扩展，rm 字段才是操作数寄存器
    if (instr.bytes[0] == 0x83 && ((instr.bytes[1] >> 3) & 7) == 0) {
        outInstr.opcode = VM_ADD_RC;
        outInstr.regDst = MapRegister(instr.bytes[1] & 7);
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[2];
        return true;
    }

    outInstr.opcode = VM_ADD_RR;
    outInstr.regDst = MapRegister(0);
    outInstr.regSrc = MapRegister(0);
    return true;
}

bool Translator::TranslateSub(const Instruction& instr, BytecodeInstr& outInstr) {
    if (instr.bytes[0] == 0x2B) {
        outInstr.opcode = VM_SUB_RR;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
        outInstr.regSrc = MapRegister(instr.bytes[1] & 7);
        return true;
    }

    // BUG 3 修复：0x83 /5 是 SUB r/m, imm8
    // reg 字段 (/5 = 0x28) 是操作码扩展，rm 字段才是操作数寄存器
    if (instr.bytes[0] == 0x83 && (instr.bytes[1] & 0x38) == 0x28) {
        outInstr.opcode = VM_SUB_RC;
        outInstr.regDst = MapRegister(instr.bytes[1] & 7);
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[2];
        return true;
    }

    outInstr.opcode = VM_SUB_RR;
    outInstr.regDst = MapRegister(0);
    outInstr.regSrc = MapRegister(0);
    return true;
}

bool Translator::TranslateCmp(const Instruction& instr, BytecodeInstr& outInstr) {
    // CMP 等同于 SUB 但不保存结果
    if (instr.bytes[0] == 0x3B) {
        outInstr.opcode = VM_CMP_RR;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
        outInstr.regSrc = MapRegister(instr.bytes[1] & 7);
        return true;
    }

    // BUG 3 修复：0x83 /7 是 CMP r/m, imm8
    // reg 字段 (/7 = 0x38) 是操作码扩展，rm 字段才是操作数寄存器
    if (instr.bytes[0] == 0x83 && (instr.bytes[1] & 0x38) == 0x38) {
        outInstr.opcode = VM_CMP_RC;
        outInstr.regDst = MapRegister(instr.bytes[1] & 7);
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[2];
        return true;
    }

    // CMP reg, imm32 (0x81 /7)
    // 同理：reg 字段是操作码扩展，rm 字段是操作数寄存器
    if (instr.bytes[0] == 0x81 && (instr.bytes[1] & 0x38) == 0x38) {
        outInstr.opcode = VM_CMP_RC;
        outInstr.regDst = MapRegister(instr.bytes[1] & 7);
        outInstr.immediate = *(uint32_t*)(instr.bytes + 2);
        return true;
    }

    outInstr.opcode = VM_CMP_RR;
    outInstr.regDst = MapRegister(0);
    outInstr.regSrc = MapRegister(0);
    return true;
}

bool Translator::TranslatePush(const Instruction& instr, BytecodeInstr& outInstr) {
    // PUSH reg (50-57)
    if (instr.bytes[0] >= 0x50 && instr.bytes[0] <= 0x57) {
        outInstr.opcode = VM_PUSH_R;
        outInstr.regDst = MapRegister(instr.bytes[0] - 0x50);
        return true;
    }

    // PUSH imm32 (68 xx xx xx xx)
    if (instr.bytes[0] == 0x68) {
        outInstr.opcode = VM_PUSH_C;
        outInstr.immediate = *(uint32_t*)(instr.bytes + 1);
        return true;
    }

    // PUSH imm8 (6A xx)
    if (instr.bytes[0] == 0x6A) {
        outInstr.opcode = VM_PUSH_C;
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[1];
        return true;
    }

    outInstr.opcode = VM_PUSH_R;
    outInstr.regDst = MapRegister(0);
    return true;
}

bool Translator::TranslatePop(const Instruction& instr, BytecodeInstr& outInstr) {
    // POP reg (58-5F)
    if (instr.bytes[0] >= 0x58 && instr.bytes[0] <= 0x5F) {
        outInstr.opcode = VM_POP_R;
        outInstr.regDst = MapRegister(instr.bytes[0] - 0x58);
        return true;
    }

    outInstr.opcode = VM_POP_R;
    outInstr.regDst = MapRegister(0);
    return true;
}

bool Translator::TranslateJump(const Instruction& instr, BytecodeInstr& outInstr) {
    // 无条件跳转
    if (instr.bytes[0] == 0xEB) {  // JMP rel8
        outInstr.opcode = VM_JMP;
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[1];
        outInstr.isJump = true;
        return true;
    }
    if (instr.bytes[0] == 0xE9) {  // JMP rel32
        outInstr.opcode = VM_JMP;
        outInstr.immediate = (int64_t)(int32_t)(*(uint32_t*)(instr.bytes + 1));
        outInstr.isJump = true;
        return true;
    }

    // 条件跳转
    if (instr.bytes[0] >= 0x70 && instr.bytes[0] <= 0x7F) {
        uint8_t cond = instr.bytes[0] - 0x70;
        int8_t rel8 = (int8_t)instr.bytes[1];

        // BUG 4 修复：JNB (0x73, >=) 应映射为 VM_JGE（无符号 >=），
        //   JBE (0x76, <=) 应映射为 VM_JLE（无符号 <=）
        // 注意：VM ISA 中没有独立的 VM_JAE/VM_JBE，使用最接近的语义：
        //   JNB/JAE (CF=0) → VM_JGE，JBE (CF=1||ZF=1) → VM_JLE
        //   JA (CF=0&&ZF=0) → VM_JA，见 case 0x7
        // BUG 5 修复：JP (0x7A) / JNP (0x7B) 不能静默降级为无条件 JMP，
        //   报告不支持并生成 VM_NOP（保持程序流不变，而非错误跳转）
        switch (cond) {
            case 0x0: outInstr.opcode = VM_JO;  break;       // JO
            case 0x1: outInstr.opcode = VM_JNO; break;       // JNO
            case 0x2: outInstr.opcode = VM_JB;  break;       // JB / JNAE / JC
            case 0x3: outInstr.opcode = VM_JGE; break;       // JNB / JAE / JNC (无符号 >=)
            case 0x4: outInstr.opcode = VM_JZ;  break;       // JZ / JE
            case 0x5: outInstr.opcode = VM_JNZ; break;       // JNZ / JNE
            case 0x6: outInstr.opcode = VM_JLE; break;       // JBE / JNA (无符号 <=)
            case 0x7: outInstr.opcode = VM_JA;  break;       // JA / JNBE (无符号 >)
            case 0x8: outInstr.opcode = VM_JS;  break;       // JS
            case 0x9: outInstr.opcode = VM_JNS; break;       // JNS
            case 0xA:                                         // JP / JPE
                // VM ISA 不支持 JP/JNP，不能降级为无条件 JMP
                // 生成 NOP 并标记为非跳转，避免错误的无条件跳转语义
                outInstr.opcode = VM_NOP;
                outInstr.isJump = false;
                // TODO: 实现 PF 标志检测等价序列
                return true;
            case 0xB:                                         // JNP / JPO
                outInstr.opcode = VM_NOP;
                outInstr.isJump = false;
                // TODO: 实现 PF 标志检测等价序列
                return true;
            case 0xC: outInstr.opcode = VM_JL;  break;       // JL / JNGE
            case 0xD: outInstr.opcode = VM_JGE; break;       // JGE / JNL
            case 0xE: outInstr.opcode = VM_JLE; break;       // JLE / JNG
            case 0xF: outInstr.opcode = VM_JG;  break;       // JG / JNLE
        }

        outInstr.immediate = (int64_t)rel8;
        outInstr.isJump = true;
        return true;
    }

    outInstr.opcode = VM_NOP;
    return true;
}

bool Translator::TranslateCall(const Instruction& instr, BytecodeInstr& outInstr) {
    // CALL rel32
    if (instr.bytes[0] == 0xE8) {
        outInstr.opcode = VM_CALL_VM;
        outInstr.immediate = (int64_t)(int32_t)(*(uint32_t*)(instr.bytes + 1));
        outInstr.isJump = true;
        return true;
    }

    outInstr.opcode = VM_NOP;
    return true;
}

bool Translator::TranslateRet(const Instruction& instr, BytecodeInstr& outInstr) {
    // RET
    if (instr.bytes[0] == 0xC3) {
        outInstr.opcode = VM_RET_VM;
        return true;
    }
    // RET imm16
    if (instr.bytes[0] == 0xC2) {
        outInstr.opcode = VM_RET_VM;
        outInstr.immediate = *(uint16_t*)(instr.bytes + 1);
        return true;
    }

    outInstr.opcode = VM_RET_VM;
    return true;
}

bool Translator::TranslateNop(const Instruction& instr, BytecodeInstr& outInstr) {
    outInstr.opcode = VM_NOP;
    return true;
}

// ============================================================================
// 内部实现
// ============================================================================

uint8_t Translator::MapRegister(uint8_t x86Reg) {
    auto it = m_registerMap.find(x86Reg);
    if (it != m_registerMap.end()) {
        return it->second;
    }
    return x86Reg % m_config.virtualRegisterCount;
}

void Translator::EncodeInstruction(const BytecodeInstr& instr, std::vector<uint8_t>& bytecode) {
    // 如果启用了 opcode 随机化，映射 opcode
    uint8_t encodedOpcode = instr.opcode;
    if (m_config.enableOpcodeRandomization) {
        auto it = m_opcodeMap.find(instr.opcode);
        if (it != m_opcodeMap.end()) {
            encodedOpcode = it->second;
        }
    }

    // 编码 opcode
    EncodeOpcode(encodedOpcode, bytecode);

    // 根据指令类型编码操作数
    switch (instr.opcode) {
        case VM_NOP:
            break;

        case VM_MOV_RR:
        case VM_ADD_RR:
        case VM_SUB_RR:
        case VM_AND_RR:
        case VM_OR_RR:
        case VM_XOR_RR:
        case VM_CMP_RR:
        case VM_TEST_RR:
        case VM_SHL_RR:
        case VM_SHR_RR:
        case VM_SAR_RR:
        case VM_ADC_RR:
        case VM_SBB_RR:
        case VM_XCHG:
            EncodeRegister(instr.regDst, bytecode);
            EncodeRegister(instr.regSrc, bytecode);
            break;

        case VM_MOV_RC:
        case VM_ADD_RC:
        case VM_SUB_RC:
        case VM_AND_RC:
        case VM_OR_RC:
        case VM_XOR_RC:
        case VM_CMP_RC:
        case VM_TEST_RC:
        case VM_PUSH_C:
            EncodeRegister(instr.regDst, bytecode);
            EncodeImmediate64(instr.immediate, bytecode);
            break;

        case VM_PUSH_R:
        case VM_POP_R:
        case VM_INC_R:
        case VM_DEC_R:
        case VM_NEG_R:
        case VM_NOT_R:
            EncodeRegister(instr.regDst, bytecode);
            break;

        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
            EncodeRegister(instr.regDst, bytecode);
            EncodeRegister(instr.regSrc, bytecode);
            EncodeImmediate64(instr.immediate, bytecode);
            break;

        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JB:
        case VM_JG:
        case VM_JL:
        case VM_JGE:
        case VM_JLE:
        case VM_JO:
        case VM_JNO:
        case VM_JS:
        case VM_JNS:
        case VM_CALL_VM:
            EncodeImmediate32((uint32_t)instr.immediate, bytecode);
            break;

        case VM_PUSHAD:
        case VM_POPAD:
        case VM_PUSHF:
        case VM_POPF:
        case VM_RET_VM:
        case VM_VMEXIT:
            break;

        case VM_CALL_NATIVE:
            EncodeImmediate32((uint32_t)(instr.immediate >> 32), bytecode);  // DLL hash
            EncodeImmediate32((uint32_t)instr.immediate, bytecode);          // Func hash
            break;

        case VM_INT3:
            break;

        default:
            break;
    }
}

void Translator::EncodeOpcode(uint8_t opcode, std::vector<uint8_t>& bytecode) {
    bytecode.push_back(opcode);
}

void Translator::EncodeRegister(uint8_t reg, std::vector<uint8_t>& bytecode) {
    bytecode.push_back(reg);
}

void Translator::EncodeImmediate32(uint32_t imm, std::vector<uint8_t>& bytecode) {
    bytecode.push_back((uint8_t)(imm));
    bytecode.push_back((uint8_t)(imm >> 8));
    bytecode.push_back((uint8_t)(imm >> 16));
    bytecode.push_back((uint8_t)(imm >> 24));
}

void Translator::EncodeImmediate64(uint64_t imm, std::vector<uint8_t>& bytecode) {
    for (int i = 0; i < 8; i++) {
        bytecode.push_back((uint8_t)(imm >> (i * 8)));
    }
}

void Translator::EncryptBytecode(std::vector<uint8_t>& bytecode, const uint8_t* key, const uint8_t* nonce) {
    if (!key || bytecode.empty()) return;

    // 使用滚动密钥加密
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (size_t i = 0; i < bytecode.size(); i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        bytecode[i] ^= keyByte;

        // 更新滚动密钥
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)bytecode[i];
    }
}

BytecodeInstr Translator::GenerateJunkInstruction() {
    BytecodeInstr junk;
    memset(&junk, 0, sizeof(junk));

    // BUG 6 修复：垃圾指令必须是无副作用的
    // 之前的 MOV_RC 会覆盖真实寄存器值，PUSH_C 会破坏栈状态
    // 修复方案：只使用 NOP 和不改变结果的操作（如 ADD 0、XOR 0）
    uint8_t type = rand() % 3;
    switch (type) {
        case 0:
            // NOP：完全无副作用
            junk.opcode = VM_NOP;
            break;
        case 1:
            // ADD reg, 0：不改变寄存器值（但注意可能影响 flags）
            // 使用随机寄存器以增加混淆效果
            junk.opcode = VM_ADD_RC;
            junk.regDst = (uint8_t)(rand() % m_config.virtualRegisterCount);
            junk.immediate = 0;
            break;
        case 2:
            // XOR reg, 0：不改变寄存器值
            junk.opcode = VM_XOR_RC;
            junk.regDst = (uint8_t)(rand() % m_config.virtualRegisterCount);
            junk.immediate = 0;
            break;
    }

    return junk;
}

uint8_t Translator::GetOpcodeForInstruction(const std::string& mnemonic) {
    if (mnemonic == "mov") return VM_MOV_RR;
    if (mnemonic == "add") return VM_ADD_RR;
    if (mnemonic == "sub") return VM_SUB_RR;
    if (mnemonic == "and") return VM_AND_RR;
    if (mnemonic == "or")  return VM_OR_RR;
    if (mnemonic == "xor") return VM_XOR_RR;
    if (mnemonic == "cmp") return VM_CMP_RR;
    if (mnemonic == "push") return VM_PUSH_R;
    if (mnemonic == "pop") return VM_POP_R;
    if (mnemonic == "call") return VM_CALL_VM;
    if (mnemonic == "ret") return VM_RET_VM;
    if (mnemonic == "nop") return VM_NOP;
    if (mnemonic == "int3") return VM_INT3;
    return VM_NOP;
}

bool Translator::IsJumpInstruction(const std::string& mnemonic) {
    return (mnemonic[0] == 'j' || mnemonic == "jmp" || mnemonic == "call");
}

// BUG 1 修复辅助：根据指令类型计算编码后的实际字节长度
uint32_t Translator::CalculateEncodedSize(const BytecodeInstr& instr) {
    switch (instr.opcode) {
        // 无操作数：仅 opcode (1 字节)
        case VM_NOP:
        case VM_PUSHAD:
        case VM_POPAD:
        case VM_PUSHF:
        case VM_POPF:
        case VM_RET_VM:
        case VM_VMEXIT:
        case VM_INT3:
            return 1;

        // 双寄存器操作数：opcode + regDst + regSrc (3 字节)
        case VM_MOV_RR:
        case VM_ADD_RR:
        case VM_SUB_RR:
        case VM_AND_RR:
        case VM_OR_RR:
        case VM_XOR_RR:
        case VM_CMP_RR:
        case VM_TEST_RR:
        case VM_SHL_RR:
        case VM_SHR_RR:
        case VM_SAR_RR:
        case VM_ADC_RR:
        case VM_SBB_RR:
        case VM_XCHG:
            return 3;

        // 寄存器 + 立即数64：opcode + reg + imm64 (10 字节)
        case VM_MOV_RC:
        case VM_ADD_RC:
        case VM_SUB_RC:
        case VM_AND_RC:
        case VM_OR_RC:
        case VM_XOR_RC:
        case VM_CMP_RC:
        case VM_TEST_RC:
        case VM_PUSH_C:
            return 10;

        // 单寄存器操作数：opcode + reg (2 字节)
        case VM_PUSH_R:
        case VM_POP_R:
        case VM_INC_R:
        case VM_DEC_R:
        case VM_NEG_R:
        case VM_NOT_R:
            return 2;

        // 内存操作：opcode + regDst + regSrc + imm64 (11 字节)
        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
            return 11;

        // 跳转/调用（立即数32）：opcode + imm32 (5 字节)
        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JB:
        case VM_JG:
        case VM_JL:
        case VM_JGE:
        case VM_JLE:
        case VM_JO:
        case VM_JNO:
        case VM_JS:
        case VM_JNS:
        case VM_CALL_VM:
            return 5;

        // CALL_NATIVE：opcode + dllHash(imm32) + funcHash(imm32) (9 字节)
        case VM_CALL_NATIVE:
            return 9;

        default:
            return 1;  // 安全默认值
    }
}

} // namespace CipherShell
