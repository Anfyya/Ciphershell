/**
 * CipherShell x86/x64 → Mirage Bytecode 转译器 - 实现
 */

#include "translator.h"
#include "../../third_party/chacha20.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>

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

    uint32_t currentOffset = 0;

    // 翻译每个基本块
    for (const auto& block : func.blocks) {
        // 记录地址映射
        result.addrMap[block.startAddress] = currentOffset;

        // 翻译块中的每条指令
        for (const auto& instr : block.instructions) {
            BytecodeInstr vmInstr;
            memset(&vmInstr, 0, sizeof(vmInstr));

            if (TranslateInstruction(instr, vmInstr)) {
                result.instructions.push_back(vmInstr);

                // 估算字节码大小
                uint32_t instrSize = 1;  // opcode
                instrSize += 2;  // 两个寄存器索引
                instrSize += 8;  // 立即数（最坏情况）
                currentOffset += instrSize;
            }

            // 插入垃圾指令
            if (m_config.enableJunkInsertion && (rand() % 100) < m_config.junkRatio) {
                BytecodeInstr junk = GenerateJunkInstruction();
                result.instructions.push_back(junk);
                currentOffset += 3;
            }
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

            uint32_t instrSize = 1 + 2 + 8;
            currentOffset += instrSize;
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
    std::random_shuffle(randomOpcodes.begin(), randomOpcodes.end());

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
    if (instr.mnemonic == "xor") {
        outInstr.opcode = VM_XOR_RR;
        outInstr.regDst = MapRegister(0);
        outInstr.regSrc = MapRegister(0);
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

    // ADD reg, imm8 (83 xx xx)
    if (instr.bytes[0] == 0x83) {
        outInstr.opcode = VM_ADD_RC;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
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

    if (instr.bytes[0] == 0x83 && (instr.bytes[1] & 0x38) == 0x28) {
        outInstr.opcode = VM_SUB_RC;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
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

    if (instr.bytes[0] == 0x83 && (instr.bytes[1] & 0x38) == 0x38) {
        outInstr.opcode = VM_CMP_RC;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
        outInstr.immediate = (int64_t)(int8_t)instr.bytes[2];
        return true;
    }

    // CMP reg, imm32
    if (instr.bytes[0] == 0x81 && (instr.bytes[1] & 0x38) == 0x38) {
        outInstr.opcode = VM_CMP_RC;
        outInstr.regDst = MapRegister((instr.bytes[1] >> 3) & 7);
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

        switch (cond) {
            case 0x0: outInstr.opcode = VM_JO;  break;
            case 0x1: outInstr.opcode = VM_JNO; break;
            case 0x2: outInstr.opcode = VM_JB;  break;
            case 0x3: outInstr.opcode = VM_JA;  break;  // JNB = JAE = JA
            case 0x4: outInstr.opcode = VM_JZ;  break;
            case 0x5: outInstr.opcode = VM_JNZ; break;
            case 0x6: outInstr.opcode = VM_JB;  break;  // JBE
            case 0x7: outInstr.opcode = VM_JA;  break;
            case 0x8: outInstr.opcode = VM_JS;  break;
            case 0x9: outInstr.opcode = VM_JNS; break;
            case 0xA: outInstr.opcode = VM_JMP; break;  // JP
            case 0xB: outInstr.opcode = VM_JMP; break;  // JNP
            case 0xC: outInstr.opcode = VM_JL;  break;
            case 0xD: outInstr.opcode = VM_JGE; break;
            case 0xE: outInstr.opcode = VM_JLE; break;
            case 0xF: outInstr.opcode = VM_JG;  break;
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

    // 生成无害的垃圾指令
    uint8_t type = rand() % 4;
    switch (type) {
        case 0:
            junk.opcode = VM_NOP;
            break;
        case 1:
            junk.opcode = VM_MOV_RC;
            junk.regDst = (uint8_t)(rand() % m_config.virtualRegisterCount);
            junk.immediate = (uint64_t)rand();
            break;
        case 2:
            junk.opcode = VM_PUSH_C;
            junk.immediate = (uint64_t)rand();
            break;
        case 3:
            junk.opcode = VM_ADD_RC;
            junk.regDst = (uint8_t)(rand() % m_config.virtualRegisterCount);
            junk.immediate = 0;  // 加 0，不影响结果
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

} // namespace CipherShell
