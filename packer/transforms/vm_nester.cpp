/**
 * CipherShell VM 嵌套器 - 实现
 */

#include "vm_nester.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

VMNester::VMNester() : m_initialized(false) {}

VMNester::~VMNester() {}

// ============================================================================
// 公共接口
// ============================================================================

bool VMNester::Initialize(const NestingConfig& config) {
    m_config = config;
    m_initialized = true;

    // 为每层创建变异引擎
    m_mutators.resize(config.maxNestingDepth);
    for (uint32_t i = 0; i < config.maxNestingDepth; i++) {
        MutationConfig mutConfig;
        mutConfig.seed = GenerateNestingSeed(i);
        mutConfig.registerCount = config.differentRegisterCount ? (16 + i * 8) : 24;
        mutConfig.randomizeOpcodeMap = config.differentISA;
        mutConfig.randomizeRegisterMap = config.differentISA;
        m_mutators[i].Initialize(mutConfig);
    }

    return true;
}

std::vector<NestingLayer> VMNester::CreateNestedVM(const MutatedISA& outerISA) {
    std::vector<NestingLayer> layers;

    if (!m_initialized) return layers;

    // 外层（level 0）
    NestingLayer outerLayer;
    outerLayer.level = 0;
    outerLayer.isa = outerISA;
    outerLayer.handlerStart = 0;
    outerLayer.handlerSize = 0;
    layers.push_back(outerLayer);

    // 创建内层
    for (uint32_t i = 1; i < m_config.maxNestingDepth; i++) {
        NestingLayer innerLayer;
        innerLayer.level = i;

        // 生成不同的 ISA
        if (m_config.differentISA) {
            innerLayer.isa = MutateISA(outerISA, i);
        } else {
            innerLayer.isa = outerISA;
        }

        innerLayer.handlerStart = 0;
        innerLayer.handlerSize = 0;

        layers.push_back(innerLayer);
    }

    m_layers = layers;
    return layers;
}

std::vector<uint8_t> VMNester::NestHandler(
    const uint8_t* handlerCode,
    uint32_t handlerSize,
    const NestingLayer& layer)
{
    if (!handlerCode || handlerSize == 0) {
        return std::vector<uint8_t>();
    }

    // 查找对应的内层
    uint32_t innerLevel = layer.level + 1;
    if (innerLevel >= m_config.maxNestingDepth) {
        // 已经是最内层，不再嵌套
        std::vector<uint8_t> result(handlerCode, handlerCode + handlerSize);
        return result;
    }

    const NestingLayer& innerLayer = m_layers[innerLevel];

    // 将 handler 代码转换为内层 VM 的字节码
    return TranslateToNestedBytecode(handlerCode, handlerSize, layer.isa, innerLayer.isa);
}

BYTE* VMNester::GenerateNestedDispatcher(
    const NestingLayer& layer,
    bool is64Bit,
    DWORD* codeSize)
{
    if (!codeSize) return nullptr;

    // 为嵌套层生成 dispatcher
    // 简化：使用与外层相同的 dispatcher 结构，但使用不同的 ISA

    if (is64Bit) {
        // x64 nested dispatcher stub
        static const BYTE x64_nested[] = {
            // 保存外层上下文
            0x50,                               // push rax
            0x51,                               // push rcx
            0x52,                               // push rdx
            0x53,                               // push rbx
            // 加载内层 ISA
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, [rip+offset]
            // 执行内层 dispatch 循环
            0xFF, 0xD0,                         // call rax
            // 恢复外层上下文
            0x5B,                               // pop rbx
            0x5A,                               // pop rdx
            0x59,                               // pop rcx
            0x58,                               // pop rax
            0xC3                                // ret
        };

        *codeSize = sizeof(x64_nested);
        BYTE* output = new BYTE[sizeof(x64_nested)];
        memcpy(output, x64_nested, sizeof(x64_nested));
        return output;
    } else {
        // x86 nested dispatcher stub
        static const BYTE x86_nested[] = {
            0x50,                               // push eax
            0x51,                               // push ecx
            0x52,                               // push edx
            0x53,                               // push ebx
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call inner_dispatch
            0x5B,                               // pop ebx
            0x5A,                               // pop edx
            0x59,                               // pop ecx
            0x58,                               // pop eax
            0xC3                                // ret
        };

        *codeSize = sizeof(x86_nested);
        BYTE* output = new BYTE[sizeof(x86_nested)];
        memcpy(output, x86_nested, sizeof(x86_nested));
        return output;
    }
}

uint32_t VMNester::GetNestingDepth() const {
    return m_config.maxNestingDepth;
}

// ============================================================================
// 内部实现
// ============================================================================

MutatedISA VMNester::MutateISA(const MutatedISA& baseISA, uint32_t level) {
    MutatedISA mutated;

    if (level >= m_mutators.size()) return baseISA;

    // 使用对应层的变异引擎生成新的 ISA
    mutated = m_mutators[level].GenerateMutatedISA();

    return mutated;
}

// BUG 7 修复辅助函数：根据操作码确定操作数长度（字节）
// 必须与 Translator::EncodeInstruction 中的编码规则一致
static uint32_t GetOpcodeOperandSize(uint8_t opcode) {
    switch (opcode) {
        // 无操作数
        case VM_NOP:
        case VM_PUSHAD:
        case VM_POPAD:
        case VM_PUSHF:
        case VM_POPF:
        case VM_RET_VM:
        case VM_VMEXIT:
        case VM_INT3:
            return 0;

        // 双寄存器：regDst + regSrc (2 字节)
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
            return 2;

        // 寄存器 + 立即数64：reg + imm64 (9 字节)
        case VM_MOV_RC:
        case VM_ADD_RC:
        case VM_SUB_RC:
        case VM_AND_RC:
        case VM_OR_RC:
        case VM_XOR_RC:
        case VM_CMP_RC:
        case VM_TEST_RC:
        case VM_PUSH_C:
            return 9;

        // 单寄存器：reg (1 字节)
        case VM_PUSH_R:
        case VM_POP_R:
        case VM_INC_R:
        case VM_DEC_R:
        case VM_NEG_R:
        case VM_NOT_R:
            return 1;

        // 内存操作：regDst + regSrc + imm64 (10 字节)
        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
            return 10;

        // 跳转/调用（立即数32）：imm32 (4 字节)
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
            return 4;

        // CALL_NATIVE：dllHash(imm32) + funcHash(imm32) (8 字节)
        case VM_CALL_NATIVE:
            return 8;

        default:
            return 0;  // 未知操作码视为无操作数
    }
}

std::vector<uint8_t> VMNester::TranslateToNestedBytecode(
    const uint8_t* code,
    uint32_t size,
    const MutatedISA& fromISA,
    const MutatedISA& toISA)
{
    std::vector<uint8_t> result;

    // BUG 7 修复：正确解析字节码流——先读操作码确定操作数长度，
    // 只映射操作码，操作数原样保留
    uint32_t i = 0;
    while (i < size) {
        uint8_t originalOp = code[i];

        // 映射操作码到内层 ISA
        uint8_t mappedOp = originalOp;
        auto it = toISA.opcodeMap.find(originalOp);
        if (it != toISA.opcodeMap.end()) {
            mappedOp = it->second;
        }
        result.push_back(mappedOp);
        i++;

        // 计算此操作码的操作数长度，操作数原样复制
        uint32_t operandSize = GetOpcodeOperandSize(originalOp);
        for (uint32_t j = 0; j < operandSize && i < size; j++, i++) {
            result.push_back(code[i]);
        }
    }

    // BUG 8 修复：VMEXIT 操作码也需要通过内层 ISA 映射
    uint8_t vmexitMapped = VM_VMEXIT;
    auto exitIt = toISA.opcodeMap.find(VM_VMEXIT);
    if (exitIt != toISA.opcodeMap.end()) {
        vmexitMapped = exitIt->second;
    }
    result.push_back(vmexitMapped);

    return result;
}

uint32_t VMNester::GenerateNestingSeed(uint32_t level) {
    // 每层使用不同的种子
    return 0xDEADBEEF + level * 0x12345678;
}

} // namespace CipherShell
