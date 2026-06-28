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

    // 确保与外层不同
    mutated.dispatchMode = (baseISA.dispatchMode + 1) % 4;

    // 不同的栈布局
    mutated.stackBase = baseISA.stackBase ^ 0x12345678;
    mutated.stackSize = baseISA.stackSize + level * 0x1000;

    return mutated;
}

std::vector<uint8_t> VMNester::TranslateToNestedBytecode(
    const uint8_t* code,
    uint32_t size,
    const MutatedISA& fromISA,
    const MutatedISA& toISA)
{
    std::vector<uint8_t> result;

    // 简化实现：将原始字节码中的 opcode 映射到内层 ISA
    for (uint32_t i = 0; i < size; i++) {
        uint8_t originalOp = code[i];
        uint8_t mappedOp = originalOp;

        // 查找内层 ISA 的 opcode 映射
        auto it = toISA.opcodeMap.find(originalOp);
        if (it != toISA.opcodeMap.end()) {
            mappedOp = it->second;
        }

        result.push_back(mappedOp);
    }

    // 添加内层 VMEXIT 指令
    result.push_back(VM_VMEXIT);

    return result;
}

uint32_t VMNester::GenerateNestingSeed(uint32_t level) {
    // 每层使用不同的种子
    return 0xDEADBEEF + level * 0x12345678;
}

} // namespace CipherShell
