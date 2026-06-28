/**
 * CipherShell 变异引擎 - 实现
 */

#include "mutation_engine.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

MutationEngine::MutationEngine()
    : m_randomState(0)
    , m_initialized(false)
{
}

MutationEngine::~MutationEngine() {}

// ============================================================================
// 公共接口
// ============================================================================

bool MutationEngine::Initialize(const MutationConfig& config) {
    m_config = config;
    m_randomState = config.seed;
    m_initialized = true;
    return true;
}

MutatedISA MutationEngine::GenerateMutatedISA() {
    MutatedISA isa;

    if (!m_initialized) return isa;

    // 随机化 opcode 映射
    if (m_config.randomizeOpcodeMap) {
        isa.opcodeMap = RandomizeOpcodeMap();
    }

    // 随机化寄存器映射
    if (m_config.randomizeRegisterMap) {
        isa.registerMap = RandomizeRegisterMap();
    }

    // 随机化 handler 排列
    isa.handlerOrder = RandomizeHandlerOrder();

    // 随机化 dispatch 模式
    if (m_config.randomizeDispatchMode) {
        isa.dispatchMode = NextRandom() % 4;
    } else {
        isa.dispatchMode = 0;
    }

    // 随机化栈布局
    if (m_config.randomizeStackLayout) {
        isa.stackBase = NextRandom() & 0xFFFFFFF0;
        isa.stackSize = 0x10000 + (NextRandom() % 0x10000);
    } else {
        isa.stackBase = 0;
        isa.stackSize = 0x20000;
    }

    // 生成假 handler 的 opcode
    for (uint32_t i = 0; i < m_config.junkHandlerCount; i++) {
        isa.junkOpcodes.push_back(NextRandomByte());
    }

    return isa;
}

MutatedHandler MutationEngine::MutateHandler(const uint8_t* originalHandler, uint32_t originalSize) {
    MutatedHandler handler;
    handler.originalOpcode = 0;
    handler.mutatedOpcode = 0;
    handler.isJunk = false;

    if (!originalHandler || originalSize == 0) return handler;

    // 复制原始代码
    handler.code.assign(originalHandler, originalHandler + originalSize);

    // 应用变异
    if (m_config.mutateHandlers) {
        MutateCode(handler.code);
    }

    handler.codeSize = (uint32_t)handler.code.size();
    return handler;
}

MutatedHandler MutationEngine::GenerateJunkHandler() {
    MutatedHandler handler;
    handler.isJunk = true;
    handler.originalOpcode = 0xFF;
    handler.mutatedOpcode = NextRandomByte();

    // 生成看起来有意义但不会被调度到的代码
    // 例如：mov reg, 0; add reg, 1; sub reg, 1; ret
    handler.code = {
        0x48, 0x31, 0xC0,                   // xor rax, rax
        0x48, 0x83, 0xC0, 0x01,             // add rax, 1
        0x48, 0x83, 0xE8, 0x01,             // sub rax, 1
        0xC3                                 // ret
    };

    // 随机化寄存器
    handler.code[2] = NextRandomByte() & 0x07;

    handler.codeSize = (uint32_t)handler.code.size();
    return handler;
}

std::vector<MutatedHandler> MutationEngine::GenerateHandlerTable(const MutatedISA& isa) {
    std::vector<MutatedHandler> table;

    // 生成真 handler
    for (int i = 0; i < 256; i++) {
        MutatedHandler handler;
        handler.originalOpcode = (uint8_t)i;

        auto it = isa.opcodeMap.find((uint8_t)i);
        handler.mutatedOpcode = (it != isa.opcodeMap.end()) ? it->second : (uint8_t)i;
        handler.isJunk = false;

        // 生成 handler 代码（简化）
        handler.code = {
            0x48, 0x83, 0xC0, 0x00,  // add rax, 0 (NOP-like)
            0xC3                       // ret
        };
        handler.codeSize = (uint32_t)handler.code.size();

        table.push_back(handler);
    }

    // 插入假 handler
    if (m_config.insertJunkHandlers) {
        for (uint32_t i = 0; i < m_config.junkHandlerCount; i++) {
            table.push_back(GenerateJunkHandler());
        }
    }

    // 随机打乱顺序
    std::random_shuffle(table.begin(), table.end());

    return table;
}

uint32_t MutationEngine::GetSeed() const {
    return m_config.seed;
}

// ============================================================================
// 内部实现
// ============================================================================

std::unordered_map<uint8_t, uint8_t> MutationEngine::RandomizeOpcodeMap() {
    std::unordered_map<uint8_t, uint8_t> map;

    // 生成 0-255 的随机排列
    std::vector<uint8_t> perm(256);
    for (int i = 0; i < 256; i++) perm[i] = (uint8_t)i;

    // Fisher-Yates 洗牌
    for (int i = 255; i > 0; i--) {
        int j = (int)(NextRandom() % (i + 1));
        uint8_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }

    // 建立映射
    for (int i = 0; i < 256; i++) {
        map[(uint8_t)i] = perm[i];
    }

    return map;
}

std::unordered_map<uint8_t, uint8_t> MutationEngine::RandomizeRegisterMap() {
    std::unordered_map<uint8_t, uint8_t> map;

    for (int i = 0; i < 16; i++) {
        map[(uint8_t)i] = (uint8_t)(NextRandom() % m_config.registerCount);
    }

    return map;
}

std::vector<uint8_t> MutationEngine::RandomizeHandlerOrder() {
    std::vector<uint8_t> order(256);
    for (int i = 0; i < 256; i++) order[i] = (uint8_t)i;

    // 洗牌
    for (int i = 255; i > 0; i--) {
        int j = (int)(NextRandom() % (i + 1));
        uint8_t tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }

    return order;
}

void MutationEngine::MutateCode(std::vector<uint8_t>& code) {
    // 1. 插入垃圾指令
    InsertJunkInstructions(code);

    // 2. 重映射寄存器
    RemapRegisters(code);

    // 3. 重排序代码
    RearrangeCode(code);
}

void MutationEngine::InsertJunkInstructions(std::vector<uint8_t>& code) {
    // 在代码中随机位置插入无害的垃圾指令
    std::vector<uint8_t> junkPatterns = {
        0x90,                               // nop
        0x48, 0x89, 0xC0,                   // mov rax, rax
        0x48, 0x83, 0xC0, 0x00,             // add rax, 0
        0x48, 0x83, 0xE8, 0x00,             // sub rax, 0
        0x48, 0x21, 0xC0,                   // and rax, rax
        0x48, 0x09, 0xC0,                   // or rax, rax
    };

    // 在随机位置插入 1-3 条垃圾指令
    int insertCount = 1 + (NextRandom() % 3);
    for (int i = 0; i < insertCount; i++) {
        size_t pos = NextRandom() % code.size();
        int patternIdx = (NextRandom() % (junkPatterns.size() / 3)) * 3;

        // 插入 nop
        code.insert(code.begin() + pos, 0x90);
    }
}

void MutationEngine::RemapRegisters(std::vector<uint8_t>& code) {
    // 简化：在某些指令中替换寄存器编码
    for (size_t i = 0; i < code.size(); i++) {
        // 检测 MOV reg, imm 指令 (B8-BF)
        if (code[i] >= 0xB8 && code[i] <= 0xBF) {
            // 随机选择一个不同的寄存器
            uint8_t newReg = (uint8_t)(NextRandom() % 8);
            code[i] = 0xB8 + newReg;
        }
    }
}

void MutationEngine::RearrangeCode(std::vector<uint8_t>& code) {
    // 简化：不改变语义的情况下重排独立指令
    // 实际实现需要数据流分析
    (void)code;
}

uint32_t MutationEngine::NextRandom() {
    // 简单的 LCG 随机数生成器
    m_randomState = m_randomState * 1103515245 + 12345;
    return (m_randomState >> 16) & 0x7FFF;
}

uint8_t MutationEngine::NextRandomByte() {
    return (uint8_t)(NextRandom() & 0xFF);
}

} // namespace CipherShell
