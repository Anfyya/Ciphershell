/**
 * CipherShell 变异引擎 - 实现
 */

#include "mutation_engine.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <random>

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
    std::random_device rd2;
    std::mt19937 g2(rd2());
    std::shuffle(table.begin(), table.end(), g2);

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
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(order.begin(), order.end(), g);

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
    // BUG 10 修复：先识别指令边界，只在指令边界处插入垃圾指令
    // 不能在多字节指令中间插入，否则会破坏原有指令编码

    // 安全的垃圾指令模板（完整的 x86-64 指令）
    struct JunkPattern {
        const uint8_t* data;
        size_t size;
    };
    static const uint8_t nop1[] = { 0x90 };                           // nop
    static const uint8_t nop2[] = { 0x66, 0x90 };                     // 66 nop (2字节 nop)
    static const uint8_t nop3[] = { 0x0F, 0x1F, 0x00 };               // nop dword [rax] (3字节 nop)
    static const uint8_t nop4[] = { 0x0F, 0x1F, 0x40, 0x00 };         // nop dword [rax+0] (4字节 nop)

    JunkPattern patterns[] = {
        { nop1, sizeof(nop1) },
        { nop2, sizeof(nop2) },
        { nop3, sizeof(nop3) },
        { nop4, sizeof(nop4) },
    };
    int patternCount = sizeof(patterns) / sizeof(patterns[0]);

    // 识别指令边界（简化实现：扫描已知前缀识别指令长度）
    // 由于这是 handler 代码变异，handler 通常较短，使用保守策略：
    // 只在 code 的开头和末尾（ret 之前）插入 NOP 序列，避免在中间破坏指令
    if (code.empty()) return;

    int insertCount = 1 + (NextRandom() % 2);
    for (int i = 0; i < insertCount; i++) {
        int patIdx = NextRandom() % patternCount;
        const JunkPattern& pat = patterns[patIdx];

        // 在代码开头插入（安全的指令边界位置）
        code.insert(code.begin(), pat.data, pat.data + pat.size);
    }
}

void MutationEngine::RemapRegisters(std::vector<uint8_t>& code) {
    // BUG 9 修复：寄存器重映射必须确保生成的指令合法
    // 之前直接修改字节可能产生非法编码
    // 修复策略：只对已知安全的编码模式进行寄存器替换

    for (size_t i = 0; i < code.size(); i++) {
        // 检测 REX 前缀（48h-4Fh），跳过以避免破坏 REX.B/R/X 位
        if (code[i] >= 0x48 && code[i] <= 0x4F) {
            // 这是 REX 前缀，下一字节才是操作码，跳过 REX
            i++;
            if (i >= code.size()) break;

            // REX + MOV reg, imm64 (B8-BF)：
            // REX.B 控制寄存器扩展，只能在 REX.B=0 时安全替换低3位
            if (code[i] >= 0xB8 && code[i] <= 0xBF) {
                uint8_t rexByte = code[i - 1];
                // 只在 REX.B == 0 时替换（否则寄存器编号受 REX.B 影响）
                if ((rexByte & 0x01) == 0) {
                    uint8_t newReg = (uint8_t)(NextRandom() % 8);
                    code[i] = 0xB8 + newReg;
                }
                // 跳过 imm64 操作数 (8 字节)
                i += 8;
            }
            // REX + 双字节指令带 ModR/M（如 89/8B 等）：
            // 不做修改，避免生成非法 ModR/M 组合
            continue;
        }

        // 非 REX 的 MOV reg, imm32 (B8-BF)
        if (code[i] >= 0xB8 && code[i] <= 0xBF) {
            uint8_t newReg = (uint8_t)(NextRandom() % 8);
            code[i] = 0xB8 + newReg;
            // 跳过 imm32 操作数 (4 字节)
            i += 4;
            continue;
        }

        // 其它指令编码不做修改，避免生成非法指令
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
