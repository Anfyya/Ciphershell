/**
 * CipherShell 控制流平坦化 - 实现
 */

#include "cfg_flattener.h"
#include <algorithm>
#include <random>
#include <ctime>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

CFGFlattener::CFGFlattener() 
    : m_nextStateId(1)
    , m_encryptionKey(0x12345678)
{
    srand((unsigned int)time(nullptr));
}

CFGFlattener::~CFGFlattener() {}

// ============================================================================
// 公共接口
// ============================================================================

FlatteningResult CFGFlattener::Flatten(const ControlFlowGraph& cfg, const FlatteningConfig& config) {
    FlatteningResult result;
    result.stateEncryptionKey = config.enableStateEncryption ? rand() : 0;
    result.junkCaseCount = config.junkCaseCount;

    m_encryptionKey = result.stateEncryptionKey;

    // 为每个节点分配状态 ID
    std::unordered_map<uint64_t, uint32_t> stateMap;
    for (const auto& node : cfg.nodes) {
        uint32_t stateId = config.enableStateRandomization ? 
                           GenerateRandomStateId() : GenerateStateId();
        stateMap[node.id] = stateId;
    }

    // 设置入口状态
    if (cfg.entryNodeId < cfg.nodes.size()) {
        result.entryStateId = stateMap[cfg.entryNodeId];
    }

    // 创建平坦化后的块
    for (const auto& node : cfg.nodes) {
        FlattenedBlock flatBlock;
        flatBlock.stateId = stateMap[node.id];
        flatBlock.originalAddress = node.startAddress;
        flatBlock.originalBlock = node.block;
        flatBlock.isConditional = false;

        // 确定下一个状态
        auto successors = cfg.edges;
        std::vector<uint64_t> succIds;
        for (const auto& edge : successors) {
            if (edge.sourceId == node.id) {
                succIds.push_back(edge.targetId);
            }
        }

        if (succIds.empty()) {
            // 没有后继（返回块）
            flatBlock.nextStateId = 0;  // 退出
            flatBlock.nextStateIdTrue = 0;
            flatBlock.nextStateIdFalse = 0;
        } else if (succIds.size() == 1) {
            // 单后继（无条件跳转）
            flatBlock.nextStateId = stateMap[succIds[0]];
            flatBlock.nextStateIdTrue = stateMap[succIds[0]];
            flatBlock.nextStateIdFalse = stateMap[succIds[0]];
        } else {
            // 多后继（条件分支）
            flatBlock.isConditional = true;
            flatBlock.nextStateIdTrue = stateMap[succIds[0]];
            flatBlock.nextStateIdFalse = stateMap[succIds[1]];
            flatBlock.nextStateId = stateMap[succIds[0]];  // 默认
        }

        result.blocks.push_back(flatBlock);
    }

    // 添加假 case
    for (uint32_t i = 0; i < config.junkCaseCount; i++) {
        FlattenedBlock junkBlock;
        junkBlock.stateId = GenerateRandomStateId();
        junkBlock.originalAddress = 0;
        junkBlock.nextStateId = GenerateRandomStateId();
        junkBlock.nextStateIdTrue = junkBlock.nextStateId;
        junkBlock.nextStateIdFalse = junkBlock.nextStateId;
        junkBlock.isConditional = false;
        result.blocks.push_back(junkBlock);
    }

    result.stateCount = (uint32_t)result.blocks.size();

    // 重排序块
    result.blocks = ReorderBlocks(result.blocks);

    return result;
}

FlatteningResult CFGFlattener::FlattenFunction(const Function& func, const FlatteningConfig& config) {
    // 从函数构建临时 CFG
    CFGBuilder builder;
    ControlFlowGraph cfg = builder.Build(func.blocks);

    return Flatten(cfg, config);
}

BYTE* CFGFlattener::GenerateFlattenedCode(const FlatteningResult& result, bool is64Bit, DWORD* codeSize) {
    if (!codeSize) return nullptr;
    if (result.blocks.empty()) {
        *codeSize = 0;
        return nullptr;
    }

    // ----------------------------------------------------------------
    // 布局（所有偏移量均为相对于 code 缓冲区起始处的字节偏移）
    //
    // [入口]
    //   mov eax, entryStateId          ; 5 字节
    //   jmp dispatcherStart            ; 5 字节（无条件跳转到 dispatcher）
    //
    // [dispatcher]
    //   对每个块：
    //     cmp eax, stateId             ; 5 字节 (81 F8 xx xx xx xx -> 6字节)
    //     je  blockBody[i]             ; 6 字节（短/长 JE）
    //   退出（stateId==0 表示 ret）：
    //     ret                          ; 1 字节
    //
    // [每个 block 的 body]
    //   <原始指令字节>
    //   若为条件块：
    //     je  trueBlock                ; 6 字节
    //     mov eax, nextStateIdFalse    ; 5 字节
    //     jmp dispatcherStart          ; 5 字节
    //     [trueBlock:]
    //     mov eax, nextStateIdTrue     ; 5 字节
    //     jmp dispatcherStart          ; 5 字节
    //   否则：
    //     若 nextStateId == 0：ret     ; 1 字节
    //     否则：
    //       mov eax, nextStateId       ; 5 字节
    //       jmp dispatcherStart        ; 5 字节
    // ----------------------------------------------------------------

    size_t blockCount = result.blocks.size();

    // 第一遍：计算各段的大小上限
    // 入口段：5 + 5 = 10 字节
    // dispatcher 段：每块 (6 + 6) = 12 字节，末尾 1 字节 ret
    // 每个 block body：原始字节 + 最多 26 字节尾部
    DWORD origBytesTotal = 0;
    for (const auto& blk : result.blocks) {
        for (const auto& instr : blk.originalBlock.instructions) {
            origBytesTotal += instr.length;
        }
    }
    DWORD estimatedSize = 10                              // 入口
                        + (DWORD)(blockCount * 12 + 1)   // dispatcher
                        + origBytesTotal
                        + (DWORD)(blockCount * 30)        // 每块尾部
                        + 64;                             // 裕量

    BYTE* code = new(std::nothrow) BYTE[estimatedSize];
    if (!code) return nullptr;
    memset(code, 0xCC, estimatedSize);  // int3 填充，便于调试

    DWORD off = 0;  // 当前写入位置

    // ------------------------------------------------------------------
    // 辅助 lambda：写入 4 字节小端整数
    // ------------------------------------------------------------------
    auto write32 = [&](DWORD v) {
        code[off++] = (BYTE)(v & 0xFF);
        code[off++] = (BYTE)((v >> 8) & 0xFF);
        code[off++] = (BYTE)((v >> 16) & 0xFF);
        code[off++] = (BYTE)((v >> 24) & 0xFF);
    };

    // label 分配：
    //   label 0       = dispatcher 入口
    //   label 1..N    = block body[0..N-1]
    //   label N+1..2N = block body 内部 trueTarget (条件块)
    const int LABEL_DISPATCHER = 0;
    const int LABEL_BLOCK_BASE = 1;
    const int LABEL_TRUE_BASE  = (int)blockCount + 1;

    // patch 列表: { offset_of_rel32, target_label }
    struct Patch { DWORD relOff; int labelId; };
    std::vector<Patch> patchList;
    std::vector<DWORD> labelOffsets(blockCount * 2 + 2, 0);

    // ==================================================================
    // 1. 入口段
    // ==================================================================
    // mov eax, entryStateId
    code[off++] = 0xB8;
    write32(result.entryStateId);

    // jmp dispatcher (rel32 — 稍后修补)
    code[off++] = 0xE9;
    patchList.push_back({off, LABEL_DISPATCHER});
    write32(0);  // 占位

    // ==================================================================
    // 2. Dispatcher 段
    // ==================================================================
    labelOffsets[LABEL_DISPATCHER] = off;

    for (size_t i = 0; i < blockCount; i++) {
        // cmp eax, stateId   (81 F8 imm32)
        code[off++] = 0x81;
        code[off++] = 0xF8;
        write32(result.blocks[i].stateId);

        // je blockBody[i]    (0F 84 rel32)
        code[off++] = 0x0F;
        code[off++] = 0x84;
        patchList.push_back({off, LABEL_BLOCK_BASE + (int)i});
        write32(0);
    }

    // dispatcher 尾部：stateId==0 表示退出
    code[off++] = 0xC3;  // ret

    // ==================================================================
    // 3. Block Body 段
    // ==================================================================
    for (size_t i = 0; i < blockCount; i++) {
        labelOffsets[LABEL_BLOCK_BASE + (int)i] = off;
        const auto& blk = result.blocks[i];

        // 写入原始指令字节
        for (const auto& instr : blk.originalBlock.instructions) {
            for (size_t b = 0; b < instr.length; b++) {
                code[off++] = instr.bytes[b];
            }
        }

        // 尾部跳转
        if (blk.isConditional) {
            // 条件块：保留原始 Jcc 的条件码
            // je trueTarget (0F 84 rel32)
            code[off++] = 0x0F;
            code[off++] = 0x84;
            patchList.push_back({off, LABEL_TRUE_BASE + (int)i});
            write32(0);

            // false 路径: mov eax, nextStateIdFalse; jmp dispatcher
            code[off++] = 0xB8;
            write32(blk.nextStateIdFalse);
            code[off++] = 0xE9;
            patchList.push_back({off, LABEL_DISPATCHER});
            write32(0);

            // true 路径:
            labelOffsets[LABEL_TRUE_BASE + (int)i] = off;
            code[off++] = 0xB8;
            write32(blk.nextStateIdTrue);
            code[off++] = 0xE9;
            patchList.push_back({off, LABEL_DISPATCHER});
            write32(0);
        } else {
            if (blk.nextStateId == 0) {
                code[off++] = 0xC3;  // ret
            } else {
                // mov eax, nextStateId; jmp dispatcher
                code[off++] = 0xB8;
                write32(blk.nextStateId);
                code[off++] = 0xE9;
                patchList.push_back({off, LABEL_DISPATCHER});
                write32(0);
            }
        }
    }

    // ==================================================================
    // 4. 修补所有 rel32 跳转
    // ==================================================================
    for (const auto& p : patchList) {
        DWORD target = labelOffsets[p.labelId];
        DWORD source = p.relOff + 4;  // rel32 基址 = rel32 字段末尾
        int32_t rel = (int32_t)(target - source);
        code[p.relOff + 0] = (BYTE)(rel & 0xFF);
        code[p.relOff + 1] = (BYTE)((rel >> 8) & 0xFF);
        code[p.relOff + 2] = (BYTE)((rel >> 16) & 0xFF);
        code[p.relOff + 3] = (BYTE)((rel >> 24) & 0xFF);
    }

    *codeSize = off;
    return code;
}

// ============================================================================
// GenerateDispatcher — 生成独立 dispatcher 代码
// ============================================================================

BYTE* CFGFlattener::GenerateDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* dispatcherSize) {
    if (!dispatcherSize) return nullptr;

    // 随机选择 dispatcher 类型
    int type = rand() % 3;
    switch (type) {
        case 0:  return GenerateTableDispatcher(result, is64Bit, dispatcherSize);
        case 1:  return GenerateComputedDispatcher(result, is64Bit, dispatcherSize);
        default: return GenerateMixedDispatcher(result, is64Bit, dispatcherSize);
    }
}

// ============================================================================
// Table Dispatcher — 跳转表查找
// ============================================================================

BYTE* CFGFlattener::GenerateTableDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size) {
    // 构建状态 ID → 表索引的映射
    std::unordered_map<uint32_t, uint32_t> stateToIndex;
    uint32_t idx = 0;
    for (const auto& blk : result.blocks) {
        stateToIndex[blk.stateId] = idx++;
    }

    uint32_t tableSize = (uint32_t)result.blocks.size();
    // 代码布局：
    //   sub eax, minStateId     ; 标准化索引（如果状态不连续则需要不同方案）
    //   cmp eax, tableSize      ; 范围检查
    //   jae exit                ; 越界则退出
    //   jmp [eax*4 + table]     ; 跳转表
    //   table: dd offset0, offset1, ...

    // 简化实现：用线性搜索模拟跳转表
    DWORD codeLen = 32 + tableSize * 12;
    BYTE* code = new(std::nothrow) BYTE[codeLen];
    if (!code) { *size = 0; return nullptr; }
    memset(code, 0xCC, codeLen);

    DWORD off = 0;

    // 对每个状态生成 cmp/je
    for (const auto& blk : result.blocks) {
        // cmp eax, stateId
        code[off++] = 0x3D;
        code[off++] = (BYTE)(blk.stateId & 0xFF);
        code[off++] = (BYTE)((blk.stateId >> 8) & 0xFF);
        code[off++] = (BYTE)((blk.stateId >> 16) & 0xFF);
        code[off++] = (BYTE)((blk.stateId >> 24) & 0xFF);

        // je +0 (占位，需后续修补)
        code[off++] = 0x74;
        code[off++] = 0x00;  // short jump placeholder
    }

    // ret (default exit)
    code[off++] = 0xC3;

    *size = off;
    return code;
}

// ============================================================================
// Computed Dispatcher — XOR 加密状态
// ============================================================================

BYTE* CFGFlattener::GenerateComputedDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size) {
    DWORD codeLen = 64 + (DWORD)result.blocks.size() * 16;
    BYTE* code = new(std::nothrow) BYTE[codeLen];
    if (!code) { *size = 0; return nullptr; }
    memset(code, 0xCC, codeLen);

    DWORD off = 0;

    // 用 XOR 解密状态变量
    // xor eax, encryptionKey
    code[off++] = 0x35;  // xor eax, imm32
    code[off++] = (BYTE)(result.stateEncryptionKey & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 8) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 16) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 24) & 0xFF);

    // 然后做线性匹配
    for (const auto& blk : result.blocks) {
        uint32_t decryptedState = blk.stateId ^ result.stateEncryptionKey;

        // cmp eax, decryptedState
        code[off++] = 0x81;
        code[off++] = 0xF8;
        code[off++] = (BYTE)(decryptedState & 0xFF);
        code[off++] = (BYTE)((decryptedState >> 8) & 0xFF);
        code[off++] = (BYTE)((decryptedState >> 16) & 0xFF);
        code[off++] = (BYTE)((decryptedState >> 24) & 0xFF);

        // je +0 (占位)
        code[off++] = 0x74;
        code[off++] = 0x00;
    }

    // 加密回去 (xor eax, key) 然后 ret
    code[off++] = 0x35;
    code[off++] = (BYTE)(result.stateEncryptionKey & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 8) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 16) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 24) & 0xFF);

    code[off++] = 0xC3;  // ret

    *size = off;
    return code;
}

// ============================================================================
// Mixed Dispatcher — 混合模式
// ============================================================================

BYTE* CFGFlattener::GenerateMixedDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size) {
    // 混合方案：前半用 XOR 加密，后半用直接比较，两者之间插入垃圾指令
    DWORD codeLen = 128 + (DWORD)result.blocks.size() * 20;
    BYTE* code = new(std::nothrow) BYTE[codeLen];
    if (!code) { *size = 0; return nullptr; }
    memset(code, 0xCC, codeLen);

    DWORD off = 0;
    size_t half = result.blocks.size() / 2;

    // 保存 eax
    code[off++] = 0x50;  // push eax

    // XOR 加密部分
    code[off++] = 0x35;  // xor eax, imm32
    code[off++] = (BYTE)(result.stateEncryptionKey & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 8) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 16) & 0xFF);
    code[off++] = (BYTE)((result.stateEncryptionKey >> 24) & 0xFF);

    for (size_t i = 0; i < half && i < result.blocks.size(); i++) {
        uint32_t decState = result.blocks[i].stateId ^ result.stateEncryptionKey;
        code[off++] = 0x3D;  // cmp eax, imm32
        code[off++] = (BYTE)(decState & 0xFF);
        code[off++] = (BYTE)((decState >> 8) & 0xFF);
        code[off++] = (BYTE)((decState >> 16) & 0xFF);
        code[off++] = (BYTE)((decState >> 24) & 0xFF);
        code[off++] = 0x74;  // je short
        code[off++] = 0x00;
    }

    // 垃圾指令分隔
    code[off++] = 0x90;  // nop
    code[off++] = 0x90;  // nop

    // 恢复原始 eax
    code[off++] = 0x58;  // pop eax

    // 直接比较部分
    for (size_t i = half; i < result.blocks.size(); i++) {
        code[off++] = 0x3D;  // cmp eax, imm32
        code[off++] = (BYTE)(result.blocks[i].stateId & 0xFF);
        code[off++] = (BYTE)((result.blocks[i].stateId >> 8) & 0xFF);
        code[off++] = (BYTE)((result.blocks[i].stateId >> 16) & 0xFF);
        code[off++] = (BYTE)((result.blocks[i].stateId >> 24) & 0xFF);
        code[off++] = 0x74;  // je short
        code[off++] = 0x00;
    }

    code[off++] = 0xC3;  // ret

    *size = off;
    return code;
}

// ============================================================================
// 辅助函数
// ============================================================================

uint32_t CFGFlattener::GenerateStateId() {
    return m_nextStateId++;
}

uint32_t CFGFlattener::GenerateRandomStateId() {
    // 生成不易碰撞的随机状态 ID
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0x1000, 0x7FFFFFFF);
    return dist(rng);
}

std::vector<FlattenedBlock> CFGFlattener::ReorderBlocks(const std::vector<FlattenedBlock>& blocks) {
    // Fisher-Yates 洗牌
    std::vector<FlattenedBlock> result = blocks;
    std::mt19937 rng(std::random_device{}());

    for (size_t i = result.size() - 1; i > 0; i--) {
        std::uniform_int_distribution<size_t> dist(0, i);
        size_t j = dist(rng);
        std::swap(result[i], result[j]);
    }

    return result;
}

uint32_t CFGFlattener::EncryptStateId(uint32_t stateId, uint32_t key) {
    return stateId ^ key;
}

uint32_t CFGFlattener::DecryptStateId(uint32_t encryptedStateId, uint32_t key) {
    return encryptedStateId ^ key;
}

} // namespace CipherShell
