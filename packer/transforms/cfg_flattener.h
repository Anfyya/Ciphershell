/**
 * CipherShell 控制流平坦化
 * 将函数的正常控制流结构拍平为状态机
 */

#ifndef CS_CFG_FLATTENER_H
#define CS_CFG_FLATTENER_H

#include "analysis/cfg_builder.h"
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// 平坦化配置
// ============================================================================

struct FlatteningConfig {
    bool        enableStateEncryption;      // 状态变量加密
    bool        enableStateRandomization;   // 状态 ID 随机化
    bool        enableDispatcherMutation;    // Dispatcher 变异
    bool        enableOpaquePredicate;       // 插入不透明谓词
    uint32_t    junkCaseCount;              // 假 case 数量
    uint32_t    stateKeyRotation;           // 状态密钥轮换周期

    FlatteningConfig() :
        enableStateEncryption(true),
        enableStateRandomization(true),
        enableDispatcherMutation(true),
        enableOpaquePredicate(false),
        junkCaseCount(5),
        stateKeyRotation(16) {}
};

// ============================================================================
// 平坦化后的基本块
// ============================================================================

struct FlattenedBlock {
    uint32_t    stateId;            // 状态 ID
    uint64_t    originalAddress;    // 原始地址
    uint32_t    nextStateId;        // 下一个状态 ID（无条件）
    uint32_t    nextStateIdTrue;    // 条件为真时的下一个状态
    uint32_t    nextStateIdFalse;   // 条件为假时的下一个状态
    bool        isConditional;      // 是否条件块
    BasicBlock  originalBlock;      // 原始基本块
};

// ============================================================================
// 平坦化结果
// ============================================================================

struct FlatteningResult {
    std::vector<FlattenedBlock> blocks;     // 平坦化后的块
    uint32_t    entryStateId;               // 入口状态 ID
    uint32_t    stateEncryptionKey;         // 状态加密密钥
    uint32_t    stateCount;                 // 状态数量
    uint32_t    junkCaseCount;              // 假 case 数量
};

// ============================================================================
// 控制流平坦化器类
// ============================================================================

class CFGFlattener {
public:
    CFGFlattener();
    ~CFGFlattener();

    /**
     * 对控制流图进行平坦化
     * @param cfg 控制流图
     * @param config 平坦化配置
     * @return 平坦化结果
     */
    FlatteningResult Flatten(const ControlFlowGraph& cfg, const FlatteningConfig& config);

    /**
     * 对单个函数进行平坦化
     * @param func 函数信息
     * @param config 平坦化配置
     * @return 平坦化结果
     */
    FlatteningResult FlattenFunction(const Function& func, const FlatteningConfig& config);

    /**
     * 生成平坦化后的代码
     * @param result 平坦化结果
     * @param is64Bit 是否 64 位
     * @param codeSize 输出代码大小
     * @return 生成的代码
     */
    BYTE* GenerateFlattenedCode(const FlatteningResult& result, bool is64Bit, DWORD* codeSize);

    /**
     * 生成 dispatcher 代码
     * @param result 平坦化结果
     * @param is64Bit 是否 64 位
     * @param dispatcherSize 输出大小
     * @return dispatcher 代码
     */
    BYTE* GenerateDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* dispatcherSize);

private:
    // 状态 ID 生成
    uint32_t GenerateStateId();
    uint32_t GenerateRandomStateId();

    // 块重排序
    std::vector<FlattenedBlock> ReorderBlocks(const std::vector<FlattenedBlock>& blocks);

    // Dispatcher 生成
    BYTE* GenerateTableDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size);
    BYTE* GenerateComputedDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size);
    BYTE* GenerateMixedDispatcher(const FlatteningResult& result, bool is64Bit, DWORD* size);

    // 辅助函数
    uint32_t EncryptStateId(uint32_t stateId, uint32_t key);
    uint32_t DecryptStateId(uint32_t encryptedStateId, uint32_t key);

    // 成员变量
    uint32_t m_nextStateId;
    uint32_t m_encryptionKey;
};

} // namespace CipherShell

#endif // CS_CFG_FLATTENER_H
