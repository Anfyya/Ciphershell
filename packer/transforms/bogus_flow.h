/**
 * CipherShell 虚假控制流
 * 在真实基本块前后插入由不透明谓词守护的假路径
 */

#ifndef CS_BOGUS_FLOW_H
#define CS_BOGUS_FLOW_H

#include "analysis/cfg_builder.h"
#include "opaque_predicates.h"
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// 虚假控制流配置
// ============================================================================

struct BogusFlowConfig {
    uint32_t    bogusBlocksPerReal;     // 每个真实块插入的假块数量
    bool        useOpaquePredicates;    // 使用不透明谓词
    bool        duplicateCode;          // 复制代码
    bool        insertDeadCode;         // 插入死代码
    uint32_t    maxNestingDepth;        // 最大嵌套深度
    float       duplicateRatio;         // 代码复制比例

    BogusFlowConfig() :
        bogusBlocksPerReal(2),
        useOpaquePredicates(true),
        duplicateCode(true),
        insertDeadCode(true),
        maxNestingDepth(3),
        duplicateRatio(0.3f) {}
};

// ============================================================================
// 虚假块信息
// ============================================================================

struct BogusBlock {
    uint64_t        id;                 // 块 ID
    uint64_t        originalId;         // 原始块 ID（如果是复制的）
    bool            isBogus;            // 是否是假块
    bool            isDuplicate;        // 是否是复制的
    BasicBlock      block;              // 关联的基本块
    OpaquePredicate guardPredicate;     // 守护谓词
};

// ============================================================================
// 虚假控制流结果
// ============================================================================

struct BogusFlowResult {
    std::vector<BogusBlock> allBlocks;          // 所有块（包括假块）
    std::vector<uint64_t> realBlockIds;         // 真实块 ID 列表
    std::vector<uint64_t> bogusBlockIds;        // 假块 ID 列表
    uint32_t    totalBlocks;                    // 总块数
    uint32_t    bogusCount;                     // 假块数量
    uint32_t    duplicateCount;                 // 复制块数量
};

// ============================================================================
// 虚假控制流注入器类
// ============================================================================

class BogusFlowInjector {
public:
    BogusFlowInjector();
    ~BogusFlowInjector();

    /**
     * 对控制流图注入虚假控制流
     * @param cfg 控制流图
     * @param config 配置
     * @return 注入结果
     */
    BogusFlowResult Inject(const ControlFlowGraph& cfg, const BogusFlowConfig& config);

    /**
     * 对单个函数注入虚假控制流
     * @param func 函数信息
     * @param config 配置
     * @return 注入结果
     */
    BogusFlowResult InjectIntoFunction(const Function& func, const BogusFlowConfig& config);

    /**
     * 生成虚假控制流后的代码
     * @param result 注入结果
     * @param is64Bit 是否 64 位
     * @param codeSize 输出代码大小
     * @return 生成的代码
     */
    BYTE* GenerateBogusCode(const BogusFlowResult& result, bool is64Bit, DWORD* codeSize);

    /**
     * 清理资源
     * @param result 注入结果
     */
    void Cleanup(BogusFlowResult& result);

private:
    // 块创建
    BogusBlock CreateBogusBlock(uint64_t originalId, const BasicBlock& originalBlock);
    BogusBlock CreateDuplicateBlock(uint64_t originalId, const BasicBlock& originalBlock);
    BasicBlock GenerateDeadCode();

    // 代码变异
    BasicBlock MutateBlock(const BasicBlock& block);
    void RemapRegisters(BasicBlock& block);
    void RearrangeInstructions(BasicBlock& block);

    // 辅助函数
    uint64_t GenerateBlockId();
    bool ShouldDuplicate(float ratio);

    // 成员变量
    OpaquePredicateGenerator m_predicateGen;
    uint64_t m_nextBlockId;
};

} // namespace CipherShell

#endif // CS_BOGUS_FLOW_H
