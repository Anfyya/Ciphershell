/**
 * CipherShell 控制流图构建器
 * 构建和分析控制流图（CFG）
 */

#ifndef CS_CFG_BUILDER_H
#define CS_CFG_BUILDER_H

#include "disassembler.h"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>

namespace CipherShell {

// ============================================================================
// 控制流图节点
// ============================================================================

struct CFGNode {
    uint64_t    id;                 // 节点 ID
    uint64_t    startAddress;       // 起始地址
    uint64_t    endAddress;         // 结束地址
    BasicBlock  block;              // 关联的基本块
    
    // 支配树信息
    uint64_t    dominatorId;        // 直接支配者 ID
    std::vector<uint64_t> dominated; // 支配的节点
    
    // 循环信息
    bool        isLoopHeader;       // 是否循环头
    uint32_t    loopDepth;          // 循环嵌套深度
    std::vector<uint64_t> loopMembers; // 循环成员
    
    // 属性
    bool        isCritical;         // 是否关键节点
    bool        isHotspot;          // 是否热点
    uint32_t    protectionLevel;    // 保护等级
};

// ============================================================================
// 控制流图边
// ============================================================================

struct CFGEdge {
    uint64_t    sourceId;           // 源节点 ID
    uint64_t    targetId;           // 目标节点 ID
    bool        isConditional;      // 是否条件分支
    bool        isBackEdge;         // 是否回边
    bool        isCritical;         // 是否关键边
};

// ============================================================================
// 控制流图
// ============================================================================

struct ControlFlowGraph {
    std::vector<CFGNode> nodes;                     // 节点列表
    std::vector<CFGEdge> edges;                     // 边列表
    std::unordered_map<uint64_t, size_t> nodeMap;   // 地址到节点索引的映射
    uint64_t    entryNodeId;                        // 入口节点 ID
    
    // 统计信息
    uint32_t    nodeCount;
    uint32_t    edgeCount;
    uint32_t    loopCount;
    uint32_t    maxLoopDepth;
};

// ============================================================================
// CFG 构建器类
// ============================================================================

class CFGBuilder {
public:
    CFGBuilder();
    ~CFGBuilder();

    /**
     * 从基本块构建 CFG
     * @param blocks 基本块列表
     * @return 控制流图
     */
    ControlFlowGraph Build(const std::vector<BasicBlock>& blocks);

    /**
     * 计算支配树
     * @param cfg 控制流图
     */
    void ComputeDominatorTree(ControlFlowGraph& cfg);

    /**
     * 识别循环
     * @param cfg 控制流图
     */
    void IdentifyLoops(ControlFlowGraph& cfg);

    /**
     * 计算节点深度
     * @param cfg 控制流图
     * @return 节点深度映射
     */
    std::unordered_map<uint64_t, uint32_t> ComputeNodeDepths(const ControlFlowGraph& cfg);

    /**
     * 查找关键路径
     * @param cfg 控制流图
     * @return 关键路径节点列表
     */
    std::vector<uint64_t> FindCriticalPath(const ControlFlowGraph& cfg);

    /**
     * 分析热点
     * @param cfg 控制流图
     * @param callFrequency 调用频率估计
     */
    void AnalyzeHotspots(ControlFlowGraph& cfg, 
                         const std::unordered_map<uint64_t, uint32_t>& callFrequency);

    /**
     * 分配保护等级
     * @param cfg 控制流图
     * @param defaultLevel 默认保护等级
     */
    void AssignProtectionLevels(ControlFlowGraph& cfg, uint32_t defaultLevel);

    /**
     * 验证 CFG 完整性
     * @param cfg 控制流图
     * @return 是否有效
     */
    bool Validate(const ControlFlowGraph& cfg);

private:
    // 支配树计算
    uint64_t Intersect(uint64_t b1, uint64_t b2, 
                       const std::unordered_map<uint64_t, uint32_t>& depth,
                       const std::unordered_map<uint64_t, uint64_t>& idom);

    // 循环识别
    void FindBackEdges(const ControlFlowGraph& cfg, std::vector<CFGEdge>& backEdges);
    void CollectLoopMembers(ControlFlowGraph& cfg, const CFGEdge& backEdge);

    // 辅助函数
    bool IsReachable(const ControlFlowGraph& cfg, uint64_t from, uint64_t to);
    std::vector<uint64_t> GetPredecessors(const ControlFlowGraph& cfg, uint64_t nodeId);
    std::vector<uint64_t> GetSuccessors(const ControlFlowGraph& cfg, uint64_t nodeId);

    // 成员变量
    std::unordered_map<uint64_t, size_t> m_nodeIndex;
};

} // namespace CipherShell

#endif // CS_CFG_BUILDER_H
