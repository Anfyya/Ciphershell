/**
 * CipherShell 控制流图构建器 - 实现
 */

#include "cfg_builder.h"
#include <algorithm>
#include <stack>
#include <set>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

CFGBuilder::CFGBuilder() {}
CFGBuilder::~CFGBuilder() {}

// ============================================================================
// 公共接口
// ============================================================================

ControlFlowGraph CFGBuilder::Build(const std::vector<BasicBlock>& blocks) {
    ControlFlowGraph cfg;
    cfg.entryNodeId = 0;
    cfg.nodeCount = 0;
    cfg.edgeCount = 0;
    cfg.loopCount = 0;
    cfg.maxLoopDepth = 0;

    if (blocks.empty()) {
        return cfg;
    }

    // 创建节点
    for (size_t i = 0; i < blocks.size(); i++) {
        CFGNode node;
        node.id = i;
        node.startAddress = blocks[i].startAddress;
        node.endAddress = blocks[i].endAddress;
        node.block = blocks[i];
        node.dominatorId = (uint64_t)-1;
        node.isLoopHeader = false;
        node.loopDepth = 0;
        node.isCritical = false;
        node.isHotspot = false;
        node.protectionLevel = 1;

        cfg.nodes.push_back(node);
        cfg.nodeMap[blocks[i].startAddress] = i;
    }

    cfg.entryNodeId = 0;
    cfg.nodeCount = (uint32_t)cfg.nodes.size();

    // 创建边
    for (size_t i = 0; i < blocks.size(); i++) {
        for (uint64_t successorAddr : blocks[i].successors) {
            auto it = cfg.nodeMap.find(successorAddr);
            if (it != cfg.nodeMap.end()) {
                CFGEdge edge;
                edge.sourceId = i;
                edge.targetId = it->second;
                edge.isConditional = false;
                edge.isBackEdge = false;
                edge.isCritical = false;

                // 检查是否是条件分支
                if (!blocks[i].instructions.empty()) {
                    const auto& lastInstr = blocks[i].instructions.back();
                    edge.isConditional = lastInstr.isConditional;
                }

                cfg.edges.push_back(edge);
                cfg.edgeCount++;
            }
        }
    }

    // 保存节点索引
    m_nodeIndex = cfg.nodeMap;

    // 计算支配树
    ComputeDominatorTree(cfg);

    // 识别循环
    IdentifyLoops(cfg);

    return cfg;
}

void CFGBuilder::ComputeDominatorTree(ControlFlowGraph& cfg) {
    if (cfg.nodes.empty()) return;

    size_t n = cfg.nodes.size();

    // 初始化
    std::unordered_map<uint64_t, uint64_t> idom;  // 直接支配者
    std::unordered_map<uint64_t, uint32_t> depth;  // 节点深度

    // 计算深度（通过 BFS）
    std::queue<uint64_t> queue;
    std::unordered_set<uint64_t> visited;

    queue.push(cfg.entryNodeId);
    depth[cfg.entryNodeId] = 0;
    visited.insert(cfg.entryNodeId);

    while (!queue.empty()) {
        uint64_t current = queue.front();
        queue.pop();

        for (uint64_t successor : GetSuccessors(cfg, current)) {
            if (visited.find(successor) == visited.end()) {
                depth[successor] = depth[current] + 1;
                visited.insert(successor);
                queue.push(successor);
            }
        }
    }

    // 简化的支配树计算
    // 对于每个节点，找到共同支配者
    for (auto& node : cfg.nodes) {
        if (node.id == cfg.entryNodeId) {
            node.dominatorId = (uint64_t)-1;  // 入口节点没有支配者
            continue;
        }

        auto predecessors = GetPredecessors(cfg, node.id);
        if (predecessors.empty()) {
            node.dominatorId = (uint64_t)-1;
            continue;
        }

        // 找到所有前驱的共同支配者
        uint64_t commonDom = predecessors[0];
        for (size_t i = 1; i < predecessors.size(); i++) {
            commonDom = Intersect(commonDom, predecessors[i], depth, idom);
        }

        idom[node.id] = commonDom;
        node.dominatorId = commonDom;

        // 添加到支配者的被支配列表
        if (commonDom < cfg.nodes.size()) {
            cfg.nodes[commonDom].dominated.push_back(node.id);
        }
    }
}

void CFGBuilder::IdentifyLoops(ControlFlowGraph& cfg) {
    // 查找回边
    std::vector<CFGEdge> backEdges;
    FindBackEdges(cfg, backEdges);

    // 对每个回边，收集循环成员
    for (const auto& backEdge : backEdges) {
        CollectLoopMembers(cfg, backEdge);
        cfg.loopCount++;
    }

    // 计算循环深度
    for (auto& node : cfg.nodes) {
        if (node.isLoopHeader) {
            uint32_t maxDepth = 0;
            for (uint64_t member : node.loopMembers) {
                if (member < cfg.nodes.size()) {
                    maxDepth = std::max(maxDepth, cfg.nodes[member].loopDepth);
                }
            }
            node.loopDepth = maxDepth + 1;
            cfg.maxLoopDepth = std::max(cfg.maxLoopDepth, node.loopDepth);
        }
    }
}

std::unordered_map<uint64_t, uint32_t> CFGBuilder::ComputeNodeDepths(const ControlFlowGraph& cfg) {
    std::unordered_map<uint64_t, uint32_t> depths;

    // BFS 计算深度
    std::queue<uint64_t> queue;
    std::unordered_set<uint64_t> visited;

    queue.push(cfg.entryNodeId);
    depths[cfg.entryNodeId] = 0;
    visited.insert(cfg.entryNodeId);

    while (!queue.empty()) {
        uint64_t current = queue.front();
        queue.pop();

        for (uint64_t successor : GetSuccessors(cfg, current)) {
            if (visited.find(successor) == visited.end()) {
                depths[successor] = depths[current] + 1;
                visited.insert(successor);
                queue.push(successor);
            }
        }
    }

    return depths;
}

std::vector<uint64_t> CFGBuilder::FindCriticalPath(const ControlFlowGraph& cfg) {
    // 使用 DFS 找到最长路径
    std::vector<uint64_t> longestPath;
    std::vector<uint64_t> currentPath;
    std::unordered_set<uint64_t> visited;

    std::function<void(uint64_t)> dfs = [&](uint64_t nodeId) {
        visited.insert(nodeId);
        currentPath.push_back(nodeId);

        if (currentPath.size() > longestPath.size()) {
            longestPath = currentPath;
        }

        for (uint64_t successor : GetSuccessors(cfg, nodeId)) {
            if (visited.find(successor) == visited.end()) {
                dfs(successor);
            }
        }

        currentPath.pop_back();
        visited.erase(nodeId);
    };

    dfs(cfg.entryNodeId);
    return longestPath;
}

void CFGBuilder::AnalyzeHotspots(ControlFlowGraph& cfg, 
                                  const std::unordered_map<uint64_t, uint32_t>& callFrequency) {
    for (auto& node : cfg.nodes) {
        // 检查调用频率
        auto it = callFrequency.find(node.startAddress);
        if (it != callFrequency.end()) {
            // 高频调用被认为是热点
            if (it->second > 100) {
                node.isHotspot = true;
            }
        }

        // 循环内的节点更可能是热点
        if (node.loopDepth > 0) {
            node.isHotspot = true;
        }
    }
}

void CFGBuilder::AssignProtectionLevels(ControlFlowGraph& cfg, uint32_t defaultLevel) {
    for (auto& node : cfg.nodes) {
        // 热点节点降低保护等级
        if (node.isHotspot) {
            node.protectionLevel = std::min(defaultLevel, (uint32_t)2);
        }
        // 循环头节点根据深度调整
        else if (node.isLoopHeader) {
            if (node.loopDepth > 2) {
                node.protectionLevel = 1;  // 深层循环，最低保护
            } else {
                node.protectionLevel = std::min(defaultLevel, (uint32_t)3);
            }
        }
        // 其他节点使用默认等级
        else {
            node.protectionLevel = defaultLevel;
        }
    }
}

bool CFGBuilder::Validate(const ControlFlowGraph& cfg) {
    if (cfg.nodes.empty()) return false;

    // 检查入口节点
    if (cfg.entryNodeId >= cfg.nodes.size()) return false;

    // 检查所有边的有效性
    for (const auto& edge : cfg.edges) {
        if (edge.sourceId >= cfg.nodes.size() || edge.targetId >= cfg.nodes.size()) {
            return false;
        }
    }

    // 检查连通性
    std::unordered_set<uint64_t> visited;
    std::queue<uint64_t> queue;
    queue.push(cfg.entryNodeId);
    visited.insert(cfg.entryNodeId);

    while (!queue.empty()) {
        uint64_t current = queue.front();
        queue.pop();

        for (uint64_t successor : GetSuccessors(cfg, current)) {
            if (visited.find(successor) == visited.end()) {
                visited.insert(successor);
                queue.push(successor);
            }
        }
    }

    // 所有节点都应该可达（对于正常函数）
    return visited.size() == cfg.nodes.size();
}

// ============================================================================
// 内部实现
// ============================================================================

uint64_t CFGBuilder::Intersect(uint64_t b1, uint64_t b2,
                                const std::unordered_map<uint64_t, uint32_t>& depth,
                                const std::unordered_map<uint64_t, uint64_t>& idom) {
    // 找到两个节点的最近共同支配者
    uint64_t finger1 = b1;
    uint64_t finger2 = b2;

    while (finger1 != finger2) {
        while (depth.at(finger1) > depth.at(finger2)) {
            auto it = idom.find(finger1);
            if (it != idom.end()) {
                finger1 = it->second;
            } else {
                break;
            }
        }
        while (depth.at(finger2) > depth.at(finger1)) {
            auto it = idom.find(finger2);
            if (it != idom.end()) {
                finger2 = it->second;
            } else {
                break;
            }
        }
    }

    return finger1;
}

void CFGBuilder::FindBackEdges(const ControlFlowGraph& cfg, std::vector<CFGEdge>& backEdges) {
    // 使用 DFS 查找回边
    std::unordered_set<uint64_t> visited;
    std::unordered_set<uint64_t> inStack;
    std::stack<uint64_t> stack;

    stack.push(cfg.entryNodeId);
    inStack.insert(cfg.entryNodeId);

    while (!stack.empty()) {
        uint64_t current = stack.top();

        if (visited.find(current) != visited.end()) {
            stack.pop();
            inStack.erase(current);
            continue;
        }

        visited.insert(current);

        bool hasUnvisitedSuccessor = false;
        for (uint64_t successor : GetSuccessors(cfg, current)) {
            if (visited.find(successor) == visited.end()) {
                stack.push(successor);
                inStack.insert(successor);
                hasUnvisitedSuccessor = true;
            } else if (inStack.find(successor) != inStack.end()) {
                // 回边
                CFGEdge backEdge;
                backEdge.sourceId = current;
                backEdge.targetId = successor;
                backEdge.isBackEdge = true;
                backEdges.push_back(backEdge);
            }
        }

        if (!hasUnvisitedSuccessor) {
            stack.pop();
            inStack.erase(current);
        }
    }
}

void CFGBuilder::CollectLoopMembers(ControlFlowGraph& cfg, const CFGEdge& backEdge) {
    uint64_t headerId = backEdge.targetId;
    uint64_t latchId = backEdge.sourceId;

    // 标记循环头
    if (headerId < cfg.nodes.size()) {
        cfg.nodes[headerId].isLoopHeader = true;
        cfg.nodes[headerId].loopMembers.push_back(headerId);
    }

    // 从 latch 向前遍历，收集循环成员
    std::queue<uint64_t> queue;
    std::unordered_set<uint64_t> visited;

    queue.push(latchId);
    visited.insert(latchId);

    while (!queue.empty()) {
        uint64_t current = queue.front();
        queue.pop();

        if (current != headerId) {
            if (headerId < cfg.nodes.size()) {
                cfg.nodes[headerId].loopMembers.push_back(current);
            }
            if (current < cfg.nodes.size()) {
                cfg.nodes[current].loopDepth++;
            }
        }

        for (uint64_t pred : GetPredecessors(cfg, current)) {
            if (visited.find(pred) == visited.end()) {
                visited.insert(pred);
                queue.push(pred);
            }
        }
    }
}

bool CFGBuilder::IsReachable(const ControlFlowGraph& cfg, uint64_t from, uint64_t to) {
    std::unordered_set<uint64_t> visited;
    std::queue<uint64_t> queue;

    queue.push(from);
    visited.insert(from);

    while (!queue.empty()) {
        uint64_t current = queue.front();
        queue.pop();

        if (current == to) return true;

        for (uint64_t successor : GetSuccessors(cfg, current)) {
            if (visited.find(successor) == visited.end()) {
                visited.insert(successor);
                queue.push(successor);
            }
        }
    }

    return false;
}

std::vector<uint64_t> CFGBuilder::GetPredecessors(const ControlFlowGraph& cfg, uint64_t nodeId) {
    std::vector<uint64_t> predecessors;

    for (const auto& edge : cfg.edges) {
        if (edge.targetId == nodeId) {
            predecessors.push_back(edge.sourceId);
        }
    }

    return predecessors;
}

std::vector<uint64_t> CFGBuilder::GetSuccessors(const ControlFlowGraph& cfg, uint64_t nodeId) {
    std::vector<uint64_t> successors;

    for (const auto& edge : cfg.edges) {
        if (edge.sourceId == nodeId) {
            successors.push_back(edge.targetId);
        }
    }

    return successors;
}

} // namespace CipherShell
