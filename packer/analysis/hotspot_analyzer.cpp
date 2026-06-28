/**
 * CipherShell 热点分析器 - 实现
 */

#include "hotspot_analyzer.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

HotspotAnalyzer::HotspotAnalyzer() {}
HotspotAnalyzer::~HotspotAnalyzer() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<HotspotInfo> HotspotAnalyzer::Analyze(
    const ControlFlowGraph& cfg,
    const HotspotConfig& config)
{
    std::vector<HotspotInfo> hotspots;

    for (const auto& node : cfg.nodes) {
        HotspotInfo info;
        info.address = node.startAddress;
        info.functionName = "";
        info.estimatedFrequency = 0;
        info.loopDepth = node.loopDepth;
        info.currentLevel = node.protectionLevel;
        info.suggestedLevel = node.protectionLevel;
        info.isCritical = false;

        // 检查是否是热点
        bool isHot = false;

        // 循环内的节点
        if (node.loopDepth >= config.loopDepthThreshold) {
            isHot = true;
            info.reason = "Loop depth " + std::to_string(node.loopDepth);
        }

        // 高入度节点（被很多地方调用）
        if (node.block.predecessors.size() > 5) {
            isHot = true;
            info.reason = "High in-degree: " + std::to_string(node.block.predecessors.size());
        }

        if (isHot) {
            hotspots.push_back(info);
        }
    }

    return hotspots;
}

std::vector<HotspotInfo> HotspotAnalyzer::AnalyzeFunctions(
    const std::vector<Function>& functions,
    const HotspotConfig& config)
{
    std::vector<HotspotInfo> hotspots;

    for (const auto& func : functions) {
        HotspotInfo info;
        info.address = func.entryAddress;
        info.functionName = func.name;
        info.currentLevel = func.assignedLevel;
        info.suggestedLevel = func.assignedLevel;
        info.loopDepth = 0;

        // 计算最大循环深度
        for (const auto& block : func.blocks) {
            // 简化：通过检查后边判断循环
            for (const auto& succ : block.successors) {
                if (succ <= block.startAddress) {
                    info.loopDepth++;
                    break;
                }
            }
        }

        // 估算调用频率
        info.estimatedFrequency = EstimateCallFrequency(func);

        // 判断是否是热点
        bool isHot = false;

        if (info.estimatedFrequency > config.frequencyThreshold) {
            isHot = true;
            info.reason = "High call frequency: " + std::to_string(info.estimatedFrequency);
        }

        if (info.loopDepth >= config.loopDepthThreshold) {
            isHot = true;
            info.reason = "Deep loop nesting: " + std::to_string(info.loopDepth);
        }

        if (IsPerformanceCritical(func.name)) {
            isHot = true;
            info.reason = "Performance-critical function";
        }

        // 估算代码大小
        uint32_t totalSize = 0;
        for (const auto& block : func.blocks) {
            totalSize += (uint32_t)(block.endAddress - block.startAddress);
        }

        // 大函数 + 高频率 = 关键热点
        if (totalSize > 1000 && info.estimatedFrequency > 10) {
            info.isCritical = true;
        }

        if (isHot) {
            hotspots.push_back(info);
        }
    }

    return hotspots;
}

std::vector<HotspotInfo> HotspotAnalyzer::GenerateSuggestions(
    std::vector<HotspotInfo>& hotspots,
    uint32_t defaultLevel)
{
    for (auto& info : hotspots) {
        double score = CalculateHotspotScore(info);

        // 根据评分决定建议等级
        if (score > 0.8) {
            info.suggestedLevel = 1;  // 最低保护
        } else if (score > 0.5) {
            info.suggestedLevel = 2;
        } else if (score > 0.3) {
            info.suggestedLevel = std::min(defaultLevel, (uint32_t)3);
        } else {
            info.suggestedLevel = defaultLevel;
        }

        // 关键热点强制降级
        if (info.isCritical && info.suggestedLevel > 2) {
            info.suggestedLevel = 2;
        }
    }

    return hotspots;
}

std::string HotspotAnalyzer::GenerateReport(const std::vector<HotspotInfo>& hotspots) {
    std::stringstream ss;

    ss << "=== CipherShell Hotspot Analysis Report ===" << std::endl;
    ss << std::endl;
    ss << "Found " << hotspots.size() << " hotspot(s)" << std::endl;
    ss << std::endl;

    for (size_t i = 0; i < hotspots.size(); i++) {
        const auto& info = hotspots[i];

        ss << "  Hotspot #" << (i + 1) << ":" << std::endl;
        ss << "    Address: 0x" << std::hex << info.address << std::dec << std::endl;

        if (!info.functionName.empty()) {
            ss << "    Function: " << info.functionName << std::endl;
        }

        ss << "    Estimated frequency: " << info.estimatedFrequency << std::endl;
        ss << "    Loop depth: " << info.loopDepth << std::endl;
        ss << "    Current level: L" << info.currentLevel << std::endl;
        ss << "    Suggested level: L" << info.suggestedLevel << std::endl;

        if (info.suggestedLevel < info.currentLevel) {
            uint32_t currentOverhead = EstimateVMOverhead(info.currentLevel);
            uint32_t suggestedOverhead = EstimateVMOverhead(info.suggestedLevel);
            ss << "    Performance improvement: ~" << (currentOverhead / suggestedOverhead) << "x" << std::endl;
        }

        if (!info.reason.empty()) {
            ss << "    Reason: " << info.reason << std::endl;
        }

        if (info.isCritical) {
            ss << "    [CRITICAL]" << std::endl;
        }

        ss << std::endl;
    }

    ss << "=== End of Report ===" << std::endl;

    return ss.str();
}

void HotspotAnalyzer::ApplySuggestions(
    std::vector<Function>& functions,
    const std::vector<HotspotInfo>& hotspots)
{
    // 构建地址到建议的映射
    std::unordered_map<uint64_t, uint32_t> suggestionMap;
    for (const auto& info : hotspots) {
        suggestionMap[info.address] = info.suggestedLevel;
    }

    // 应用建议
    for (auto& func : functions) {
        auto it = suggestionMap.find(func.entryAddress);
        if (it != suggestionMap.end()) {
            func.assignedLevel = it->second;
        }
    }
}

// ============================================================================
// 内部实现
// ============================================================================

uint32_t HotspotAnalyzer::EstimateCallFrequency(const Function& func) {
    // 简化的频率估算
    // 实际应该通过调用图分析

    uint32_t frequency = 1;

    // 如果是叶子函数（不调用其他函数），可能被频繁调用
    if (func.isLeaf) {
        frequency *= 10;
    }

    // 函数名启发式
    if (IsPerformanceCritical(func.name)) {
        frequency *= 50;
    }

    // 代码大小启发式：小函数通常被频繁调用
    uint32_t totalSize = 0;
    for (const auto& block : func.blocks) {
        totalSize += (uint32_t)(block.endAddress - block.startAddress);
    }
    if (totalSize < 50) {
        frequency *= 20;
    }

    return frequency;
}

uint32_t HotspotAnalyzer::EstimateLoopFrequency(const BasicBlock& block, uint32_t depth) {
    // 循环深度越大，执行频率越高
    uint32_t baseFreq = 10;
    for (uint32_t i = 0; i < depth; i++) {
        baseFreq *= 10;
    }
    return baseFreq;
}

double HotspotAnalyzer::CalculateHotspotScore(const HotspotInfo& info) {
    double score = 0.0;

    // 频率贡献
    if (info.estimatedFrequency > 1000) score += 0.4;
    else if (info.estimatedFrequency > 100) score += 0.3;
    else if (info.estimatedFrequency > 10) score += 0.2;

    // 循环深度贡献
    if (info.loopDepth >= 3) score += 0.3;
    else if (info.loopDepth >= 2) score += 0.2;
    else if (info.loopDepth >= 1) score += 0.1;

    // 关键函数贡献
    if (info.isCritical) score += 0.3;

    return score;
}

bool HotspotAnalyzer::IsPerformanceCritical(const std::string& funcName) {
    // 检查是否是性能敏感的函数名
    const char* criticalPatterns[] = {
        "render", "draw", "paint", "display",
        "update", "tick", "loop", "frame",
        "process", "calculate", "compute",
        "memcpy", "memset", "memmove",
        "strlen", "strcmp", "strcpy",
        "malloc", "free", "realloc",
        "send", "recv", "read", "write",
        nullptr
    };

    for (int i = 0; criticalPatterns[i]; i++) {
        if (funcName.find(criticalPatterns[i]) != std::string::npos) {
            return true;
        }
    }

    return false;
}

uint32_t HotspotAnalyzer::EstimateVMOverhead(uint32_t protectionLevel) {
    switch (protectionLevel) {
        case 1: return 1;      // L1: ~1.05x
        case 2: return 3;      // L2: ~2-3x
        case 3: return 8;      // L3: ~5-8x
        case 4: return 30;     // L4: ~15-30x
        case 5: return 100;    // L5: ~50-100x
        default: return 1;
    }
}

} // namespace CipherShell
