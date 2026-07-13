/**
 * CipherShell 热点分析器
 * 识别性能敏感的代码区域，建议降低保护等级
 */

#ifndef CS_HOTSPOT_ANALYZER_H
#define CS_HOTSPOT_ANALYZER_H

#include "cfg_builder.h"
#include <cstdint>
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// 热点信息
// ============================================================================

struct HotspotInfo {
    uint64_t    address;            // 函数/块地址
    std::string functionName;       // 函数名
    uint32_t    estimatedFrequency;// 估算调用频率
    uint32_t    loopDepth;          // 循环嵌套深度
    uint32_t    currentLevel;       // 当前保护等级
    uint32_t    suggestedLevel;     // 建议保护等级
    std::string reason;             // 建议原因
    bool        isCritical;         // 是否关键热点
};

// ============================================================================
// 热点配置
// ============================================================================

struct HotspotConfig {
    uint32_t    frequencyThreshold;     // 频率阈值
    uint32_t    loopDepthThreshold;     // 循环深度阈值
    uint32_t    maxAllowedLevel;        // 热点最大允许保护等级
    double      maxVMOverheadRatio;     // 最大 VM 开销倍率
    bool        autoDowngrade;          // 自动降级
    bool        generateReport;         // 生成报告

    HotspotConfig() :
        frequencyThreshold(100),
        loopDepthThreshold(2),
        maxAllowedLevel(2),
        maxVMOverheadRatio(15.0),
        autoDowngrade(true),
        generateReport(true) {}
};

// ============================================================================
// 热点分析器类
// ============================================================================

class HotspotAnalyzer {
public:
    HotspotAnalyzer();
    ~HotspotAnalyzer();

    /**
     * 分析控制流图中的热点
     * @param cfg 控制流图
     * @param config 热点配置
     * @return 热点列表
     */
    std::vector<HotspotInfo> Analyze(
        const ControlFlowGraph& cfg,
        const HotspotConfig& config
    );

    /**
     * 分析函数热点
     * @param functions 函数列表
     * @param config 热点配置
     * @return 热点列表
     */
    std::vector<HotspotInfo> AnalyzeFunctions(
        const std::vector<Function>& functions,
        const HotspotConfig& config
    );

    /**
     * 生成保护等级建议
     * @param hotspots 热点列表
     * @param defaultLevel 默认保护等级
     * @return 更新后的热点列表
     */
    std::vector<HotspotInfo> GenerateSuggestions(
        std::vector<HotspotInfo>& hotspots,
        uint32_t defaultLevel,
        const HotspotConfig& config
    );

    /**
     * 生成热点报告
     * @param hotspots 热点列表
     * @return 报告文本
     */
    std::string GenerateReport(const std::vector<HotspotInfo>& hotspots);

    /**
     * 应用建议到函数
     * @param functions 函数列表
     * @param hotspots 热点列表
     */
    void ApplySuggestions(
        std::vector<Function>& functions,
        const std::vector<HotspotInfo>& hotspots
    );

private:
    // 频率估算
    uint32_t EstimateCallFrequency(const Function& func);
    uint32_t EstimateLoopFrequency(const BasicBlock& block, uint32_t depth);

    // 热点评分
    double CalculateHotspotScore(const HotspotInfo& info);

    // 辅助函数
    bool IsPerformanceCritical(const std::string& funcName);
    uint32_t EstimateVMOverhead(uint32_t protectionLevel);
};

} // namespace CipherShell

#endif // CS_HOTSPOT_ANALYZER_H
