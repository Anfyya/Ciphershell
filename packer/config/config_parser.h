/**
 * CipherShell 配置解析器
 * 解析 TOML 格式的保护配置文件
 */

#ifndef CS_CONFIG_PARSER_H
#define CS_CONFIG_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

namespace CipherShell {

// ============================================================================
// 函数级覆盖配置
// ============================================================================

struct FunctionOverride {
    std::string     pattern;        // 函数名匹配模式（支持通配符）
    int             level;          // 保护等级 1-5
    int             vmNesting;      // VM 嵌套层数
};

// ============================================================================
// 全局配置
// ============================================================================

struct GlobalConfig {
    int             protectionLevel;    // 全局默认保护等级 1-5
    bool            stripDebugInfo;     // 删除调试信息
    bool            stripRichHeader;    // 删除 Rich Header
    bool            stripTimestamps;    // 时间戳归零
    bool            randomizeSections;  // Section 名称随机化
    std::string     antiDebugMode;      // "explicit" | "implicit" | "hybrid"
    bool            stringEncryption;   // 字符串加密
    bool            importObfuscation;  // 导入表混淆
    bool            resourceEncryption; // 资源加密

    GlobalConfig() :
        protectionLevel(1),
        stripDebugInfo(true),
        stripRichHeader(true),
        stripTimestamps(true),
        randomizeSections(true),
        antiDebugMode("implicit"),
        stringEncryption(true),
        importObfuscation(true),
        resourceEncryption(false) {}
};

// ============================================================================
// VM 配置
// ============================================================================

struct VMConfig {
    bool            enabled;
    bool            enabledSet;
    int             strength;
    std::vector<std::string> targetFunctions;
    int             registerCount;      // 虚拟寄存器数量 (16-64)
    int             stackSize;          // 虚拟栈大小
    std::string     opcodeWidth;        // "fixed_8" | "fixed_16" | "variable"
    bool            handlerMutation;    // Handler 代码变异
    std::string     bytecodeEncryption; // "none" | "xor" | "rolling" | "aes_ctr"
    bool            embedJunkHandlers;  // 嵌入假 handler

    VMConfig() :
        enabled(false),
        enabledSet(false),
        strength(0),
        registerCount(24),
        stackSize(0x20000),
        opcodeWidth("variable"),
        handlerMutation(true),
        bytecodeEncryption("rolling"),
        embedJunkHandlers(true) {}
};

// ============================================================================
// ============================================================================
// 模块化保护配置
// ============================================================================

struct StringEncryptionConfig {
    bool            enabled;
    bool            enabledSet;
    int             strength;
    std::string     mode;
    bool            ascii;
    bool            utf16;
    bool            resources;
    bool            clearAfterUse;

    StringEncryptionConfig() :
        enabled(false),
        enabledSet(false),
        strength(0),
        mode(""),
        ascii(true),
        utf16(true),
        resources(false),
        clearAfterUse(false) {}
};

struct ImportProtectionConfig {
    bool            enabled;
    bool            enabledSet;
    int             strength;

    ImportProtectionConfig() :
        enabled(false),
        enabledSet(false),
        strength(0) {}
};

struct ControlFlowConfigFile {
    bool            enabled;
    bool            enabledSet;
    int             strength;
    bool            flatteningEnabled;
    bool            flatteningEnabledSet;
    int             flatteningStrength;
    std::vector<std::string> flatteningTargets;
    bool            bogusEnabled;
    bool            bogusEnabledSet;
    int             bogusStrength;

    ControlFlowConfigFile() :
        enabled(false),
        enabledSet(false),
        strength(0),
        flatteningEnabled(false),
        flatteningEnabledSet(false),
        flatteningStrength(0),
        bogusEnabled(false),
        bogusEnabledSet(false),
        bogusStrength(0) {}
};
// 反调试配置
// ============================================================================

struct AntiDebugConfigFile {
    bool            timingChecks;
    bool            hardwareBPDetection;
    bool            softwareBPDetection;
    bool            memoryIntegrity;
    bool            debuggerWindowScan;
    bool            parentProcessCheck;
    bool            threadHiding;
    bool            kernelDebuggerCheck;

    AntiDebugConfigFile() :
        timingChecks(true),
        hardwareBPDetection(true),
        softwareBPDetection(true),
        memoryIntegrity(true),
        debuggerWindowScan(false),
        parentProcessCheck(true),
        threadHiding(true),
        kernelDebuggerCheck(true) {}
};

// ============================================================================
// 反 Dump 配置
// ============================================================================

struct AntiDumpConfig {
    bool            erasePEHeader;
    bool            sectionPermissionGuard;
    bool            nanomitePatches;

    AntiDumpConfig() :
        erasePEHeader(true),
        sectionPermissionGuard(true),
        nanomitePatches(true) {}
};

// ============================================================================
// 性能配置
// ============================================================================

struct PerformanceConfig {
    bool            autoHotspotAnalysis;
    double          maxVMOverheadRatio;

    PerformanceConfig() :
        autoHotspotAnalysis(true),
        maxVMOverheadRatio(15.0) {}
};

// ============================================================================
// 完整配置
// ============================================================================

struct CipherShellConfig {
    GlobalConfig                global;
    VMConfig                    vm;
    StringEncryptionConfig      stringEncryption;
    ImportProtectionConfig      importProtection;
    ControlFlowConfigFile       controlFlow;
    AntiDebugConfigFile         antiDebug;
    AntiDumpConfig              antiDump;
    PerformanceConfig           performance;
    std::vector<FunctionOverride> functionOverrides;
};

// ============================================================================
// 配置解析器类
// ============================================================================

class ConfigParser {
public:
    ConfigParser();
    ~ConfigParser();

    /**
     * 从文件加载配置
     * @param filePath 配置文件路径
     * @return 解析后的配置
     */
    CipherShellConfig LoadFromFile(const std::string& filePath);

    /**
     * 从字符串解析配置
     * @param content 配置内容
     * @return 解析后的配置
     */
    CipherShellConfig LoadFromString(const std::string& content);

    /**
     * 生成默认配置文件
     * @param filePath 输出文件路径
     * @return 是否成功
     */
    bool GenerateDefaultConfig(const std::string& filePath);

    // BUG 16 修复：添加错误查询接口，调用方可据此决定行为
    /**
     * 检查上次操作是否有错误
     * @return 是否有错误
     */
    bool HasError() const { return !m_lastError.empty(); }

    /**
     * 获取上次错误信息
     * @return 错误描述字符串
     */
    const std::string& GetLastError() const { return m_lastError; }

private:
    // 解析各个配置段
    void ParseGlobalSection(const std::string& content, GlobalConfig& config);
    void ParseVMSection(const std::string& content, VMConfig& config);
    void ParseStringEncryptionSection(const std::string& content, StringEncryptionConfig& config);
    void ParseImportProtectionSection(const std::string& content, ImportProtectionConfig& config);
    void ParseControlFlowSection(const std::string& content, ControlFlowConfigFile& config);
    void ParseAntiDebugSection(const std::string& content, AntiDebugConfigFile& config);
    void ParseAntiDumpSection(const std::string& content, AntiDumpConfig& config);
    void ParsePerformanceSection(const std::string& content, PerformanceConfig& config);
    void ParseFunctionOverrides(const std::string& content, std::vector<FunctionOverride>& overrides);

    // 辅助函数
    std::string Trim(const std::string& str);
    std::string ExtractSection(const std::string& content, const std::string& sectionName);
    bool ParseBool(const std::string& value);
    int ParseInt(const std::string& value);
    double ParseDouble(const std::string& value);
    std::string ParseString(const std::string& value);
    std::vector<std::string> ParseStringArray(const std::string& value);

    // BUG 16 修复：错误状态
    std::string m_lastError;
};

} // namespace CipherShell

#endif // CS_CONFIG_PARSER_H
