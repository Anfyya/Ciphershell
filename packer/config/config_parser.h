#ifndef CS_CONFIG_PARSER_H
#define CS_CONFIG_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct FunctionOverride {
    std::string pattern;
    int level;
    int vmNesting;
};

struct GlobalConfig {
    int protectionLevel;
    bool stripDebugInfo;
    bool stripRichHeader;
    bool stripTimestamps;
    bool randomizeSections;
    std::string antiDebugMode;
    bool stringEncryption;
    bool importObfuscation;
    bool resourceEncryption;

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

struct VMConfig {
    bool enabled;
    bool enabledSet;
    int strength;
    std::vector<std::string> targetFunctions;
    std::vector<uint32_t> targetRVAs;
    int registerCount;
    int stackSize;
    bool opcodeRandomization;
    bool handlerMutation;
    bool bytecodeEncryption;
    std::string nativeBodyPolicy;
    std::string x86CallAbi;
    bool embedJunkHandlers;
    bool simdBridge;
    bool x87Bridge;

    VMConfig() :
        enabled(false),
        enabledSet(false),
        strength(0),
        registerCount(24),
        stackSize(0x20000),
        opcodeRandomization(true),
        handlerMutation(false),
        bytecodeEncryption(true),
        nativeBodyPolicy("destroy"),
        x86CallAbi("auto"),
        embedJunkHandlers(false),
        simdBridge(true),
        x87Bridge(true) {}
};

struct StringEncryptionConfig {
    bool enabled;
    bool enabledSet;
    int strength;
    std::string mode;
    bool ascii;
    bool utf16;
    bool resources;
    bool clearAfterUse;

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
    bool enabled;
    bool enabledSet;
    int strength;

    ImportProtectionConfig() :
        enabled(false),
        enabledSet(false),
        strength(0) {}
};

struct SectionEncryptionConfig {
    bool enabled;
    bool enabledSet;
    int strength;
    std::string mode;

    SectionEncryptionConfig() :
        enabled(false),
        enabledSet(false),
        strength(0),
        mode("") {}
};

struct ControlFlowConfigFile {
    bool enabled;
    bool enabledSet;
    int strength;
    bool flatteningEnabled;
    bool flatteningEnabledSet;
    int flatteningStrength;
    std::vector<std::string> flatteningTargets;
    bool bogusEnabled;
    bool bogusEnabledSet;
    int bogusStrength;

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

struct AntiDebugConfigFile {
    bool timingChecks;
    bool hardwareBPDetection;
    bool softwareBPDetection;
    bool memoryIntegrity;
    bool debuggerWindowScan;
    bool parentProcessCheck;
    bool threadHiding;
    bool kernelDebuggerCheck;

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

struct AntiDumpConfig {
    bool erasePEHeader;
    bool sectionPermissionGuard;
    bool nanomitePatches;

    AntiDumpConfig() :
        erasePEHeader(true),
        sectionPermissionGuard(true),
        nanomitePatches(true) {}
};

struct PerformanceConfig {
    bool autoHotspotAnalysis;
    double maxVMOverheadRatio;

    PerformanceConfig() :
        autoHotspotAnalysis(true),
        maxVMOverheadRatio(15.0) {}
};

struct CipherShellConfig {
    GlobalConfig global;
    VMConfig vm;
    StringEncryptionConfig stringEncryption;
    ImportProtectionConfig importProtection;
    SectionEncryptionConfig sectionEncryption;
    ControlFlowConfigFile controlFlow;
    AntiDebugConfigFile antiDebug;
    AntiDumpConfig antiDump;
    PerformanceConfig performance;
    std::vector<FunctionOverride> functionOverrides;
};

class ConfigParser {
public:
    ConfigParser();
    ~ConfigParser();

    CipherShellConfig LoadFromFile(const std::string& filePath);
    CipherShellConfig LoadFromString(const std::string& content);
    bool GenerateDefaultConfig(const std::string& filePath);

    bool HasError() const { return !m_lastError.empty(); }
    const std::string& GetLastError() const { return m_lastError; }
    const std::vector<std::string>& GetWarnings() const { return m_warnings; }

private:
    bool ValidateProductionSyntax(const std::string& content);
    void ParseGlobalSection(const std::string& content, GlobalConfig& config);
    void ParseVMSection(const std::string& content, VMConfig& config);
    void ParseStringEncryptionSection(const std::string& content, StringEncryptionConfig& config);
    void ParseImportProtectionSection(const std::string& content, ImportProtectionConfig& config);
    void ParseSectionEncryptionSection(const std::string& content, SectionEncryptionConfig& config);
    void ParseControlFlowSection(const std::string& content, ControlFlowConfigFile& config);
    void ParseAntiDebugSection(const std::string& content, AntiDebugConfigFile& config);
    void ParseAntiDumpSection(const std::string& content, AntiDumpConfig& config);
    void ParsePerformanceSection(const std::string& content, PerformanceConfig& config);
    void ParseFunctionOverrides(const std::string& content, std::vector<FunctionOverride>& overrides);

    std::string Trim(const std::string& str);
    std::string ExtractSection(const std::string& content, const std::string& sectionName);
    bool ParseBool(const std::string& value);
    int ParseInt(const std::string& value);
    double ParseDouble(const std::string& value);
    std::string ParseString(const std::string& value);
    std::vector<std::string> ParseStringArray(const std::string& value);
    std::vector<uint32_t> ParseUint32Array(const std::string& value);

    std::string m_lastError;
    std::vector<std::string> m_warnings;
};

} // namespace CipherShell

#endif // CS_CONFIG_PARSER_H
