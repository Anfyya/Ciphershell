/**
 * CipherShell 配置解析器 - 实现
 * 简化的 TOML 解析实现
 */

#include "config_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>
#include <iostream>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

ConfigParser::ConfigParser() {}
ConfigParser::~ConfigParser() {}

bool HasAnyAntiDebugRequest(const AntiDebugConfigFile& config) {
    return config.timingChecks ||
        config.hardwareBPDetection ||
        config.softwareBPDetection ||
        config.memoryIntegrity ||
        config.debuggerWindowScan ||
        config.parentProcessCheck ||
        config.threadHiding ||
        config.kernelDebuggerCheck;
}

bool HasAnyAntiDumpRequest(const AntiDumpConfig& config) {
    return config.erasePEHeader ||
        config.sectionPermissionGuard ||
        config.nanomitePatches;
}

// ============================================================================
// 公共接口
// ============================================================================

CipherShellConfig ConfigParser::LoadFromFile(const std::string& filePath) {
    CipherShellConfig config;
    m_lastError.clear();  // BUG 16 修复：清除之前的错误状态
    m_warnings.clear();

    std::ifstream file(filePath);
    if (!file.is_open()) {
        // BUG 16 修复：设置错误信息而非仅打印到 stderr，调用方可检查 HasError()
        m_lastError = "无法打开配置文件: " + filePath;
        std::cerr << "[ConfigParser] " << m_lastError << std::endl;
        return config;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    if (content.empty()) {
        m_lastError = "配置文件为空: " + filePath;
        std::cerr << "[ConfigParser] " << m_lastError << std::endl;
        return config;
    }

    return LoadFromString(content);
}

CipherShellConfig ConfigParser::LoadFromString(const std::string& content) {
    CipherShellConfig config;
    m_lastError.clear();  // BUG 16 修复：清除之前的错误状态
    m_warnings.clear();

    if (!ValidateProductionSyntax(content)) return config;
    const std::string canonicalContent = StripComments(content);

    // 所有 Parse* 只消费去除注释后的同一份规范文本。否则注释中的同名键
    // 可能被 regex_search 先命中，使可见配置与实际生效值发生串线。
    ParseGlobalSection(canonicalContent, config.global);
    ParseVMSection(canonicalContent, config.vm);
    ParseStringEncryptionSection(canonicalContent, config.stringEncryption);
    ParseImportProtectionSection(canonicalContent, config.importProtection);
    ParseSectionEncryptionSection(canonicalContent, config.sectionEncryption);
    ParseControlFlowSection(canonicalContent, config.controlFlow);
    ParseAntiDebugSection(canonicalContent, config.antiDebug);
    ParseAntiDumpSection(canonicalContent, config.antiDump);
    ParsePerformanceSection(canonicalContent, config.performance);
    ParseFunctionOverrides(canonicalContent, config.functionOverrides);

    return config;
}

bool ConfigParser::GenerateDefaultConfig(const std::string& filePath) {
    std::ofstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    file << R"(# CipherShell 保护配置文件
# 自动生成 - 请根据需要修改

[global]
protection_level = 3              # 全局默认保护等级 1-5
strip_debug_info = true           # 清零 Debug DataDirectory 引用；不擦除失去引用的原始载荷
strip_rich_header = true          # 检测到 Rich 时清零整个 DOS stub/Rich 扫描区
strip_timestamps = true           # COFF FileHeader.TimeDateStamp 归零
randomize_section_names = true    # 随机化除严格 .rsrc/.reloc 外的 Section 名称

[vm]
enabled = false                   # 显式功能开关；L1-L5 只提供未显式设置时的 preset
strength = 80                    # 当前仅解析/往返；生产 Handler 尚未消费
target_functions = []             # 与 target_rvas 均空时自动筛选 VM 安全函数；非空时按名称通配选择
target_rvas = []                  # 与 target_functions 均空时自动筛选；非空时按入口 RVA 精确选择
register_count = 24               # 虚拟寄存器数量（16-32）
stack_size = 0x20000              # 虚拟栈大小
opcode_randomization = true       # 每次构建生成完整 opcode permutation
handler_mutation = true           # 生产构建默认启用 handler 入口布局与执行路径变异
bytecode_encryption = true        # ChaCha20 加密 + SipHash 完整性认证
native_body_policy = "destroy"    # 原 native 函数体销毁
x86_call_abi = "auto"            # "auto" | "cdecl" | "stdcall" | "fastcall" | "thiscall"
embed_junk_handlers = true        # 生成不可由合法 opcode 到达的垃圾 handler 槽
simd_bridge = true                # SSE2/SSE4/AVX/AVX2 严格指令桥
x87_bridge = true                 # x87 严格指令桥
variant_group_count = 0            # VM Variant Group 数量；0 = 按候选函数数量自适应，>=1 为显式固定组数
variant_group_max = 4              # 自适应模式下的组数上限（仅影响 variant_group_count=0 时）
variant_group_functions_per_group = 4  # 自适应模式下，大约每多少个候选函数增加一个 Group

[string_encryption]
# Fail-closed: 弱加密（未认证算法 + 可恢复密钥），默认关闭。
# 显式 enabled = true 会在 CapabilityChecker 阶段（任何 PE 修改之前）被 fatal 拒绝。
enabled = false
strength = 60
mode = "startup"
ascii = true
utf16 = true
resources = false
clear_after_use = false

[import_protection]
# Fail-closed: 仅追加假导入并保留真实 IAT，未改写 callsite。默认关闭。
# 显式 enabled = true 会在 CapabilityChecker 阶段被 fatal 拒绝。
enabled = false
strength = 50

[section_encryption]
# Fail-closed: 弱加密（未认证算法 + 可恢复密钥），默认关闭。
# 显式 enabled = true 会在 CapabilityChecker 阶段被 fatal 拒绝。
enabled = false
strength = 58
mode = "startup"

[control_flow]
# flattening 是可独立使用的本地 CFG 保护；bogus flow 仍为 fail-closed。
# 总开关与子开关必须一致。
enabled = false
strength = 55

[control_flow.flattening]
# 真实块体 + 编码状态分发器；不依赖 VM。
enabled = false
strength = 55
target_functions = []

[control_flow.bogus]
enabled = false
strength = 50

[anti_debug]
# CipherShell Plus 反调试尚未接入 transform/runtime；显式开启会在任何 PE 修改前
# 被 fail-closed 拒绝。以下项目仅保留可编辑配置契约，默认不得声称已生效。
timing_checks = false             # 未实现：时序检测
hardware_bp_detection = false     # 未实现：硬件断点检测
software_bp_detection = false     # 未实现：INT3 / 0xCC 扫描
memory_integrity = false          # 未实现：运行时代码完整性校验
debugger_window_scan = false      # 未实现：调试器窗口类名扫描
parent_process_check = false      # 未实现：父进程检测
thread_hiding = false             # 未实现：NtSetInformationThread HideFromDebugger
kernel_debugger_check = false     # 未实现：内核调试器检测

[anti_dump]
# CipherShell Plus 反 Dump/nanomite 尚未接入生产闭环；显式开启同样会 fail-closed 拒绝。
erase_pe_header = false           # 未实现：运行时擦除 PE 头
section_permission_guard = false  # 未实现：运行时 section 权限守卫
nanomite_patches = false          # 未实现：INT3 Nanomite 运行时闭环

[performance]
auto_hotspot_analysis = true      # 自动分析热点函数并降低其保护等级
max_vm_overhead_ratio = 15.0      # 仅解析/往返；当前尚未参与生产判定
)";

    file.close();
    return true;
}

// ============================================================================
// 内部实现
// ============================================================================

bool ConfigParser::ValidateProductionSyntax(const std::string& content) {
    enum class ValueKind {
        Boolean,
        Integer,
        HexOrDecimalInteger,
        Number,
        String,
        StringArray,
        UintArray
    };
    using KeySchema = std::map<std::string, ValueKind>;
    static const std::map<std::string, KeySchema> schema = {
        {"global", {
            {"protection_level", ValueKind::Integer},
            {"strip_debug_info", ValueKind::Boolean},
            {"strip_rich_header", ValueKind::Boolean},
            {"strip_timestamps", ValueKind::Boolean},
            {"randomize_section_names", ValueKind::Boolean}
        }},
        {"vm", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer},
            {"target_functions", ValueKind::StringArray}, {"target_rvas", ValueKind::UintArray},
            {"register_count", ValueKind::Integer},
            {"stack_size", ValueKind::HexOrDecimalInteger},
            {"opcode_randomization", ValueKind::Boolean}, {"handler_mutation", ValueKind::Boolean},
            {"bytecode_encryption", ValueKind::Boolean}, {"native_body_policy", ValueKind::String},
            {"x86_call_abi", ValueKind::String}, {"embed_junk_handlers", ValueKind::Boolean},
            {"simd_bridge", ValueKind::Boolean}, {"x87_bridge", ValueKind::Boolean},
            {"variant_group_count", ValueKind::Integer}, {"variant_group_max", ValueKind::Integer},
            {"variant_group_functions_per_group", ValueKind::Integer}
        }},
        {"string_encryption", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer},
            {"mode", ValueKind::String}, {"ascii", ValueKind::Boolean},
            {"utf16", ValueKind::Boolean}, {"resources", ValueKind::Boolean},
            {"clear_after_use", ValueKind::Boolean}
        }},
        {"import_protection", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer}
        }},
        {"section_encryption", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer},
            {"mode", ValueKind::String}
        }},
        {"control_flow", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer}
        }},
        {"control_flow.flattening", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer},
            {"target_functions", ValueKind::StringArray}
        }},
        {"control_flow.bogus", {
            {"enabled", ValueKind::Boolean}, {"strength", ValueKind::Integer}
        }},
        {"anti_debug", {
            {"timing_checks", ValueKind::Boolean}, {"hardware_bp_detection", ValueKind::Boolean},
            {"software_bp_detection", ValueKind::Boolean}, {"memory_integrity", ValueKind::Boolean},
            {"debugger_window_scan", ValueKind::Boolean}, {"parent_process_check", ValueKind::Boolean},
            {"thread_hiding", ValueKind::Boolean}, {"kernel_debugger_check", ValueKind::Boolean}
        }},
        {"anti_dump", {
            {"erase_pe_header", ValueKind::Boolean},
            {"section_permission_guard", ValueKind::Boolean},
            {"nanomite_patches", ValueKind::Boolean}
        }},
        {"performance", {
            {"auto_hotspot_analysis", ValueKind::Boolean},
            {"max_vm_overhead_ratio", ValueKind::Number}
        }}
    };
    const std::regex sectionPattern(R"(^\[([A-Za-z0-9_.]+)\]$)");
    const std::regex keyPattern(R"(^([A-Za-z0-9_]+)\s*=\s*(.+)$)");
    const std::regex booleanPattern(R"(^(true|false)$)");
    const std::regex integerPattern(R"(^[0-9]+$)");
    const std::regex hexOrDecimalIntegerPattern(
        R"(^(0x[0-9A-Fa-f]+|[0-9]+)$)");
    const std::regex numberPattern(R"(^([0-9]+(\.[0-9]+)?|\.[0-9]+)$)");
    const std::regex stringPattern(R"RE(^"[^"\r\n]*"$)RE");
    const std::regex stringArrayPattern(
        R"RE(^\[\s*("[^"\r\n]*"\s*(,\s*"[^"\r\n]*"\s*)*)?\]$)RE");
    const std::regex uintArrayPattern(
        R"(^\[\s*((0x[0-9A-Fa-f]+|[0-9]+)\s*(,\s*(0x[0-9A-Fa-f]+|[0-9]+)\s*)*)?\]$)");

    std::istringstream lines(content);
    std::string line;
    std::string currentSection;
    std::set<std::string> seenSections;
    std::set<std::pair<std::string, std::string>> seenKeys;
    size_t lineNumber = 0;
    while (std::getline(lines, line)) {
        ++lineNumber;
        bool quoted = false;
        size_t comment = std::string::npos;
        for (size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '"') quoted = !quoted;
            else if (line[i] == '#' && !quoted) { comment = i; break; }
        }
        if (quoted) {
            m_lastError = "配置第 " + std::to_string(lineNumber) + " 行存在未闭合字符串";
            return false;
        }
        if (comment != std::string::npos) line.resize(comment);
        line = Trim(line);
        if (line.empty()) continue;

        std::smatch match;
        if (std::regex_match(line, match, sectionPattern)) {
            currentSection = match[1].str();
            if (schema.find(currentSection) == schema.end()) {
                m_lastError = "配置第 " + std::to_string(lineNumber) +
                    " 行包含未知 section: [" + currentSection + "]";
                return false;
            }
            if (!seenSections.insert(currentSection).second) {
                m_lastError = "配置第 " + std::to_string(lineNumber) +
                    " 行重复定义 section: [" + currentSection + "]";
                return false;
            }
            continue;
        }
        if (currentSection.empty() || !std::regex_match(line, match, keyPattern)) {
            m_lastError = "配置第 " + std::to_string(lineNumber) + " 行不是有效键值";
            return false;
        }
        const std::string key = match[1].str();
        const std::string value = Trim(match[2].str());
        const auto keyIt = schema.at(currentSection).find(key);
        if (keyIt == schema.at(currentSection).end()) {
            m_lastError = "配置第 " + std::to_string(lineNumber) + " 行包含未知字段: [" +
                currentSection + "]." + key;
            return false;
        }
        if (!seenKeys.emplace(currentSection, key).second) {
            m_lastError = "配置第 " + std::to_string(lineNumber) + " 行重复定义字段: [" +
                currentSection + "]." + key;
            return false;
        }
        auto validInteger = [](const std::string& text, int base) {
            try {
                size_t consumed = 0;
                const unsigned long long parsed =
                    std::stoull(text, &consumed, base);
                return consumed == text.size() &&
                    parsed <= static_cast<unsigned long long>(
                        (std::numeric_limits<int>::max)());
            } catch (...) {
                return false;
            }
        };
        bool valid = false;
        switch (keyIt->second) {
            case ValueKind::Boolean: valid = std::regex_match(value, booleanPattern); break;
            case ValueKind::Integer:
                valid = std::regex_match(value, integerPattern) &&
                    validInteger(value, 10);
                break;
            case ValueKind::HexOrDecimalInteger: {
                const bool isHex = value.size() > 2 && value[0] == '0' &&
                    (value[1] == 'x' || value[1] == 'X');
                valid = std::regex_match(
                            value, hexOrDecimalIntegerPattern) &&
                    validInteger(value, isHex ? 16 : 10);
                break;
            }
            case ValueKind::Number:
                valid = std::regex_match(value, numberPattern);
                if (valid) {
                    try {
                        size_t consumed = 0;
                        const double parsed =
                            std::stod(value, &consumed);
                        valid = consumed == value.size() &&
                            std::isfinite(parsed);
                    } catch (...) {
                        valid = false;
                    }
                }
                break;
            case ValueKind::String: valid = std::regex_match(value, stringPattern); break;
            case ValueKind::StringArray: valid = std::regex_match(value, stringArrayPattern); break;
            case ValueKind::UintArray: valid = std::regex_match(value, uintArrayPattern); break;
        }
        if (!valid) {
            m_lastError = "配置第 " + std::to_string(lineNumber) + " 行字段类型错误: [" +
                currentSection + "]." + key;
            return false;
        }
    }
    return true;
}

void ConfigParser::ParseGlobalSection(const std::string& content, GlobalConfig& config) {
    const std::string section = ExtractSection(content, "global");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "protection_level", value)) {
        config.protectionLevel = ParseInt(value);
        config.protectionLevelSet = true;
    }
    if (FindValue(section, "strip_debug_info", value))
        config.stripDebugInfo = ParseBool(value);
    if (FindValue(section, "strip_rich_header", value))
        config.stripRichHeader = ParseBool(value);
    if (FindValue(section, "strip_timestamps", value))
        config.stripTimestamps = ParseBool(value);
    if (FindValue(section, "randomize_section_names", value))
        config.randomizeSections = ParseBool(value);
}

void ConfigParser::ParseVMSection(const std::string& content, VMConfig& config) {
    const std::string section = ExtractSection(content, "vm");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "register_count", value))
        config.registerCount = ParseInt(value);
    if (FindValue(section, "stack_size", value))
        config.stackSize = ParseInt(value);
    if (FindValue(section, "opcode_randomization", value))
        config.opcodeRandomization = ParseBool(value);
    if (FindValue(section, "handler_mutation", value))
        config.handlerMutation = ParseBool(value);
    if (FindValue(section, "bytecode_encryption", value))
        config.bytecodeEncryption = ParseBool(value);
    if (FindValue(section, "native_body_policy", value))
        config.nativeBodyPolicy = ParseString(value);
    if (FindValue(section, "x86_call_abi", value))
        config.x86CallAbi = ParseString(value);
    if (FindValue(section, "embed_junk_handlers", value))
        config.embedJunkHandlers = ParseBool(value);
    if (FindValue(section, "enabled", value)) {
        config.enabled = ParseBool(value);
        config.enabledSet = true;
    }
    if (FindValue(section, "strength", value))
        config.strength = ParseInt(value);
    if (FindValue(section, "target_functions", value))
        config.targetFunctions = ParseStringArray(value);
    if (FindValue(section, "target_rvas", value))
        config.targetRVAs = ParseUint32Array(value);
    if (FindValue(section, "simd_bridge", value))
        config.simdBridge = ParseBool(value);
    if (FindValue(section, "x87_bridge", value))
        config.x87Bridge = ParseBool(value);
    if (FindValue(section, "variant_group_count", value))
        config.variantGroupCount = ParseInt(value);
    if (FindValue(section, "variant_group_max", value))
        config.variantGroupMax = ParseInt(value);
    if (FindValue(section, "variant_group_functions_per_group", value))
        config.variantGroupFunctionsPerGroup = ParseInt(value);
}

void ConfigParser::ParseStringEncryptionSection(const std::string& content, StringEncryptionConfig& config) {
    const std::string section = ExtractSection(content, "string_encryption");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "enabled", value)) {
        config.enabled = ParseBool(value);
        config.enabledSet = true;
    }
    if (FindValue(section, "strength", value))
        config.strength = ParseInt(value);
    if (FindValue(section, "mode", value))
        config.mode = ParseString(value);
    if (FindValue(section, "ascii", value))
        config.ascii = ParseBool(value);
    if (FindValue(section, "utf16", value))
        config.utf16 = ParseBool(value);
    if (FindValue(section, "resources", value))
        config.resources = ParseBool(value);
    if (FindValue(section, "clear_after_use", value))
        config.clearAfterUse = ParseBool(value);
}

void ConfigParser::ParseImportProtectionSection(const std::string& content, ImportProtectionConfig& config) {
    const std::string section = ExtractSection(content, "import_protection");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "enabled", value)) {
        config.enabled = ParseBool(value);
        config.enabledSet = true;
    }
    if (FindValue(section, "strength", value))
        config.strength = ParseInt(value);
}

void ConfigParser::ParseSectionEncryptionSection(const std::string& content, SectionEncryptionConfig& config) {
    const std::string section = ExtractSection(content, "section_encryption");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "enabled", value)) {
        config.enabled = ParseBool(value);
        config.enabledSet = true;
    }
    if (FindValue(section, "strength", value))
        config.strength = ParseInt(value);
    if (FindValue(section, "mode", value))
        config.mode = ParseString(value);
}

void ConfigParser::ParseControlFlowSection(const std::string& content, ControlFlowConfigFile& config) {
    const std::string section = ExtractSection(content, "control_flow");
    const std::string flattening =
        ExtractSection(content, "control_flow.flattening");
    const std::string bogus =
        ExtractSection(content, "control_flow.bogus");
    std::string value;

    if (!section.empty()) {
        if (FindValue(section, "enabled", value)) {
            config.enabled = ParseBool(value);
            config.enabledSet = true;
        }
        if (FindValue(section, "strength", value))
            config.strength = ParseInt(value);
    }
    if (!flattening.empty()) {
        if (FindValue(flattening, "enabled", value)) {
            config.flatteningEnabled = ParseBool(value);
            config.flatteningEnabledSet = true;
        }
        if (FindValue(flattening, "strength", value))
            config.flatteningStrength = ParseInt(value);
        if (FindValue(flattening, "target_functions", value))
            config.flatteningTargets = ParseStringArray(value);
    }
    if (!bogus.empty()) {
        if (FindValue(bogus, "enabled", value)) {
            config.bogusEnabled = ParseBool(value);
            config.bogusEnabledSet = true;
        }
        if (FindValue(bogus, "strength", value))
            config.bogusStrength = ParseInt(value);
    }
}

void ConfigParser::ParseAntiDebugSection(const std::string& content, AntiDebugConfigFile& config) {
    const std::string section = ExtractSection(content, "anti_debug");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "timing_checks", value))
        config.timingChecks = ParseBool(value);
    if (FindValue(section, "hardware_bp_detection", value))
        config.hardwareBPDetection = ParseBool(value);
    if (FindValue(section, "software_bp_detection", value))
        config.softwareBPDetection = ParseBool(value);
    if (FindValue(section, "memory_integrity", value))
        config.memoryIntegrity = ParseBool(value);
    if (FindValue(section, "debugger_window_scan", value))
        config.debuggerWindowScan = ParseBool(value);
    if (FindValue(section, "parent_process_check", value))
        config.parentProcessCheck = ParseBool(value);
    if (FindValue(section, "thread_hiding", value))
        config.threadHiding = ParseBool(value);
    if (FindValue(section, "kernel_debugger_check", value))
        config.kernelDebuggerCheck = ParseBool(value);
}

void ConfigParser::ParseAntiDumpSection(const std::string& content, AntiDumpConfig& config) {
    const std::string section = ExtractSection(content, "anti_dump");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "erase_pe_header", value))
        config.erasePEHeader = ParseBool(value);
    if (FindValue(section, "section_permission_guard", value))
        config.sectionPermissionGuard = ParseBool(value);
    if (FindValue(section, "nanomite_patches", value))
        config.nanomitePatches = ParseBool(value);
}

void ConfigParser::ParsePerformanceSection(const std::string& content, PerformanceConfig& config) {
    const std::string section = ExtractSection(content, "performance");
    if (section.empty()) return;

    std::string value;
    if (FindValue(section, "auto_hotspot_analysis", value))
        config.autoHotspotAnalysis = ParseBool(value);
    if (FindValue(section, "max_vm_overhead_ratio", value))
        config.maxVMOverheadRatio = ParseDouble(value);
}

void ConfigParser::ParseFunctionOverrides(const std::string& content, std::vector<FunctionOverride>& overrides) {
    (void)content;
    overrides.clear();
    // ValidateProductionSyntax 已按整行 section 语法拒绝
    // [[function_overrides]]。这里不能再做裸 substring 搜索，否则合法目标
    // 字符串里的同名文本会被误判成 section。
}
// ============================================================================
// 辅助函数
// ============================================================================

std::string ConfigParser::Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::string ConfigParser::StripComments(const std::string& content) {
    std::istringstream lines(content);
    std::string line;
    std::string result;
    while (std::getline(lines, line)) {
        bool quoted = false;
        size_t comment = std::string::npos;
        for (size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '"') quoted = !quoted;
            else if (line[i] == '#' && !quoted) {
                comment = i;
                break;
            }
        }
        if (comment != std::string::npos) line.resize(comment);
        result += line;
        result.push_back('\n');
    }
    return result;
}

std::string ConfigParser::ExtractSection(const std::string& content, const std::string& sectionName) {
    const std::string header = "[" + sectionName + "]";
    std::istringstream lines(content);
    std::string line;
    std::string section;
    bool collecting = false;
    while (std::getline(lines, line)) {
        const std::string trimmed = Trim(line);
        if (trimmed == header) {
            collecting = true;
            continue;
        }
        if (collecting && trimmed.size() >= 2 &&
            trimmed.front() == '[' && trimmed.back() == ']') {
            break;
        }
        if (collecting) {
            section += line;
            section.push_back('\n');
        }
    }
    return section;
}

bool ConfigParser::FindValue(const std::string& section,
        const std::string& key, std::string& value) {
    std::istringstream lines(section);
    std::string line;
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (line.empty()) continue;
        const size_t equals = line.find('=');
        if (equals == std::string::npos ||
            Trim(line.substr(0, equals)) != key) {
            continue;
        }
        value = Trim(line.substr(equals + 1));
        return true;
    }
    value.clear();
    return false;
}

bool ConfigParser::ParseBool(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return (lower == "true" || lower == "1" || lower == "yes");
}

int ConfigParser::ParseInt(const std::string& value) {
    try {
        size_t consumed = 0;
        const bool isHex = value.length() > 2 &&
            (value.substr(0, 2) == "0x" ||
             value.substr(0, 2) == "0X");
        const unsigned long long parsed =
            std::stoull(value, &consumed, isHex ? 16 : 10);
        if (consumed != value.size() ||
            parsed > static_cast<unsigned long long>(
                (std::numeric_limits<int>::max)())) {
            throw std::out_of_range("integer outside int range");
        }
        return static_cast<int>(parsed);
    } catch (...) {
        if (m_lastError.empty()) {
            m_lastError = "配置整数无法无损解析: " + value;
        }
        return 0;
    }
}

double ConfigParser::ParseDouble(const std::string& value) {
    try {
        size_t consumed = 0;
        const double parsed = std::stod(value, &consumed);
        if (consumed != value.size() || !std::isfinite(parsed)) {
            throw std::out_of_range("number is not finite");
        }
        return parsed;
    } catch (...) {
        if (m_lastError.empty()) {
            m_lastError = "配置数值无法无损解析: " + value;
        }
        return 0.0;
    }
}

std::string ConfigParser::ParseString(const std::string& value) {
    // 去掉引号
    if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
        std::string raw = value.substr(1, value.length() - 2);

        // BUG 15 修复：处理 TOML 字符串中的转义字符
        std::string result;
        result.reserve(raw.size());
        for (size_t i = 0; i < raw.size(); i++) {
            if (raw[i] == '\\' && i + 1 < raw.size()) {
                switch (raw[i + 1]) {
                    case 'n':  result += '\n'; i++; break;
                    case 't':  result += '\t'; i++; break;
                    case 'r':  result += '\r'; i++; break;
                    case '\\': result += '\\'; i++; break;
                    case '"':  result += '"';  i++; break;
                    case 'b':  result += '\b'; i++; break;
                    case 'f':  result += '\f'; i++; break;
                    default:
                        // 未知转义序列，原样保留
                        result += raw[i];
                        break;
                }
            } else {
                result += raw[i];
            }
        }
        return result;
    }
    return value;
}

std::vector<std::string> ConfigParser::ParseStringArray(const std::string& value) {
    std::vector<std::string> result;
    size_t begin = value.find('[');
    size_t end = value.rfind(']');
    if (begin == std::string::npos || end == std::string::npos || end <= begin) return result;

    std::string body = value.substr(begin + 1, end - begin - 1);
    size_t pos = 0;
    while (pos < body.size()) {
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == ',')) pos++;
        if (pos >= body.size()) break;
        if (body[pos] != '"') break;
        size_t close = body.find('"', pos + 1);
        if (close == std::string::npos) break;
        result.push_back(body.substr(pos + 1, close - pos - 1));
        pos = close + 1;
    }
    return result;
}

std::vector<uint32_t> ConfigParser::ParseUint32Array(const std::string& value) {
    std::vector<uint32_t> result;
    const size_t begin = value.find('[');
    const size_t end = value.rfind(']');
    if (begin == std::string::npos || end == std::string::npos || end <= begin) {
        m_lastError = "invalid uint32 array syntax";
        return result;
    }

    std::stringstream stream(value.substr(begin + 1, end - begin - 1));
    std::string token;
    while (std::getline(stream, token, ',')) {
        token = Trim(token);
        if (token.empty()) continue;
        try {
            size_t consumed = 0;
            const int base = token.size() > 2 && token[0] == '0' &&
                (token[1] == 'x' || token[1] == 'X') ? 16 : 10;
            const unsigned long long parsed = std::stoull(token, &consumed, base);
            if (consumed != token.size() || parsed == 0 || parsed > 0xFFFFFFFFULL) {
                m_lastError = "target_rvas contains an invalid nonzero uint32 RVA: " + token;
                return {};
            }
            result.push_back(static_cast<uint32_t>(parsed));
        } catch (...) {
            m_lastError = "target_rvas contains an invalid RVA: " + token;
            return {};
        }
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}
} // namespace CipherShell
