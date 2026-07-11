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
#include <map>
#include <set>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

ConfigParser::ConfigParser() {}
ConfigParser::~ConfigParser() {}

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

    // 解析各个配置段
    ParseGlobalSection(content, config.global);
    ParseVMSection(content, config.vm);
    ParseStringEncryptionSection(content, config.stringEncryption);
    ParseImportProtectionSection(content, config.importProtection);
    ParseSectionEncryptionSection(content, config.sectionEncryption);
    ParseControlFlowSection(content, config.controlFlow);
    ParseAntiDebugSection(content, config.antiDebug);
    ParseAntiDumpSection(content, config.antiDump);
    ParsePerformanceSection(content, config.performance);
    ParseFunctionOverrides(content, config.functionOverrides);

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
strip_debug_info = true           # 删除所有调试信息
strip_rich_header = true          # 删除 Rich Header（编译器指纹）
strip_timestamps = true           # 时间戳归零
randomize_section_names = true    # Section 名称随机化

[vm]
enabled = false                   # 显式功能开关；L1-L5 只提供未显式设置时的 preset
strength = 80
target_functions = []             # 按导出名或 sub_RVA 通配选择
target_rvas = []                  # 按函数入口 RVA 精确选择
register_count = 24               # 虚拟寄存器数量（16-64）
stack_size = 0x20000              # 虚拟栈大小
opcode_randomization = true       # 每次构建生成完整 opcode permutation
handler_mutation = true           # 生产构建默认启用 handler 入口布局与执行路径变异
bytecode_encryption = true        # ChaCha20 加密 + SipHash 完整性认证
native_body_policy = "destroy"    # 原 native 函数体销毁
x86_call_abi = "auto"            # "auto" | "cdecl" | "stdcall" | "fastcall" | "thiscall"
embed_junk_handlers = true        # 生成不可由合法 opcode 到达的垃圾 handler 槽
simd_bridge = true                # SSE2/SSE4/AVX/AVX2 严格指令桥
x87_bridge = true                 # x87 严格指令桥

[string_encryption]
enabled = false                  # 未认证滚动/XOR格式尚未达到生产要求
strength = 60
mode = "startup"
ascii = true
utf16 = true
resources = false
clear_after_use = false

[import_protection]
enabled = false                  # 尚未改写真实 IAT 调用点
strength = 50

[section_encryption]
enabled = false                  # 任务表仍携带可恢复密钥，暂时 fail-closed
strength = 58
mode = "startup"

[control_flow]
enabled = false
strength = 55

[control_flow.flattening]
enabled = false                  # 尚未完成 RIP/CALL/unwind/CFG 修复
strength = 55
target_functions = []

[control_flow.bogus]
enabled = false                  # 尚未证明原函数语义保持
strength = 50

[anti_debug]
timing_checks = true              # 时序检测
hardware_bp_detection = true      # 硬件断点检测
software_bp_detection = true      # INT3 / 0xCC 扫描
memory_integrity = true           # 代码完整性校验
debugger_window_scan = false      # 扫描调试器窗口类名（可选，易被绕过）
parent_process_check = true       # 父进程检测
thread_hiding = true              # NtSetInformationThread HideFromDebugger
kernel_debugger_check = true      # 内核调试器检测

[anti_dump]
erase_pe_header = true            # 运行时擦除 PE 头
section_permission_guard = true   # 动态权限管理
nanomite_patches = true           # INT3 Nanomite 技术

[performance]
auto_hotspot_analysis = true      # 自动分析热点函数并降低其保护等级
max_vm_overhead_ratio = 15.0      # VM 执行最大允许倍率（超过则自动降级）
)";

    file.close();
    return true;
}

// ============================================================================
// 内部实现
// ============================================================================

bool ConfigParser::ValidateProductionSyntax(const std::string& content) {
    enum class ValueKind { Boolean, Integer, Number, String, StringArray, UintArray };
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
            {"register_count", ValueKind::Integer}, {"stack_size", ValueKind::Integer},
            {"opcode_randomization", ValueKind::Boolean}, {"handler_mutation", ValueKind::Boolean},
            {"bytecode_encryption", ValueKind::Boolean}, {"native_body_policy", ValueKind::String},
            {"x86_call_abi", ValueKind::String}, {"embed_junk_handlers", ValueKind::Boolean},
            {"simd_bridge", ValueKind::Boolean}, {"x87_bridge", ValueKind::Boolean}
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
    const std::regex integerPattern(R"(^(0x[0-9A-Fa-f]+|[0-9]+)$)");
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
        bool valid = false;
        switch (keyIt->second) {
            case ValueKind::Boolean: valid = std::regex_match(value, booleanPattern); break;
            case ValueKind::Integer: valid = std::regex_match(value, integerPattern); break;
            case ValueKind::Number: valid = std::regex_match(value, numberPattern); break;
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
    std::string section = ExtractSection(content, "global");
    if (section.empty()) return;

    // 解析各个配置项
    std::regex regex_protection(R"(protection_level\s*=\s*(\d+))");
    std::regex regex_debug(R"(strip_debug_info\s*=\s*(true|false))");
    std::regex regex_rich(R"(strip_rich_header\s*=\s*(true|false))");
    std::regex regex_timestamps(R"(strip_timestamps\s*=\s*(true|false))");
    std::regex regex_sections(R"(randomize_section_names\s*=\s*(true|false))");
    std::regex regex_antidebug(R"RE(anti_debug_mode\s*=\s*"([^"]+)")RE");
    std::regex regex_strings(R"(string_encryption\s*=\s*(true|false))");
    std::regex regex_imports(R"(import_obfuscation\s*=\s*(true|false))");
    std::regex regex_resources(R"(resource_encryption\s*=\s*(true|false))");

    std::smatch match;
    if (std::regex_search(section, match, regex_protection)) config.protectionLevel = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_debug)) config.stripDebugInfo = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_rich)) config.stripRichHeader = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_timestamps)) config.stripTimestamps = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_sections)) config.randomizeSections = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_antidebug)) config.antiDebugMode = match[1];
    if (std::regex_search(section, match, regex_strings)) {
        config.stringEncryption = ParseBool(match[1]);
        m_warnings.push_back("[global].string_encryption is deprecated; use [string_encryption].enabled instead");
    }
    if (std::regex_search(section, match, regex_imports)) {
        config.importObfuscation = ParseBool(match[1]);
        m_warnings.push_back("[global].import_obfuscation is deprecated; use [import_protection].enabled instead");
    }
    if (std::regex_search(section, match, regex_resources)) {
        config.resourceEncryption = ParseBool(match[1]);
        m_warnings.push_back("[global].resource_encryption is deprecated; use [section_encryption].resources when available");
    }
}

void ConfigParser::ParseVMSection(const std::string& content, VMConfig& config) {
    std::string section = ExtractSection(content, "vm");
    if (section.empty()) return;

    std::regex regex_reg(R"(register_count\s*=\s*(\d+))");
    std::regex regex_stack(R"(stack_size\s*=\s*(0x[0-9a-fA-F]+|\d+))");
    std::regex regex_opcode_randomization(R"RE(opcode_randomization\s*=\s*(true|false))RE");
    std::regex regex_mutation(R"(handler_mutation\s*=\s*(true|false))");
    std::regex regex_encrypt(R"RE(bytecode_encryption\s*=\s*(true|false))RE");
    std::regex regex_native_body(R"RE(native_body_policy\s*=\s*"([^"]+)")RE");
    std::regex regex_x86_call_abi(R"RE(x86_call_abi\s*=\s*"([^"]+)")RE");
    std::regex regex_junk(R"(embed_junk_handlers\s*=\s*(true|false))");
    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::regex regex_targets(R"RE(target_functions\s*=\s*(\[[^\]]*\]))RE");
    std::regex regex_target_rvas(R"RE(target_rvas\s*=\s*(\[[^\]]*\]))RE");
    std::regex regex_simd_bridge(R"(simd_bridge\s*=\s*(true|false))");
    std::regex regex_x87_bridge(R"(x87_bridge\s*=\s*(true|false))");

    std::smatch match;
    if (std::regex_search(section, match, regex_reg)) config.registerCount = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_stack)) config.stackSize = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_opcode_randomization)) config.opcodeRandomization = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_mutation)) config.handlerMutation = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_encrypt)) config.bytecodeEncryption = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_native_body)) config.nativeBodyPolicy = match[1];
    if (std::regex_search(section, match, regex_x86_call_abi)) config.x86CallAbi = match[1];
    if (std::regex_search(section, match, regex_junk)) config.embedJunkHandlers = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_targets)) config.targetFunctions = ParseStringArray(match[1]);
    if (std::regex_search(section, match, regex_target_rvas)) config.targetRVAs = ParseUint32Array(match[1]);
    if (std::regex_search(section, match, regex_simd_bridge)) config.simdBridge = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_x87_bridge)) config.x87Bridge = ParseBool(match[1]);
}

void ConfigParser::ParseStringEncryptionSection(const std::string& content, StringEncryptionConfig& config) {
    std::string section = ExtractSection(content, "string_encryption");
    if (section.empty()) return;

    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::regex regex_mode(R"RE(mode\s*=\s*"([^"]+)")RE");
    std::regex regex_ascii(R"(ascii\s*=\s*(true|false))");
    std::regex regex_utf16(R"(utf16\s*=\s*(true|false))");
    std::regex regex_resources(R"(resources\s*=\s*(true|false))");
    std::regex regex_clear(R"(clear_after_use\s*=\s*(true|false))");

    std::smatch match;
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_mode)) config.mode = match[1];
    if (std::regex_search(section, match, regex_ascii)) config.ascii = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_utf16)) config.utf16 = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_resources)) config.resources = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_clear)) config.clearAfterUse = ParseBool(match[1]);
}

void ConfigParser::ParseImportProtectionSection(const std::string& content, ImportProtectionConfig& config) {
    std::string section = ExtractSection(content, "import_protection");
    std::string legacySection = ExtractSection(content, "import_obfuscation");
    if (section.empty() && !legacySection.empty()) {
        section = legacySection;
        m_warnings.push_back("[import_obfuscation] is deprecated; use [import_protection] instead");
    }
    if (section.empty()) return;

    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::smatch match;
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
}

void ConfigParser::ParseSectionEncryptionSection(const std::string& content, SectionEncryptionConfig& config) {
    std::string section = ExtractSection(content, "section_encryption");
    if (section.empty()) return;

    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::regex regex_mode(R"RE(mode\s*=\s*"([^"]+)")RE");
    std::smatch match;
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_mode)) config.mode = match[1];
}
void ConfigParser::ParseControlFlowSection(const std::string& content, ControlFlowConfigFile& config) {
    std::string section = ExtractSection(content, "control_flow");
    std::string flattening = ExtractSection(content, "control_flow.flattening");
    std::string bogus = ExtractSection(content, "control_flow.bogus");

    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::regex regex_targets(R"RE(target_functions\s*=\s*(\[[^\]]*\]))RE");
    std::smatch match;

    if (!section.empty()) {
        if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
        if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
    }
    if (!flattening.empty()) {
        if (std::regex_search(flattening, match, regex_enabled)) { config.flatteningEnabled = ParseBool(match[1]); config.flatteningEnabledSet = true; }
        if (std::regex_search(flattening, match, regex_strength)) config.flatteningStrength = ParseInt(match[1]);
        if (std::regex_search(flattening, match, regex_targets)) config.flatteningTargets = ParseStringArray(match[1]);
    }
    if (!bogus.empty()) {
        if (std::regex_search(bogus, match, regex_enabled)) { config.bogusEnabled = ParseBool(match[1]); config.bogusEnabledSet = true; }
        if (std::regex_search(bogus, match, regex_strength)) config.bogusStrength = ParseInt(match[1]);
    }
}
void ConfigParser::ParseAntiDebugSection(const std::string& content, AntiDebugConfigFile& config) {
    std::string section = ExtractSection(content, "anti_debug");
    if (section.empty()) return;

    std::regex regex_timing(R"(timing_checks\s*=\s*(true|false))");
    std::regex regex_hwbp(R"(hardware_bp_detection\s*=\s*(true|false))");
    std::regex regex_swbp(R"(software_bp_detection\s*=\s*(true|false))");
    std::regex regex_mem(R"(memory_integrity\s*=\s*(true|false))");
    std::regex regex_window(R"(debugger_window_scan\s*=\s*(true|false))");
    std::regex regex_parent(R"(parent_process_check\s*=\s*(true|false))");
    std::regex regex_thread(R"(thread_hiding\s*=\s*(true|false))");
    std::regex regex_kernel(R"(kernel_debugger_check\s*=\s*(true|false))");

    std::smatch match;
    if (std::regex_search(section, match, regex_timing)) config.timingChecks = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_hwbp)) config.hardwareBPDetection = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_swbp)) config.softwareBPDetection = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_mem)) config.memoryIntegrity = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_window)) config.debuggerWindowScan = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_parent)) config.parentProcessCheck = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_thread)) config.threadHiding = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_kernel)) config.kernelDebuggerCheck = ParseBool(match[1]);
}

void ConfigParser::ParseAntiDumpSection(const std::string& content, AntiDumpConfig& config) {
    std::string section = ExtractSection(content, "anti_dump");
    if (section.empty()) return;

    std::regex regex_header(R"(erase_pe_header\s*=\s*(true|false))");
    std::regex regex_perm(R"(section_permission_guard\s*=\s*(true|false))");
    std::regex regex_nano(R"(nanomite_patches\s*=\s*(true|false))");

    std::smatch match;
    if (std::regex_search(section, match, regex_header)) config.erasePEHeader = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_perm)) config.sectionPermissionGuard = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_nano)) config.nanomitePatches = ParseBool(match[1]);
}

void ConfigParser::ParsePerformanceSection(const std::string& content, PerformanceConfig& config) {
    std::string section = ExtractSection(content, "performance");
    if (section.empty()) return;

    std::regex regex_hotspot(R"(auto_hotspot_analysis\s*=\s*(true|false))");
    std::regex regex_ratio(R"(max_vm_overhead_ratio\s*=\s*([\d.]+))");

    std::smatch match;
    if (std::regex_search(section, match, regex_hotspot)) config.autoHotspotAnalysis = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_ratio)) config.maxVMOverheadRatio = ParseDouble(match[1]);
}

void ConfigParser::ParseFunctionOverrides(const std::string& content, std::vector<FunctionOverride>& overrides) {
    const std::string marker = "[[function_overrides]]";
    overrides.clear();
    if (content.find(marker) != std::string::npos) {
        m_lastError = "[[function_overrides]] is not part of the production schema; use [vm].target_functions/target_rvas";
    }
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

std::string ConfigParser::ExtractSection(const std::string& content, const std::string& sectionName) {
    // 查找 [sectionName]
    std::string header = "[" + sectionName + "]";
    size_t start = content.find(header);
    if (start == std::string::npos) return "";

    start += header.length();

    // 查找下一个 [ 开头（下一个 section）
    size_t end = content.find("\n[", start);
    if (end == std::string::npos) {
        end = content.length();
    }

    return content.substr(start, end - start);
}

bool ConfigParser::ParseBool(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return (lower == "true" || lower == "1" || lower == "yes");
}

int ConfigParser::ParseInt(const std::string& value) {
    try {
        if (value.length() > 2 && (value.substr(0, 2) == "0x" || value.substr(0, 2) == "0X")) {
            return std::stoi(value, nullptr, 16);
        }
        return std::stoi(value);
    } catch (...) {
        return 0;
    }
}

double ConfigParser::ParseDouble(const std::string& value) {
    try {
        return std::stod(value);
    } catch (...) {
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
