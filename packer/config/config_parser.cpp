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

    // 解析各个配置段
    ParseGlobalSection(content, config.global);
    ParseVMSection(content, config.vm);
    ParseStringEncryptionSection(content, config.stringEncryption);
    ParseImportProtectionSection(content, config.importProtection);
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
anti_debug_mode = "implicit"      # "explicit" | "implicit" | "hybrid"
string_encryption = true          # 全局字符串加密
import_obfuscation = true         # 导入表混淆
resource_encryption = false       # 资源加密（可能影响兼容性）

[vm]
register_count = 24               # 虚拟寄存器数量（16-64）
stack_size = 0x20000              # 虚拟栈大小
opcode_width = "variable"         # "fixed_8" | "fixed_16" | "variable"
handler_mutation = true           # Handler 代码变异
bytecode_encryption = "rolling"   # "none" | "xor" | "rolling" | "aes_ctr"
embed_junk_handlers = true        # 嵌入无意义的假 handler 干扰分析

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

# 函数级精确控制
[[function_overrides]]
pattern = "main"                  # 函数名匹配（支持通配符）
level = 5                         # 覆盖为最高保护

[[function_overrides]]
pattern = "render_*"              # 渲染相关函数
level = 1                         # 性能敏感，仅做基础加密

[[function_overrides]]
pattern = "license_check*"        # 授权验证函数
level = 5                         # 最高保护
vm_nesting = 2                    # 双层 VM 嵌套

[[function_overrides]]
pattern = "crypto_*"              # 已有加密函数
level = 2                         # 避免过度保护影响性能
)";

    file.close();
    return true;
}

// ============================================================================
// 内部实现
// ============================================================================

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
    if (std::regex_search(section, match, regex_strings)) config.stringEncryption = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_imports)) config.importObfuscation = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_resources)) config.resourceEncryption = ParseBool(match[1]);
}

void ConfigParser::ParseVMSection(const std::string& content, VMConfig& config) {
    std::string section = ExtractSection(content, "vm");
    if (section.empty()) return;

    std::regex regex_reg(R"(register_count\s*=\s*(\d+))");
    std::regex regex_stack(R"(stack_size\s*=\s*(0x[0-9a-fA-F]+|\d+))");
    std::regex regex_opcode(R"RE(opcode_width\s*=\s*"([^"]+)")RE");
    std::regex regex_mutation(R"(handler_mutation\s*=\s*(true|false))");
    std::regex regex_encrypt(R"RE(bytecode_encryption\s*=\s*"([^"]+)")RE");
    std::regex regex_junk(R"(embed_junk_handlers\s*=\s*(true|false))");
    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::regex regex_targets(R"RE(target_functions\s*=\s*(\[[^\]]*\]))RE");

    std::smatch match;
    if (std::regex_search(section, match, regex_reg)) config.registerCount = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_stack)) config.stackSize = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_opcode)) config.opcodeWidth = match[1];
    if (std::regex_search(section, match, regex_mutation)) config.handlerMutation = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_encrypt)) config.bytecodeEncryption = match[1];
    if (std::regex_search(section, match, regex_junk)) config.embedJunkHandlers = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_targets)) config.targetFunctions = ParseStringArray(match[1]);
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
    if (section.empty()) return;

    std::regex regex_enabled(R"(enabled\s*=\s*(true|false))");
    std::regex regex_strength(R"(strength\s*=\s*(\d+))");
    std::smatch match;
    if (std::regex_search(section, match, regex_enabled)) { config.enabled = ParseBool(match[1]); config.enabledSet = true; }
    if (std::regex_search(section, match, regex_strength)) config.strength = ParseInt(match[1]);
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
    std::regex regex_pattern(R"RE(pattern\s*=\s*"([^"]+)")RE");
    std::regex regex_level(R"(level\s*=\s*(\d+))");
    std::regex regex_nesting(R"(vm_nesting\s*=\s*(\d+))");

    size_t pos = 0;
    while ((pos = content.find(marker, pos)) != std::string::npos) {
        size_t blockStart = pos + marker.length();
        size_t blockEnd = content.find("\n[", blockStart);
        if (blockEnd == std::string::npos) {
            blockEnd = content.length();
        }

        std::string block = content.substr(blockStart, blockEnd - blockStart);
        FunctionOverride override{};
        override.level = 0;
        override.vmNesting = 0;

        std::smatch match;
        if (std::regex_search(block, match, regex_pattern)) override.pattern = match[1];
        if (std::regex_search(block, match, regex_level)) override.level = ParseInt(match[1]);
        if (std::regex_search(block, match, regex_nesting)) override.vmNesting = ParseInt(match[1]);

        if (!override.pattern.empty()) {
            if (override.level < 1) override.level = 1;
            if (override.level > 5) override.level = 5;
            overrides.push_back(override);
        }

        pos = blockEnd;
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
} // namespace CipherShell
