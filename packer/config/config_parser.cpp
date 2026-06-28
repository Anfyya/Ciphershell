/**
 * CipherShell 配置解析器 - 实现
 * 简化的 TOML 解析实现
 */

#include "config_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>

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

    std::ifstream file(filePath);
    if (!file.is_open()) {
        return config;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    return LoadFromString(content);
}

CipherShellConfig ConfigParser::LoadFromString(const std::string& content) {
    CipherShellConfig config;

    // 解析各个配置段
    ParseGlobalSection(content, config.global);
    ParseVMSection(content, config.vm);
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

    std::smatch match;
    if (std::regex_search(section, match, regex_reg)) config.registerCount = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_stack)) config.stackSize = ParseInt(match[1]);
    if (std::regex_search(section, match, regex_opcode)) config.opcodeWidth = match[1];
    if (std::regex_search(section, match, regex_mutation)) config.handlerMutation = ParseBool(match[1]);
    if (std::regex_search(section, match, regex_encrypt)) config.bytecodeEncryption = match[1];
    if (std::regex_search(section, match, regex_junk)) config.embedJunkHandlers = ParseBool(match[1]);
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
    // 查找所有 [[function_overrides]] 段
    std::regex regex_block(R"(\[\[function_overrides\]\]\s*\n(.*?)(?=\[\[|$))");
    std::regex regex_pattern(R"RE(pattern\s*=\s*"([^"]+)")RE");
    std::regex regex_level(R"(level\s*=\s*(\d+))");
    std::regex regex_nesting(R"(vm_nesting\s*=\s*(\d+))");

    std::sregex_iterator it(content.begin(), content.end(), regex_block);
    std::sregex_iterator end;

    for (; it != end; ++it) {
        std::string block = (*it)[1];
        FunctionOverride override;

        std::smatch match;
        if (std::regex_search(block, match, regex_pattern)) override.pattern = match[1];
        if (std::regex_search(block, match, regex_level)) override.level = ParseInt(match[1]);
        if (std::regex_search(block, match, regex_nesting)) override.vmNesting = ParseInt(match[1]);

        if (!override.pattern.empty()) {
            overrides.push_back(override);
        }
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
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
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
        return value.substr(1, value.length() - 2);
    }
    return value;
}

} // namespace CipherShell
