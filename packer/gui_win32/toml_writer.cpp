#include "toml_writer.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace CipherShellGui {
namespace {

// config_parser.cpp 的 stringPattern 是 ^"[^"\r\n]*"$ —— 值里完全不允许
// 出现引号（连转义都不支持），也不允许换行。直接丢弃这些字符，好过生成一份
// 会被 ValidateProductionSyntax 拒绝的配置文件。
std::string SanitizeTomlString(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        if (c == '"' || c == '\r' || c == '\n') continue;
        out.push_back(c);
    }
    return out;
}

std::string QuoteTomlString(const std::string& raw) {
    return "\"" + SanitizeTomlString(raw) + "\"";
}

std::string FormatBool(bool value) {
    return value ? "true" : "false";
}

// register_count / variant_group_* 等字段在 config_parser.cpp 里用
// `\d+`（纯十进制）单独匹配，即便 ValidateProductionSyntax 的 Integer 类型
// 本身允许十六进制，写十六进制也会被那个更窄的正则悄悄吃成错误的值。这里统一
// 用十进制，只有 stack_size / target_rvas 走十六进制（对应的 regex 显式支持
// 0x 前缀）。
std::string FormatDecimal(long long value) {
    return std::to_string(value);
}

std::string FormatHex(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
        static_cast<unsigned long long>(value));
    return std::string(buf);
}

std::string FormatRatio(double value) {
    if (value < 0.0) value = 0.0;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.3f", value);
    std::string text(buf);
    const size_t dot = text.find('.');
    if (dot != std::string::npos) {
        size_t last = text.find_last_not_of('0');
        if (last == dot) ++last;  // 至少保留一位小数
        text.erase(last + 1);
    }
    return text;
}

std::string FormatStringArray(const std::vector<std::string>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out += ", ";
        out += QuoteTomlString(values[i]);
    }
    out += "]";
    return out;
}

std::string FormatUintArray(const std::vector<uint32_t>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out += ", ";
        out += FormatHex(values[i]);
    }
    out += "]";
    return out;
}

void AppendLine(std::ostringstream& out, const std::string& line) {
    out << line << "\n";
}

} // namespace

std::string BuildConfigToml(const AppConfig& config) {
    std::ostringstream out;

    AppendLine(out, "# 由 CipherShell GUI 自动生成，随本次保护任务临时使用。");
    AppendLine(out, "# 字段集合与 config/full_example.toml 保持一致，语法遵循");
    AppendLine(out, "# packer/config/config_parser.cpp::ValidateProductionSyntax。");
    out << "\n";

    AppendLine(out, "[global]");
    AppendLine(out, "protection_level = " + FormatDecimal(config.cli.protectionLevel));
    AppendLine(out, "strip_debug_info = " + FormatBool(config.global.stripDebugInfo));
    AppendLine(out, "strip_rich_header = " + FormatBool(config.global.stripRichHeader));
    AppendLine(out, "strip_timestamps = " + FormatBool(config.global.stripTimestamps));
    AppendLine(out, "randomize_section_names = " + FormatBool(config.global.randomizeSectionNames));
    out << "\n";

    const VmOptions& vm = config.vm;
    AppendLine(out, "[vm]");
    AppendLine(out, "enabled = " + FormatBool(vm.enabled));
    AppendLine(out, "strength = " + FormatDecimal(vm.strength));
    AppendLine(out, "target_functions = " + FormatStringArray(vm.targetFunctions));
    AppendLine(out, "target_rvas = " + FormatUintArray(vm.targetRVAs));
    AppendLine(out, "register_count = " + FormatDecimal(vm.registerCount));
    AppendLine(out, "stack_size = " + FormatHex(vm.stackSize));
    AppendLine(out, "opcode_randomization = " + FormatBool(vm.opcodeRandomization));
    AppendLine(out, "handler_mutation = " + FormatBool(vm.handlerMutation));
    AppendLine(out, "bytecode_encryption = " + FormatBool(vm.bytecodeEncryption));
    AppendLine(out, "native_body_policy = " + QuoteTomlString(vm.nativeBodyPolicy));
    AppendLine(out, "x86_call_abi = " + QuoteTomlString(vm.x86CallAbi));
    AppendLine(out, "embed_junk_handlers = " + FormatBool(vm.embedJunkHandlers));
    AppendLine(out, "simd_bridge = " + FormatBool(vm.simdBridge));
    AppendLine(out, "x87_bridge = " + FormatBool(vm.x87Bridge));
    AppendLine(out, "variant_group_count = " + FormatDecimal(vm.variantGroupCount));
    AppendLine(out, "variant_group_max = " + FormatDecimal(vm.variantGroupMax));
    AppendLine(out, "variant_group_functions_per_group = " +
        FormatDecimal(vm.variantGroupFunctionsPerGroup));
    out << "\n";

    // Fail-closed：CapabilityChecker 对这三个模块的 enabled=true 无条件 fatal
    // 拒绝（packer/analysis/capability_checker.cpp）。GUI 不提供开关，这里恒定
    // 写 false；其余字段保留 full_example.toml 里的真实默认值，仅用于保持
    // 配置 schema 完整、可读。
    const auto& stringDefaults = config.unavailable.stringEncryption;
    AppendLine(out, "[string_encryption]");
    AppendLine(out, "enabled = false");
    AppendLine(out, "strength = " + FormatDecimal(stringDefaults.strength));
    AppendLine(out, "mode = " + QuoteTomlString(stringDefaults.mode));
    AppendLine(out, "ascii = " + FormatBool(stringDefaults.ascii));
    AppendLine(out, "utf16 = " + FormatBool(stringDefaults.utf16));
    AppendLine(out, "resources = " + FormatBool(stringDefaults.resources));
    AppendLine(out, "clear_after_use = " + FormatBool(stringDefaults.clearAfterUse));
    out << "\n";

    const auto& importDefaults = config.unavailable.importProtection;
    AppendLine(out, "[import_protection]");
    AppendLine(out, "enabled = false");
    AppendLine(out, "strength = " + FormatDecimal(importDefaults.strength));
    out << "\n";

    const auto& sectionDefaults = config.unavailable.sectionEncryption;
    AppendLine(out, "[section_encryption]");
    AppendLine(out, "enabled = false");
    AppendLine(out, "strength = " + FormatDecimal(sectionDefaults.strength));
    AppendLine(out, "mode = " + QuoteTomlString(sectionDefaults.mode));
    out << "\n";

    // control_flow 主开关必须和子开关状态一致，否则 CapabilityChecker 会
    // fatal 拒绝（"master switch enabled but no sub-feature active" /
    // "sub-feature enabled while master switch is off"）。这里让主开关直接
    // 跟随 flattening.enabled，bogus 恒为 false，从结构上保证一致性，UI
    // 侧不需要单独暴露主开关。
    const ControlFlowOptions& cf = config.controlFlow;
    AppendLine(out, "[control_flow]");
    AppendLine(out, "enabled = " + FormatBool(cf.flatteningEnabled));
    AppendLine(out, "strength = " + FormatDecimal(cf.flatteningStrength));
    out << "\n";

    AppendLine(out, "[control_flow.flattening]");
    AppendLine(out, "enabled = " + FormatBool(cf.flatteningEnabled));
    AppendLine(out, "strength = " + FormatDecimal(cf.flatteningStrength));
    AppendLine(out, "target_functions = " + FormatStringArray(cf.flatteningTargets));
    out << "\n";

    AppendLine(out, "[control_flow.bogus]");
    AppendLine(out, "enabled = " + FormatBool(ControlFlowOptions::kBogusEnabled));
    AppendLine(out, "strength = " + FormatDecimal(ControlFlowOptions::kBogusStrength));
    out << "\n";

    const AntiDebugOptions& ad = config.antiDebug;
    AppendLine(out, "[anti_debug]");
    AppendLine(out, "timing_checks = " + FormatBool(ad.timingChecks));
    AppendLine(out, "hardware_bp_detection = " + FormatBool(ad.hardwareBpDetection));
    AppendLine(out, "software_bp_detection = " + FormatBool(ad.softwareBpDetection));
    AppendLine(out, "memory_integrity = " + FormatBool(ad.memoryIntegrity));
    AppendLine(out, "debugger_window_scan = " + FormatBool(ad.debuggerWindowScan));
    AppendLine(out, "parent_process_check = " + FormatBool(ad.parentProcessCheck));
    AppendLine(out, "thread_hiding = " + FormatBool(ad.threadHiding));
    AppendLine(out, "kernel_debugger_check = " + FormatBool(ad.kernelDebuggerCheck));
    out << "\n";

    const AntiDumpOptions& adump = config.antiDump;
    AppendLine(out, "[anti_dump]");
    AppendLine(out, "erase_pe_header = " + FormatBool(adump.erasePeHeader));
    AppendLine(out, "section_permission_guard = " + FormatBool(adump.sectionPermissionGuard));
    AppendLine(out, "nanomite_patches = " + FormatBool(adump.nanomitePatches));
    out << "\n";

    const PerformanceOptions& perf = config.performance;
    AppendLine(out, "[performance]");
    AppendLine(out, "auto_hotspot_analysis = " + FormatBool(perf.autoHotspotAnalysis));
    AppendLine(out, "max_vm_overhead_ratio = " + FormatRatio(perf.maxVmOverheadRatio));

    return out.str();
}

bool WriteConfigTomlToFile(
    const AppConfig& config, const std::wstring& path, std::wstring& error)
{
    // 用 std::filesystem::path 承接宽字符路径再交给 ofstream：
    // libstdc++（MinGW）没有 std::ofstream(std::wstring) 这个 MSVC 专属重载，
    // 但两边都支持标准的 C++17 fstream(const std::filesystem::path&)。
    // 二进制模式避免 CRLF 转换改变字节数（这里都是 ASCII/UTF-8 文本，无关
    // 字节内容，但保持写盘方式简单可预期）。
    const std::filesystem::path filePath(path);
    std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        error = L"无法创建临时配置文件";
        return false;
    }
    const std::string content = BuildConfigToml(config);
    file.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!file) {
        error = L"写入临时配置文件失败";
        return false;
    }
    return true;
}

} // namespace CipherShellGui
