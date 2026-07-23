#include "packer/config/config_parser.h"
#include "packer/gui_win32/config_model.h"
#include "packer/gui_win32/input_validation.h"
#include "packer/gui_win32/toml_writer.h"
#include "packer/path_identity.h"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

namespace {

int g_failures = 0;

void Check(bool condition, const char* message) {
    if (condition) {
        return;
    }
    std::cerr << "[失败] " << message << '\n';
    ++g_failures;
}

bool RequestsUnimplementedPlus(const CipherShell::CipherShellConfig& config) {
    return CipherShell::HasAnyAntiDebugRequest(config.antiDebug) ||
        CipherShell::HasAnyAntiDumpRequest(config.antiDump);
}

bool RequestsAnyFailClosedModule(const CipherShell::CipherShellConfig& config) {
    return RequestsUnimplementedPlus(config) ||
        config.stringEncryption.enabled ||
        config.importProtection.enabled ||
        config.sectionEncryption.enabled ||
        config.controlFlow.bogusEnabled;
}

void CheckGuiRuntimeDefaults() {
    const CipherShellGui::AppConfig defaults;

    Check(defaults.vm.targetFunctions.empty(),
        "GUI VM 运行默认目标必须为空，不能继承示例占位符");
    Check(defaults.vm.targetRVAs.empty(),
        "GUI VM 运行默认 RVA 目标必须为空");
    Check(defaults.controlFlow.flatteningTargets.empty(),
        "GUI flattening 运行默认目标必须为空，不能继承示例占位符");

    const auto& antiDebug = defaults.antiDebug;
    Check(!antiDebug.timingChecks, "GUI timing_checks 默认必须为 false");
    Check(!antiDebug.hardwareBpDetection,
        "GUI hardware_bp_detection 默认必须为 false");
    Check(!antiDebug.softwareBpDetection,
        "GUI software_bp_detection 默认必须为 false");
    Check(!antiDebug.memoryIntegrity,
        "GUI memory_integrity 默认必须为 false");
    Check(!antiDebug.debuggerWindowScan,
        "GUI debugger_window_scan 默认必须为 false");
    Check(!antiDebug.parentProcessCheck,
        "GUI parent_process_check 默认必须为 false");
    Check(!antiDebug.threadHiding,
        "GUI thread_hiding 默认必须为 false");
    Check(!antiDebug.kernelDebuggerCheck,
        "GUI kernel_debugger_check 默认必须为 false");

    const auto& antiDump = defaults.antiDump;
    Check(!antiDump.erasePeHeader,
        "GUI erase_pe_header 默认必须为 false");
    Check(!antiDump.sectionPermissionGuard,
        "GUI section_permission_guard 默认必须为 false");
    Check(!antiDump.nanomitePatches,
        "GUI nanomite_patches 默认必须为 false");
}

void CheckTargetRvaInputValidation() {
    uint32_t value = 0;
    Check(CipherShellGui::TryParseHexOrDecimalUint32(L"010", value) &&
            value == 10u,
        "无前缀 uint32 必须与生产解析器一致按十进制解释");
    Check(CipherShellGui::TryParseHexOrDecimalUint32(L"0X70000", value) &&
            value == 0x70000u,
        "uint32 输入必须接受大写 0X 十六进制前缀");
    Check(!CipherShellGui::TryParseHexOrDecimalUint32(L"12junk", value),
        "uint32 输入必须拒绝尾随字符");
    Check(!CipherShellGui::TryParseHexOrDecimalUint32(
            L"4294967296", value),
        "uint32 输入必须拒绝溢出");

    int decimal = 0;
    Check(CipherShellGui::TryParseDecimalIntInRange(
            L"64", 0, 64, decimal) && decimal == 64,
        "十进制范围解析必须接受上边界");
    Check(!CipherShellGui::TryParseDecimalIntInRange(
            L"", 0, 64, decimal),
        "十进制范围解析必须拒绝空文本，不能静默回退默认值");
    Check(!CipherShellGui::TryParseDecimalIntInRange(
            L"65", 0, 64, decimal),
        "十进制范围解析必须拒绝越界值，不能静默截断");
    Check(!CipherShellGui::TryParseDecimalIntInRange(
            L"0x10", 0, 64, decimal),
        "纯十进制字段必须拒绝十六进制文本");

    Check(CipherShellGui::TryParseTargetRva(L"1", value) && value == 1,
        "target_rvas 必须接受最小非零十进制 RVA");
    Check(CipherShellGui::TryParseTargetRva(L"0x1234", value) &&
            value == 0x1234u,
        "target_rvas 必须接受完整十六进制 RVA");
    Check(CipherShellGui::TryParseTargetRva(L"4294967295", value) &&
            value == 0xffffffffu,
        "target_rvas 必须接受 uint32_t 最大值");
    Check(CipherShellGui::TryParseTargetRva(L"010", value) && value == 10u,
        "target_rvas 的无前缀数值必须与生产解析器一致按十进制解释");

    const wchar_t* invalidValues[] = {
        L"", L"0", L"-1", L"0x", L"123junk",
        L"4294967296", L"0x100000000",
        L"18446744073709551616",
    };
    for (const wchar_t* invalid : invalidValues) {
        value = 0x12345678u;
        Check(!CipherShellGui::TryParseTargetRva(invalid, value),
            "target_rvas 必须 fail-closed 拒绝空值、零值、尾随字符与溢出");
        Check(value == 0,
            "target_rvas 解析失败时不得残留旧值");
    }
}

void CheckPathIdentityContract() {
    const std::filesystem::path sourceRoot(CS_SOURCE_ROOT);
    const auto defaultConfig =
        sourceRoot / "config" / "default.toml";
    const auto fullConfig =
        sourceRoot / "config" / "full_example.toml";
    bool same = false;
    std::string reason;
    Check(CipherShell::PathsReferToSameTarget(
            defaultConfig, defaultConfig, same, reason) && same,
        "路径身份检查必须识别同一个已存在文件");
    Check(CipherShell::PathsReferToSameTarget(
            defaultConfig, fullConfig, same, reason) && !same,
        "路径身份检查不得混淆两个不同文件");

    const auto missingViaDots =
        sourceRoot / "config" / ".." / "contract_missing.bin";
    const auto missingNormalized =
        sourceRoot / "contract_missing.bin";
    Check(CipherShell::PathsReferToSameTarget(
            missingViaDots, missingNormalized, same, reason) && same,
        "不存在叶子路径也必须通过现有父目录规范化识别同一目标");
}

void CheckTomlStringInputContract() {
    Check(CipherShellGui::IsSupportedTomlStringValue(L"verify_*"),
        "普通目标函数模式必须可写入 TOML");
    Check(!CipherShellGui::IsSupportedTomlStringValue(L"bad\"target"),
        "目标函数模式中的双引号必须被 GUI 明确拒绝");
    Check(!CipherShellGui::IsSupportedTomlStringValue(L"bad\ntarget"),
        "目标函数模式中的换行必须被 GUI 明确拒绝");

    CipherShellGui::AppConfig invalidModel;
    invalidModel.vm.targetFunctions = {"bad\"target"};
    const std::string toml =
        CipherShellGui::BuildConfigToml(invalidModel);
    Check(toml.find("bad\"target") != std::string::npos,
        "TomlWriter 不得静默删除目标函数中的不支持字符");
    CipherShell::ConfigParser parser;
    parser.LoadFromString(toml);
    Check(parser.HasError(),
        "绕过 GUI 验证的不支持字符串必须由生产解析器 fail-closed");
}

void CheckDefaultGuiRoundTrip() {
    const CipherShellGui::AppConfig guiDefaults;
    const std::string toml = CipherShellGui::BuildConfigToml(guiDefaults);

    CipherShell::ConfigParser parser;
    const CipherShell::CipherShellConfig parsed = parser.LoadFromString(toml);

    Check(!parser.HasError(),
        "GUI 默认模型经 TomlWriter 写出后必须能被 ConfigParser 接受");
    Check(parsed.global.protectionLevelSet,
        "GUI 写出的 protection_level 必须被标记为显式配置");
    Check(parsed.vm.targetFunctions.empty(),
        "GUI 默认 TOML 解析后的 VM 名称目标必须为空");
    Check(parsed.vm.targetRVAs.empty(),
        "GUI 默认 TOML 解析后的 VM RVA 目标必须为空");
    Check(parsed.controlFlow.flatteningTargets.empty(),
        "GUI 默认 TOML 解析后的 flattening 目标必须为空");
    Check(!RequestsAnyFailClosedModule(parsed),
        "GUI 默认 TOML 不得请求任何尚未闭环的 fail-closed 功能");
}

void CheckConfigParserTruthfulnessContracts() {
    {
        CipherShell::ConfigParser parser;
        const auto parsed = parser.LoadFromString(R"(
[global]
# protection_level = 1
protection_level = 5
# strip_debug_info = true
strip_debug_info = false

[vm]
# enabled = false
enabled = true
# strength = 1
strength = 73
native_body_policy = "destroy#literal"

[anti_dump]
# nanomite_patches = true
nanomite_patches = false
)");
        Check(!parser.HasError(),
            "注释去除后的合法配置必须解析成功");
        Check(parsed.global.protectionLevelSet &&
                parsed.global.protectionLevel == 5,
            "注释中的 protection_level 不得覆盖可见配置");
        Check(!parsed.global.stripDebugInfo,
            "注释中的 global 布尔值不得覆盖可见配置");
        Check(parsed.vm.enabledSet && parsed.vm.enabled,
            "注释中的 vm.enabled 不得覆盖可见配置");
        Check(parsed.vm.strength == 73,
            "注释中的 vm.strength 不得覆盖可见配置");
        Check(parsed.vm.nativeBodyPolicy == "destroy#literal",
            "引号内的 # 必须作为字符串内容保留");
        Check(!parsed.antiDump.nanomitePatches,
            "注释中的 fail-closed 开关不得被误解析为启用");
    }

    {
        CipherShell::ConfigParser parser;
        const auto parsed = parser.LoadFromString(
            "[vm]\nenabled = false\n");
        Check(!parser.HasError(),
            "省略 global.protection_level 的部分配置必须可解析");
        Check(!parsed.global.protectionLevelSet,
            "省略 protection_level 时不得伪装成显式配置，以便 CLI -l 保持生效");
    }

    {
        CipherShell::ConfigParser parser;
        const auto parsed = parser.LoadFromString(R"(
[vm]
native_body_policy = "enabled = true"
target_functions = ["strength = 1", "[[function_overrides]]"]
)");
        Check(!parser.HasError(),
            "包含键名样文本的合法字符串配置必须可解析");
        Check(!parsed.vm.enabledSet && !parsed.vm.enabled,
            "字符串中的 enabled = true 不得串线为 VM 开关");
        Check(parsed.vm.strength == 0,
            "数组字符串中的 strength = 1 不得串线为 VM strength");
        Check(parsed.vm.nativeBodyPolicy == "enabled = true",
            "native_body_policy 字符串必须原样解析");
        Check(parsed.vm.targetFunctions.size() == 2 &&
                parsed.vm.targetFunctions[0] == "strength = 1",
            "target_functions 中的键名样文本必须保留为普通目标");
        Check(parsed.vm.targetFunctions[1] == "[[function_overrides]]",
            "目标字符串中的旧 section 名不得被误判为真实 section");
    }

    {
        CipherShell::ConfigParser parser;
        parser.LoadFromString(
            "[vm]\nvariant_group_count = 999999999999999999999999\n");
        Check(parser.HasError(),
            "溢出的 variant_group_count 必须 fail-closed，不能静默变成 0 自适应");
    }

    {
        CipherShell::ConfigParser parser;
        parser.LoadFromString(
            "[vm]\nstrength = 999999999999999999999999\n");
        Check(parser.HasError(),
            "溢出的 strength 必须 fail-closed，不能静默落回 preset");
    }

    {
        CipherShell::ConfigParser parser;
        const auto parsed = parser.LoadFromString(
            "[vm]\nstack_size = 010\n");
        Check(!parser.HasError() && parsed.vm.stackSize == 10,
            "无 0x 前缀的 stack_size 必须按十进制解释");
    }
}

void CheckEditedGuiRoundTrip() {
    CipherShellGui::AppConfig edited;
    edited.cli.protectionLevel = 5;
    edited.global.stripDebugInfo = false;
    edited.global.stripRichHeader = true;
    edited.global.stripTimestamps = false;
    edited.global.randomizeSectionNames = true;

    edited.vm.enabled = true;
    edited.vm.strength = 73;
    edited.vm.targetFunctions = {"entry_*", "verify_main"};
    edited.vm.targetRVAs = {0x1234u, 0x5678u};
    edited.vm.registerCount = 28;
    edited.vm.stackSize = 0x24000u;
    edited.vm.opcodeRandomization = false;
    edited.vm.handlerMutation = true;
    edited.vm.bytecodeEncryption = false;
    edited.vm.nativeBodyPolicy = "destroy";
    edited.vm.x86CallAbi = "fastcall";
    edited.vm.embedJunkHandlers = true;
    edited.vm.simdBridge = false;
    edited.vm.x87Bridge = true;
    edited.vm.variantGroupCount = 3;
    edited.vm.variantGroupMax = 6;
    edited.vm.variantGroupFunctionsPerGroup = 2;

    edited.controlFlow.flatteningEnabled = true;
    edited.controlFlow.flatteningStrength = 67;
    edited.controlFlow.flatteningTargets = {"dispatch_*", "worker"};

    // 这些字段目前会被生产入口 fail-closed 拒绝，Win32 GUI 控件也已禁用；
    // model/schema 仍需保留既有 TOML 的兼容解析。本测试用手工构造的 model
    // 验证序列化/解析不会静默篡改已有配置。
    edited.antiDebug.timingChecks = true;
    edited.antiDebug.hardwareBpDetection = false;
    edited.antiDebug.softwareBpDetection = true;
    edited.antiDebug.memoryIntegrity = false;
    edited.antiDebug.debuggerWindowScan = true;
    edited.antiDebug.parentProcessCheck = false;
    edited.antiDebug.threadHiding = true;
    edited.antiDebug.kernelDebuggerCheck = false;
    edited.antiDump.erasePeHeader = true;
    edited.antiDump.sectionPermissionGuard = false;
    edited.antiDump.nanomitePatches = true;

    edited.performance.autoHotspotAnalysis = false;
    edited.performance.maxVmOverheadRatio = 7.125;

    CipherShell::ConfigParser parser;
    const CipherShell::CipherShellConfig parsed =
        parser.LoadFromString(CipherShellGui::BuildConfigToml(edited));

    Check(!parser.HasError(),
        "编辑后的 GUI 模型经 TomlWriter 写出后必须能被 ConfigParser 接受");
    Check(parsed.global.protectionLevel == edited.cli.protectionLevel,
        "protection_level 往返不一致");
    Check(parsed.global.stripDebugInfo == edited.global.stripDebugInfo,
        "strip_debug_info 往返不一致");
    Check(parsed.global.stripRichHeader == edited.global.stripRichHeader,
        "strip_rich_header 往返不一致");
    Check(parsed.global.stripTimestamps == edited.global.stripTimestamps,
        "strip_timestamps 往返不一致");
    Check(parsed.global.randomizeSections == edited.global.randomizeSectionNames,
        "randomize_section_names 往返不一致");

    Check(parsed.vm.enabled == edited.vm.enabled, "vm.enabled 往返不一致");
    Check(parsed.vm.strength == edited.vm.strength, "vm.strength 往返不一致");
    Check(parsed.vm.targetFunctions == edited.vm.targetFunctions,
        "vm.target_functions 往返不一致");
    Check(parsed.vm.targetRVAs == edited.vm.targetRVAs,
        "vm.target_rvas 往返不一致");
    Check(parsed.vm.registerCount == edited.vm.registerCount,
        "vm.register_count 往返不一致");
    Check(parsed.vm.stackSize == static_cast<int>(edited.vm.stackSize),
        "vm.stack_size 往返不一致");
    Check(parsed.vm.opcodeRandomization == edited.vm.opcodeRandomization,
        "vm.opcode_randomization 往返不一致");
    Check(parsed.vm.handlerMutation == edited.vm.handlerMutation,
        "vm.handler_mutation 往返不一致");
    Check(parsed.vm.bytecodeEncryption == edited.vm.bytecodeEncryption,
        "vm.bytecode_encryption 往返不一致");
    Check(parsed.vm.nativeBodyPolicy == edited.vm.nativeBodyPolicy,
        "vm.native_body_policy 往返不一致");
    Check(parsed.vm.x86CallAbi == edited.vm.x86CallAbi,
        "vm.x86_call_abi 往返不一致");
    Check(parsed.vm.embedJunkHandlers == edited.vm.embedJunkHandlers,
        "vm.embed_junk_handlers 往返不一致");
    Check(parsed.vm.simdBridge == edited.vm.simdBridge,
        "vm.simd_bridge 往返不一致");
    Check(parsed.vm.x87Bridge == edited.vm.x87Bridge,
        "vm.x87_bridge 往返不一致");
    Check(parsed.vm.variantGroupCount == edited.vm.variantGroupCount,
        "vm.variant_group_count 往返不一致");
    Check(parsed.vm.variantGroupMax == edited.vm.variantGroupMax,
        "vm.variant_group_max 往返不一致");
    Check(parsed.vm.variantGroupFunctionsPerGroup ==
            edited.vm.variantGroupFunctionsPerGroup,
        "vm.variant_group_functions_per_group 往返不一致");

    Check(parsed.controlFlow.enabled == edited.controlFlow.flatteningEnabled,
        "control_flow.enabled 必须跟随 flattening 开关");
    Check(parsed.controlFlow.flatteningEnabled ==
            edited.controlFlow.flatteningEnabled,
        "control_flow.flattening.enabled 往返不一致");
    Check(parsed.controlFlow.flatteningStrength ==
            edited.controlFlow.flatteningStrength,
        "control_flow.flattening.strength 往返不一致");
    Check(parsed.controlFlow.flatteningTargets ==
            edited.controlFlow.flatteningTargets,
        "control_flow.flattening.target_functions 往返不一致");

    Check(parsed.antiDebug.timingChecks == edited.antiDebug.timingChecks,
        "timing_checks 往返不一致");
    Check(parsed.antiDebug.hardwareBPDetection ==
            edited.antiDebug.hardwareBpDetection,
        "hardware_bp_detection 往返不一致");
    Check(parsed.antiDebug.softwareBPDetection ==
            edited.antiDebug.softwareBpDetection,
        "software_bp_detection 往返不一致");
    Check(parsed.antiDebug.memoryIntegrity == edited.antiDebug.memoryIntegrity,
        "memory_integrity 往返不一致");
    Check(parsed.antiDebug.debuggerWindowScan ==
            edited.antiDebug.debuggerWindowScan,
        "debugger_window_scan 往返不一致");
    Check(parsed.antiDebug.parentProcessCheck ==
            edited.antiDebug.parentProcessCheck,
        "parent_process_check 往返不一致");
    Check(parsed.antiDebug.threadHiding == edited.antiDebug.threadHiding,
        "thread_hiding 往返不一致");
    Check(parsed.antiDebug.kernelDebuggerCheck ==
            edited.antiDebug.kernelDebuggerCheck,
        "kernel_debugger_check 往返不一致");
    Check(parsed.antiDump.erasePEHeader == edited.antiDump.erasePeHeader,
        "erase_pe_header 往返不一致");
    Check(parsed.antiDump.sectionPermissionGuard ==
            edited.antiDump.sectionPermissionGuard,
        "section_permission_guard 往返不一致");
    Check(parsed.antiDump.nanomitePatches == edited.antiDump.nanomitePatches,
        "nanomite_patches 往返不一致");

    Check(parsed.performance.autoHotspotAnalysis ==
            edited.performance.autoHotspotAnalysis,
        "performance.auto_hotspot_analysis 往返不一致");
    Check(parsed.performance.maxVMOverheadRatio ==
            edited.performance.maxVmOverheadRatio,
        "performance.max_vm_overhead_ratio 往返不一致");
}

void CheckGlobalOneHotRoundTrips() {
    for (int enabledIndex = 0; enabledIndex < 4; ++enabledIndex) {
        CipherShellGui::AppConfig model;
        model.global.stripDebugInfo = false;
        model.global.stripRichHeader = false;
        model.global.stripTimestamps = false;
        model.global.randomizeSectionNames = false;
        switch (enabledIndex) {
        case 0: model.global.stripDebugInfo = true; break;
        case 1: model.global.stripRichHeader = true; break;
        case 2: model.global.stripTimestamps = true; break;
        case 3: model.global.randomizeSectionNames = true; break;
        default: break;
        }

        CipherShell::ConfigParser parser;
        const auto parsed =
            parser.LoadFromString(CipherShellGui::BuildConfigToml(model));
        Check(!parser.HasError(), "global one-hot TOML 解析失败");
        const bool values[] = {
            parsed.global.stripDebugInfo,
            parsed.global.stripRichHeader,
            parsed.global.stripTimestamps,
            parsed.global.randomizeSections,
        };
        for (int index = 0; index < 4; ++index) {
            Check(values[index] == (index == enabledIndex),
                "global 字段 one-hot 往返发生串线");
        }
    }
}

void CheckVmBooleanOneHotRoundTrips() {
    for (int enabledIndex = 0; enabledIndex < 7; ++enabledIndex) {
        CipherShellGui::AppConfig model;
        model.vm.enabled = false;
        model.vm.opcodeRandomization = false;
        model.vm.handlerMutation = false;
        model.vm.bytecodeEncryption = false;
        model.vm.embedJunkHandlers = false;
        model.vm.simdBridge = false;
        model.vm.x87Bridge = false;
        switch (enabledIndex) {
        case 0: model.vm.enabled = true; break;
        case 1: model.vm.opcodeRandomization = true; break;
        case 2: model.vm.handlerMutation = true; break;
        case 3: model.vm.bytecodeEncryption = true; break;
        case 4: model.vm.embedJunkHandlers = true; break;
        case 5: model.vm.simdBridge = true; break;
        case 6: model.vm.x87Bridge = true; break;
        default: break;
        }

        CipherShell::ConfigParser parser;
        const auto parsed =
            parser.LoadFromString(CipherShellGui::BuildConfigToml(model));
        Check(!parser.HasError(), "VM one-hot TOML 解析失败");
        const bool values[] = {
            parsed.vm.enabled,
            parsed.vm.opcodeRandomization,
            parsed.vm.handlerMutation,
            parsed.vm.bytecodeEncryption,
            parsed.vm.embedJunkHandlers,
            parsed.vm.simdBridge,
            parsed.vm.x87Bridge,
        };
        for (int index = 0; index < 7; ++index) {
            Check(values[index] == (index == enabledIndex),
                "VM 布尔字段 one-hot 往返发生串线");
        }
    }
}

void CheckPlusCompatibilityOneHotRoundTrips() {
    for (int enabledIndex = 0; enabledIndex < 8; ++enabledIndex) {
        CipherShellGui::AppConfig model;
        switch (enabledIndex) {
        case 0: model.antiDebug.timingChecks = true; break;
        case 1: model.antiDebug.hardwareBpDetection = true; break;
        case 2: model.antiDebug.softwareBpDetection = true; break;
        case 3: model.antiDebug.memoryIntegrity = true; break;
        case 4: model.antiDebug.debuggerWindowScan = true; break;
        case 5: model.antiDebug.parentProcessCheck = true; break;
        case 6: model.antiDebug.threadHiding = true; break;
        case 7: model.antiDebug.kernelDebuggerCheck = true; break;
        default: break;
        }

        CipherShell::ConfigParser parser;
        const auto parsed =
            parser.LoadFromString(CipherShellGui::BuildConfigToml(model));
        Check(!parser.HasError(), "anti_debug one-hot TOML 解析失败");
        const bool values[] = {
            parsed.antiDebug.timingChecks,
            parsed.antiDebug.hardwareBPDetection,
            parsed.antiDebug.softwareBPDetection,
            parsed.antiDebug.memoryIntegrity,
            parsed.antiDebug.debuggerWindowScan,
            parsed.antiDebug.parentProcessCheck,
            parsed.antiDebug.threadHiding,
            parsed.antiDebug.kernelDebuggerCheck,
        };
        for (int index = 0; index < 8; ++index) {
            Check(values[index] == (index == enabledIndex),
                "anti_debug 字段 one-hot 往返发生串线");
        }
    }

    for (int enabledIndex = 0; enabledIndex < 3; ++enabledIndex) {
        CipherShellGui::AppConfig model;
        switch (enabledIndex) {
        case 0: model.antiDump.erasePeHeader = true; break;
        case 1: model.antiDump.sectionPermissionGuard = true; break;
        case 2: model.antiDump.nanomitePatches = true; break;
        default: break;
        }

        CipherShell::ConfigParser parser;
        const auto parsed =
            parser.LoadFromString(CipherShellGui::BuildConfigToml(model));
        Check(!parser.HasError(), "anti_dump one-hot TOML 解析失败");
        const bool values[] = {
            parsed.antiDump.erasePEHeader,
            parsed.antiDump.sectionPermissionGuard,
            parsed.antiDump.nanomitePatches,
        };
        for (int index = 0; index < 3; ++index) {
            Check(values[index] == (index == enabledIndex),
                "anti_dump 字段 one-hot 往返发生串线");
        }
    }
}

void CheckGeneratedDefaultConfig() {
    const std::filesystem::path path =
        std::filesystem::current_path() /
        "test_gui_config_contract.generated.toml";
    std::error_code cleanupError;
    std::filesystem::remove(path, cleanupError);

    CipherShell::ConfigParser generator;
    const bool generated = generator.GenerateDefaultConfig(path.string());
    Check(generated, "GenerateDefaultConfig 必须成功创建默认配置");

    if (generated) {
        CipherShell::ConfigParser parser;
        const CipherShell::CipherShellConfig parsed =
            parser.LoadFromFile(path.string());
        Check(!parser.HasError(),
            "GenerateDefaultConfig 产物必须能被 ConfigParser 重新解析");
        Check(!RequestsAnyFailClosedModule(parsed),
            "生成的默认配置不得请求任何尚未完成的 fail-closed 模块");
        Check(parsed.vm.targetFunctions.empty(),
            "生成的默认配置 VM 目标必须为空");
        Check(parsed.vm.targetRVAs.empty(),
            "生成的默认配置 VM RVA 目标必须为空");
        Check(parsed.controlFlow.flatteningTargets.empty(),
            "生成的默认配置 flattening 目标必须为空");
    }

    cleanupError.clear();
    std::filesystem::remove(path, cleanupError);
    Check(!cleanupError, "默认配置测试临时文件清理失败");
}

void CheckCheckedInConfigs() {
    const std::filesystem::path sourceRoot(CS_SOURCE_ROOT);
    const std::filesystem::path configPaths[] = {
        sourceRoot / "config" / "default.toml",
        sourceRoot / "config" / "full_example.toml",
    };

    for (const auto& path : configPaths) {
        CipherShell::ConfigParser parser;
        const CipherShell::CipherShellConfig parsed =
            parser.LoadFromFile(path.string());
        Check(!parser.HasError(),
            "仓库内置配置必须能被生产 ConfigParser 接受");
        Check(!RequestsAnyFailClosedModule(parsed),
            "仓库内置配置不得默认请求任何 fail-closed 模块");
        Check(parsed.vm.targetFunctions.empty(),
            "仓库内置配置不得硬编码 VM 样例函数名");
        Check(parsed.vm.targetRVAs.empty(),
            "仓库内置配置不得硬编码 VM 样例 RVA");
        Check(parsed.controlFlow.flatteningTargets.empty(),
            "仓库内置配置不得硬编码 flattening 样例函数名");
    }
}

} // namespace

int main() {
    CheckGuiRuntimeDefaults();
    CheckTargetRvaInputValidation();
    CheckPathIdentityContract();
    CheckTomlStringInputContract();
    CheckDefaultGuiRoundTrip();
    CheckConfigParserTruthfulnessContracts();
    CheckEditedGuiRoundTrip();
    CheckGlobalOneHotRoundTrips();
    CheckVmBooleanOneHotRoundTrips();
    CheckPlusCompatibilityOneHotRoundTrips();
    CheckGeneratedDefaultConfig();
    CheckCheckedInConfigs();

    if (g_failures != 0) {
        std::cerr << "GUI 配置契约测试失败，共 " << g_failures << " 项\n";
        return 1;
    }
    std::cout << "GUI 配置契约测试通过\n";
    return 0;
}
