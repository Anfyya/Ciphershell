// CipherShell GUI - 配置数据模型
//
// 这里的字段与默认值直接镜像 packer/config/config_parser.h 里的
// CipherShellConfig 系列结构体，以及 config/full_example.toml 给出的真实
// 生产配置样例。GUI 进程不链接 ciphershell_packer，所以这里是一份独立的
// 数据模型，但字段集合、取值范围、默认值都必须和后端 schema 一一对应——
// 新增/删减字段时，请同时核对 packer/cli_options.h、
// packer/config/config_parser.h、config/full_example.toml 三处是否一致。
//
// string_encryption / import_protection / section_encryption 以及
// control_flow.bogus 这几个开关在当前后端里是 fail-closed：显式启用会被
// CapabilityChecker 在任何 PE 改动之前 fatal 拒绝（见
// packer/analysis/capability_checker.cpp）。本模型仍保留这些字段（配合
// UI 上以只读方式展示真实默认值），但没有对应的“启用”状态可写，写出的
// TOML 里这些模块永远是 enabled = false。
//
// control_flow.flattening 不在上面这份 fail-closed 名单里：它有独立的本地
// 代码/重定位/unwind/入口修补闭环（CapabilityChecker::CheckImage 不会无条件
// 拒绝它，只有 control_flow.bogus 和主开关/子开关不一致时才会拒绝），所以
// 作为一个真实可用、但目标函数必须满足静态安全条件的进阶功能暴露出来。

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace CipherShellGui {

// 对应 cli_options.h 里的 CommandLineOptions（不含 inputFile/outputFile，
// 那两个由 AppState 里的路径字段单独持有，方便和文件对话框/拖放对接）。
struct CliOptions {
    int protectionLevel = 4;        // -l/--level，1-5；full_example.toml 的示例值。
    bool verbose = false;           // -v/--verbose
    bool exportVmHandlerEvidence = false;
    std::wstring vmHandlerEvidencePath;  // --vm-handler-evidence <文件>
};

// 对应 config_parser.h::GlobalConfig（仅暴露 ValidateProductionSyntax 真正
// 接受的 [global] 字段：protection_level 走 CliOptions.protectionLevel，
// 不在这里重复）。
struct GlobalOptions {
    bool stripDebugInfo = true;
    bool stripRichHeader = true;
    bool stripTimestamps = true;
    bool randomizeSectionNames = true;
};

// 对应 config_parser.h::VMConfig，字段与默认值取自 config/full_example.toml
// 的 [vm] 段。
struct VmOptions {
    bool enabled = true;
    int strength = 90;                          // 1-100
    std::vector<std::string> targetFunctions = {"license_*", "verify_*"};
    std::vector<uint32_t> targetRVAs;            // 空 = 不按 RVA 精确选择
    int registerCount = 24;                      // 后端 ValidateVMRegisterMap 强制 16-32
    uint32_t stackSize = 0x20000;                // 后端强制 0x4000-0x70000 且按 0x1000 对齐
    bool opcodeRandomization = true;
    bool handlerMutation = true;
    bool bytecodeEncryption = true;
    std::string nativeBodyPolicy = "destroy";    // main.cpp 目前只接受 "destroy"
    std::string x86CallAbi = "auto";             // auto|cdecl|stdcall|fastcall|thiscall
    bool embedJunkHandlers = true;
    bool simdBridge = true;
    bool x87Bridge = true;
    int variantGroupCount = 0;                   // 0 = 自适应
    int variantGroupMax = 4;
    int variantGroupFunctionsPerGroup = 4;
};

// 对应 config_parser.h::ControlFlowConfigFile。
// 只暴露 flattening（真实可用）；bogus 固定为 false，仅用于只读展示。
struct ControlFlowOptions {
    bool flatteningEnabled = false;              // full_example.toml 默认关闭，非任何等级预设的一部分
    int flatteningStrength = 60;
    std::vector<std::string> flatteningTargets = {"license_*"};

    // 只读展示用；CapabilityChecker 无条件拒绝 bogus.enabled=true。
    static constexpr bool kBogusEnabled = false;
    static constexpr int kBogusStrength = 50;
};

// 对应 config_parser.h::AntiDebugConfigFile，全部字段真实可调。
struct AntiDebugOptions {
    bool timingChecks = true;
    bool hardwareBpDetection = true;
    bool softwareBpDetection = true;
    bool memoryIntegrity = true;
    bool debuggerWindowScan = false;
    bool parentProcessCheck = true;
    bool threadHiding = true;
    bool kernelDebuggerCheck = true;
};

// 对应 config_parser.h::AntiDumpConfig。
struct AntiDumpOptions {
    bool erasePeHeader = true;
    bool sectionPermissionGuard = true;
    bool nanomitePatches = true;
};

// 对应 config_parser.h::PerformanceConfig。
struct PerformanceOptions {
    bool autoHotspotAnalysis = true;
    double maxVmOverheadRatio = 15.0;
};

// 只读展示：string_encryption / import_protection / section_encryption 的
// 真实默认字段值（取自 config/full_example.toml），用于在“当前不可用模块”
// 页面里如实显示 schema，而不是让用户凭空猜。enabled 恒为 false。
struct UnavailableModuleDefaults {
    struct {
        int strength = 80;
        std::string mode = "startup";
        bool ascii = true;
        bool utf16 = true;
        bool resources = false;
        bool clearAfterUse = false;
    } stringEncryption;

    struct {
        int strength = 60;
    } importProtection;

    struct {
        int strength = 70;
        std::string mode = "startup";
    } sectionEncryption;
};

struct AppConfig {
    CliOptions cli;
    GlobalOptions global;
    VmOptions vm;
    ControlFlowOptions controlFlow;
    AntiDebugOptions antiDebug;
    AntiDumpOptions antiDump;
    PerformanceOptions performance;
    UnavailableModuleDefaults unavailable;  // 只读展示用，不写入 TOML 的可变部分
};

} // namespace CipherShellGui
