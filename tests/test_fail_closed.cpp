// CipherShell fail-closed 基线测试
//
// 本文件通过 ctest 实际运行（见 tests/CMakeLists.txt 的 fail_closed_baseline）。
// 覆盖：
//   A. 默认配置不隐式启用高开销模块；显式启用已闭环的 flattening
//      可通过 image 级能力检查，bogus/import/section/string 仍在任何 PE
//      修改之前 fatal 拒绝；controlFlow 主/子开关保持一致。
//   SignatureEliminator 保持只读数据段权限不变（NormalizePermissions 已移除）。
//
// 约束：本测试不运行任何生成的 EXE，仅静态断言。

#include "../packer/config/config_parser.h"
#include "../packer/config/protection_build_context.h"
#include "../packer/analysis/capability_checker.h"
#include "../packer/signature/signature_eliminator.h"
#include "../packer/pe_parser/pe_parser.h"
#include "../packer/pe_parser/pe_rebuilder.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <string>

// Release 构建会定义 NDEBUG，标准 assert 会被编译为空，导致测试表达式不执行、
// 局部变量“未引用”。使用始终求值的自定义检查宏。
#define CS_TEST_CHECK(cond) do { if (!(cond)) std::abort(); } while (0)

namespace {

// 构造一个最小合法 PE32/PE32+：DOS + NT + 一个 .text section。
// signatureMetadata 为 true 时额外放入可验证的
// Rich/Debug/timestamp/checksum 元数据。
// 返回的 image 拥有 buffer 所有权，调用方负责 FreeImage。
CipherShell::CS_PE_IMAGE* BuildMinimalImage(bool cetCompatible = false,
        bool signatureMetadata = false, bool is64Bit = true,
        DWORD richMarkerOffset = 0x90u) {
    const DWORD kSize = signatureMetadata ? 0x800u : 0x400u;
    const size_t kNtOffset = signatureMetadata ? 0x100u : 0x40u;
    const DWORD kSectionRawOffset = signatureMetadata ? 0x400u : 0x200u;
    // Signature、FileHeader 与架构对应的 OptionalHeader 必须背靠背；错误
    // 的固定偏移会让 PE32/PE32+ 其中一支静默覆盖后续字段。
    const size_t kFileHeaderOffset = kNtOffset + sizeof(DWORD);
    const size_t kOptionalHeaderOffset =
        kFileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    BYTE* buf = new BYTE[kSize];
    std::memset(buf, 0, kSize);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(kNtOffset);

    std::memcpy(buf + kNtOffset, "PE\0\0", 4);

    auto* fh = reinterpret_cast<IMAGE_FILE_HEADER*>(buf + kFileHeaderOffset);
    fh->Machine = is64Bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = static_cast<WORD>(is64Bit
        ? sizeof(IMAGE_OPTIONAL_HEADER64)
        : sizeof(IMAGE_OPTIONAL_HEADER32));
    if (signatureMetadata) {
        fh->TimeDateStamp = 0x5F3759DFu;
    }

    if (is64Bit) {
        auto* oh = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
            buf + kOptionalHeaderOffset);
        oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        oh->FileAlignment = 0x200;
        oh->SectionAlignment = 0x1000;
        oh->SizeOfHeaders = kSectionRawOffset;
        oh->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh->ImageBase = 0x140000000ULL;
        oh->AddressOfEntryPoint = 0x1000;
        oh->SizeOfImage = 0x2000;
        if (signatureMetadata) {
            oh->CheckSum = 0x12345678u;
        }
        if (cetCompatible || signatureMetadata) {
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0x1020;
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
                static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));
        }
    } else {
        auto* oh = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
            buf + kOptionalHeaderOffset);
        oh->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        oh->FileAlignment = 0x200;
        oh->SectionAlignment = 0x1000;
        oh->SizeOfHeaders = kSectionRawOffset;
        oh->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh->ImageBase = 0x00400000u;
        oh->AddressOfEntryPoint = 0x1000;
        oh->SizeOfImage = 0x2000;
        if (signatureMetadata) {
            oh->CheckSum = 0x12345678u;
        }
        if (cetCompatible || signatureMetadata) {
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0x1020;
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
                static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));
        }
    }
    if (signatureMetadata) {
        CS_TEST_CHECK(richMarkerOffset >= sizeof(IMAGE_DOS_HEADER));
        CS_TEST_CHECK(richMarkerOffset + sizeof(DWORD) <= kNtOffset);
        std::memcpy(buf + richMarkerOffset, "Rich", 4);
    }

    const size_t secOff = kOptionalHeaderOffset + fh->SizeOfOptionalHeader;
    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(buf + secOff);
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x10;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = kSectionRawOffset;
    sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    if (cetCompatible || signatureMetadata) {
        constexpr DWORD kExtendedDllCharacteristicsType = 20u;
        auto* debug = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
            buf + kSectionRawOffset + 0x20);
        debug->Type = cetCompatible
            ? kExtendedDllCharacteristicsType
            : IMAGE_DEBUG_TYPE_CODEVIEW;
        debug->SizeOfData = static_cast<DWORD>(sizeof(WORD));
        debug->AddressOfRawData = 0x1040;
        debug->PointerToRawData = kSectionRawOffset + 0x40;
        const WORD extendedCharacteristics = cetCompatible ? 0x0001u : 0x4242u;
        std::memcpy(buf + debug->PointerToRawData,
            &extendedCharacteristics, sizeof(extendedCharacteristics));
    }

    CipherShell::PEParser parser;
    return parser.LoadFromBuffer(buf, kSize);
}

IMAGE_FILE_HEADER& FileHeader(CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->FileHeader
        : image->ntHeaders32->FileHeader;
}

DWORD& ImageChecksum(CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.CheckSum
        : image->ntHeaders32->OptionalHeader.CheckSum;
}

IMAGE_DATA_DIRECTORY& DebugDirectory(CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
        : image->ntHeaders32->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
}

DWORD& NumberOfRvaAndSizes(CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.NumberOfRvaAndSizes
        : image->ntHeaders32->OptionalHeader.NumberOfRvaAndSizes;
}

bool ContextHasFatal(const CipherShell::CapabilityReport& report, const std::string& module) {
    for (const auto& issue : report.issues) {
        if (issue.fatal && (module.empty() || issue.module == module)) return true;
    }
    return false;
}

void TestDefaultConfigDisablesDangerousFeatures() {
    CipherShell::ConfigParser parser;
    // 空配置 → 全部默认值。
    CipherShell::CipherShellConfig config = parser.LoadFromString("");
    CS_TEST_CHECK(!parser.HasError());

    CipherShell::ProtectionBuildContext ctx =
        CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    // preset 绝不隐式开启以下模块。
    CS_TEST_CHECK(!ctx.sectionEncryption.enabled);
    CS_TEST_CHECK(!ctx.stringEncryption.enabled);
    CS_TEST_CHECK(!ctx.importProtection.enabled);
    CS_TEST_CHECK(!ctx.controlFlow.enabled);
    CS_TEST_CHECK(!ctx.flattening.enabled);
    CS_TEST_CHECK(!ctx.bogusFlow.enabled);
}

void TestProtectionLevelPrecedenceUsesExplicitSetState() {
    CipherShell::ConfigParser parser;
    const auto implicitConfig =
        parser.LoadFromString("[vm]\ntarget_functions = []\n");
    CS_TEST_CHECK(!parser.HasError());
    CS_TEST_CHECK(!implicitConfig.global.protectionLevelSet);
    const auto cliLevelContext =
        CipherShell::ProtectionBuildContext::FromConfig(
            implicitConfig, 4, false);
    CS_TEST_CHECK(cliLevelContext.quickLevel == 4);
    CS_TEST_CHECK(cliLevelContext.vm.enabled);

    const auto explicitConfig = parser.LoadFromString(
        "[global]\nprotection_level = 2\n");
    CS_TEST_CHECK(!parser.HasError());
    CS_TEST_CHECK(explicitConfig.global.protectionLevelSet);
    const auto configLevelContext =
        CipherShell::ProtectionBuildContext::FromConfig(
            explicitConfig, 5, false);
    CS_TEST_CHECK(configLevelContext.quickLevel == 2);
    CS_TEST_CHECK(!configLevelContext.vm.enabled);
}

void TestExplicitFlatteningAcceptedAtImageGate() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString(
        "[control_flow]\nenabled = true\n"
        "[control_flow.flattening]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.flattening.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    auto report = checker.CheckImage(image, ctx);
    CS_TEST_CHECK(report.ok);
    CS_TEST_CHECK(!ContextHasFatal(report, "ControlFlow"));
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestCetFlatteningRejectedBeforeMutation() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString(
        "[control_flow]\nenabled = true\n"
        "[control_flow.flattening]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);

    auto* image = BuildMinimalImage(true);
    CS_TEST_CHECK(image && image->isValid && image->debugDir.hasCetCompat);
    CipherShell::CapabilityChecker checker;
    const auto report = checker.CheckImage(image, ctx);
    CS_TEST_CHECK(!report.ok);
    CS_TEST_CHECK(ContextHasFatal(report, "ControlFlow"));
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestExplicitBogusRejected() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString("[control_flow.bogus]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.bogusFlow.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    CS_TEST_CHECK(!checker.CheckImage(image, ctx).ok);
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestExplicitImportProtectionRejected() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString("[import_protection]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.importProtection.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    auto report = checker.CheckImage(image, ctx);
    CS_TEST_CHECK(!report.ok);
    CS_TEST_CHECK(ContextHasFatal(report, "ImportProtection"));
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestExplicitSectionEncryptionRejected() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString("[section_encryption]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.sectionEncryption.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    auto report = checker.CheckImage(image, ctx);
    CS_TEST_CHECK(!report.ok);
    CS_TEST_CHECK(ContextHasFatal(report, "SectionEncryption"));
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestExplicitStringEncryptionRejected() {
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString("[string_encryption]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.stringEncryption.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    auto report = checker.CheckImage(image, ctx);
    CS_TEST_CHECK(!report.ok);
    CS_TEST_CHECK(ContextHasFatal(report, "StringEncryption"));
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestControlFlowMasterNoopRejected() {
    // 总开关开启但无子功能 → no-op，被 fatal 拒绝。
    CipherShell::ConfigParser parser;
    auto config = parser.LoadFromString("[control_flow]\nenabled = true\n");
    CS_TEST_CHECK(!parser.HasError());
    auto ctx = CipherShell::ProtectionBuildContext::FromConfig(config, 1, false);
    CS_TEST_CHECK(ctx.controlFlow.enabled);
    CS_TEST_CHECK(!ctx.flattening.enabled && !ctx.bogusFlow.enabled);

    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    CipherShell::CapabilityChecker checker;
    CS_TEST_CHECK(!checker.CheckImage(image, ctx).ok);
    CipherShell::PEParser parser2;
    parser2.FreeImage(image);
}

void TestSignatureEliminatorKeepsReadOnlyPermissions() {
    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    const DWORD before = image->sections[0].Characteristics;

    CipherShell::SignatureEliminator elim;
    CipherShell::EliminationConfig ec;
    std::string elimReason;
    bool ok = elim.EliminateSignatures(image, ec, elimReason);
    CS_TEST_CHECK(ok);

    // NormalizePermissions 已移除：只读可执行段权限必须保持不变。
    CS_TEST_CHECK(image->sections[0].Characteristics == before);
    // 不应被擅自加上 WRITE。
    CS_TEST_CHECK((image->sections[0].Characteristics & IMAGE_SCN_MEM_WRITE) == 0);

    CipherShell::PEParser parser;
    parser.FreeImage(image);
}

void DisableGlobalSignatureControls(CipherShell::EliminationConfig& config) {
    config.randomizeSectionNames = false;
    config.randomizeTimestamps = false;
    config.clearRichHeader = false;
    config.clearDebugDirectory = false;
}

void TestSignatureEliminatorHonorsEnabledGlobalControls() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, true, is64Bit);
        CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);
        CS_TEST_CHECK((image->is64Bit != FALSE) == is64Bit);
        const DWORD beforePermissions = image->sections[0].Characteristics;
        BYTE beforeName[8] = {};
        std::memcpy(beforeName, image->sections[0].Name, sizeof(beforeName));

        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationConfig config;
        CipherShell::EliminationState beforeState;
        CipherShell::EliminationState afterState;
        std::string reason;
        CS_TEST_CHECK(eliminator.CaptureState(
            image, beforeState, reason));
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(reason.empty());
        CS_TEST_CHECK(eliminator.VerifyTransition(
            beforeState, image, config, afterState, reason));
        CS_TEST_CHECK(reason.empty());

        CS_TEST_CHECK(std::memcmp(beforeName, image->sections[0].Name,
            sizeof(beforeName)) != 0);
        for (BYTE value : image->sections[0].Name) {
            CS_TEST_CHECK(value >= static_cast<BYTE>('a') &&
                value <= static_cast<BYTE>('z'));
        }
        CS_TEST_CHECK(!image->hasRichHeader);
        DWORD richMarker = 1;
        std::memcpy(&richMarker, image->rawData + 0x90, sizeof(richMarker));
        CS_TEST_CHECK(richMarker == 0);
        const auto& debugDirectory = DebugDirectory(image);
        CS_TEST_CHECK(debugDirectory.VirtualAddress == 0 &&
            debugDirectory.Size == 0);
        CS_TEST_CHECK(FileHeader(image).TimeDateStamp == 0);
        CS_TEST_CHECK(ImageChecksum(image) == 0);
        CS_TEST_CHECK(image->sections[0].Characteristics == beforePermissions);

        // strip_debug_info 的精确契约只移除目录引用，不擦除失去引用的载荷。
        WORD residualDebugPayload = 0;
        std::memcpy(&residualDebugPayload, image->rawData + 0x440,
            sizeof(residualDebugPayload));
        CS_TEST_CHECK(residualDebugPayload == 0x4242u);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestSignatureEliminatorPreservesDisabledGlobalControls() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, true, is64Bit);
        CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);

        BYTE beforeName[8] = {};
        std::memcpy(beforeName, image->sections[0].Name, sizeof(beforeName));
        const DWORD beforeTimestamp = FileHeader(image).TimeDateStamp;
        const IMAGE_DATA_DIRECTORY beforeDebug = DebugDirectory(image);
        DWORD beforeRichMarker = 0;
        std::memcpy(&beforeRichMarker, image->rawData + 0x90,
            sizeof(beforeRichMarker));
        CS_TEST_CHECK(ImageChecksum(image) != 0);

        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationConfig config;
        DisableGlobalSignatureControls(config);
        CipherShell::EliminationState beforeState;
        CipherShell::EliminationState afterState;
        std::string reason;
        CS_TEST_CHECK(eliminator.CaptureState(
            image, beforeState, reason));
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(eliminator.VerifyTransition(
            beforeState, image, config, afterState, reason));

        CS_TEST_CHECK(std::memcmp(beforeName, image->sections[0].Name,
            sizeof(beforeName)) == 0);
        CS_TEST_CHECK(image->hasRichHeader);
        DWORD afterRichMarker = 0;
        std::memcpy(&afterRichMarker, image->rawData + 0x90,
            sizeof(afterRichMarker));
        CS_TEST_CHECK(afterRichMarker == beforeRichMarker);
        const auto& afterDebug = DebugDirectory(image);
        CS_TEST_CHECK(afterDebug.VirtualAddress == beforeDebug.VirtualAddress);
        CS_TEST_CHECK(afterDebug.Size == beforeDebug.Size);
        CS_TEST_CHECK(FileHeader(image).TimeDateStamp == beforeTimestamp);

        // Checksum 没有 global/UI 开关；保持现有强制输出卫生策略。
        CS_TEST_CHECK(ImageChecksum(image) == 0);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestConfiguredSignatureVerifierIgnoresUnrequestedMatches() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, true, is64Bit);
        CS_TEST_CHECK(image && image->isValid);
        std::memset(image->sections[0].Name, 0, sizeof(image->sections[0].Name));
        std::memcpy(image->sections[0].Name, "UPX0", 4);
        BYTE* entry = image->rawData + image->sections[0].PointerToRawData;
        entry[0] = 0x60;
        entry[1] = 0x89;
        entry[2] = 0xE5;

        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationConfig config;
        DisableGlobalSignatureControls(config);
        config.randomizeTimestamps = true;
        std::string reason;
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));

        // 旧的全镜像检测会看到 UPX/通用入口特征；按配置 verifier 只验证
        // 本次请求的 timestamp 与强制 checksum，不能误拒绝未请求项。
        CS_TEST_CHECK(!eliminator.VerifyElimination(image));
        CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(image->hasRichHeader);
        CS_TEST_CHECK(DebugDirectory(image).VirtualAddress != 0);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestConfiguredSignatureVerifierRejectsBrokenPostconditions() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, true, is64Bit);
        CS_TEST_CHECK(image && image->isValid);

        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationConfig config;
        std::string reason;
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));

        BYTE randomizedName[8] = {};
        std::memcpy(randomizedName, image->sections[0].Name,
            sizeof(randomizedName));
        std::memset(image->sections[0].Name, 0,
            sizeof(image->sections[0].Name));
        std::memcpy(image->sections[0].Name, ".rsrcX", 6);
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "section_name_not_randomized index=0");
        std::memcpy(image->sections[0].Name, randomizedName,
            sizeof(randomizedName));

        std::memcpy(image->rawData + 0x90, "Rich", 4);
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "rich_header_marker_present");
        std::memset(image->rawData + 0x90, 0, 4);

        auto& debugDirectory = DebugDirectory(image);
        debugDirectory.VirtualAddress = 0x1020;
        debugDirectory.Size = sizeof(IMAGE_DEBUG_DIRECTORY);
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "debug_directory_present");
        debugDirectory.VirtualAddress = 0;
        debugDirectory.Size = 0;

        FileHeader(image).TimeDateStamp = 1;
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "timestamp_not_cleared");
        FileHeader(image).TimeDateStamp = 0;

        ImageChecksum(image) = 1;
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "checksum_not_cleared");

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestGlobalConfigMapsOneHotToEliminationPolicy() {
    for (int enabledIndex = 0; enabledIndex < 4; ++enabledIndex) {
        CipherShell::GlobalConfig global;
        global.stripDebugInfo = false;
        global.stripRichHeader = false;
        global.stripTimestamps = false;
        global.randomizeSections = false;
        switch (enabledIndex) {
        case 0: global.stripDebugInfo = true; break;
        case 1: global.stripRichHeader = true; break;
        case 2: global.stripTimestamps = true; break;
        case 3: global.randomizeSections = true; break;
        default: std::abort();
        }

        const CipherShell::EliminationConfig mapped =
            CipherShell::BuildEliminationConfig(global);
        CS_TEST_CHECK(mapped.clearDebugDirectory == (enabledIndex == 0));
        CS_TEST_CHECK(mapped.clearRichHeader == (enabledIndex == 1));
        CS_TEST_CHECK(mapped.randomizeTimestamps == (enabledIndex == 2));
        CS_TEST_CHECK(mapped.randomizeSectionNames == (enabledIndex == 3));
        CS_TEST_CHECK(mapped.clearChecksum);
        CS_TEST_CHECK(!mapped.randomizeFileAlignment);
        CS_TEST_CHECK(!mapped.randomizeSectionAlignment);
        CS_TEST_CHECK(!mapped.addFakeImports);
        CS_TEST_CHECK(!mapped.addFakeResources);
    }
}

void TestPlusRequestsReachFailClosedDetectors() {
    const char* antiDebugKeys[] = {
        "timing_checks",
        "hardware_bp_detection",
        "software_bp_detection",
        "memory_integrity",
        "debugger_window_scan",
        "parent_process_check",
        "thread_hiding",
        "kernel_debugger_check",
    };
    for (const char* key : antiDebugKeys) {
        CipherShell::ConfigParser parser;
        const auto config = parser.LoadFromString(
            std::string("[anti_debug]\n") + key + " = true\n");
        CS_TEST_CHECK(!parser.HasError());
        CS_TEST_CHECK(CipherShell::HasAnyAntiDebugRequest(config.antiDebug));
        CS_TEST_CHECK(!CipherShell::HasAnyAntiDumpRequest(config.antiDump));
    }

    const char* antiDumpKeys[] = {
        "erase_pe_header",
        "section_permission_guard",
        "nanomite_patches",
    };
    for (const char* key : antiDumpKeys) {
        CipherShell::ConfigParser parser;
        const auto config = parser.LoadFromString(
            std::string("[anti_dump]\n") + key + " = true\n");
        CS_TEST_CHECK(!parser.HasError());
        CS_TEST_CHECK(!CipherShell::HasAnyAntiDebugRequest(config.antiDebug));
        CS_TEST_CHECK(CipherShell::HasAnyAntiDumpRequest(config.antiDump));
    }
}

void TestUnsupportedEliminationOptionsFailClosed() {
    using OptionMember = bool CipherShell::EliminationConfig::*;
    const OptionMember unsupportedOptions[] = {
        &CipherShell::EliminationConfig::randomizeFileAlignment,
        &CipherShell::EliminationConfig::randomizeSectionAlignment,
        &CipherShell::EliminationConfig::addFakeImports,
        &CipherShell::EliminationConfig::addFakeResources,
    };

    for (const OptionMember option : unsupportedOptions) {
        auto* image = BuildMinimalImage();
        CS_TEST_CHECK(image && image->isValid);
        CipherShell::EliminationConfig config;
        DisableGlobalSignatureControls(config);
        config.clearChecksum = false;
        config.*option = true;

        CipherShell::SignatureEliminator eliminator;
        std::string reason;
        CS_TEST_CHECK(!eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(reason == "unsupported_elimination_option_enabled");

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestMalformedRichHeaderFailsClosed() {
    auto* image = BuildMinimalImage(false, true);
    CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);
    image->dosHeader->e_lfanew =
        static_cast<LONG>(sizeof(IMAGE_DOS_HEADER));

    CipherShell::EliminationConfig config;
    DisableGlobalSignatureControls(config);
    config.clearChecksum = false;
    config.clearRichHeader = true;

    CipherShell::SignatureEliminator eliminator;
    std::string reason;
    CS_TEST_CHECK(!eliminator.EliminateSignatures(image, config, reason));
    CS_TEST_CHECK(reason == "clear_rich_header_failed");

    CipherShell::PEParser parser;
    parser.FreeImage(image);
}

void TestEarlyRichHeaderUsesParserAlignedClearRange() {
    constexpr DWORD kEarlyRichOffset = 0x70u;
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(
            false, true, is64Bit, kEarlyRichOffset);
        CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);

        CipherShell::EliminationConfig config;
        DisableGlobalSignatureControls(config);
        config.clearRichHeader = true;
        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationState beforeState;
        CipherShell::EliminationState afterState;
        std::string reason;
        CS_TEST_CHECK(eliminator.CaptureState(
            image, beforeState, reason));
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(eliminator.VerifyTransition(
            beforeState, image, config, afterState, reason));
        DWORD marker = 1;
        std::memcpy(&marker, image->rawData + kEarlyRichOffset,
            sizeof(marker));
        CS_TEST_CHECK(marker == 0);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestRichVerifierAcceptsEmptyRangeAndRejectsOutOfBounds() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, false, is64Bit);
        CS_TEST_CHECK(image && image->isValid && !image->hasRichHeader);
        CS_TEST_CHECK(image->dosHeader->e_lfanew ==
            static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)));

        CipherShell::EliminationConfig config;
        DisableGlobalSignatureControls(config);
        config.clearRichHeader = true;
        CipherShell::SignatureEliminator eliminator;
        std::string reason;
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));

        image->dosHeader->e_lfanew =
            static_cast<LONG>(image->rawSize + 1u);
        CS_TEST_CHECK(!eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(reason == "rich_header_bounds_invalid");

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestExactResourceAndRelocationNamesAreTheOnlyPreservedNames() {
    for (const char* preservedName : {".rsrc", ".reloc"}) {
        auto* image = BuildMinimalImage();
        CS_TEST_CHECK(image && image->isValid);
        std::memset(image->sections[0].Name, 0,
            sizeof(image->sections[0].Name));
        std::memcpy(image->sections[0].Name, preservedName,
            std::strlen(preservedName));

        CipherShell::SignatureEliminator eliminator;
        CipherShell::EliminationConfig config;
        config.clearRichHeader = false;
        config.clearDebugDirectory = false;
        config.randomizeTimestamps = false;
        std::string reason;
        CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
        CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));
        CS_TEST_CHECK(std::memcmp(image->sections[0].Name, preservedName,
            std::strlen(preservedName)) == 0);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestExactStateRejectsNoOpAndFinalSectionSubstitution() {
    auto* image = BuildMinimalImage();
    CS_TEST_CHECK(image && image->isValid);
    const BYTE lowercaseInput[IMAGE_SIZEOF_SHORT_NAME] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    std::memcpy(image->sections[0].Name, lowercaseInput,
        sizeof(lowercaseInput));

    CipherShell::SignatureEliminator eliminator;
    CipherShell::EliminationConfig config;
    DisableGlobalSignatureControls(config);
    config.randomizeSectionNames = true;
    config.clearChecksum = false;
    CipherShell::EliminationState beforeState;
    CipherShell::EliminationState verifiedState;
    std::string reason;
    CS_TEST_CHECK(eliminator.CaptureState(image, beforeState, reason));
    CS_TEST_CHECK(!eliminator.VerifyTransition(
        beforeState, image, config, verifiedState, reason));
    CS_TEST_CHECK(reason == "section_name_not_changed index=0");
    CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
    CS_TEST_CHECK(eliminator.VerifyTransition(
        beforeState, image, config, verifiedState, reason));
    CS_TEST_CHECK(std::memcmp(image->sections[0].Name, lowercaseInput,
        sizeof(lowercaseInput)) != 0);

    BYTE verifiedName[IMAGE_SIZEOF_SHORT_NAME] = {};
    std::memcpy(verifiedName, image->sections[0].Name,
        sizeof(verifiedName));

    const BYTE secondRandomShape[IMAGE_SIZEOF_SHORT_NAME] = {
        'z', 'y', 'x', 'w', 'v', 'u', 't', 's'};
    std::memcpy(image->sections[0].Name, secondRandomShape,
        sizeof(secondRandomShape));
    CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));
    CS_TEST_CHECK(!eliminator.VerifyExactState(
        image, verifiedState, reason));
    CS_TEST_CHECK(reason == "final_section_names_changed");

    std::memset(image->sections[0].Name, 0,
        sizeof(image->sections[0].Name));
    std::memcpy(image->sections[0].Name, ".rsrc", 5);
    CS_TEST_CHECK(eliminator.VerifyElimination(image, config, reason));
    CS_TEST_CHECK(!eliminator.VerifyExactState(
        image, verifiedState, reason));
    CS_TEST_CHECK(reason == "final_section_names_changed");

    std::memcpy(image->sections[0].Name, verifiedName,
        sizeof(verifiedName));
    CS_TEST_CHECK(eliminator.VerifyExactState(
        image, verifiedState, reason));

    const DWORD originalDirectoryCount = NumberOfRvaAndSizes(image);
    NumberOfRvaAndSizes(image) = 0;
    CS_TEST_CHECK(!eliminator.VerifyExactState(
        image, verifiedState, reason));
    CS_TEST_CHECK(reason == "final_layout_changed");
    NumberOfRvaAndSizes(image) = originalDirectoryCount;
    CS_TEST_CHECK(eliminator.VerifyExactState(
        image, verifiedState, reason));

    CipherShell::PEParser parser;
    parser.FreeImage(image);
}

void TestSignatureDetectorRejectsWrappedEntryRawOffset() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, false, is64Bit);
        CS_TEST_CHECK(image && image->isValid);

        // 旧实现使用 DWORD(PointerToRawData + delta) 和 offset + 16，
        // 这里会双重回绕后通过错误的 bounds 判断并越界读取。
        image->sections[0].PointerToRawData = 0xFFFFFFF0u;
        CipherShell::SignatureEliminator eliminator;
        const auto matches = eliminator.DetectSignatures(image);
        CS_TEST_CHECK(matches.empty());

        CipherShell::PEParser parser;
        parser.FreeImage(image);
    }
}

void TestStandaloneRebuilderHonorsExactMetadataContract() {
    for (const bool is64Bit : {false, true}) {
        auto* image = BuildMinimalImage(false, true, is64Bit, 0x70u);
        CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);
        std::memset(image->sections[0].Name, 0,
            sizeof(image->sections[0].Name));
        std::memcpy(image->sections[0].Name, ".rsrcX", 6);

        CipherShell::CS_REBUILD_CONFIG rebuildConfig;
        rebuildConfig.randomizeSectionNames = TRUE;
        rebuildConfig.zeroTimestamps = TRUE;
        rebuildConfig.preserveRichHeader = FALSE;
        rebuildConfig.preserveDebugInfo = FALSE;
        rebuildConfig.preserveChecksum = FALSE;

        CipherShell::PERebuilder rebuilder;
        DWORD outputSize = 0;
        BYTE* output = rebuilder.RebuildImage(
            image, rebuildConfig, &outputSize);
        CS_TEST_CHECK(output && outputSize == image->rawSize);

        CipherShell::PEParser parser;
        parser.FreeImage(image);
        auto* rebuilt = parser.LoadFromBuffer(output, outputSize);
        CS_TEST_CHECK(rebuilt && rebuilt->isValid);
        for (BYTE value : rebuilt->sections[0].Name) {
            CS_TEST_CHECK(value >= static_cast<BYTE>('a') &&
                value <= static_cast<BYTE>('z'));
        }
        CS_TEST_CHECK(!rebuilt->hasRichHeader);
        CS_TEST_CHECK(DebugDirectory(rebuilt).VirtualAddress == 0);
        CS_TEST_CHECK(DebugDirectory(rebuilt).Size == 0);
        CS_TEST_CHECK(FileHeader(rebuilt).TimeDateStamp == 0);
        CS_TEST_CHECK(ImageChecksum(rebuilt) == 0);

        WORD residualDebugPayload = 0;
        std::memcpy(&residualDebugPayload, rebuilt->rawData + 0x440,
            sizeof(residualDebugPayload));
        CS_TEST_CHECK(residualDebugPayload == 0x4242u);
        parser.FreeImage(rebuilt);
    }
}

void TestStandaloneRebuilderPreservesExactSystemSectionNames() {
    for (const bool is64Bit : {false, true}) {
        for (const char* preservedName : {".rsrc", ".reloc"}) {
            auto* image = BuildMinimalImage(false, false, is64Bit);
            CS_TEST_CHECK(image && image->isValid);
            BYTE expectedName[IMAGE_SIZEOF_SHORT_NAME] = {};
            std::memcpy(expectedName, preservedName,
                std::strlen(preservedName));
            std::memcpy(image->sections[0].Name, expectedName,
                sizeof(expectedName));

            CipherShell::CS_REBUILD_CONFIG rebuildConfig;
            rebuildConfig.randomizeSectionNames = TRUE;
            rebuildConfig.preserveRichHeader = TRUE;
            rebuildConfig.preserveDebugInfo = TRUE;
            rebuildConfig.preserveTimestamps = TRUE;
            rebuildConfig.zeroTimestamps = FALSE;

            CipherShell::PERebuilder rebuilder;
            DWORD outputSize = 0;
            BYTE* output = rebuilder.RebuildImage(
                image, rebuildConfig, &outputSize);
            CS_TEST_CHECK(output && outputSize == image->rawSize);

            CipherShell::PEParser parser;
            parser.FreeImage(image);
            auto* rebuilt = parser.LoadFromBuffer(output, outputSize);
            CS_TEST_CHECK(rebuilt && rebuilt->isValid);
            CS_TEST_CHECK(std::memcmp(rebuilt->sections[0].Name,
                expectedName, sizeof(expectedName)) == 0);
            parser.FreeImage(rebuilt);
        }
    }
}

void TestRebuilderRejectsMutatedHeaderBounds() {
    for (const bool is64Bit : {false, true}) {
        auto reject = [](CipherShell::CS_PE_IMAGE* image) {
            CipherShell::PERebuilder rebuilder;
            CipherShell::CS_REBUILD_CONFIG config;
            DWORD outputSize = 0xFFFFFFFFu;
            BYTE* output = rebuilder.RebuildImage(
                image, config, &outputSize);
            CS_TEST_CHECK(output == nullptr);
            CS_TEST_CHECK(outputSize == 0);
        };

        auto* badNtOffset = BuildMinimalImage(false, false, is64Bit);
        CS_TEST_CHECK(badNtOffset && badNtOffset->isValid);
        badNtOffset->dosHeader->e_lfanew =
            static_cast<LONG>(badNtOffset->rawSize);
        reject(badNtOffset);
        CipherShell::PEParser parser;
        parser.FreeImage(badNtOffset);

        auto* badOptionalSize = BuildMinimalImage(false, false, is64Bit);
        CS_TEST_CHECK(badOptionalSize && badOptionalSize->isValid);
        FileHeader(badOptionalSize).SizeOfOptionalHeader = 0;
        reject(badOptionalSize);
        parser.FreeImage(badOptionalSize);

        auto* badSectionCount = BuildMinimalImage(false, false, is64Bit);
        CS_TEST_CHECK(badSectionCount && badSectionCount->isValid);
        FileHeader(badSectionCount).NumberOfSections = 0xFFFFu;
        reject(badSectionCount);
        parser.FreeImage(badSectionCount);

        auto* zeroSectionCount = BuildMinimalImage(
            false, false, is64Bit);
        CS_TEST_CHECK(zeroSectionCount && zeroSectionCount->isValid);
        FileHeader(zeroSectionCount).NumberOfSections = 0;
        zeroSectionCount->numSections = 0;
        reject(zeroSectionCount);
        parser.FreeImage(zeroSectionCount);

        auto* excessiveSectionCount = BuildMinimalImage(
            false, false, is64Bit);
        CS_TEST_CHECK(excessiveSectionCount &&
            excessiveSectionCount->isValid);
        FileHeader(excessiveSectionCount).NumberOfSections = 97;
        excessiveSectionCount->numSections = 97;
        reject(excessiveSectionCount);
        parser.FreeImage(excessiveSectionCount);
    }
}

void TestRebuilderRejectsUnsupportedPolicies() {
    auto reject = [](CipherShell::CS_REBUILD_CONFIG config) {
        auto* image = BuildMinimalImage();
        CS_TEST_CHECK(image && image->isValid);
        CipherShell::PERebuilder rebuilder;
        DWORD outputSize = 0xFFFFFFFFu;
        BYTE* output = rebuilder.RebuildImage(
            image, config, &outputSize);
        CS_TEST_CHECK(output == nullptr);
        CS_TEST_CHECK(outputSize == 0);
        CipherShell::PEParser parser;
        parser.FreeImage(image);
    };

    CipherShell::CS_REBUILD_CONFIG randomizedTimestamp;
    randomizedTimestamp.randomizeTimestamps = TRUE;
    reject(randomizedTimestamp);

    CipherShell::CS_REBUILD_CONFIG removeSignature;
    removeSignature.preserveSignature = FALSE;
    reject(removeSignature);

    CipherShell::CS_REBUILD_CONFIG removeOverlay;
    removeOverlay.preserveOverlay = FALSE;
    reject(removeOverlay);

    CipherShell::CS_REBUILD_CONFIG ambiguousTimestamp;
    ambiguousTimestamp.preserveTimestamps = TRUE;
    ambiguousTimestamp.zeroTimestamps = TRUE;
    reject(ambiguousTimestamp);

    CipherShell::CS_REBUILD_CONFIG missingTimestampPolicy;
    missingTimestampPolicy.preserveTimestamps = FALSE;
    missingTimestampPolicy.zeroTimestamps = FALSE;
    reject(missingTimestampPolicy);
}

void TestRebuildAndFinalParsePreserveConfiguredSignatureState() {
    for (const bool is64Bit : {false, true}) {
        for (const bool controlsEnabled : {false, true}) {
            auto* image = BuildMinimalImage(false, true, is64Bit);
            CS_TEST_CHECK(image && image->isValid && image->hasRichHeader);

            BYTE originalName[8] = {};
            std::memcpy(originalName, image->sections[0].Name,
                sizeof(originalName));
            const DWORD originalTimestamp = FileHeader(image).TimeDateStamp;
            const IMAGE_DATA_DIRECTORY originalDebug = DebugDirectory(image);

            CipherShell::EliminationConfig config;
            if (!controlsEnabled) {
                DisableGlobalSignatureControls(config);
            }
            CipherShell::SignatureEliminator eliminator;
            CipherShell::EliminationState beforeState;
            CipherShell::EliminationState expectedFinalState;
            std::string reason;
            CS_TEST_CHECK(eliminator.CaptureState(
                image, beforeState, reason));
            CS_TEST_CHECK(eliminator.EliminateSignatures(image, config, reason));
            CS_TEST_CHECK(eliminator.VerifyTransition(beforeState, image,
                config, expectedFinalState, reason));

            CipherShell::CS_REBUILD_CONFIG rebuildConfig;
            rebuildConfig.randomizeSectionNames = FALSE;
            rebuildConfig.preserveTimestamps = TRUE;
            rebuildConfig.randomizeTimestamps = FALSE;
            rebuildConfig.zeroTimestamps = FALSE;
            rebuildConfig.preserveRichHeader = TRUE;
            rebuildConfig.preserveDebugInfo = TRUE;
            rebuildConfig.preserveChecksum = FALSE;

            CipherShell::PERebuilder rebuilder;
            DWORD outputSize = 0;
            BYTE* output = rebuilder.RebuildImage(
                image, rebuildConfig, &outputSize);
            CS_TEST_CHECK(output && outputSize == image->rawSize);

            CipherShell::PEParser parser;
            parser.FreeImage(image);
            auto* rebuilt = parser.LoadFromBuffer(output, outputSize);
            CS_TEST_CHECK(rebuilt && rebuilt->isValid);
            CS_TEST_CHECK((rebuilt->is64Bit != FALSE) == is64Bit);
            CS_TEST_CHECK(eliminator.VerifyElimination(
                rebuilt, config, reason));
            CS_TEST_CHECK(eliminator.VerifyExactState(
                rebuilt, expectedFinalState, reason));

            if (controlsEnabled) {
                CS_TEST_CHECK(std::memcmp(originalName,
                    rebuilt->sections[0].Name, sizeof(originalName)) != 0);
                CS_TEST_CHECK(!rebuilt->hasRichHeader);
                CS_TEST_CHECK(DebugDirectory(rebuilt).VirtualAddress == 0);
                CS_TEST_CHECK(DebugDirectory(rebuilt).Size == 0);
                CS_TEST_CHECK(FileHeader(rebuilt).TimeDateStamp == 0);
            } else {
                CS_TEST_CHECK(std::memcmp(originalName,
                    rebuilt->sections[0].Name, sizeof(originalName)) == 0);
                CS_TEST_CHECK(rebuilt->hasRichHeader);
                CS_TEST_CHECK(DebugDirectory(rebuilt).VirtualAddress ==
                    originalDebug.VirtualAddress);
                CS_TEST_CHECK(DebugDirectory(rebuilt).Size ==
                    originalDebug.Size);
                CS_TEST_CHECK(FileHeader(rebuilt).TimeDateStamp ==
                    originalTimestamp);
            }
            CS_TEST_CHECK(ImageChecksum(rebuilt) == 0);

            WORD residualDebugPayload = 0;
            std::memcpy(&residualDebugPayload, rebuilt->rawData + 0x440,
                sizeof(residualDebugPayload));
            CS_TEST_CHECK(residualDebugPayload == 0x4242u);

            parser.FreeImage(rebuilt);
        }
    }
}

} // namespace

int main() {
    TestDefaultConfigDisablesDangerousFeatures();
    TestProtectionLevelPrecedenceUsesExplicitSetState();
    TestExplicitFlatteningAcceptedAtImageGate();
    TestCetFlatteningRejectedBeforeMutation();
    TestExplicitBogusRejected();
    TestExplicitImportProtectionRejected();
    TestExplicitSectionEncryptionRejected();
    TestExplicitStringEncryptionRejected();
    TestControlFlowMasterNoopRejected();
    TestSignatureEliminatorKeepsReadOnlyPermissions();
    TestSignatureEliminatorHonorsEnabledGlobalControls();
    TestSignatureEliminatorPreservesDisabledGlobalControls();
    TestConfiguredSignatureVerifierIgnoresUnrequestedMatches();
    TestConfiguredSignatureVerifierRejectsBrokenPostconditions();
    TestGlobalConfigMapsOneHotToEliminationPolicy();
    TestPlusRequestsReachFailClosedDetectors();
    TestUnsupportedEliminationOptionsFailClosed();
    TestMalformedRichHeaderFailsClosed();
    TestEarlyRichHeaderUsesParserAlignedClearRange();
    TestRichVerifierAcceptsEmptyRangeAndRejectsOutOfBounds();
    TestExactResourceAndRelocationNamesAreTheOnlyPreservedNames();
    TestExactStateRejectsNoOpAndFinalSectionSubstitution();
    TestSignatureDetectorRejectsWrappedEntryRawOffset();
    TestStandaloneRebuilderHonorsExactMetadataContract();
    TestStandaloneRebuilderPreservesExactSystemSectionNames();
    TestRebuilderRejectsMutatedHeaderBounds();
    TestRebuilderRejectsUnsupportedPolicies();
    TestRebuildAndFinalParsePreserveConfiguredSignatureState();
    return 0;
}
