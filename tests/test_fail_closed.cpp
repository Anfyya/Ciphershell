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

#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// Release 构建会定义 NDEBUG，标准 assert 会被编译为空，导致测试表达式不执行、
// 局部变量“未引用”。使用始终求值的自定义检查宏。
#define CS_TEST_CHECK(cond) do { if (!(cond)) std::abort(); } while (0)

namespace {

// 构造一个最小合法 PE32+：DOS + NT + 一个 .text section，无数据目录。
// 返回的 image 拥有 buffer 所有权，调用方负责 FreeImage。
CipherShell::CS_PE_IMAGE* BuildMinimalImage(bool cetCompatible = false) {
    constexpr DWORD kSize = 0x400;
    constexpr size_t kNtOffset = 0x40;
    // Computed, not hardcoded: IMAGE_NT_HEADERS64 is Signature(4) + FileHeader
    // + OptionalHeader back-to-back, so a wrong literal silently overlaps
    // OptionalHeader with the FileHeader tail and corrupts Magic/NumberOf-
    // RvaAndSizes with whatever garbage sits between them.
    constexpr size_t kFileHeaderOffset = kNtOffset + sizeof(DWORD);
    constexpr size_t kOptionalHeaderOffset = kFileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    BYTE* buf = new BYTE[kSize];
    std::memset(buf, 0, kSize);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(kNtOffset);

    std::memcpy(buf + kNtOffset, "PE\0\0", 4);

    auto* fh = reinterpret_cast<IMAGE_FILE_HEADER*>(buf + kFileHeaderOffset);
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

    auto* oh = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(buf + kOptionalHeaderOffset);
    oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh->FileAlignment = 0x200;
    oh->SectionAlignment = 0x1000;
    oh->SizeOfHeaders = 0x200;
    oh->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    oh->ImageBase = 0x140000000ULL;
    oh->AddressOfEntryPoint = 0x1000;
    oh->SizeOfImage = 0x2000;
    if (cetCompatible) {
        oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0x1020;
        oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
            static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));
    }

    const size_t secOff = kOptionalHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER64);
    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(buf + secOff);
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x10;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = 0x200;
    sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    if (cetCompatible) {
        constexpr DWORD kExtendedDllCharacteristicsType = 20u;
        auto* debug = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(buf + 0x220);
        debug->Type = kExtendedDllCharacteristicsType;
        debug->SizeOfData = static_cast<DWORD>(sizeof(WORD));
        debug->AddressOfRawData = 0x1040;
        debug->PointerToRawData = 0x240;
        const WORD extendedCharacteristics = 0x0001u;
        std::memcpy(buf + debug->PointerToRawData,
            &extendedCharacteristics, sizeof(extendedCharacteristics));
    }

    CipherShell::PEParser parser;
    return parser.LoadFromBuffer(buf, kSize);
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

} // namespace

int main() {
    TestDefaultConfigDisablesDangerousFeatures();
    TestExplicitFlatteningAcceptedAtImageGate();
    TestCetFlatteningRejectedBeforeMutation();
    TestExplicitBogusRejected();
    TestExplicitImportProtectionRejected();
    TestExplicitSectionEncryptionRejected();
    TestExplicitStringEncryptionRejected();
    TestControlFlowMasterNoopRejected();
    TestSignatureEliminatorKeepsReadOnlyPermissions();
    return 0;
}
