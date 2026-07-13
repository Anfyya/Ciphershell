/**
 * CipherShell 主程序入口
 * 命令行界面
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <cstring>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <array>
#include <unordered_set>
#include <cctype>
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif

#include "pe_parser/pe_parser.h"
#include "pe_parser/pe_rebuilder.h"
#include "pe_parser/pe_emitter.h"
#include "pe_parser/pe_utils.h"
#include "transforms/section_encryptor.h"
#include "transforms/string_encryptor.h"
#include "transforms/import_obfuscator.h"
#include "transforms/reloc_fixer.h"
#include "config/config_parser.h"
#include "signature/signature_eliminator.h"
#include "analysis/disassembler.h"
#include "analysis/function_discovery.h"
#include "analysis/cfg_builder.h"
#include "transforms/cfg_flattener.h"
#include "transforms/opaque_predicates.h"
#include "transforms/bogus_flow.h"
#include "transforms/stub_builder.h"
#include "transforms/translator.h"
#include "transforms/vm_section_emitter.h"
#include "mutation/mutation_engine.h"
#include "gui/console_gui.h"
#include "transforms/function_trampoline_patcher.h"
#include "transforms/vm_runtime_builder.h"
#include "transforms/vm_instruction_bridge_builder.h"
#include "transforms/loader_import_builder.h"
#include "analysis/capability_checker.h"
#include "analysis/hotspot_analyzer.h"
#include "config/protection_build_context.h"
#include "vm/vm_verifier.h"
#include "cli_options.h"

namespace fs = std::filesystem;

// ============================================================================
// 帮助信息
// ============================================================================

void PrintHelp() {
    std::cout << R"(
CipherShell v0.1 - 自研高强度代码保护壳

用法: ciphershell [选项] <输入文件>

选项:
  -o, --output <文件>      指定输出文件路径
  -l, --level <1-5>        设置保护等级 (默认: 1)
  -c, --config <文件>      指定配置文件路径 (TOML 格式)
  -v, --verbose            显示详细信息
  -h, --help               显示此帮助信息

保护等级:
  L1 (Guard)    基础加密保护 (~1.05x 性能开销)
  L2 (Shield)   控制流平坦化 (~2-3x 性能开销)
  L3 (Armor)    高级混淆 (~5-8x 性能开销)
  L4 (Fortress) 代码虚拟化 (~15-30x 性能开销)
  L5 (Citadel)  多层嵌套 VM (~50-100x+ 性能开销)

示例:
  ciphershell input.exe -o protected.exe -l 3
  ciphershell input.dll -l 2 -c config.toml
)" << std::endl;
}

static void PrintFeatureStatus(const std::string& name, const std::string& status, const std::string& reason = std::string()) {
    std::cout << "FEATURE_STATUS name=" << name << " status=" << status;
    if (!reason.empty()) {
        std::cout << " reason=" << reason;
    }
    std::cout << std::endl;
}
// ============================================================================
// 主函数
// ============================================================================


static bool IsRuntimeInterpreterOpcode(uint8_t opcode, bool is64Bit) {
    const auto* descriptor = CipherShell::VMSchema::Lookup(opcode);
    return descriptor &&
        (is64Bit ? descriptor->runtimeSupportedX64 : descriptor->runtimeSupportedX86);
}

static bool IsRuntimeInterpreterProgram(
    const std::vector<CipherShell::MicroInstruction>& instructions,
    bool is64Bit,
    std::string& reason)
{
    for (const auto& instr : instructions) {
        if (!IsRuntimeInterpreterOpcode(
                static_cast<uint8_t>(instr.opcode), is64Bit)) {
            reason = "runtime_handler_missing_for_opcode_" +
                std::to_string(static_cast<unsigned>(instr.opcode));
            return false;
        }
    }
    return true;
}
static void PrintVMRegisterMapReport(const std::unordered_map<uint8_t, uint8_t>& registerMap) {
    static const char* kNativeNames[16] = {
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"
    };
    for (uint8_t i = 0; i < 16; i++) {
        auto it = registerMap.find(i);
        uint8_t vmReg = (it != registerMap.end()) ? it->second : i;
        std::cout << "VM_REG_MAP native=" << kNativeNames[i]
                  << " vm=" << static_cast<unsigned>(vmReg) << std::endl;
    }
}

static bool ValidateVMRegisterMap(
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint32_t registerCount,
    std::string& reason)
{
    if (registerCount < 16 || registerCount > 32) {
        reason = "register_count_out_of_range";
        return false;
    }

    bool seen[32] = {};
    for (uint8_t nativeReg = 0; nativeReg < 16; nativeReg++) {
        auto it = registerMap.find(nativeReg);
        if (it == registerMap.end()) {
            reason = "missing_native_register_" + std::to_string(static_cast<unsigned>(nativeReg));
            return false;
        }
        if (it->second >= registerCount) {
            reason = "mapped_register_out_of_range_native_" +
                std::to_string(static_cast<unsigned>(nativeReg));
            return false;
        }
        if (seen[it->second]) {
            reason = "duplicate_vm_register_" + std::to_string(static_cast<unsigned>(it->second));
            return false;
        }
        seen[it->second] = true;
    }
    return true;
}

static const char* PatchKindName(CipherShell::FunctionPatchKind kind) {
    switch (kind) {
        case CipherShell::FunctionPatchKind::NearRel32: return "rel32";
        case CipherShell::FunctionPatchKind::X64AbsoluteIndirect: return "abs64_indirect";
        default: return "none";
    }
}

static bool RvaRangeHasPermissions(
    const CipherShell::CS_PE_IMAGE* image,
    uint32_t rva,
    uint32_t size,
    DWORD required,
    DWORD forbidden)
{
    if (!image || !image->sections) return false;
    if (size == 0) return false;
    for (WORD i = 0; i < image->numSections; ++i) {
        const auto& section = image->sections[i];
        if (!CipherShell::PEUtils::RvaInSection(section, rva)) continue;
        const uint32_t span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
        const uint32_t offset = rva - section.VirtualAddress;
        return offset <= span && size <= span - offset &&
            (section.Characteristics & required) == required &&
            (section.Characteristics & forbidden) == 0;
    }
    return false;
}

static bool IsReadOnlyExecutableRva(const CipherShell::CS_PE_IMAGE* image, uint32_t rva) {
    return RvaRangeHasPermissions(image, rva, 1,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE);
}

static bool WildcardMatchInsensitive(const std::string& pattern, const std::string& value) {
    size_t patternIndex = 0;
    size_t valueIndex = 0;
    size_t star = std::string::npos;
    size_t retry = 0;
    auto equal = [](char left, char right) {
        return std::tolower(static_cast<unsigned char>(left)) ==
            std::tolower(static_cast<unsigned char>(right));
    };
    while (valueIndex < value.size()) {
        if (patternIndex < pattern.size() &&
            (pattern[patternIndex] == '?' || equal(pattern[patternIndex], value[valueIndex]))) {
            ++patternIndex;
            ++valueIndex;
        } else if (patternIndex < pattern.size() && pattern[patternIndex] == '*') {
            star = patternIndex++;
            retry = valueIndex;
        } else if (star != std::string::npos) {
            patternIndex = star + 1;
            valueIndex = ++retry;
        } else return false;
    }
    while (patternIndex < pattern.size() && pattern[patternIndex] == '*') ++patternIndex;
    return patternIndex == pattern.size();
}

static bool FunctionSelected(
    const CipherShell::Function& function,
    const std::vector<std::string>& patterns,
    const std::vector<uint32_t>& targetRVAs)
{
    if (patterns.empty() && targetRVAs.empty()) return true;
    if (function.entryAddress <= 0xFFFFFFFFULL &&
        std::binary_search(targetRVAs.begin(), targetRVAs.end(),
            static_cast<uint32_t>(function.entryAddress))) return true;
    std::ostringstream rva;
    rva << "0x" << std::hex << function.entryAddress;
    for (const auto& pattern : patterns) {
        if (WildcardMatchInsensitive(pattern, function.name) ||
            WildcardMatchInsensitive(pattern, rva.str())) return true;
    }
    return false;
}

static bool ParseX86CallAbi(const std::string& value, VM_CALL_ABI& abi) {
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (normalized == "auto") abi = VM_ABI_X86_AUTO;
    else if (normalized == "cdecl") abi = VM_ABI_X86_CDECL;
    else if (normalized == "stdcall") abi = VM_ABI_X86_STDCALL;
    else if (normalized == "fastcall") abi = VM_ABI_X86_FASTCALL;
    else if (normalized == "thiscall") abi = VM_ABI_X86_THISCALL;
    else return false;
    return true;
}

static std::string FormatImageBytesAtRva(CipherShell::CS_PE_IMAGE* image, uint32_t rva, uint32_t count) {
    CipherShell::PEEmitter emitter(image);
    uint32_t offset = emitter.RvaToOffset(rva);
    if (offset == 0 || offset >= image->rawSize) return "<unavailable>";
    uint32_t available = image->rawSize - offset;
    uint32_t n = std::min(count, available);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t i = 0; i < n; i++) {
        if (i) oss << ' ';
        oss << std::setw(2) << static_cast<unsigned>(image->rawData[offset + i]);
    }
    return oss.str();
}

static bool ValidateVMStaticLink(
    CipherShell::CS_PE_IMAGE* image,
    const std::vector<CipherShell::VMFunctionRecord>& records,
    const std::vector<uint8_t>& bytecode,
    const CipherShell::VMEmitResult& emitResult,
    const CipherShell::VMRuntimeBuildResult& runtimeResult,
    const CipherShell::VMInstructionBridgeBuildResult& bridgeResult,
    const std::vector<CipherShell::FunctionPatchResult>& patchResults,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint32_t registerCount,
    std::unordered_map<uint32_t, uint32_t>& opcodeCounts,
    std::string& reason)
{
    opcodeCounts.clear();
    if (!runtimeResult.executionReady || !runtimeResult.keySharePatched ||
        !runtimeResult.cfgVerified || !runtimeResult.relocationsVerified ||
        !runtimeResult.handlerSynthesisVerified ||
        !runtimeResult.directThreadedVerified ||
        !runtimeResult.handlerEncryptionVerified ||
        !runtimeResult.runtimeContentVerified ||
        !runtimeResult.referenceRuntimeBlobFreeVerified) {
        reason = "runtime_not_execution_ready_or_linkage_unverified";
        return false;
    }
    std::string runtimeIntegrityReason;
    if (!CipherShell::VMRuntimeBuilder::VerifyRuntimeContents(
            image, runtimeResult, runtimeIntegrityReason)) {
        reason = "runtime_content_integrity_failed: " + runtimeIntegrityReason;
        return false;
    }
    if (!bridgeResult.success || !bridgeResult.cfgTableVerified || !bridgeResult.unwindVerified) {
        reason = "instruction_bridge_not_statically_linked";
        return false;
    }
    if (!emitResult.success || emitResult.sectionRVA == 0 || emitResult.sectionRawOffset == 0 ||
        emitResult.sectionSize == 0 || emitResult.metadataRVA == 0 || emitResult.bytecodeRVA == 0) {
        reason = "metadata_or_bytecode_not_linked";
        return false;
    }
    if (runtimeResult.sectionRVA == 0 || runtimeResult.sectionRawOffset == 0 || runtimeResult.sectionSize == 0 ||
        runtimeResult.runtimeEntryRVA == 0 || runtimeResult.trampolines.empty()) {
        reason = "runtime_or_trampoline_missing";
        return false;
    }
    if (!RvaRangeHasPermissions(image, emitResult.metadataRVA, emitResult.metadataSize,
            IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE) ||
        !RvaRangeHasPermissions(image, emitResult.bytecodeRVA,
            static_cast<uint32_t>(bytecode.size()), IMAGE_SCN_MEM_READ,
            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
        reason = "metadata_or_bytecode_section_permissions_invalid";
        return false;
    }
    if (!RvaRangeHasPermissions(image, runtimeResult.sectionRVA,
            runtimeResult.runtimeImageSize,
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE) ||
        !IsReadOnlyExecutableRva(image, runtimeResult.runtimeEntryRVA)) {
        reason = "runtime_section_permissions_invalid";
        return false;
    }
    for (const auto& trampoline : runtimeResult.trampolines) {
        if (!RvaRangeHasPermissions(image, trampoline.trampolineRVA,
                trampoline.trampolineSize,
                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE)) {
            reason = "trampoline_section_permissions_invalid";
            return false;
        }
    }
    if (records.empty() || bytecode.empty()) { reason = "records_or_bytecode_empty"; return false; }
    if (opcodeMap.empty() || registerMap.empty()) { reason = "opcode_or_register_map_missing"; return false; }
    std::string registerMapReason;
    if (!ValidateVMRegisterMap(registerMap, registerCount, registerMapReason)) {
        reason = "invalid_register_map: " + registerMapReason;
        return false;
    }
    if (runtimeResult.trampolines.size() != records.size()) { reason = "trampoline_count_mismatch"; return false; }
    if (patchResults.size() != records.size()) { reason = "patch_result_count_mismatch"; return false; }
    if (runtimeResult.architecture == VM_ARCH_X64) {
        if (!runtimeResult.unwindVerified || runtimeResult.unwindEntries.size() < records.size()) {
            reason = "x64_runtime_or_trampoline_unwind_missing";
            return false;
        }
        for (const auto& unwind : runtimeResult.unwindEntries) {
            const auto found = std::find_if(image->exceptions.entries.begin(), image->exceptions.entries.end(),
                [&unwind](const CipherShell::CS_RUNTIME_FUNCTION& entry) {
                    return entry.beginAddress == unwind.beginRVA &&
                        entry.endAddress == unwind.endRVA && entry.unwindData == unwind.unwindRVA;
                });
            if (found == image->exceptions.entries.end()) {
                reason = "x64_runtime_unwind_not_linked_into_exception_directory";
                return false;
            }
        }
    }

    std::array<uint8_t, 256> reverseOpcodeMap{};
    std::array<uint8_t, 256> seenEncodedOpcodes{};
    if (opcodeMap.size() != 256) {
        reason = "opcode_map_is_not_a_full_permutation";
        return false;
    }
    for (const auto& mapping : opcodeMap) {
        if (seenEncodedOpcodes[mapping.second]) {
            reason = "opcode_map_is_not_injective";
            return false;
        }
        seenEncodedOpcodes[mapping.second] = 1;
        reverseOpcodeMap[mapping.second] = mapping.first;
    }
    std::unordered_set<uint32_t> guardTargets(image->loadConfig.guardFunctionRVAs.begin(),
        image->loadConfig.guardFunctionRVAs.end());
    size_t verifiedBridgeCount = 0;

    for (const auto& record : records) {
        if (record.functionRVA == 0 || record.functionSize == 0 || record.bytecodeSize == 0) {
            reason = "invalid_function_record";
            return false;
        }
        if (record.bytecodeOffset > bytecode.size() || record.bytecodeSize > bytecode.size() - record.bytecodeOffset) {
            reason = "record_bytecode_range_outside_blob";
            return false;
        }
        bool hasTrampoline = false;
        for (const auto& tr : runtimeResult.trampolines) {
            if (tr.functionRVA == record.functionRVA && tr.trampolineRVA != 0 && tr.trampolineSize != 0) {
                hasTrampoline = true;
                break;
            }
        }
        if (!hasTrampoline) {
            reason = "record_without_trampoline";
            return false;
        }
        bool hasVerifiedPatch = false;
        for (const auto& patch : patchResults) {
            if (patch.functionRVA == record.functionRVA && patch.success && patch.verified &&
                patch.nativeBodyDestroyed && patch.trampolineRVA != 0) {
                std::string patchVerificationError;
                if (!CipherShell::FunctionTrampolinePatcher::VerifyAppliedPatch(
                        image, patch, patchVerificationError)) {
                    reason = "function_patch_reverification_failed: " + patchVerificationError;
                    return false;
                }
                hasVerifiedPatch = true;
                break;
            }
        }
        if (!hasVerifiedPatch) {
            reason = "record_without_verified_function_patch";
            return false;
        }

        const auto verification = CipherShell::VMBytecodeVerifier::VerifyPlainRecord(
            record, bytecode, opcodeMap, registerMap,
            emitResult.operandCodecSeed, registerCount,
            runtimeResult.architecture == VM_ARCH_X64);
        if (!verification.success) {
            reason = "bytecode_decoder_check_failed: " + verification.error;
            return false;
        }
        opcodeCounts[record.functionRVA] = verification.instructionCount;

        const VM_OPERAND_CODEC codec = CipherShell::VMSchema::DeriveOperandCodec(
            emitResult.operandCodecSeed, record.functionRVA);
        std::vector<CipherShell::DecodedMicroInstruction> decoded;
        std::string decodeReason;
        if (!CipherShell::VMSchema::DecodeStream(
                bytecode.data() + record.bytecodeOffset,
                record.bytecodeSize,
                reverseOpcodeMap.data(),
                codec,
                decoded,
                decodeReason)) {
            reason = "micro_stream_static_decode_failed: " + decodeReason;
            return false;
        }
        for (const auto& decodedInstruction : decoded) {
            const auto& instruction = decodedInstruction.instruction;
            if (instruction.handlerVariant >= VM_HANDLER_VARIANT_COUNT) {
                reason = "micro_stream_handler_variant_out_of_range";
                return false;
            }
            if (instruction.opcode != VM_UOP_BRIDGE_EXTENDED) continue;
            const uint32_t thunkRVA = static_cast<uint32_t>(instruction.operands[0]);
            const uint32_t bridgeFlags = static_cast<uint32_t>(instruction.operands[1]);
            const auto linked = std::find_if(bridgeResult.links.begin(), bridgeResult.links.end(),
                [&](const CipherShell::VMInstructionBridgeLink& link) {
                    return link.functionRVA == record.functionRVA &&
                        link.thunkRVA == thunkRVA;
                });
            if (linked == bridgeResult.links.end() ||
                !IsReadOnlyExecutableRva(image, linked->thunkRVA) ||
                !IsReadOnlyExecutableRva(image, linked->nativeInstructionRVA) ||
                (bridgeFlags & VM_MICRO_BRIDGE_LINKED) == 0 ||
                (linked->usesAvx && (record.flags & VM_RECORD_FLAG_USES_AVX) == 0)) {
                reason = "bridge_target_or_record_flags_not_linked";
                return false;
            }
            if (linked->usesX87) {
                if (!linked->usesX87 || (record.flags & VM_RECORD_FLAG_USES_X87) == 0) {
                    reason = "x87_bridge_record_flag_missing";
                    return false;
                }
            } else if (linked->usesX87 || (record.flags & VM_RECORD_FLAG_USES_SIMD) == 0) {
                reason = "simd_bridge_record_flag_missing";
                return false;
            }
            if (image->loadConfig.hasCFG && guardTargets.count(linked->thunkRVA) == 0) {
                reason = "bridge_thunk_missing_from_guard_cf_table";
                return false;
            }
            if (image->is64Bit) {
                const auto exactUnwind = std::find_if(image->exceptions.entries.begin(),
                    image->exceptions.entries.end(), [&](const CipherShell::CS_RUNTIME_FUNCTION& entry) {
                        return entry.beginAddress == linked->unwindBeginRVA &&
                            entry.endAddress == linked->nativeInstructionRVA +
                                linked->nativeInstructionSize && entry.unwindData != 0;
                    });
                if (exactUnwind == image->exceptions.entries.end()) {
                    reason = "x64_bridge_native_instruction_unwind_missing";
                    return false;
                }
            }
            ++verifiedBridgeCount;
        }
    }
    if (verifiedBridgeCount != bridgeResult.links.size()) {
        reason = "bridge_link_count_mismatch";
        return false;
    }
    std::string emittedVerificationError;
    if (!CipherShell::VMBytecodeVerifier::VerifyEmittedMetadataAndBytecode(
            image, emitResult.metadataRVA, records, bytecode,
            emitResult.runtimeKeyShare,
            emitResult.handlerSemanticToSlot,
            emitResult.handlerSlotToSemantic,
            emitResult.handlerVariants,
            emitResult.junkHandlerCount,
            emitResult.handlerMutationEnabled,
            emitResult.junkHandlersEnabled,
            emittedVerificationError)) {
        reason = "emitted_metadata_or_bytecode_verification_failed: " + emittedVerificationError;
        return false;
    }
    return true;
}

static bool ValidateLoaderStaticLink(
    const CipherShell::CS_PE_IMAGE* image,
    const CipherShell::StubEmbedResult& loader,
    uint32_t originalEntryPoint,
    std::string& reason)
{
    if (!image || !image->isValid || !loader.success || !loader.wxVerified ||
        loader.stubRVA == 0 || loader.stubSize == 0 ||
        loader.virtualProtectIatRVA == 0 || loader.flushInstructionCacheIatRVA == 0) {
        reason = "loader_result_incomplete";
        return false;
    }
    bool foundVirtualProtect = false;
    bool foundFlushInstructionCache = false;
    for (const auto& dll : image->imports.dlls) {
        for (const auto& function : dll.functions) {
            if (function.thunkRVA == loader.virtualProtectIatRVA &&
                function.name == "VirtualProtect") foundVirtualProtect = true;
            if (function.thunkRVA == loader.flushInstructionCacheIatRVA &&
                function.name == "FlushInstructionCache") foundFlushInstructionCache = true;
        }
    }
    if (!foundVirtualProtect || !foundFlushInstructionCache) {
        reason = "loader_runtime_imports_missing";
        return false;
    }
    bool stubInRxSection = false;
    for (uint32_t i = 0; i < image->numSections; ++i) {
        const auto& section = image->sections[i];
        const uint32_t span = (std::max)(section.Misc.VirtualSize,
            static_cast<DWORD>(section.SizeOfRawData));
        const bool execute = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (execute && write) {
            reason = "writable_executable_section_present index=" + std::to_string(i);
            return false;
        }
        if (span != 0 && loader.stubRVA >= section.VirtualAddress &&
            loader.stubRVA - section.VirtualAddress < span) {
            stubInRxSection = execute && !write &&
                (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        }
    }
    if (!stubInRxSection) {
        reason = "loader_stub_not_in_rx_section";
        return false;
    }
    const uint32_t entryPoint = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.AddressOfEntryPoint
        : image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    if (loader.installedAsTlsCallback) {
        const uint64_t imageBase = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.ImageBase
            : image->ntHeaders32->OptionalHeader.ImageBase;
        if (!image->tls.valid || image->tls.callbackAddresses.empty() ||
            image->tls.callbackAddresses.front() != imageBase + loader.stubRVA ||
            entryPoint != originalEntryPoint) {
            reason = "tls_loader_order_not_preserved";
            return false;
        }
    } else if (entryPoint != loader.stubRVA) {
        reason = "entrypoint_loader_not_linked";
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    // 设置控制台为 UTF-8 编码
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // 如果没有参数，启动 GUI 模式
    if (argc == 1) {
        CipherShell::ConsoleGUI gui;
        gui.Initialize();
        gui.ShowMainMenu();
        return 0;
    }

    std::cout << "CipherShell v0.1 - 自研高强度代码保护壳" << std::endl;
    std::cout << "======================================" << std::endl;

    CipherShell::CommandLineOptions cli;
    std::string cliError;
    if (!CipherShell::ParseCommandLine(argc, argv, cli, cliError)) {
        std::cerr << "错误: " << cliError << std::endl;
        PrintHelp();
        return 1;
    }
    if (cli.showHelp) {
        PrintHelp();
        return 0;
    }

    std::string inputFile = std::move(cli.inputFile);
    std::string outputFile = std::move(cli.outputFile);
    std::string configFile = std::move(cli.configFile);
    int protectionLevel = cli.protectionLevel;
    const bool verbose = cli.verbose;

    if (!fs::exists(inputFile)) {
        std::cerr << "错误: 输入文件不存在: " << inputFile << std::endl;
        return 1;
    }

    // 自动生成输出文件名
    if (outputFile.empty()) {
        fs::path inputPath(inputFile);
        outputFile = inputPath.stem().string() + "_protected" + inputPath.extension().string();
    }

    std::cout << "输入文件: " << inputFile << std::endl;
    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "保护等级: L" << protectionLevel << std::endl;

    // ============================================================================
    // Step 1: 解析输入 PE
    // ============================================================================

    std::cout << "\n[1/5] 解析输入 PE 文件..." << std::endl;

    CipherShell::PEParser parser;
    auto imageDeleter = [&parser](CipherShell::CS_PE_IMAGE* img) {
        if (img) parser.FreeImage(img);
    };
    std::unique_ptr<CipherShell::CS_PE_IMAGE, decltype(imageDeleter)> image(
        parser.LoadFromFile(inputFile),
        imageDeleter
    );

    if (!image || !image->isValid) {
        std::cerr << "错误: 无法解析 PE 文件";
        if (image) {
            std::cerr << " - " << image->errorMessage;
        }
        std::cerr << std::endl;
        return 1;
    }

    std::cout << "  PE 解析成功" << std::endl;
    std::cout << "  架构: " << (image->is64Bit ? "x64" : "x86") << std::endl;
    std::cout << "  入口点: 0x" << std::hex;
    if (image->is64Bit) {
        std::cout << image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        std::cout << image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    std::cout << std::dec << std::endl;
    std::cout << "  Section 数量: " << image->numSections << std::endl;

    if (verbose) {
        std::cout << "  导入 DLL 数量: " << image->imports.dlls.size() << std::endl;
        std::cout << "  导出函数数量: " << image->exports.functions.size() << std::endl;
        std::cout << "  重定位条目数量: " << image->relocs.entries.size() << std::endl;
    }

    // ============================================================================
    // Step 1.5: 加载配置
    // ============================================================================

    CipherShell::CipherShellConfig config;
    CipherShell::ConfigParser configParser;

    if (!configFile.empty()) {
        std::cout << "\n[1.5] 加载配置文件: " << configFile << std::endl;
        config = configParser.LoadFromFile(configFile);
        if (configParser.HasError()) {
            std::cerr << "错误: " << configParser.GetLastError() << std::endl;
            return 1;
        }
        protectionLevel = config.global.protectionLevel;
        if (protectionLevel < 1 || protectionLevel > 5) {
            std::cerr << "错误: 配置中的保护等级必须在 1-5 之间" << std::endl;
            return 1;
        }
    } else {
        // 使用默认配置
        config.global.protectionLevel = protectionLevel;
    }

    CipherShell::ProtectionBuildContext buildCtx =
        CipherShell::ProtectionBuildContext::FromConfig(config, protectionLevel, verbose);
    if (!buildCtx.entropyReady) {
        std::cerr << "BUILD_CONTEXT_FAIL module=ProtectionBuildContext"
                  << " reason=system_csprng_unavailable" << std::endl;
        return 1;
    }

    for (const auto& warning : configParser.GetWarnings()) {
        std::cerr << "CONFIG_WARN module=ConfigParser reason=" << warning << std::endl;
    }

    CipherShell::CapabilityChecker capabilityChecker;
    auto capabilityReport = capabilityChecker.CheckImage(image.get(), buildCtx);
    for (const auto& issue : capabilityReport.issues) {
        std::cerr << "CAPABILITY_" << (issue.fatal ? "FAIL" : "WARN")
                  << " module=" << issue.module
                  << " rva=0x" << std::hex << issue.rva << std::dec
                  << " reason=" << issue.reason << std::endl;
    }
    if (!capabilityReport.ok) {
        return 1;
    }
    // ============================================================================
    // Step 1.5: 保存原始入口点
    // ============================================================================

    DWORD originalOEP = 0;
    if (image->is64Bit) {
        originalOEP = image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        originalOEP = image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    const WORD originalSectionCount = image->numSections;
    (void)originalSectionCount;  // section encryption 已 fail-closed，不再需要该边界
    std::cout << "  原始入口点 (OEP): 0x" << std::hex << originalOEP << std::dec << std::endl;

    // ============================================================================
    // Step 2: 应用保护变换
    // 重要: 先做代码分析/变换（明文代码可反汇编），最后才做 Section 加密
    // ============================================================================

    std::cout << "\n[2/5] 应用保护变换 (L" << protectionLevel << ")..." << std::endl;

    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedStringRegions;

    // Phase A: 字符串加密 —— 弱加密（未认证算法 + 可恢复密钥），不具备生产语义闭环。
    // 由 CapabilityChecker 在任何 PE 修改之前 fatal 拒绝；此处保留显式 fail-closed 守卫，
    // 绝不应用，绝不打印 applied/partial。
    if (buildCtx.stringEncryption.enabled) {
        std::cerr << "STRING_ENCRYPTION_REJECT module=StringEncryption"
                  << " reason=fail_closed_unfinished_cipher_with_recoverable_key" << std::endl;
        PrintFeatureStatus("string_encryption", "rejected", "fail_closed_unfinished_closure");
        return 1;
    }
    PrintFeatureStatus("string_encryption", "skipped", "disabled");

    // Phase B: 导入表混淆 —— 仅追加假导入并保留真实 IAT，未改写 callsite，不具备生产闭环。
    // 由 CapabilityChecker 在任何 PE 修改之前 fatal 拒绝；此处保留显式 fail-closed 守卫。
    if (buildCtx.importProtection.enabled) {
        std::cerr << "IMPORT_PROTECTION_REJECT module=ImportProtection"
                  << " reason=fail_closed_real_iat_callsite_not_rewritten" << std::endl;
        PrintFeatureStatus("import_protection", "rejected", "fail_closed_unfinished_closure");
        return 1;
    }
    PrintFeatureStatus("import_protection", "skipped", "disabled");

    // Phase C: 控制流平坦化 —— 缺少 RIP-relative/CALL 重定位、ABI、unwind、CFG 修复，
    // 无法保证原函数语义。由 CapabilityChecker 在任何 PE 修改之前 fatal 拒绝；
    // 此处保留显式 fail-closed 守卫，绝不应用。
    if (buildCtx.flattening.enabled) {
        std::cerr << "CFG_FLATTEN_REJECT module=ControlFlow"
                  << " reason=fail_closed_no_relocation_abi_unwind_cfg_repair" << std::endl;
        PrintFeatureStatus("control_flow.flattening", "rejected", "fail_closed_unfinished_closure");
        return 1;
    }
    PrintFeatureStatus("control_flow.flattening", "skipped", "disabled");

    // Phase D: 虚假控制流 —— 无法证明原函数语义保持，不具备生产闭环。
    // 由 CapabilityChecker 在任何 PE 修改之前 fatal 拒绝；此处保留显式 fail-closed 守卫。
    if (buildCtx.bogusFlow.enabled) {
        std::cerr << "CFG_BOGUS_REJECT module=ControlFlow"
                  << " reason=fail_closed_cannot_prove_semantic_preservation" << std::endl;
        PrintFeatureStatus("control_flow.bogus", "rejected", "fail_closed_unfinished_closure");
        return 1;
    }
    PrintFeatureStatus("control_flow.bogus", "skipped", "disabled");

    bool vmApplied = false;
    uint32_t vmRegisterCount = 0;
    uint64_t vmOperandCodecSeed = 0;
    std::vector<uint8_t> vmBytecodeBlob;
    std::vector<CipherShell::VMFunctionRecord> vmRecords;
    std::vector<CipherShell::Function> protectedFunctions;
    CipherShell::VMInstructionBridgeBuildResult bridgeResult{};
    CipherShell::VMEmitResult emitResult{};
    CipherShell::VMRuntimeBuildResult runtimeResult{};
    std::vector<CipherShell::FunctionPatchResult> patchResults;
    CipherShell::LoaderImportBuildResult vmRuntimeImports{};

    // Phase E: 函数级 VM 保护。这里只允许完整落盘的数据进入下一步，失败必须明确诊断。
    if (buildCtx.vm.enabled) {
        std::cout << "  应用代码虚拟化 (Mirage VM)..." << std::endl;

        if (!config.vm.opcodeRandomization || !config.vm.handlerMutation ||
            !config.vm.embedJunkHandlers) {
            std::cerr << "VM_INIT_FAIL module=VMGenerationPolicy"
                      << " reason=opcode_handler_and_junk_mutation_are_mandatory"
                      << std::endl;
            PrintFeatureStatus("vm", "failed",
                "mandatory_per_build_mutation_disabled");
            return 1;
        }

        VM_CALL_ABI configuredX86CallAbi = VM_ABI_X86_AUTO;
        if (!config.vm.bytecodeEncryption || config.vm.nativeBodyPolicy != "destroy" ||
            !ParseX86CallAbi(config.vm.x86CallAbi, configuredX86CallAbi)) {
            std::cerr << "VM_INIT_FAIL module=CapabilityChecker"
                      << " reason=invalid_production_vm_configuration"
                      << " bytecode_encryption=" << (config.vm.bytecodeEncryption ? "true" : "false")
                      << " native_body_policy=" << config.vm.nativeBodyPolicy
                      << " x86_call_abi=" << config.vm.x86CallAbi << std::endl;
            PrintFeatureStatus("vm", "failed", "invalid_production_vm_configuration");
            return 1;
        }

        if (config.vm.stackSize < 0x4000 || config.vm.stackSize > 0x70000 ||
            (config.vm.stackSize & 0x0FFF) != 0) {
            std::cerr << "VM_INIT_FAIL module=CapabilityChecker"
                      << " reason=guest_stack_size_must_be_page_aligned_16k_to_448k"
                      << " stack_size=" << config.vm.stackSize << std::endl;
            PrintFeatureStatus("vm", "failed", "invalid_guest_stack_size");
            return 1;
        }

        CipherShell::MutationEngine mutEngine;
        CipherShell::MutationConfig mutConfig;
        mutConfig.randomizeOpcodeMap = true;
        mutConfig.randomizeRegisterMap = true;
        mutConfig.registerCount = static_cast<uint32_t>(config.vm.registerCount);
        mutConfig.seed = buildCtx.isaSeed;
        mutConfig.mutateHandlers = true;
        mutConfig.embedJunkHandlers = true;
        mutConfig.requestedJunkHandlerCount = 16u;
        for (const auto& descriptor : CipherShell::VMSchema::Opcodes()) {
            const bool runtimeSupported = image->is64Bit
                ? descriptor.runtimeSupportedX64
                : descriptor.runtimeSupportedX86;
            if (runtimeSupported) {
                mutConfig.validOpcodes.push_back(
                    static_cast<uint8_t>(descriptor.opcode));
            }
        }
        if (!mutEngine.Initialize(mutConfig)) {
            std::cerr << "VM_INIT_FAIL module=MutationEngine reason=register_count_must_be_16_to_32" << std::endl;
            PrintFeatureStatus("vm", "failed", "invalid_register_count");
            return 1;
        }

        CipherShell::MutatedISA mutatedISA = mutEngine.GenerateMutatedISA();
        vmOperandCodecSeed = mutEngine.GetSeedFingerprint();
        buildCtx.opcodeMap = mutatedISA.opcodeMap;
        buildCtx.registerMap = mutatedISA.registerMap;
        std::string registerMapReason;
        if (!ValidateVMRegisterMap(buildCtx.registerMap, mutConfig.registerCount, registerMapReason)) {
            std::cerr << "VM_INIT_FAIL module=MutationEngine reason=" << registerMapReason << std::endl;
            PrintFeatureStatus("vm", "failed", registerMapReason);
            return 1;
        }
        std::cout << "    ISA seed fingerprint: 0x" << std::hex
                  << vmOperandCodecSeed << std::dec << std::endl;
        std::cout << "VM_HANDLER_LAYOUT mutated="
                  << (mutatedISA.handlerMutationEnabled ? "true" : "false")
                  << " junk_handlers=" << mutatedISA.junkHandlerCount
                  << " variant_count=" << VM_HANDLER_VARIANT_COUNT << std::endl;

        CipherShell::Translator translator;
        CipherShell::TranslationConfig transConfig;
        transConfig.virtualRegisterCount = mutConfig.registerCount;
        transConfig.buildSeed = vmOperandCodecSeed;
        transConfig.density = CipherShell::VMMicroDensity::Heavy;
        transConfig.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
        transConfig.x86CallAbi = configuredX86CallAbi;
        transConfig.enableSimdBridge = config.vm.simdBridge;
        transConfig.enableX87Bridge = config.vm.x87Bridge;
        vmRegisterCount = transConfig.virtualRegisterCount;
        for (const auto& dll : image->imports.dlls) {
            for (const auto& imported : dll.functions) {
                transConfig.importThunkRVAs.insert(imported.thunkRVA);
            }
        }
        if (!translator.Initialize(transConfig)) {
            std::cerr << "VM_INIT_FAIL module=Translator reason=initialize_failed" << std::endl;
            return 1;
        }
        translator.SetOpcodeMap(buildCtx.opcodeMap);
        translator.SetRegisterMap(buildCtx.registerMap);
        CipherShell::Translator lightTranslator;
        CipherShell::TranslationConfig lightConfig = transConfig;
        lightConfig.density = CipherShell::VMMicroDensity::Light;
        if (!lightTranslator.Initialize(lightConfig)) {
            std::cerr << "VM_INIT_FAIL module=Translator reason=light_initialize_failed" << std::endl;
            return 1;
        }
        lightTranslator.SetOpcodeMap(buildCtx.opcodeMap);
        lightTranslator.SetRegisterMap(buildCtx.registerMap);
        PrintVMRegisterMapReport(buildCtx.registerMap);
        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        disasm.Initialize(is64, is64 ? image->ntHeaders64->OptionalHeader.ImageBase
                                     : image->ntHeaders32->OptionalHeader.ImageBase);
        uint32_t virtualizedCount = 0;
        uint32_t rejectedCount = 0;
        uint32_t selectedCount = 0;
        std::vector<CipherShell::TranslationResult> pendingTranslations;

        CipherShell::FunctionDiscovery functionDiscovery;
        auto discoveryResult = functionDiscovery.Discover(
            image.get(), disasm, buildCtx.vm.targetRVAs);
        if (!discoveryResult.success) {
            std::cerr << "VM_DISCOVERY_FAIL module=FunctionDiscovery reason="
                      << discoveryResult.error << std::endl;
            PrintFeatureStatus("vm", "failed", discoveryResult.error);
            return 1;
        }
        for (auto& function : discoveryResult.functions) {
            function.assignedLevel = static_cast<uint32_t>((std::max)(1, buildCtx.quickLevel));
        }
        if (config.performance.autoHotspotAnalysis) {
            CipherShell::HotspotAnalyzer hotspotAnalyzer;
            CipherShell::HotspotConfig hotspotConfig;
            hotspotConfig.maxAllowedLevel = 2;
            auto hotspots = hotspotAnalyzer.AnalyzeFunctions(
                discoveryResult.functions, hotspotConfig);
            hotspotAnalyzer.GenerateSuggestions(
                hotspots,
                static_cast<uint32_t>((std::max)(1, buildCtx.quickLevel)),
                hotspotConfig);
            hotspotAnalyzer.ApplySuggestions(discoveryResult.functions, hotspots);
            std::cout << "VM_HOTSPOT_PROFILE analyzed="
                      << discoveryResult.functions.size()
                      << " downgraded=" << hotspots.size() << std::endl;
        }
        for (const auto& issue : discoveryResult.issues) {
            std::cerr << "VM_DISCOVERY_REJECT module=FunctionDiscovery rva=0x" << std::hex
                      << issue.rva << std::dec << " reason=" << issue.reason << std::endl;
        }
        if (verbose) {
            for (const auto& function : discoveryResult.functions) {
                std::cout << "VM_FUNCTION_DISCOVERY rva=0x" << std::hex
                          << function.entryAddress << " size=0x" << function.size << std::dec
                          << " source=" << (function.discoverySource.empty() ? "unknown" : function.discoverySource)
                          << " boundary_trusted=" << (function.boundaryTrusted ? "true" : "false")
                          << std::endl;
            }
        }

        for (const auto& pattern : buildCtx.vm.targetFunctions) {
            const bool matched = std::any_of(discoveryResult.functions.begin(),
                discoveryResult.functions.end(), [&](const CipherShell::Function& function) {
                    std::ostringstream rva;
                    rva << "0x" << std::hex << function.entryAddress;
                    return WildcardMatchInsensitive(pattern, function.name) ||
                        WildcardMatchInsensitive(pattern, rva.str());
                });
            if (!matched) {
                std::cerr << "VM_BUILD_FAIL module=FunctionSelect reason=target_pattern_matched_none"
                          << " pattern=" << pattern << std::endl;
                PrintFeatureStatus("vm", "failed", "target_pattern_matched_none");
                return 1;
            }
        }
        for (uint32_t targetRVA : buildCtx.vm.targetRVAs) {
            const bool matched = std::any_of(discoveryResult.functions.begin(),
                discoveryResult.functions.end(), [&](const CipherShell::Function& function) {
                    return function.entryAddress == targetRVA;
                });
            if (!matched) {
                std::cerr << "VM_BUILD_FAIL module=FunctionSelect reason=target_rva_matched_none"
                          << " rva=0x" << std::hex << targetRVA << std::dec << std::endl;
                PrintFeatureStatus("vm", "failed", "target_rva_matched_none");
                return 1;
            }
        }

        for (const auto& func : discoveryResult.functions) {
                if (!FunctionSelected(func, buildCtx.vm.targetFunctions,
                        buildCtx.vm.targetRVAs)) continue;
                ++selectedCount;
                const bool explicitlySelected =
                    !buildCtx.vm.targetFunctions.empty() ||
                    !buildCtx.vm.targetRVAs.empty();
                if (!explicitlySelected && func.assignedLevel <= 1) {
                    std::cout << "VM_PROFILE function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " mode=cfg_only vm=skipped" << std::endl;
                    continue;
                }
                if (func.size < 5) {
                    ++rejectedCount;
                    std::cerr << "VM_REJECT module=FunctionSelect rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " reason=function_too_small" << std::endl;
                    continue;
                }
                if (func.entryAddress > 0xFFFFFFFFULL) {
                    std::cerr << "VM_REJECT module=FunctionSelect rva=0x" << std::hex << func.entryAddress
                              << std::dec << " reason=function_range_too_large" << std::endl;
                    rejectedCount++;
                    continue;
                }

                std::string vmSafetyReason;
                if (!capabilityChecker.IsFunctionVmSafe(image.get(), func, vmSafetyReason)) {
                    std::cerr << "VM_REJECT module=CapabilityChecker rva=0x" << std::hex << func.entryAddress
                              << std::dec << " reason=" << vmSafetyReason << std::endl;
                    rejectedCount++;
                    continue;
                }

                CipherShell::Translator& selectedTranslator =
                    (!explicitlySelected && func.assignedLevel <= 2)
                    ? lightTranslator : translator;
                auto transResult = selectedTranslator.TranslateFunction(func);
                if (!transResult.success || transResult.instructions.empty()) {
                    rejectedCount++;
                    if (!transResult.failures.empty()) {
                        const auto& failure = transResult.failures.front();
                        std::cerr << "VM_TRANSLATE_FAIL module=Translator function_rva=0x" << std::hex
                                  << func.entryAddress << " instr_rva=0x" << failure.address << std::dec
                                  << " mnemonic=" << failure.mnemonic
                                  << " bytes=" << (failure.bytes.empty() ? "<empty>" : failure.bytes)
                                  << " reason=" << failure.reason << std::endl;
                    } else {
                        std::cerr << "VM_TRANSLATE_FAIL module=Translator function_rva=0x" << std::hex
                                  << func.entryAddress << std::dec
                                  << " reason=no_vm_instructions" << std::endl;
                    }
                    continue;
                }
                std::cout << "VM_PROFILE function_rva=0x" << std::hex
                          << func.entryAddress << std::dec
                          << " mode="
                          << (transResult.density == CipherShell::VMMicroDensity::Heavy
                              ? "heavy_micro" : "light_micro")
                          << " native_insn=" << transResult.nativeInstructionCount
                          << " micro_ops=" << transResult.microOpCount
                          << " ratio=" << transResult.microOpRatio << std::endl;

                std::string interpreterRejectReason;
                if (!IsRuntimeInterpreterProgram(transResult.instructions, is64, interpreterRejectReason)) {
                    std::cerr << "VM_REJECT module=VMRuntimeBuilder function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " reason=" << interpreterRejectReason << std::endl;
                    rejectedCount++;
                    continue;
                }

                CipherShell::VMIRModelPreflightConfig modelConfig{};
                modelConfig.corpusSeed =
                    vmOperandCodecSeed ^ func.entryAddress;
                modelConfig.corpusCount = 256;
                const auto modelPreflight =
                    CipherShell::VMIRModelPreflightVerifier::Verify(
                    func, transResult, buildCtx.opcodeMap,
                    buildCtx.registerMap, modelConfig);
                if (!modelPreflight.success) {
                    std::cerr << "VM_IR_MODEL_PREFLIGHT_FAIL module=VMIRModelPreflightVerifier"
                              << " function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " case=" << modelPreflight.failingCase
                              << " reason=" << modelPreflight.error << std::endl;
                    ++rejectedCount;
                    continue;
                }
                std::cout << "VM_IR_MODEL_PREFLIGHT_PASS function_rva=0x" << std::hex
                          << func.entryAddress << std::dec
                          << " cases=" << modelPreflight.casesExecuted
                          << " evidence=software_model_only" << std::endl;

                CipherShell::VMNativeDifferentialConfig nativeConfig{};
                nativeConfig.corpusSeed = modelConfig.corpusSeed;
                nativeConfig.corpusCount = modelConfig.corpusCount;
                nativeConfig.memorySize = modelConfig.memorySize;
                nativeConfig.timeoutMilliseconds = 1000;
                // 当前生产链没有隔离的同架构 native/handler worker，也尚未绑定
                // 本次 handler image。这里必须显式缺席并 fail-closed；软件 IR
                // 预检绝不能代替真实 CPU 与合成 handler 的逐例证据。
                nativeConfig.expectedHandlerImageDigest = 0;
                nativeConfig.evidenceProvider = nullptr;
                const auto nativeDifferential =
                    CipherShell::VMNativeDifferentialVerifier::Verify(
                        func, transResult, buildCtx.opcodeMap,
                        buildCtx.registerMap, nativeConfig);
                if (!nativeDifferential.success ||
                    !nativeDifferential.nativeCpuEvidenceVerified ||
                    !nativeDifferential.synthesizedHandlerEvidenceVerified) {
                    std::cerr << "VM_NATIVE_DIFFERENTIAL_FAIL"
                              << " module=VMNativeDifferentialVerifier"
                              << " function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " case=" << nativeDifferential.failingCase
                              << " reason=" << nativeDifferential.error << std::endl;
                    ++rejectedCount;
                    continue;
                }
                std::cout << "VM_NATIVE_DIFFERENTIAL_PASS function_rva=0x" << std::hex
                          << func.entryAddress << std::dec
                          << " cases=" << nativeDifferential.casesVerified
                          << " native_cpu=true synthesized_handlers=true" << std::endl;

                protectedFunctions.push_back(func);
                pendingTranslations.push_back(std::move(transResult));
        }

        const bool explicitTargets = !buildCtx.vm.targetFunctions.empty() ||
            !buildCtx.vm.targetRVAs.empty();
        if (explicitTargets && selectedCount == 0) {
            std::cerr << "VM_BUILD_FAIL module=FunctionSelect reason=explicit_targets_matched_none"
                      << std::endl;
            PrintFeatureStatus("vm", "failed", "explicit_targets_matched_none");
            return 1;
        }
        if (explicitTargets && rejectedCount != 0) {
            std::cerr << "VM_BUILD_FAIL module=FunctionSelect reason=explicit_target_rejected count="
                      << rejectedCount << std::endl;
            PrintFeatureStatus("vm", "failed", "explicit_target_rejected");
            return 1;
        }

        if (!pendingTranslations.empty()) {
            CipherShell::VMInstructionBridgeBuilder bridgeBuilder;
            bridgeResult = bridgeBuilder.Build(image.get(), protectedFunctions,
                pendingTranslations, buildCtx.vmBridgeSectionName,
                buildCtx.vmBridgeUnwindSectionName, buildCtx.vmGuardSectionName);
            if (!bridgeResult.success) {
                std::cerr << "VM_BRIDGE_FAIL module=VMInstructionBridgeBuilder reason="
                          << bridgeResult.error << std::endl;
                PrintFeatureStatus("vm", "failed", bridgeResult.error);
                return 1;
            }
            for (size_t i = 0; i < pendingTranslations.size(); ++i) {
                auto vmBytecode = translator.GenerateBytecode(pendingTranslations[i]);
                if (vmBytecode.empty()) {
                    std::cerr << "VM_BYTECODE_FAIL module=TranslatorBytecode function_rva=0x"
                              << std::hex << protectedFunctions[i].entryAddress << std::dec
                              << " reason=unlinked_or_invalid_bytecode" << std::endl;
                    PrintFeatureStatus("vm", "failed", "unlinked_or_invalid_bytecode");
                    return 1;
                }
                CipherShell::VMFunctionRecord record{};
                record.functionRVA = static_cast<uint32_t>(protectedFunctions[i].entryAddress);
                record.functionSize = protectedFunctions[i].size;
                record.bytecodeOffset = static_cast<uint32_t>(vmBytecodeBlob.size());
                record.bytecodeSize = static_cast<uint32_t>(vmBytecode.size());
                record.flags = is64 ? static_cast<uint32_t>(VM_RECORD_FLAG_X64) : 0u;
                if (pendingTranslations[i].usesSimd) record.flags |= VM_RECORD_FLAG_USES_SIMD;
                if (pendingTranslations[i].usesAvx) record.flags |= VM_RECORD_FLAG_USES_AVX;
                if (pendingTranslations[i].usesX87) record.flags |= VM_RECORD_FLAG_USES_X87;
                record.returnStackCleanup = pendingTranslations[i].returnStackCleanup;
                record.guestStackSize = static_cast<uint32_t>(config.vm.stackSize);
                vmRecords.push_back(record);
                vmBytecodeBlob.insert(vmBytecodeBlob.end(), vmBytecode.begin(), vmBytecode.end());
                ++virtualizedCount;
            }
        }

        if (!vmRecords.empty()) {
            CipherShell::LoaderImportBuilder runtimeImportBuilder;
            vmRuntimeImports = runtimeImportBuilder.Build(
                image.get(), buildCtx.vmRuntimeApiSectionName);
            if (!vmRuntimeImports.success ||
                vmRuntimeImports.virtualProtectIatRVA == 0 ||
                vmRuntimeImports.flushInstructionCacheIatRVA == 0) {
                std::cerr << "VM_INIT_FAIL module=LoaderImportBuilder reason="
                          << vmRuntimeImports.error << std::endl;
                PrintFeatureStatus("vm", "failed",
                    "runtime_api_imports_unavailable");
                return 1;
            }

            CipherShell::VMSectionEmitter vmEmitter;
            emitResult = vmEmitter.Emit(image.get(), vmBytecodeBlob, vmRecords,
                buildCtx.opcodeMap, buildCtx.registerMap,
                mutatedISA.handlerSemanticToSlot, mutatedISA.handlerSlotToSemantic,
                mutatedISA.handlerVariants, mutatedISA.junkHandlerCount,
                mutatedISA.handlerMutationEnabled, mutatedISA.junkHandlersEnabled,
                vmOperandCodecSeed,
                0, buildCtx.vmSectionName);
            if (!emitResult.success) {
                std::cerr << "VM_EMIT_FAIL module=VMSectionEmitter reason=" << emitResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", emitResult.error);
                return 1;
            }
            vmRecords = emitResult.records;

            CipherShell::VMRuntimeBuilder runtimeBuilder;
            CipherShell::VMHandlerSynthesisConfig synthesisConfig{};
            synthesisConfig.architecture = is64
                ? CipherShell::VMHandlerArchitecture::X64
                : CipherShell::VMHandlerArchitecture::X86;
            synthesisConfig.buildSeed = buildCtx.isaSeed;
            synthesisConfig.handlerSemanticToSlot =
                emitResult.handlerSemanticToSlot;
            synthesisConfig.handlerSlotToSemantic =
                emitResult.handlerSlotToSemantic;
            synthesisConfig.handlerVariants = emitResult.handlerVariants;
            synthesisConfig.variantCount = VM_HANDLER_VARIANT_COUNT;
            synthesisConfig.operandCodec.opcodeXor =
                static_cast<uint8_t>(buildCtx.isaSeed[3] | 1u);
            synthesisConfig.operandCodec.opcodeAdd =
                static_cast<uint8_t>(buildCtx.isaSeed[7] | 1u);
            synthesisConfig.operandCodec.opcodeRotate =
                static_cast<uint8_t>((buildCtx.isaSeed[11] % 7u) + 1u);
            synthesisConfig.virtualProtectIatRVA =
                vmRuntimeImports.virtualProtectIatRVA;
            synthesisConfig.flushInstructionCacheIatRVA =
                vmRuntimeImports.flushInstructionCacheIatRVA;
            runtimeResult = runtimeBuilder.Build(image.get(), vmRecords,
                emitResult.metadataRVA, emitResult.runtimeKeyShare,
                synthesisConfig,
                buildCtx.vmRuntimeSectionName,
                buildCtx.vmUnwindSectionName,
                buildCtx.vmRelocSectionName);
            if (!runtimeResult.success ||
                !runtimeResult.handlerSynthesisVerified ||
                !runtimeResult.directThreadedVerified ||
                !runtimeResult.handlerEncryptionVerified ||
                !runtimeResult.runtimeContentVerified) {
                std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder reason=" << runtimeResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", runtimeResult.error);
                return 1;
            }

            std::string patchError;
            const uint32_t runtimeVerifiedFlags =
                (runtimeResult.unwindVerified
                    ? static_cast<uint32_t>(VM_METADATA_FLAG_UNWIND_VERIFIED) : 0u) |
                VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
                VM_METADATA_FLAG_DIRECT_THREADED |
                VM_METADATA_FLAG_HANDLER_ENCRYPTED;
            const uint32_t linkageVerifiedFlags = runtimeVerifiedFlags |
                (runtimeResult.cfgVerified
                    ? static_cast<uint32_t>(VM_METADATA_FLAG_CFG_VERIFIED) : 0u);
            if (!vmEmitter.PatchLinkage(image.get(), emitResult.metadataRVA,
                    runtimeResult.sectionRVA, runtimeResult.runtimeEntryRVA,
                    runtimeResult.runtimeImageSize,
                    runtimeResult.trampolines, emitResult.runtimeKeyShare,
                    linkageVerifiedFlags, &patchError)) {
                std::cerr << "VM_METADATA_FAIL module=VMMetadataResolver reason=" << patchError << std::endl;
                                PrintFeatureStatus("vm", "failed", patchError);
                return 1;
            }

            if (!runtimeResult.executionReady) {
                std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder reason=" << runtimeResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", runtimeResult.error);
                return 1;
            }

            CipherShell::FunctionTrampolinePatcher patcher;
            patchResults = patcher.PatchFunctions(
                image.get(), runtimeResult.trampolines, vmRecords, protectedFunctions, true);
            for (const auto& patch : patchResults) {
                if (!patch.success) {
                    std::cerr << "VM_PATCH_FAIL module=FunctionTrampolinePatcher function_rva=0x"
                              << std::hex << patch.functionRVA << std::dec
                              << " reason=" << patch.error << std::endl;
                                        PrintFeatureStatus("vm", "failed", patch.error);
                    return 1;
                }
            }

            if (!vmEmitter.PatchLinkage(image.get(), emitResult.metadataRVA,
                    runtimeResult.sectionRVA, runtimeResult.runtimeEntryRVA,
                    runtimeResult.runtimeImageSize,
                    runtimeResult.trampolines,
                    emitResult.runtimeKeyShare,
                    VM_METADATA_FLAG_NATIVE_BODY_DESTROYED | linkageVerifiedFlags, &patchError)) {
                std::cerr << "VM_METADATA_FAIL module=VMMetadataResolver reason=" << patchError << std::endl;
                PrintFeatureStatus("vm", "failed", patchError);
                return 1;
            }

            std::string staticCheckReason;
            std::unordered_map<uint32_t, uint32_t> vmOpcodeCounts;
            if (!ValidateVMStaticLink(image.get(), vmRecords, vmBytecodeBlob, emitResult, runtimeResult,
                    bridgeResult,
                    patchResults, buildCtx.opcodeMap, buildCtx.registerMap,
                    transConfig.virtualRegisterCount, vmOpcodeCounts, staticCheckReason)) {
                std::cerr << "VM_STATIC_CHECK_FAIL module=VMStaticLinkChecker reason="
                          << staticCheckReason << std::endl;
                PrintFeatureStatus("vm", "failed", staticCheckReason);
                return 1;
            }
            std::cout << "VM_STATIC_CHECK_PASS module=VMStaticLinkChecker records="
                      << vmRecords.size() << std::endl;
            vmApplied = true;
            std::cout << "VM_RUNTIME_SECTION rva=0x" << std::hex << runtimeResult.sectionRVA
                      << " raw=0x" << runtimeResult.sectionRawOffset
                      << " size=0x" << runtimeResult.sectionSize
                      << " entry=0x" << runtimeResult.runtimeEntryRVA << std::dec << std::endl;
            std::cout << "VM_METADATA_SECTION rva=0x" << std::hex << emitResult.sectionRVA
                      << " raw=0x" << emitResult.sectionRawOffset
                      << " size=0x" << emitResult.sectionSize
                      << " metadata=0x" << emitResult.metadataRVA
                      << " bytecode=0x" << emitResult.bytecodeRVA << std::dec << std::endl;
            std::cout << "VM_RUNTIME_CAPABILITIES schema=0x" << std::hex << VM_SCHEMA_VERSION
                      << " metadata=0x" << VM_METADATA_VERSION
                      << " runtime=0x" << VM_RUNTIME_VERSION << std::dec
                      << " scalar_memory=true memory_arithmetic=true"
                      << " native_call_bridge=false intra_vm_direct_call=true simd_x87_bridge=true"
                      << " fail_policy=error_code_in_eax_then_int3_ud2" << std::endl;

            for (const auto& record : vmRecords) {
                const CipherShell::VMTrampolineRecord* trampoline = nullptr;
                const CipherShell::FunctionPatchResult* patch = nullptr;
                for (const auto& tr : runtimeResult.trampolines) {
                    if (tr.functionRVA == record.functionRVA) { trampoline = &tr; break; }
                }
                for (const auto& pr : patchResults) {
                    if (pr.functionRVA == record.functionRVA) { patch = &pr; break; }
                }
                uint32_t opcodeCount = 0;
                auto countIt = vmOpcodeCounts.find(record.functionRVA);
                if (countIt != vmOpcodeCounts.end()) opcodeCount = countIt->second;
                std::cout << "VM_RECORD function_rva=0x" << std::hex << record.functionRVA
                          << " original_size=0x" << record.functionSize
                          << " trampoline_rva=0x" << (trampoline ? trampoline->trampolineRVA : 0)
                          << " trampoline_size=0x" << (trampoline ? trampoline->trampolineSize : 0)
                          << " patch_type=" << (patch ? PatchKindName(patch->patchKind) : "none")
                          << " bytecode_offset=0x" << record.bytecodeOffset
                          << " bytecode_size=0x" << record.bytecodeSize
                          << " guest_stack_size=0x" << record.guestStackSize
                          << " opcode_count=" << std::dec << opcodeCount
                          << " patched_first16=" << FormatImageBytesAtRva(image.get(), record.functionRVA, 16)
                          << " trampoline_first16=" << FormatImageBytesAtRva(image.get(), trampoline ? trampoline->trampolineRVA : 0, 16)
                          << std::endl;
            }
        } else {
            std::cerr << "VM_BUILD_FAIL module=VM reason=no_supported_functions" << std::endl;
            PrintFeatureStatus("vm", "failed", "no_supported_functions");
            return 1;
        }

        std::cout << "    VM bytecode 写入函数数: " << virtualizedCount
                  << "，拒绝函数数: " << rejectedCount << std::endl;

    }
    // Phase F: Section 加密 —— 弱加密（未认证算法 + 可恢复密钥），不具备生产语义闭环。
    // 由 CapabilityChecker 在任何 PE 修改之前 fatal 拒绝；此处保留显式 fail-closed 守卫，
    // 绝不应用，绝不打印 applied/partial。
    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedSections;
    CipherShell::StubEmbedResult loaderResult{};
    bool loaderApplied = false;
    if (buildCtx.sectionEncryption.enabled) {
        std::cerr << "SECTION_ENCRYPTION_REJECT module=SectionEncryption"
                  << " reason=fail_closed_unfinished_cipher_with_recoverable_key" << std::endl;
        PrintFeatureStatus("section_encryption", "rejected", "fail_closed_unfinished_closure");
        return 1;
    }
    PrintFeatureStatus("section_encryption", "skipped", "disabled");

    // 字符串运行时解密任务区域始终为空（string encryption 已 fail-closed）。
    (void)encryptedStringRegions;

    // ============================================================================
    // Step 3: 签名消除
    // ============================================================================

    std::cout << "\n[3/5] 消除壳签名..." << std::endl;

    {
        CipherShell::SignatureEliminator sigEliminator;

        auto sigMatches = sigEliminator.DetectSignatures(image.get());
        if (!sigMatches.empty()) {
            std::cout << "  发现 " << sigMatches.size() << " 个签名匹配:" << std::endl;
            for (const auto& match : sigMatches) {
                std::cout << "    - " << match.signatureName << " (" << match.detector << ")" << std::endl;
            }
        }

        CipherShell::EliminationConfig elimConfig;
        sigEliminator.EliminateSignatures(image.get(), elimConfig);

        if (sigEliminator.VerifyElimination(image.get())) {
            std::cout << "  签名消除成功" << std::endl;
        } else {
            std::cout << "  警告: 仍有签名残留" << std::endl;
        }
    }

    // ============================================================================
    // Step 4: 嵌入 Stub
    // ============================================================================

    std::cout << "\n[4/6] 嵌入解密 Stub..." << std::endl;

    if (!encryptedSections.empty()) {
        CipherShell::StubBuilder stubBuilder;
        loaderResult = stubBuilder.EmbedStub(
            image.get(), encryptedSections, originalOEP, buildCtx.vm.enabled);
        if (!loaderResult.success) {
            std::cerr << "LOADER_BUILD_FAIL module=StubBuilder reason="
                      << loaderResult.error << std::endl;
            return 1;
        }
        std::cout << "LOADER_WX_PASS stub_rva=0x" << std::hex << loaderResult.stubRVA
                  << " stub_size=0x" << loaderResult.stubSize
                  << " virtual_protect_iat=0x" << loaderResult.virtualProtectIatRVA
                  << " flush_icache_iat=0x" << loaderResult.flushInstructionCacheIatRVA
                  << " tls_callback_array=0x" << loaderResult.tlsCallbackArrayRVA
                  << std::dec << " mode="
                  << (loaderResult.installedAsTlsCallback ? "tls_first" : "entrypoint")
                  << " wx_verified=" << (loaderResult.wxVerified ? "true" : "false")
                  << std::endl;
        loaderApplied = true;
    } else {
        std::cout << "  跳过（没有需要解密的 section）" << std::endl;
    }

    // ============================================================================
    // Step 5: 重建 PE
    // ============================================================================

    std::cout << "\n[5/6] 写入输出文件..." << std::endl;

    CipherShell::PERebuilder rebuilder;
    CipherShell::CS_REBUILD_CONFIG rebuildConfig;

    rebuildConfig.randomizeSectionNames = config.global.randomizeSections;
    rebuildConfig.zeroTimestamps = config.global.stripTimestamps;
    rebuildConfig.preserveRichHeader = !config.global.stripRichHeader;
    rebuildConfig.preserveDebugInfo = !config.global.stripDebugInfo;

    DWORD outputSize = 0;
    std::unique_ptr<BYTE[]> outputData(rebuilder.RebuildImage(image.get(), rebuildConfig, &outputSize));

    if (!outputData || outputSize == 0) {
        std::cerr << "错误: PE 重建失败" << std::endl;
        return 1;
    }

    BYTE* verificationBuffer = new(std::nothrow) BYTE[outputSize];
    if (!verificationBuffer) {
        std::cerr << "PE_STATIC_CHECK_FAIL module=PEVerifier reason=allocation_failed" << std::endl;
        return 1;
    }
    std::memcpy(verificationBuffer, outputData.get(), outputSize);
    CipherShell::CS_PE_IMAGE* rebuiltImage = parser.LoadFromBuffer(verificationBuffer, outputSize);
    if (!rebuiltImage || !rebuiltImage->isValid) {
        if (rebuiltImage) parser.FreeImage(rebuiltImage);
        else delete[] verificationBuffer;
        std::cerr << "PE_STATIC_CHECK_FAIL module=PEVerifier reason=rebuilt_image_parse_failed" << std::endl;
        return 1;
    }
    if (vmApplied) {
        std::string finalVMReason;
        std::unordered_map<uint32_t, uint32_t> finalOpcodeCounts;
        if (!ValidateVMStaticLink(rebuiltImage, vmRecords, vmBytecodeBlob, emitResult,
                runtimeResult, bridgeResult, patchResults, buildCtx.opcodeMap,
                buildCtx.registerMap, vmRegisterCount, finalOpcodeCounts, finalVMReason)) {
            parser.FreeImage(rebuiltImage);
            std::cerr << "VM_FINAL_STATIC_CHECK_FAIL module=VMStaticLinkChecker reason="
                      << finalVMReason << std::endl;
            return 1;
        }
    }
    if (loaderApplied) {
        std::string loaderReason;
        if (!ValidateLoaderStaticLink(rebuiltImage, loaderResult, originalOEP, loaderReason)) {
            parser.FreeImage(rebuiltImage);
            std::cerr << "LOADER_FINAL_STATIC_CHECK_FAIL module=LoaderVerifier reason="
                      << loaderReason << std::endl;
            return 1;
        }
        std::cout << "LOADER_FINAL_STATIC_CHECK_PASS module=LoaderVerifier" << std::endl;
    }
    parser.FreeImage(rebuiltImage);
    std::cout << "PE_STATIC_CHECK_PASS module=PEVerifier" << std::endl;

    std::cout << "  PE 重建成功" << std::endl;
    std::cout << "  输出大小: " << outputSize << " 字节" << std::endl;

    // 写入输出文件
    FILE* outFile = fopen(outputFile.c_str(), "wb");
    if (!outFile) {
        std::cerr << "错误: 无法创建输出文件: " << outputFile << std::endl;
        return 1;
    }
    const size_t written = fwrite(outputData.get(), 1, outputSize, outFile);
    const int closeResult = fclose(outFile);
    if (written != outputSize || closeResult != 0) {
        std::remove(outputFile.c_str());
        std::cerr << "PE_WRITE_FAIL module=PEWriter reason=short_or_failed_write"
                  << " expected=" << outputSize << " written=" << written << std::endl;
        return 1;
    }

    std::cout << "  输出文件已保存: " << outputFile << std::endl;
    std::cout << "  文件大小: " << outputSize << " 字节" << std::endl;

    // ============================================================================
    // Step 6: 验证输出
    // ============================================================================

    std::cout << "\n[6/6] 验证输出文件..." << std::endl;

    CipherShell::CS_PE_IMAGE* verifyImage = parser.LoadFromFile(outputFile);
    if (!verifyImage || !verifyImage->isValid) {
        if (verifyImage) parser.FreeImage(verifyImage);
        std::remove(outputFile.c_str());
        std::cerr << "PE_WRITE_VERIFY_FAIL module=PEVerifier reason=written_image_parse_failed" << std::endl;
        return 1;
    }
    if (vmApplied) {
        std::string writtenVMReason;
        std::unordered_map<uint32_t, uint32_t> writtenOpcodeCounts;
        if (!ValidateVMStaticLink(verifyImage, vmRecords, vmBytecodeBlob, emitResult,
                runtimeResult, bridgeResult, patchResults, buildCtx.opcodeMap,
                buildCtx.registerMap, vmRegisterCount, writtenOpcodeCounts,
                writtenVMReason)) {
            parser.FreeImage(verifyImage);
            std::remove(outputFile.c_str());
            std::cerr << "VM_WRITE_VERIFY_FAIL module=VMStaticLinkChecker reason="
                      << writtenVMReason << std::endl;
            return 1;
        }
    }
    if (loaderApplied) {
        std::string loaderReason;
        if (!ValidateLoaderStaticLink(verifyImage, loaderResult, originalOEP, loaderReason)) {
            parser.FreeImage(verifyImage);
            std::remove(outputFile.c_str());
            std::cerr << "LOADER_WRITE_VERIFY_FAIL module=LoaderVerifier reason="
                      << loaderReason << std::endl;
            return 1;
        }
    }
    parser.FreeImage(verifyImage);
    std::cout << "  输出文件静态复验成功" << std::endl;
    if (vmApplied) {
        PrintFeatureStatus("vm", "applied", "functions=" + std::to_string(vmRecords.size()));
    }

    std::cout << "\n======================================" << std::endl;
    std::cout << "CipherShell 处理完成!" << std::endl;
    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}
