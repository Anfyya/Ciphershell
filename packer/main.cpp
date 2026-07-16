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
#include "differential/vm_native_differential_provider.h"
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

// ============================================================================
// VM Variant Group：分发去中心化 + 函数级 VM 异构的统一编排抽象。
//
// 现状（改动前）：VMHandlerSynthesizer::Synthesize() 对整个产物只调用一次，
// 所有被虚拟化函数共用同一份 opcode map / handler K 变体选择 / dispatch
// table。这里把它升级为 N 个相互独立的 Group：每个 Group 各自完整走一遍
// MutationEngine -> Translator -> VMHandlerSynthesizer -> VMSectionEmitter ->
// VMRuntimeBuilder -> FunctionTrampolinePatcher 这条既有流水线，只是种子、
// section 名字与函数子集不同。不改动 54 个微操作语义本身的 codegen
// （GenerateVMHandlerSemanticKernel），K 变体机制原样复用，只是"跑几遍、
// 每遍独立"。函数按 build seed 派生的哈希分到唯一一个 Group，组间不共享
// 可变状态，因而攻破一个 Group 的 opcode map/dispatch table 不直接复用于
// 其它 Group（§5 函数级异构）；同一产物里同时存在 N 套独立分发子，取代
// 原来"全二进制一张集中 dispatch table"的结构（§4 分发去中心化）。
namespace {

uint64_t MixVMGroupSeed(uint64_t value) {
    value ^= value >> 33;
    value *= 0xFF51AFD7ED558CCDULL;
    value ^= value >> 33;
    value *= 0xC4CEB9FE1A85EC53ULL;
    value ^= value >> 33;
    return value;
}

// groupCount==1 时必须与今天单 Group 行为逐位一致：groupId 0 的种子直接
// 复用 buildSeed 本身（不做任何变换），只有 groupId>=1 才真正派生出新种子。
std::array<uint8_t, 32> DeriveVMGroupSeed(
    const std::array<uint8_t, 32>& buildSeed, uint32_t groupId)
{
    if (groupId == 0) return buildSeed;
    std::array<uint8_t, 32> out{};
    for (size_t lane = 0; lane < 4; ++lane) {
        uint64_t base = 0;
        std::memcpy(&base, buildSeed.data() + lane * 8, 8);
        const uint64_t mixed = MixVMGroupSeed(base ^
            (static_cast<uint64_t>(groupId) << 32) ^
            (0x9E3779B97F4A7C15ULL * (lane + 1)) ^
            0x56475250554F5450ULL /* "VGROUPTP" 标签 */);
        std::memcpy(out.data() + lane * 8, &mixed, 8);
    }
    return out;
}

// 函数到 Group 的分配只依赖 build seed 与函数自身入口地址，不依赖遍历
// 顺序或候选函数总数，因此同一函数在同一次 build 里始终落在同一个 Group。
uint32_t AssignVMGroupId(
    const std::array<uint8_t, 32>& buildSeed,
    uint64_t functionEntryAddress,
    uint32_t groupCount)
{
    if (groupCount <= 1) return 0;
    uint64_t base = 0;
    std::memcpy(&base, buildSeed.data(), 8);
    const uint64_t mixed = MixVMGroupSeed(base ^ functionEntryAddress ^
        0x47524F5550494421ULL /* "GROUPID!" 标签 */);
    return static_cast<uint32_t>(mixed % groupCount);
}

// 每个 Group 的"预构建期"状态：变异引擎产生的 opcode map / handler 变体
// 布局、两个密度档的 Translator、原生差分证据源，全部按该 Group 自己的
// 种子生成，不与其它 Group 共享。
struct VMGroupRuntime {
    uint32_t groupId = 0;
    std::array<uint8_t, 32> groupSeed{};
    char sectionName[8] = {0};
    char runtimeSectionName[8] = {0};
    char unwindSectionName[8] = {0};
    char relocSectionName[8] = {0};
    char runtimeApiSectionName[8] = {0};
    CipherShell::MutationEngine mutEngine;
    CipherShell::MutatedISA mutatedISA;
    uint64_t operandCodecSeed = 0;
    CipherShell::Translator translator;
    CipherShell::Translator lightTranslator;
    CipherShell::VMWindowsNativeDifferentialEvidenceProvider nativeDifferentialProvider;
    bool nativeDifferentialProviderReady = false;
};

// 每个 Group 构建完成后的产物，供收尾阶段的两次静态复验（重建后/写盘后）
// 复用，且各 Group 独立校验，不合并进一张全局表。
struct VMGroupOutcome {
    uint32_t groupId = 0;
    std::vector<CipherShell::Function> protectedFunctions;
    std::vector<CipherShell::VMFunctionRecord> vmRecords;
    std::vector<uint8_t> vmBytecodeBlob;
    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;
    CipherShell::VMInstructionBridgeBuildResult bridgeResult{};
    CipherShell::VMEmitResult emitResult{};
    CipherShell::VMRuntimeBuildResult runtimeResult{};
    std::vector<CipherShell::FunctionPatchResult> patchResults;
    std::unordered_map<uint32_t, uint32_t> vmOpcodeCounts;
};

} // namespace

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

    // Phase C: 先建立独立 CFG 保护计划，此时不修改原始代码。
    // 真正的本地块拷贝/分发/入口修补放在 VM 之后一次性提交，
    // 使 CFG-only 与 VM+CFG 都走同一条完整闭环。
    bool cfgApplied = false;
    CipherShell::CFGProtectionResult cfgProtectionResult{};
    std::vector<CipherShell::Function> cfgProtectedFunctions;
    std::unordered_set<uint32_t> cfgFunctionRVAs;
    if (buildCtx.flattening.enabled) {
        CipherShell::Disassembler cfgDisassembler;
        const bool cfgIs64 = image->is64Bit != 0;
        cfgDisassembler.Initialize(cfgIs64,
            cfgIs64 ? image->ntHeaders64->OptionalHeader.ImageBase
                    : image->ntHeaders32->OptionalHeader.ImageBase);
        CipherShell::FunctionDiscovery cfgDiscovery;
        auto cfgDiscoveryResult = cfgDiscovery.Discover(
            image.get(), cfgDisassembler, buildCtx.flattening.targetRVAs);
        if (!cfgDiscoveryResult.success) {
            std::cerr << "CFG_DISCOVERY_FAIL module=FunctionDiscovery reason="
                      << cfgDiscoveryResult.error << std::endl;
            PrintFeatureStatus("control_flow.flattening", "failed",
                cfgDiscoveryResult.error);
            return 1;
        }
        for (const auto& issue : cfgDiscoveryResult.issues) {
            std::cerr << "CFG_DISCOVERY_REJECT module=FunctionDiscovery rva=0x"
                      << std::hex << issue.rva << std::dec
                      << " reason=" << issue.reason << std::endl;
        }
        for (const auto& pattern : buildCtx.flattening.targetFunctions) {
            const bool matched = std::any_of(cfgDiscoveryResult.functions.begin(),
                cfgDiscoveryResult.functions.end(), [&](const CipherShell::Function& function) {
                    std::ostringstream rva;
                    rva << "0x" << std::hex << function.entryAddress;
                    return WildcardMatchInsensitive(pattern, function.name) ||
                        WildcardMatchInsensitive(pattern, rva.str());
                });
            if (!matched) {
                std::cerr << "CFG_BUILD_FAIL module=FunctionSelect"
                          << " reason=target_pattern_matched_none pattern="
                          << pattern << std::endl;
                PrintFeatureStatus("control_flow.flattening", "failed",
                    "target_pattern_matched_none");
                return 1;
            }
        }
        const bool cfgExplicitSelection =
            !buildCtx.flattening.targetFunctions.empty() ||
            !buildCtx.flattening.targetRVAs.empty();
        uint32_t cfgRejected = 0u;
        for (const CipherShell::Function& function : cfgDiscoveryResult.functions) {
            if (!FunctionSelected(function, buildCtx.flattening.targetFunctions,
                    buildCtx.flattening.targetRVAs)) continue;
            std::string safetyReason;
            if (!capabilityChecker.IsFunctionCfgSafe(
                    image.get(), function, safetyReason)) {
                ++cfgRejected;
                std::cerr << "CFG_REJECT module=CapabilityChecker rva=0x"
                          << std::hex << function.entryAddress << std::dec
                          << " reason=" << safetyReason << std::endl;
                if (cfgExplicitSelection) {
                    PrintFeatureStatus("control_flow.flattening", "failed",
                        "explicit_target_not_cfg_safe");
                    return 1;
                }
                continue;
            }
            const uint32_t rva = static_cast<uint32_t>(function.entryAddress);
            cfgFunctionRVAs.insert(rva);
            cfgProtectedFunctions.push_back(function);
        }
        if (cfgProtectedFunctions.empty()) {
            std::cerr << "CFG_BUILD_FAIL module=FunctionSelect"
                      << " reason=no_cfg_safe_functions rejected=" << cfgRejected
                      << std::endl;
            PrintFeatureStatus("control_flow.flattening", "failed",
                "no_cfg_safe_functions");
            return 1;
        }
        const bool vmExplicitSelection = !buildCtx.vm.targetFunctions.empty() ||
            !buildCtx.vm.targetRVAs.empty();
        if (buildCtx.vm.enabled && vmExplicitSelection) {
            for (const CipherShell::Function& function : cfgProtectedFunctions) {
                if (FunctionSelected(function, buildCtx.vm.targetFunctions,
                        buildCtx.vm.targetRVAs)) {
                    std::cerr << "CFG_BUILD_FAIL module=FunctionSelect rva=0x"
                              << std::hex << function.entryAddress << std::dec
                              << " reason=explicit_vm_cfg_target_overlap" << std::endl;
                    PrintFeatureStatus("control_flow.flattening", "failed",
                        "explicit_vm_cfg_target_overlap");
                    return 1;
                }
            }
        }
        std::cout << "CFG_PLAN_PASS module=CFGFlattener functions="
                  << cfgProtectedFunctions.size()
                  << " rejected=" << cfgRejected
                  << " vm_independent=true" << std::endl;
    } else {
        PrintFeatureStatus("control_flow.flattening", "skipped", "disabled");
    }

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
    std::vector<VMGroupOutcome> vmGroupOutcomes;
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

        const uint32_t vmRegisterCountConfig = static_cast<uint32_t>(config.vm.registerCount);
        constexpr uint32_t kVmNativeDifferentialMemorySize = 0x10000u;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        disasm.Initialize(is64, is64 ? image->ntHeaders64->OptionalHeader.ImageBase
                                     : image->ntHeaders32->OptionalHeader.ImageBase);
        uint32_t virtualizedCount = 0;
        uint32_t rejectedCount = 0;
        uint32_t selectedCount = 0;
        std::vector<CipherShell::Function> allProtectedFunctions;
        std::vector<CipherShell::TranslationResult> allPendingTranslations;
        std::vector<uint32_t> allFunctionGroupIds;

        CipherShell::FunctionDiscovery functionDiscovery;
        auto discoveryResult = functionDiscovery.Discover(
            image.get(), disasm, buildCtx.vm.targetRVAs);
        if (!discoveryResult.success) {
            std::cerr << "VM_DISCOVERY_FAIL module=FunctionDiscovery reason="
                      << discoveryResult.error << std::endl;
            // discoveryResult.error 只是最终的汇总性失败（比如"没有发现任何
            // 可信函数边界"）；success=false 时上面这一条会直接 return，之前
            // 每个候选 root 具体为什么被拒绝（issues）从未被打印过，诊断时
            // 完全看不到中间过程。这里补上，纯诊断，不改变任何判定逻辑。
            for (const auto& issue : discoveryResult.issues) {
                std::cerr << "VM_DISCOVERY_REJECT module=FunctionDiscovery rva=0x"
                          << std::hex << issue.rva << std::dec
                          << " reason=" << issue.reason << std::endl;
            }
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

        // Pass A：只做与 Group 无关的筛选（显式目标匹配 / CFG 互斥 / native_unprotected
        // 降级 / 尺寸与地址范围校验 / CapabilityChecker），先拿到真正会进入 VM 的候选
        // 函数列表，Group 数量的自适应策略要量的是"实际候选数"，不是"全部发现函数数"。
        std::vector<CipherShell::Function> eligibleFunctions;
        for (const auto& func : discoveryResult.functions) {
                if (!FunctionSelected(func, buildCtx.vm.targetFunctions,
                        buildCtx.vm.targetRVAs)) continue;
                if (func.entryAddress <= 0xFFFFFFFFULL &&
                    cfgFunctionRVAs.count(static_cast<uint32_t>(func.entryAddress)) != 0u) {
                    std::cout << "VM_PROFILE function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " mode=cfg_flatten vm=skipped" << std::endl;
                    continue;
                }
                ++selectedCount;
                const bool explicitlySelectedForEligibility =
                    !buildCtx.vm.targetFunctions.empty() ||
                    !buildCtx.vm.targetRVAs.empty();
                if (!explicitlySelectedForEligibility && func.assignedLevel <= 1) {
                    std::cout << "VM_PROFILE function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " mode=native_unprotected vm=skipped" << std::endl;
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

                eligibleFunctions.push_back(func);
        }

        // Group 数量：variant_group_count==0 表示自适应——按候选函数数量
        // ceil(eligible / variant_group_functions_per_group)，夹在
        // [1, variant_group_max] 之间；否则使用显式配置的固定组数。两种
        // 模式都不允许得到 0：vmGroupCount==1 时 DeriveVMGroupSeed/
        // AssignVMGroupId/DeriveGroupSectionName 均退化为改动前的单 Group
        // 行为，逐位一致。
        if (config.vm.variantGroupCount < 0 || config.vm.variantGroupCount > 64) {
            std::cerr << "VM_INIT_FAIL module=VMGroupPolicy reason=variant_group_count_out_of_range"
                      << " value=" << config.vm.variantGroupCount << std::endl;
            PrintFeatureStatus("vm", "failed", "variant_group_count_out_of_range");
            return 1;
        }
        if (config.vm.variantGroupMax < 1 || config.vm.variantGroupMax > 64) {
            std::cerr << "VM_INIT_FAIL module=VMGroupPolicy reason=variant_group_max_out_of_range"
                      << " value=" << config.vm.variantGroupMax << std::endl;
            PrintFeatureStatus("vm", "failed", "variant_group_max_out_of_range");
            return 1;
        }
        if (config.vm.variantGroupFunctionsPerGroup < 1) {
            std::cerr << "VM_INIT_FAIL module=VMGroupPolicy"
                      << " reason=variant_group_functions_per_group_must_be_positive"
                      << " value=" << config.vm.variantGroupFunctionsPerGroup << std::endl;
            PrintFeatureStatus("vm", "failed", "variant_group_functions_per_group_must_be_positive");
            return 1;
        }
        uint32_t vmGroupCount;
        if (config.vm.variantGroupCount > 0) {
            vmGroupCount = static_cast<uint32_t>(config.vm.variantGroupCount);
        } else {
            const uint32_t functionsPerGroup =
                static_cast<uint32_t>(config.vm.variantGroupFunctionsPerGroup);
            const uint32_t eligibleCount = static_cast<uint32_t>(eligibleFunctions.size());
            const uint32_t autoCount = eligibleCount == 0
                ? 1u
                : (eligibleCount + functionsPerGroup - 1u) / functionsPerGroup;
            vmGroupCount = (std::max)(1u, (std::min)(
                autoCount, static_cast<uint32_t>(config.vm.variantGroupMax)));
        }
        std::cout << "VM_GROUP_POLICY mode="
                  << (config.vm.variantGroupCount > 0 ? "explicit" : "auto")
                  << " eligible_functions=" << eligibleFunctions.size()
                  << " vm_group_count=" << vmGroupCount << std::endl;

        std::vector<VMGroupRuntime> vmGroups(vmGroupCount);
        for (uint32_t g = 0; g < vmGroupCount; ++g) {
            VMGroupRuntime& grp = vmGroups[g];
            grp.groupId = g;
            grp.groupSeed = DeriveVMGroupSeed(buildCtx.isaSeed, g);
            CipherShell::ProtectionBuildContext::DeriveGroupSectionName(
                grp.sectionName, buildCtx, buildCtx.vmSectionName, 0xC0DEu, g);
            CipherShell::ProtectionBuildContext::DeriveGroupSectionName(
                grp.runtimeSectionName, buildCtx, buildCtx.vmRuntimeSectionName, 0x51A7u, g);
            CipherShell::ProtectionBuildContext::DeriveGroupSectionName(
                grp.unwindSectionName, buildCtx, buildCtx.vmUnwindSectionName, 0xDA7Au, g);
            CipherShell::ProtectionBuildContext::DeriveGroupSectionName(
                grp.relocSectionName, buildCtx, buildCtx.vmRelocSectionName, 0x2E10u, g);

            CipherShell::MutationConfig mutConfig;
            mutConfig.randomizeOpcodeMap = true;
            mutConfig.randomizeRegisterMap = true;
            mutConfig.registerCount = vmRegisterCountConfig;
            mutConfig.seed = grp.groupSeed;
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
            if (!grp.mutEngine.Initialize(mutConfig)) {
                std::cerr << "VM_INIT_FAIL module=MutationEngine reason=register_count_must_be_16_to_32"
                          << " vm_group=" << g << std::endl;
                PrintFeatureStatus("vm", "failed", "invalid_register_count");
                return 1;
            }

            grp.mutatedISA = grp.mutEngine.GenerateMutatedISA();
            grp.operandCodecSeed = grp.mutEngine.GetSeedFingerprint();
            std::string registerMapReason;
            if (!ValidateVMRegisterMap(grp.mutatedISA.registerMap, mutConfig.registerCount, registerMapReason)) {
                std::cerr << "VM_INIT_FAIL module=MutationEngine reason=" << registerMapReason
                          << " vm_group=" << g << std::endl;
                PrintFeatureStatus("vm", "failed", registerMapReason);
                return 1;
            }
            std::cout << "    ISA seed fingerprint (vm_group=" << g << "): 0x" << std::hex
                      << grp.operandCodecSeed << std::dec << std::endl;
            std::cout << "VM_HANDLER_LAYOUT vm_group=" << g
                      << " mutated=" << (grp.mutatedISA.handlerMutationEnabled ? "true" : "false")
                      << " junk_handlers=" << grp.mutatedISA.junkHandlerCount
                      << " variant_count=" << VM_HANDLER_VARIANT_COUNT << std::endl;

            // 隔离原生差分证据源：每个 Group 只合成一次 handler 镜像（与
            // 该 Group 最终 PE 里写入的 handler 语义等价，只是 decryptor
            // IAT 槽位不同——那两个槽位只影响 W^X 解密流程，不影响任何
            // 一条微语义的计算结果），后续这个 Group 里每个候选函数的每
            // 个 corpus case 都复用它。worker 缺失、初始化失败或架构不
            // 匹配都必须让这个 Group 下每个函数的 native differential
            // 检查 fail-closed，不能有静默降级路径。
            CipherShell::VMHandlerOperandCodecConfig nativeDifferentialOperandCodec{};
            nativeDifferentialOperandCodec.opcodeXor = static_cast<uint8_t>(grp.groupSeed[3] | 1u);
            nativeDifferentialOperandCodec.opcodeAdd = static_cast<uint8_t>(grp.groupSeed[7] | 1u);
            nativeDifferentialOperandCodec.opcodeRotate =
                static_cast<uint8_t>((grp.groupSeed[11] % 7u) + 1u);
            std::string nativeDifferentialInitError;
            grp.nativeDifferentialProviderReady = grp.nativeDifferentialProvider.Initialize(
                image->is64Bit
                    ? CipherShell::VMHandlerArchitecture::X64
                    : CipherShell::VMHandlerArchitecture::X86,
                grp.groupSeed,
                grp.mutatedISA.handlerSemanticToSlot,
                grp.mutatedISA.handlerSlotToSemantic,
                grp.mutatedISA.handlerVariants,
                nativeDifferentialOperandCodec,
                kVmNativeDifferentialMemorySize,
                nativeDifferentialInitError);
            if (!grp.nativeDifferentialProviderReady) {
                std::cerr << "VM_NATIVE_DIFFERENTIAL_PROVIDER_INIT_FAIL vm_group=" << g
                          << " reason=" << nativeDifferentialInitError << std::endl;
                std::cerr << "VM_NATIVE_DIFFERENTIAL_PROVIDER_INIT_FAIL every candidate function "
                             "in this group will fail closed at the native differential gate below"
                          << std::endl;
            }

            CipherShell::TranslationConfig transConfig;
            transConfig.virtualRegisterCount = mutConfig.registerCount;
            transConfig.buildSeed = grp.operandCodecSeed;
            transConfig.density = CipherShell::VMMicroDensity::Heavy;
            transConfig.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
            transConfig.x86CallAbi = configuredX86CallAbi;
            transConfig.enableSimdBridge = config.vm.simdBridge;
            transConfig.enableX87Bridge = config.vm.x87Bridge;
            for (const auto& dll : image->imports.dlls) {
                for (const auto& imported : dll.functions) {
                    transConfig.importThunkRVAs.insert(imported.thunkRVA);
                }
            }
            if (!grp.translator.Initialize(transConfig)) {
                std::cerr << "VM_INIT_FAIL module=Translator reason=initialize_failed"
                          << " vm_group=" << g << std::endl;
                return 1;
            }
            grp.translator.SetOpcodeMap(grp.mutatedISA.opcodeMap);
            grp.translator.SetRegisterMap(grp.mutatedISA.registerMap);
            CipherShell::TranslationConfig lightConfig = transConfig;
            lightConfig.density = CipherShell::VMMicroDensity::Light;
            if (!grp.lightTranslator.Initialize(lightConfig)) {
                std::cerr << "VM_INIT_FAIL module=Translator reason=light_initialize_failed"
                          << " vm_group=" << g << std::endl;
                return 1;
            }
            grp.lightTranslator.SetOpcodeMap(grp.mutatedISA.opcodeMap);
            grp.lightTranslator.SetRegisterMap(grp.mutatedISA.registerMap);
            if (g == 0) PrintVMRegisterMapReport(grp.mutatedISA.registerMap);
        }
        vmRegisterCount = vmRegisterCountConfig;
        vmGroupOutcomes.resize(vmGroupCount);
        for (uint32_t g = 0; g < vmGroupCount; ++g) vmGroupOutcomes[g].groupId = g;

        // Pass B：对 Pass A 筛出的候选函数分组、翻译、软件模型/原生差分校验。
        for (const auto& func : eligibleFunctions) {
                const bool explicitlySelected =
                    !buildCtx.vm.targetFunctions.empty() ||
                    !buildCtx.vm.targetRVAs.empty();

                // 函数级 VM 异构：分组只依赖 build seed 与函数自身入口地址，
                // 与遍历顺序、CFG/native_unprotected 之类的其它分支无关。
                const uint32_t vmGroupId = AssignVMGroupId(
                    buildCtx.isaSeed, func.entryAddress, vmGroupCount);
                VMGroupRuntime& grp = vmGroups[vmGroupId];

                CipherShell::Translator& selectedTranslator =
                    (!explicitlySelected && func.assignedLevel <= 2)
                    ? grp.lightTranslator : grp.translator;
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
                          << " vm_group=" << vmGroupId
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
                    grp.operandCodecSeed ^ func.entryAddress;
                modelConfig.corpusCount = 256;
                // Must match kVmNativeDifferentialMemorySize: the native
                // differential gate below reuses this corpus's memory size.
                modelConfig.memorySize = kVmNativeDifferentialMemorySize;
                // 纯标注，不影响校验逻辑：让 result.vmGroupId 能回答"这份
                // 证据是哪个 VM Variant Group 产出的"，为后续多 Group 交叉
                // 校验（确认互不干扰）打基础。
                modelConfig.vmGroupId = vmGroupId;
                const auto modelPreflight =
                    CipherShell::VMIRModelPreflightVerifier::Verify(
                    func, transResult, grp.mutatedISA.opcodeMap,
                    grp.mutatedISA.registerMap, modelConfig);
                if (!modelPreflight.success) {
                    std::cerr << "VM_IR_MODEL_PREFLIGHT_FAIL module=VMIRModelPreflightVerifier"
                              << " function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " vm_group=" << modelPreflight.vmGroupId
                              << " case=" << modelPreflight.failingCase
                              << " reason=" << modelPreflight.error << std::endl;
                    ++rejectedCount;
                    continue;
                }
                std::cout << "VM_IR_MODEL_PREFLIGHT_PASS function_rva=0x" << std::hex
                          << func.entryAddress << std::dec
                          << " vm_group=" << modelPreflight.vmGroupId
                          << " cases=" << modelPreflight.casesExecuted
                          << " evidence=software_model_only" << std::endl;

                // The synthesized handler's operand decode-plan table is keyed by
                // function RVA (matching how VMRuntimeBuilder builds the real
                // shipped table later), so it must be (re)prepared per function
                // before any of that function's corpus cases run.
                bool nativeDifferentialFunctionReady = false;
                if (grp.nativeDifferentialProviderReady) {
                    std::string prepareError;
                    nativeDifferentialFunctionReady = grp.nativeDifferentialProvider.PrepareForFunction(
                        static_cast<uint32_t>(func.entryAddress), transResult.operandCodec,
                        prepareError);
                    if (!nativeDifferentialFunctionReady) {
                        std::cerr << "VM_NATIVE_DIFFERENTIAL_PROVIDER_PREPARE_FAIL function_rva=0x"
                                  << std::hex << func.entryAddress << std::dec
                                  << " reason=" << prepareError << std::endl;
                    }
                }

                CipherShell::VMNativeDifferentialConfig nativeConfig{};
                nativeConfig.corpusSeed = modelConfig.corpusSeed;
                nativeConfig.corpusCount = modelConfig.corpusCount;
                nativeConfig.memorySize = modelConfig.memorySize;
                nativeConfig.timeoutMilliseconds = 1000;
                // A missing/failed-to-initialize provider (worker binary absent,
                // wrong architecture, synthesis failure) must fail closed here,
                // never fall back to the software IR preflight as evidence.
                nativeConfig.expectedHandlerImageDigest = nativeDifferentialFunctionReady
                    ? grp.nativeDifferentialProvider.SemanticIdentityDigest() : 0;
                nativeConfig.evidenceProvider = nativeDifferentialFunctionReady
                    ? &grp.nativeDifferentialProvider : nullptr;
                // 同上：纯标注，供后续多 Group 交叉校验把每条证据和它的
                // Group 对应起来。
                nativeConfig.vmGroupId = vmGroupId;
                const auto nativeDifferential =
                    CipherShell::VMNativeDifferentialVerifier::Verify(
                        func, transResult, grp.mutatedISA.opcodeMap,
                        grp.mutatedISA.registerMap, nativeConfig);
                if (!nativeDifferential.success ||
                    !nativeDifferential.nativeCpuEvidenceVerified ||
                    !nativeDifferential.synthesizedHandlerEvidenceVerified) {
                    std::cerr << "VM_NATIVE_DIFFERENTIAL_FAIL"
                              << " module=VMNativeDifferentialVerifier"
                              << " function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " vm_group=" << nativeDifferential.vmGroupId
                              << " case=" << nativeDifferential.failingCase
                              << " reason=" << nativeDifferential.error << std::endl;
                    ++rejectedCount;
                    continue;
                }
                std::cout << "VM_NATIVE_DIFFERENTIAL_PASS function_rva=0x" << std::hex
                          << func.entryAddress << std::dec
                          << " vm_group=" << nativeDifferential.vmGroupId
                          << " cases=" << nativeDifferential.casesVerified
                          << " native_cpu=true synthesized_handlers=true" << std::endl;

                allProtectedFunctions.push_back(func);
                allPendingTranslations.push_back(std::move(transResult));
                allFunctionGroupIds.push_back(vmGroupId);
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

        if (!allPendingTranslations.empty()) {
            // Native bridge/CALL 桥接是一个与 opcode map/dispatch 无关的
            // 通用子系统，不需要按 Group 分化：所有 Group 的函数共用同一份
            // bridge/guard section，构建一次即可，随后按各自 Group 拆分
            // bytecode/record。
            CipherShell::VMInstructionBridgeBuilder bridgeBuilder;
            auto sharedBridgeResult = bridgeBuilder.Build(image.get(), allProtectedFunctions,
                allPendingTranslations, buildCtx.vmBridgeSectionName,
                buildCtx.vmBridgeUnwindSectionName, buildCtx.vmGuardSectionName);
            if (!sharedBridgeResult.success) {
                std::cerr << "VM_BRIDGE_FAIL module=VMInstructionBridgeBuilder reason="
                          << sharedBridgeResult.error << std::endl;
                PrintFeatureStatus("vm", "failed", sharedBridgeResult.error);
                return 1;
            }
            for (auto& outcome : vmGroupOutcomes) outcome.bridgeResult = sharedBridgeResult;

            for (size_t i = 0; i < allProtectedFunctions.size(); ++i) {
                const uint32_t g = allFunctionGroupIds[i];
                VMGroupRuntime& grp = vmGroups[g];
                VMGroupOutcome& outcome = vmGroupOutcomes[g];
                auto vmBytecode = grp.translator.GenerateBytecode(allPendingTranslations[i]);
                if (vmBytecode.empty()) {
                    std::cerr << "VM_BYTECODE_FAIL module=TranslatorBytecode function_rva=0x"
                              << std::hex << allProtectedFunctions[i].entryAddress << std::dec
                              << " vm_group=" << g
                              << " reason=unlinked_or_invalid_bytecode" << std::endl;
                    PrintFeatureStatus("vm", "failed", "unlinked_or_invalid_bytecode");
                    return 1;
                }
                CipherShell::VMFunctionRecord record{};
                record.functionRVA = static_cast<uint32_t>(allProtectedFunctions[i].entryAddress);
                record.functionSize = allProtectedFunctions[i].size;
                record.bytecodeOffset = static_cast<uint32_t>(outcome.vmBytecodeBlob.size());
                record.bytecodeSize = static_cast<uint32_t>(vmBytecode.size());
                record.flags = is64 ? static_cast<uint32_t>(VM_RECORD_FLAG_X64) : 0u;
                if (allPendingTranslations[i].usesSimd) record.flags |= VM_RECORD_FLAG_USES_SIMD;
                if (allPendingTranslations[i].usesAvx) record.flags |= VM_RECORD_FLAG_USES_AVX;
                if (allPendingTranslations[i].usesX87) record.flags |= VM_RECORD_FLAG_USES_X87;
                record.returnStackCleanup = allPendingTranslations[i].returnStackCleanup;
                record.guestStackSize = static_cast<uint32_t>(config.vm.stackSize);
                outcome.vmRecords.push_back(record);
                outcome.vmBytecodeBlob.insert(outcome.vmBytecodeBlob.end(), vmBytecode.begin(), vmBytecode.end());
                outcome.protectedFunctions.push_back(allProtectedFunctions[i]);
                ++virtualizedCount;
            }
        }

        uint32_t totalVmRecords = 0;
        for (const auto& outcome : vmGroupOutcomes) totalVmRecords += static_cast<uint32_t>(outcome.vmRecords.size());

        if (totalVmRecords > 0) {
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

            for (uint32_t g = 0; g < vmGroupCount; ++g) {
                VMGroupOutcome& outcome = vmGroupOutcomes[g];
                if (outcome.vmRecords.empty()) continue;
                VMGroupRuntime& grp = vmGroups[g];

                CipherShell::VMSectionEmitter vmEmitter;
                outcome.emitResult = vmEmitter.Emit(image.get(), outcome.vmBytecodeBlob, outcome.vmRecords,
                    grp.mutatedISA.opcodeMap, grp.mutatedISA.registerMap,
                    grp.mutatedISA.handlerSemanticToSlot, grp.mutatedISA.handlerSlotToSemantic,
                    grp.mutatedISA.handlerVariants, grp.mutatedISA.junkHandlerCount,
                    grp.mutatedISA.handlerMutationEnabled, grp.mutatedISA.junkHandlersEnabled,
                    grp.operandCodecSeed,
                    0, grp.sectionName);
                if (!outcome.emitResult.success) {
                    std::cerr << "VM_EMIT_FAIL module=VMSectionEmitter vm_group=" << g
                              << " reason=" << outcome.emitResult.error << std::endl;
                    PrintFeatureStatus("vm", "failed", outcome.emitResult.error);
                    return 1;
                }
                outcome.vmRecords = outcome.emitResult.records;
                outcome.opcodeMap = grp.mutatedISA.opcodeMap;
                outcome.registerMap = grp.mutatedISA.registerMap;

                CipherShell::VMRuntimeBuilder runtimeBuilder;
                CipherShell::VMHandlerSynthesisConfig synthesisConfig{};
                synthesisConfig.architecture = is64
                    ? CipherShell::VMHandlerArchitecture::X64
                    : CipherShell::VMHandlerArchitecture::X86;
                synthesisConfig.buildSeed = grp.groupSeed;
                synthesisConfig.handlerSemanticToSlot =
                    outcome.emitResult.handlerSemanticToSlot;
                synthesisConfig.handlerSlotToSemantic =
                    outcome.emitResult.handlerSlotToSemantic;
                synthesisConfig.handlerVariants = outcome.emitResult.handlerVariants;
                synthesisConfig.variantCount = VM_HANDLER_VARIANT_COUNT;
                synthesisConfig.operandCodec.opcodeXor =
                    static_cast<uint8_t>(grp.groupSeed[3] | 1u);
                synthesisConfig.operandCodec.opcodeAdd =
                    static_cast<uint8_t>(grp.groupSeed[7] | 1u);
                synthesisConfig.operandCodec.opcodeRotate =
                    static_cast<uint8_t>((grp.groupSeed[11] % 7u) + 1u);
                synthesisConfig.virtualProtectIatRVA =
                    vmRuntimeImports.virtualProtectIatRVA;
                synthesisConfig.flushInstructionCacheIatRVA =
                    vmRuntimeImports.flushInstructionCacheIatRVA;
                outcome.runtimeResult = runtimeBuilder.Build(image.get(), outcome.vmRecords,
                    outcome.emitResult.metadataRVA, outcome.emitResult.runtimeKeyShare,
                    synthesisConfig,
                    grp.runtimeSectionName,
                    grp.unwindSectionName,
                    grp.relocSectionName);
                if (!outcome.runtimeResult.success ||
                    !outcome.runtimeResult.handlerSynthesisVerified ||
                    !outcome.runtimeResult.directThreadedVerified ||
                    !outcome.runtimeResult.handlerEncryptionVerified ||
                    !outcome.runtimeResult.runtimeContentVerified) {
                    std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder vm_group=" << g
                              << " reason=" << outcome.runtimeResult.error << std::endl;
                    PrintFeatureStatus("vm", "failed", outcome.runtimeResult.error);
                    return 1;
                }

                std::string patchError;
                const uint32_t runtimeVerifiedFlags =
                    (outcome.runtimeResult.unwindVerified
                        ? static_cast<uint32_t>(VM_METADATA_FLAG_UNWIND_VERIFIED) : 0u) |
                    VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
                    VM_METADATA_FLAG_DIRECT_THREADED |
                    VM_METADATA_FLAG_HANDLER_ENCRYPTED;
                const uint32_t linkageVerifiedFlags = runtimeVerifiedFlags |
                    (outcome.runtimeResult.cfgVerified
                        ? static_cast<uint32_t>(VM_METADATA_FLAG_CFG_VERIFIED) : 0u);
                if (!vmEmitter.PatchLinkage(image.get(), outcome.emitResult.metadataRVA,
                        outcome.runtimeResult.sectionRVA, outcome.runtimeResult.runtimeEntryRVA,
                        outcome.runtimeResult.runtimeImageSize,
                        outcome.runtimeResult.trampolines, outcome.emitResult.runtimeKeyShare,
                        linkageVerifiedFlags, &patchError)) {
                    std::cerr << "VM_METADATA_FAIL module=VMMetadataResolver vm_group=" << g
                              << " reason=" << patchError << std::endl;
                    PrintFeatureStatus("vm", "failed", patchError);
                    return 1;
                }

                if (!outcome.runtimeResult.executionReady) {
                    std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder vm_group=" << g
                              << " reason=" << outcome.runtimeResult.error << std::endl;
                    PrintFeatureStatus("vm", "failed", outcome.runtimeResult.error);
                    return 1;
                }

                CipherShell::FunctionTrampolinePatcher patcher;
                outcome.patchResults = patcher.PatchFunctions(
                    image.get(), outcome.runtimeResult.trampolines, outcome.vmRecords,
                    outcome.protectedFunctions, true);
                for (const auto& patch : outcome.patchResults) {
                    if (!patch.success) {
                        std::cerr << "VM_PATCH_FAIL module=FunctionTrampolinePatcher function_rva=0x"
                                  << std::hex << patch.functionRVA << std::dec
                                  << " vm_group=" << g
                                  << " reason=" << patch.error << std::endl;
                        PrintFeatureStatus("vm", "failed", patch.error);
                        return 1;
                    }
                }

                if (!vmEmitter.PatchLinkage(image.get(), outcome.emitResult.metadataRVA,
                        outcome.runtimeResult.sectionRVA, outcome.runtimeResult.runtimeEntryRVA,
                        outcome.runtimeResult.runtimeImageSize,
                        outcome.runtimeResult.trampolines,
                        outcome.emitResult.runtimeKeyShare,
                        VM_METADATA_FLAG_NATIVE_BODY_DESTROYED | linkageVerifiedFlags, &patchError)) {
                    std::cerr << "VM_METADATA_FAIL module=VMMetadataResolver vm_group=" << g
                              << " reason=" << patchError << std::endl;
                    PrintFeatureStatus("vm", "failed", patchError);
                    return 1;
                }

                std::string staticCheckReason;
                if (!ValidateVMStaticLink(image.get(), outcome.vmRecords, outcome.vmBytecodeBlob,
                        outcome.emitResult, outcome.runtimeResult, outcome.bridgeResult,
                        outcome.patchResults, outcome.opcodeMap, outcome.registerMap,
                        vmRegisterCount, outcome.vmOpcodeCounts, staticCheckReason)) {
                    std::cerr << "VM_STATIC_CHECK_FAIL module=VMStaticLinkChecker vm_group=" << g
                              << " reason=" << staticCheckReason << std::endl;
                    PrintFeatureStatus("vm", "failed", staticCheckReason);
                    return 1;
                }
                std::cout << "VM_STATIC_CHECK_PASS module=VMStaticLinkChecker vm_group=" << g
                          << " records=" << outcome.vmRecords.size() << std::endl;
                vmApplied = true;
                std::cout << "VM_RUNTIME_SECTION vm_group=" << g << " rva=0x" << std::hex
                          << outcome.runtimeResult.sectionRVA
                          << " raw=0x" << outcome.runtimeResult.sectionRawOffset
                          << " size=0x" << outcome.runtimeResult.sectionSize
                          << " entry=0x" << outcome.runtimeResult.runtimeEntryRVA << std::dec << std::endl;
                // ciphershellpro.md §8 "Per-build 差异度":opcodeMapDigest/
                // handlerBodyDigest(明文 handler 体哈希，见
                // VMHandlerSynthesizer::Synthesize 里对 ExtractPlaintextBodies
                // 结果取的哈希，不受本次加密 key 影响)/dispatchKeyDigest/
                // variantSelectorDigest 这四个值 VMRuntimeBuilder 自检时已经算
                // 好；encryptedHandlers 是相对 sectionRVA 的真实 handler 密文
                // 字节范围。这里原样打印出来，供 CI 的两次构建相似度校验直接
                // 解析，不需要再新增一条单独的落盘协议。
                std::cout << "VM_RUNTIME_DIGESTS vm_group=" << g << std::hex
                          << " opcode_map=0x" << outcome.runtimeResult.opcodeMapDigest
                          << " handler_body=0x" << outcome.runtimeResult.handlerBodyDigest
                          << " dispatch_key=0x" << outcome.runtimeResult.dispatchKeyDigest
                          << " variant_selector=0x" << outcome.runtimeResult.variantSelectorDigest
                          << " encrypted_handlers_offset=0x"
                          << outcome.runtimeResult.integrityExpectation.encryptedHandlers.offset
                          << " encrypted_handlers_size=0x"
                          << outcome.runtimeResult.integrityExpectation.encryptedHandlers.size
                          << std::dec << std::endl;
                std::cout << "VM_METADATA_SECTION vm_group=" << g << " rva=0x" << std::hex
                          << outcome.emitResult.sectionRVA
                          << " raw=0x" << outcome.emitResult.sectionRawOffset
                          << " size=0x" << outcome.emitResult.sectionSize
                          << " metadata=0x" << outcome.emitResult.metadataRVA
                          << " bytecode=0x" << outcome.emitResult.bytecodeRVA << std::dec << std::endl;
                std::cout << "VM_RUNTIME_CAPABILITIES vm_group=" << g << " schema=0x" << std::hex << VM_SCHEMA_VERSION
                          << " metadata=0x" << VM_METADATA_VERSION
                          << " runtime=0x" << VM_RUNTIME_VERSION << std::dec
                          << " scalar_memory=true memory_arithmetic=true"
                          << " native_call_bridge=false intra_vm_direct_call=true simd_x87_bridge=true"
                          << " fail_policy=error_code_in_eax_then_int3_ud2" << std::endl;

                for (const auto& record : outcome.vmRecords) {
                    const CipherShell::VMTrampolineRecord* trampoline = nullptr;
                    const CipherShell::FunctionPatchResult* patch = nullptr;
                    for (const auto& tr : outcome.runtimeResult.trampolines) {
                        if (tr.functionRVA == record.functionRVA) { trampoline = &tr; break; }
                    }
                    for (const auto& pr : outcome.patchResults) {
                        if (pr.functionRVA == record.functionRVA) { patch = &pr; break; }
                    }
                    uint32_t opcodeCount = 0;
                    auto countIt = outcome.vmOpcodeCounts.find(record.functionRVA);
                    if (countIt != outcome.vmOpcodeCounts.end()) opcodeCount = countIt->second;
                    std::cout << "VM_RECORD vm_group=" << g << " function_rva=0x" << std::hex << record.functionRVA
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
            }
        } else {
            std::cerr << "VM_BUILD_FAIL module=VM reason=no_supported_functions" << std::endl;
            PrintFeatureStatus("vm", "failed", "no_supported_functions");
            return 1;
        }

        std::cout << "    VM bytecode 写入函数数: " << virtualizedCount
                  << "，拒绝函数数: " << rejectedCount << std::endl;

    }

    if (buildCtx.flattening.enabled) {
        CipherShell::FlatteningConfig flatteningConfig{};
        static_assert(sizeof(flatteningConfig.buildSeed) <=
            std::tuple_size<decltype(buildCtx.isaSeed)>::value,
            "CFG seed must fit the per-build entropy buffer");
        std::memcpy(&flatteningConfig.buildSeed, buildCtx.isaSeed.data(),
            sizeof(flatteningConfig.buildSeed));
        if (flatteningConfig.buildSeed == 0u)
            flatteningConfig.buildSeed = 0x434647464C415454ULL;
        flatteningConfig.junkCaseCount = static_cast<uint32_t>((std::max)(2,
            (std::min)(16, buildCtx.flattening.strength / 8)));

        CipherShell::CFGFlattener cfgFlattener;
        cfgProtectionResult = cfgFlattener.Protect(
            image.get(), cfgProtectedFunctions, flatteningConfig,
            buildCtx.cfgCodeSectionName, buildCtx.cfgUnwindSectionName,
            buildCtx.cfgExceptionSectionName, buildCtx.cfgRelocSectionName);
        if (!cfgProtectionResult.success) {
            std::cerr << "CFG_BUILD_FAIL module=CFGFlattener reason="
                      << cfgProtectionResult.error << std::endl;
            PrintFeatureStatus("control_flow.flattening", "failed",
                cfgProtectionResult.error);
            return 1;
        }
        std::string cfgVerifyReason;
        if (!CipherShell::CFGFlattener::VerifyAppliedProtection(
                image.get(), cfgProtectionResult, cfgVerifyReason)) {
            std::cerr << "CFG_STATIC_CHECK_FAIL module=CFGFlattener reason="
                      << cfgVerifyReason << std::endl;
            PrintFeatureStatus("control_flow.flattening", "failed",
                cfgVerifyReason);
            return 1;
        }
        cfgApplied = true;
        std::cout << "CFG_STATIC_CHECK_PASS module=CFGFlattener functions="
                  << cfgProtectionResult.functions.size()
                  << " section_rva=0x" << std::hex
                  << cfgProtectionResult.codeSectionRVA << std::dec << std::endl;
        for (const auto& function : cfgProtectionResult.functions) {
            std::cout << "CFG_RECORD function_rva=0x" << std::hex
                      << function.flattened.originalFunctionRVA
                      << " flattened_rva=0x" << function.flattened.codeRVA
                      << std::dec << " blocks=" << function.flattened.blocks.size()
                      << " states=" << function.flattened.dispatchCases.size()
                      << " transitions=" << function.flattened.transitions.size()
                      << std::endl;
        }
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
        // 每个 Group 是一份独立的 handler/dispatch 产物，逐组复验，不合并
        // 成一次调用——这样任何一个 Group 的复验失败都能定位到具体 Group。
        for (const auto& outcome : vmGroupOutcomes) {
            if (outcome.vmRecords.empty()) continue;
            std::string finalVMReason;
            std::unordered_map<uint32_t, uint32_t> finalOpcodeCounts;
            if (!ValidateVMStaticLink(rebuiltImage, outcome.vmRecords, outcome.vmBytecodeBlob,
                    outcome.emitResult, outcome.runtimeResult, outcome.bridgeResult,
                    outcome.patchResults, outcome.opcodeMap,
                    outcome.registerMap, vmRegisterCount, finalOpcodeCounts, finalVMReason)) {
                parser.FreeImage(rebuiltImage);
                std::cerr << "VM_FINAL_STATIC_CHECK_FAIL module=VMStaticLinkChecker vm_group="
                          << outcome.groupId << " reason=" << finalVMReason << std::endl;
                return 1;
            }
        }
    }
    if (cfgApplied) {
        std::string finalCfgReason;
        if (!CipherShell::CFGFlattener::VerifyAppliedProtection(
                rebuiltImage, cfgProtectionResult, finalCfgReason)) {
            parser.FreeImage(rebuiltImage);
            std::cerr << "CFG_FINAL_STATIC_CHECK_FAIL module=CFGFlattener reason="
                      << finalCfgReason << std::endl;
            return 1;
        }
        std::cout << "CFG_FINAL_STATIC_CHECK_PASS module=CFGFlattener" << std::endl;
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
        for (const auto& outcome : vmGroupOutcomes) {
            if (outcome.vmRecords.empty()) continue;
            std::string writtenVMReason;
            std::unordered_map<uint32_t, uint32_t> writtenOpcodeCounts;
            if (!ValidateVMStaticLink(verifyImage, outcome.vmRecords, outcome.vmBytecodeBlob,
                    outcome.emitResult, outcome.runtimeResult, outcome.bridgeResult,
                    outcome.patchResults, outcome.opcodeMap,
                    outcome.registerMap, vmRegisterCount, writtenOpcodeCounts,
                    writtenVMReason)) {
                parser.FreeImage(verifyImage);
                std::remove(outputFile.c_str());
                std::cerr << "VM_WRITE_VERIFY_FAIL module=VMStaticLinkChecker vm_group="
                          << outcome.groupId << " reason=" << writtenVMReason << std::endl;
                return 1;
            }
        }
    }
    if (cfgApplied) {
        std::string writtenCfgReason;
        if (!CipherShell::CFGFlattener::VerifyAppliedProtection(
                verifyImage, cfgProtectionResult, writtenCfgReason)) {
            parser.FreeImage(verifyImage);
            std::remove(outputFile.c_str());
            std::cerr << "CFG_WRITE_VERIFY_FAIL module=CFGFlattener reason="
                      << writtenCfgReason << std::endl;
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
        uint32_t vmAppliedFunctionCount = 0;
        uint32_t vmActiveGroupCount = 0;
        for (const auto& outcome : vmGroupOutcomes) {
            if (outcome.vmRecords.empty()) continue;
            vmAppliedFunctionCount += static_cast<uint32_t>(outcome.vmRecords.size());
            ++vmActiveGroupCount;
        }
        PrintFeatureStatus("vm", "applied", "functions=" + std::to_string(vmAppliedFunctionCount) +
            " vm_groups=" + std::to_string(vmActiveGroupCount));
        // Scope note (do not drop this when editing nearby logging): "applied"
        // means every emitted function passed real native-CPU-vs-synthesized-
        // handler differential evidence (VM_NATIVE_DIFFERENTIAL_PASS) for its
        // corpus -- semantic correctness is verified for those functions.
        // It does NOT mean VM protection as a whole is production-ready or
        // hardened against generic unpacking/deobfuscation tooling: K-variant
        // instruction-sequence diversity beyond ADD/SUB/AND/OR/XOR/NOT/NEG is
        // still incomplete (see vm_kernel_static_gate's insufficient-real-k-
        // variant-coverage check), so most emitted micro-op semantics still
        // share one fixed core instruction sequence across builds/variants.
        // Never report or log this as "ready to enable in production" until
        // that gap is closed.
        std::cout << "VM_PROTECTION_SCOPE_NOTE correctness=verified "
                     "anti_cracking_hardening=incomplete "
                     "reason=k_variant_coverage_below_target" << std::endl;
    }
    if (cfgApplied) {
        PrintFeatureStatus("control_flow.flattening", "applied",
            "functions=" + std::to_string(cfgProtectionResult.functions.size()));
        std::cout << "CFG_PROTECTION_SCOPE_NOTE correctness=static_link_verified "
                     "execution_differential=covered_by_cfg_flattener_differential_test "
                     "vm_dependency=false" << std::endl;
    }

    std::cout << "\n======================================" << std::endl;
    std::cout << "CipherShell 处理完成!" << std::endl;
    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}
