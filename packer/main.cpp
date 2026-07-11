/**
 * CipherShell 涓荤▼搴忓叆鍙?
 * 鍛戒护琛岀晫闈?
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
#include "analysis/capability_checker.h"
#include "config/protection_build_context.h"
#include "vm/vm_verifier.h"

namespace fs = std::filesystem;

// ============================================================================
// 甯姪淇℃伅
// ============================================================================

void PrintHelp() {
    std::cout << R"(
CipherShell v0.1 - 鑷爺楂樺己搴︿唬鐮佷繚鎶ゅ３

鐢ㄦ硶: ciphershell [閫夐」] <杈撳叆鏂囦欢>

閫夐」:
  -o, --output <鏂囦欢>      鎸囧畾杈撳嚭鏂囦欢璺緞
  -l, --level <1-5>        璁剧疆淇濇姢绛夌骇 (榛樿: 1)
  -c, --config <鏂囦欢>      鎸囧畾閰嶇疆鏂囦欢璺緞 (TOML 鏍煎紡)
  -v, --verbose            鏄剧ず璇︾粏淇℃伅
  -h, --help               鏄剧ず姝ゅ府鍔╀俊鎭?

淇濇姢绛夌骇:
  L1 (Guard)    鍩虹鍔犲瘑淇濇姢 (~1.05x 鎬ц兘寮€閿€)
  L2 (Shield)   鎺у埗娴佸钩鍧﹀寲 (~2-3x 鎬ц兘寮€閿€)
  L3 (Armor)    楂樼骇娣锋穯 (~5-8x 鎬ц兘寮€閿€)
  L4 (Fortress) 浠ｇ爜铏氭嫙鍖?(~15-30x 鎬ц兘寮€閿€)
  L5 (Citadel)  澶氬眰宓屽 VM (~50-100x+ 鎬ц兘寮€閿€)

绀轰緥:
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
// 涓诲嚱鏁?
// ============================================================================


static bool IsRuntimeInterpreterOpcode(uint8_t opcode, bool is64Bit) {
    const auto* descriptor = CipherShell::VMSchema::Lookup(opcode);
    return descriptor &&
        (is64Bit ? descriptor->runtimeSupportedX64 : descriptor->runtimeSupportedX86);
}

static bool IsRuntimeInterpreterProgram(
    const std::vector<CipherShell::BytecodeInstr>& instructions,
    bool is64Bit,
    std::string& reason)
{
    for (const auto& instr : instructions) {
        if (!IsRuntimeInterpreterOpcode(instr.opcode, is64Bit)) {
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
        !runtimeResult.cfgVerified || !runtimeResult.relocationsVerified) {
        reason = "runtime_not_execution_ready_or_linkage_unverified";
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
            record, bytecode, opcodeMap, registerMap, registerCount,
            runtimeResult.architecture == VM_ARCH_X64);
        if (!verification.success) {
            reason = "bytecode_decoder_check_failed: " + verification.error;
            return false;
        }
        opcodeCounts[record.functionRVA] = verification.instructionCount;

        for (uint32_t offset = 0; offset < record.bytecodeSize;
             offset += CipherShell::VMSchema::InstructionSize()) {
            CipherShell::BytecodeInstr instruction{};
            std::string decodeReason;
            if (!CipherShell::VMSchema::Decode(
                    bytecode.data() + record.bytecodeOffset + offset,
                    CipherShell::VMSchema::InstructionSize(), reverseOpcodeMap.data(),
                    instruction, decodeReason)) {
                reason = "bridge_static_decode_failed: " + decodeReason;
                return false;
            }
            if (instruction.opcode == VM_CALL_NATIVE) {
                if (instruction.immediate > 0xFFFFFFFFULL ||
                    !IsReadOnlyExecutableRva(image,
                        static_cast<uint32_t>(instruction.immediate))) {
                    reason = "direct_native_call_target_is_not_read_only_executable";
                    return false;
                }
            } else if (instruction.opcode == VM_CALL_IMPORT) {
                const uint32_t pointerSize = image->is64Bit ? 8u : 4u;
                if (instruction.immediate > 0xFFFFFFFFULL ||
                    !RvaRangeHasPermissions(image,
                        static_cast<uint32_t>(instruction.immediate), pointerSize,
                        IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUTE)) {
                    reason = "import_call_iat_slot_permissions_invalid";
                    return false;
                }
            }
            if (instruction.opcode != VM_BRIDGE_SIMD && instruction.opcode != VM_BRIDGE_X87) continue;
            const auto linked = std::find_if(bridgeResult.links.begin(), bridgeResult.links.end(),
                [&](const CipherShell::VMInstructionBridgeLink& link) {
                    return link.functionRVA == record.functionRVA &&
                        link.thunkRVA == instruction.immediate;
                });
            if (linked == bridgeResult.links.end() ||
                !IsReadOnlyExecutableRva(image, linked->thunkRVA) ||
                !IsReadOnlyExecutableRva(image, linked->nativeInstructionRVA) ||
                (instruction.flags & VM_OPERAND_BRIDGE_LINKED) == 0 ||
                (linked->usesAvx && (record.flags & VM_RECORD_FLAG_USES_AVX) == 0)) {
                reason = "bridge_target_or_record_flags_not_linked";
                return false;
            }
            if (instruction.opcode == VM_BRIDGE_X87) {
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
    // 璁剧疆鎺у埗鍙颁负 UTF-8 缂栫爜
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // 濡傛灉娌℃湁鍙傛暟锛屽惎鍔?GUI 妯″紡
    if (argc == 1) {
        CipherShell::ConsoleGUI gui;
        gui.Initialize();
        gui.ShowMainMenu();
        return 0;
    }

    std::cout << "CipherShell v0.1 - 鑷爺楂樺己搴︿唬鐮佷繚鎶ゅ３" << std::endl;
    std::cout << "======================================" << std::endl;

    // 瑙ｆ瀽鍛戒护琛屽弬鏁?
    std::string inputFile;
    std::string outputFile;
    std::string configFile;
    int protectionLevel = 1;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            PrintHelp();
            return 0;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            } else {
                std::cerr << "错误: -o 选项需要指定输出文件路径" << std::endl;
                return 1;
            }
        } else if (arg == "-l" || arg == "--level") {
            if (i + 1 < argc) {
                protectionLevel = std::stoi(argv[++i]);
                if (protectionLevel < 1 || protectionLevel > 5) {
                    std::cerr << "閿欒: 淇濇姢绛夌骇蹇呴』鍦?1-5 涔嬮棿" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "错误: -l 选项需要指定保护等级" << std::endl;
                return 1;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                configFile = argv[++i];
            } else {
                std::cerr << "错误: -c 选项需要指定配置文件路径" << std::endl;
                return 1;
            }
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (inputFile.empty()) {
            inputFile = arg;
        } else {
            std::cerr << "閿欒: 鏈煡鍙傛暟 '" << arg << "'" << std::endl;
            return 1;
        }
    }

    // 妫€鏌ヨ緭鍏ユ枃浠?
    if (inputFile.empty()) {
        std::cerr << "错误: 未指定输入文件" << std::endl;
        PrintHelp();
        return 1;
    }

    if (!fs::exists(inputFile)) {
        std::cerr << "閿欒: 杈撳叆鏂囦欢涓嶅瓨鍦? " << inputFile << std::endl;
        return 1;
    }

    // 鑷姩鐢熸垚杈撳嚭鏂囦欢鍚?
    if (outputFile.empty()) {
        fs::path inputPath(inputFile);
        outputFile = inputPath.stem().string() + "_protected" + inputPath.extension().string();
    }

    std::cout << "杈撳叆鏂囦欢: " << inputFile << std::endl;
    std::cout << "杈撳嚭鏂囦欢: " << outputFile << std::endl;
    std::cout << "淇濇姢绛夌骇: L" << protectionLevel << std::endl;

    // ============================================================================
    // Step 1: 瑙ｆ瀽杈撳叆 PE
    // ============================================================================

    std::cout << "\n[1/5] 瑙ｆ瀽杈撳叆 PE 鏂囦欢..." << std::endl;

    CipherShell::PEParser parser;
    auto imageDeleter = [&parser](CipherShell::CS_PE_IMAGE* img) {
        if (img) parser.FreeImage(img);
    };
    std::unique_ptr<CipherShell::CS_PE_IMAGE, decltype(imageDeleter)> image(
        parser.LoadFromFile(inputFile),
        imageDeleter
    );

    if (!image || !image->isValid) {
        std::cerr << "閿欒: 鏃犳硶瑙ｆ瀽 PE 鏂囦欢";
        if (image) {
            std::cerr << " - " << image->errorMessage;
        }
        std::cerr << std::endl;
        return 1;
    }

    std::cout << "  PE 瑙ｆ瀽鎴愬姛" << std::endl;
    std::cout << "  鏋舵瀯: " << (image->is64Bit ? "x64" : "x86") << std::endl;
    std::cout << "  鍏ュ彛鐐? 0x" << std::hex;
    if (image->is64Bit) {
        std::cout << image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        std::cout << image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    std::cout << std::dec << std::endl;
    std::cout << "  Section 鏁伴噺: " << image->numSections << std::endl;

    if (verbose) {
        std::cout << "  瀵煎叆 DLL 鏁伴噺: " << image->imports.dlls.size() << std::endl;
        std::cout << "  瀵煎嚭鍑芥暟鏁伴噺: " << image->exports.functions.size() << std::endl;
        std::cout << "  閲嶅畾浣嶆潯鐩暟閲? " << image->relocs.entries.size() << std::endl;
    }

    // ============================================================================
    // Step 1.5: 鍔犺浇閰嶇疆
    // ============================================================================

    CipherShell::CipherShellConfig config;
    CipherShell::ConfigParser configParser;

    if (!configFile.empty()) {
        std::cout << "\n[1.5] 鍔犺浇閰嶇疆鏂囦欢: " << configFile << std::endl;
        config = configParser.LoadFromFile(configFile);
        if (configParser.HasError()) {
            std::cerr << "閿欒: " << configParser.GetLastError() << std::endl;
            return 1;
        }
        protectionLevel = config.global.protectionLevel;
        if (protectionLevel < 1 || protectionLevel > 5) {
            std::cerr << "閿欒: 閰嶇疆涓殑淇濇姢绛夌骇蹇呴』鍦?1-5 涔嬮棿" << std::endl;
            return 1;
        }
    } else {
        // 浣跨敤榛樿閰嶇疆
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
    // Step 1.5: 淇濆瓨鍘熷鍏ュ彛鐐?
    // ============================================================================

    DWORD originalOEP = 0;
    if (image->is64Bit) {
        originalOEP = image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        originalOEP = image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    const WORD originalSectionCount = image->numSections;
    std::cout << "  鍘熷鍏ュ彛鐐?(OEP): 0x" << std::hex << originalOEP << std::dec << std::endl;

    // ============================================================================
    // Step 2: 搴旂敤淇濇姢鍙樻崲
    // 閲嶈: 鍏堝仛浠ｇ爜鍒嗘瀽/鍙樻崲锛堟槑鏂囦唬鐮佸彲鍙嶆眹缂栵級锛屾渶鍚庢墠鍋?Section 鍔犲瘑
    // ============================================================================

    std::cout << "\n[2/5] 搴旂敤淇濇姢鍙樻崲 (L" << protectionLevel << ")..." << std::endl;

    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedStringRegions;

    // Phase A: 瀛楃涓插姞瀵嗭紙鏄庢枃浠ｇ爜娈典腑鐨勫唴鑱斿瓧绗︿覆锛孡2+锛?
    if (buildCtx.stringEncryption.enabled) {
        std::cout << "  搴旂敤瀛楃涓插姞瀵?.." << std::endl;

        CipherShell::StringEncryptor strEncryptor;
        CipherShell::CS_STRING_CONFIG strConfig;
        strConfig.encryptAnsiStrings = buildCtx.stringAscii;
        strConfig.encryptWideStrings = buildCtx.stringUtf16;
        strConfig.scanResources = buildCtx.stringResources;
        strConfig.scanReadableSections = true;

        auto strings = strEncryptor.ScanStrings(image.get(), strConfig);
        if (strEncryptor.HasError()) {
            std::cerr << "STRING_ENCRYPTION_FAIL module=StringEncryptor reason="
                      << strEncryptor.GetLastError() << std::endl;
            PrintFeatureStatus("string_encryption", "failed", strEncryptor.GetLastError());
            return 1;
        }
        std::cout << "    鍙戠幇 " << strings.size() << " 涓瓧绗︿覆" << std::endl;

        if (!strings.empty()) {
            if (!strEncryptor.EncryptStrings(image.get(), strings)) {
                std::cerr << "STRING_ENCRYPTION_FAIL module=StringEncryptor reason="
                          << strEncryptor.GetLastError() << std::endl;
                PrintFeatureStatus("string_encryption", "failed", strEncryptor.GetLastError());
                return 1;
            }
            encryptedStringRegions.reserve(encryptedStringRegions.size() + strings.size());
            for (const auto& s : strings) {
                CipherShell::CS_ENCRYPTED_SECTION region{};
                region.sectionIndex = 0xFFFF;
                region.originalRVA = s.rva;
                region.originalSize = s.length;
                region.encryptedSize = s.length;
                region.originalCharacteristics = IMAGE_SCN_MEM_READ;
                for (uint32_t sectionIndex = 0; sectionIndex < image->numSections; ++sectionIndex) {
                    const auto& section = image->sections[sectionIndex];
                    const uint32_t span = (std::max)(section.Misc.VirtualSize,
                        static_cast<DWORD>(section.SizeOfRawData));
                    if (span != 0 && s.rva >= section.VirtualAddress &&
                        s.rva - section.VirtualAddress < span) {
                        region.originalCharacteristics = section.Characteristics;
                        break;
                    }
                }
                memcpy(region.sectionKey.key, s.key, 32);
                memcpy(region.sectionKey.nonce, s.nonce, 12);
                region.sectionKey.counter = 0;
                encryptedStringRegions.push_back(region);
            }
            std::cout << "    已加密字符串并登记运行时解密任务" << std::endl;
            PrintFeatureStatus("string_encryption", "applied", "mode=" + buildCtx.stringEncryption.mode);
        } else {
            PrintFeatureStatus("string_encryption", "skipped", "no_strings_found");
        }
    } else {
        PrintFeatureStatus("string_encryption", "skipped", "disabled");
    }

    // Phase B: 瀵煎叆琛ㄦ贩娣嗭紙L2+锛?
    if (buildCtx.importProtection.enabled) {
        std::cout << "  搴旂敤瀵煎叆琛ㄦ贩娣?.." << std::endl;

        CipherShell::ImportObfuscator obfuscator;
        CipherShell::CS_IMPORT_OBFUSCATION_CONFIG obfConfig;
        obfConfig.strategy = CipherShell::ImportObfuscationStrategy::StrategyB;

        CipherShell::APIResolver resolver;
        if (!resolver.Initialize()) {
            std::cerr << "IMPORT_PROTECTION_FAIL module=APIResolver reason=initialize_failed" << std::endl;
            PrintFeatureStatus("import_protection", "failed", "resolver_initialize_failed");
            return 1;
        }

        auto obfImports = obfuscator.ObfuscateImports(image.get(), obfConfig, &resolver);
        if (!obfuscator.WasApplied()) {
            std::cerr << "IMPORT_PROTECTION_FAIL module=ImportObfuscator reason="
                      << obfuscator.GetLastError() << std::endl;
            PrintFeatureStatus("import_protection", "failed", obfuscator.GetLastError());
            return 1;
        }
        std::cout << "    已处理 " << obfImports.size() << " 个导入函数" << std::endl;
        PrintFeatureStatus(
            "import_protection",
            "applied",
            "mode=rebuilt_import_directory real_iat=preserved fake_imports=" +
                std::to_string(obfuscator.GetWrittenFakeImportCount()));
    } else {
        PrintFeatureStatus("import_protection", "skipped", "disabled");
    }

    // Phase C: 鎺у埗娴佸钩鍧﹀寲锛圠3+锛屾殏绂佺敤鈥斺€擥enerateFlattenedCode 闇€瑕佷紭鍖栵級
    if (buildCtx.flattening.enabled) {  // FIXME: 鏆傛椂绂佺敤锛屽緟浼樺寲
        std::cout << "  搴旂敤鎺у埗娴佸钩鍧﹀寲..." << std::endl;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        disasm.Initialize(is64, is64 ? image->ntHeaders64->OptionalHeader.ImageBase
                                     : image->ntHeaders32->OptionalHeader.ImageBase);

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            BYTE* secData = image->rawData + secOffset;
            uint64_t baseAddr = sec.VirtualAddress;

            auto functions = disasm.AnalyzeCode(secData, secSize, baseAddr, is64);
            if (disasm.HasError()) {
                std::cerr << "CFG_FLATTEN_FAIL module=ZydisDecoder reason="
                          << disasm.GetLastError() << std::endl;
                PrintFeatureStatus("control_flow.flattening", "failed", disasm.GetLastError());
                return 1;
            }
            if (functions.empty()) {
                std::cout << "    代码段[" << si << "]: 未识别到可处理函数" << std::endl;
                continue;
            }
            std::cout << "    代码段[" << si << "]: 识别到 " << functions.size() << " 个函数" << std::endl;

            CipherShell::CFGFlattener flattener;
            CipherShell::FlatteningConfig flatConfig;
            flatConfig.enableStateEncryption = true;
            flatConfig.enableStateRandomization = true;
            flatConfig.junkCaseCount = 5;

            uint32_t flattenedCount = 0;
            for (const auto& func : functions) {
                if (func.blocks.size() < 2) continue;

                auto flatResult = flattener.FlattenFunction(func, flatConfig);
                DWORD codeSize = 0;
                BYTE* flatCode = flattener.GenerateFlattenedCode(flatResult, is64, &codeSize);
                if (flatCode && codeSize > 0) {
                    DWORD funcSize = (DWORD)(func.size);
                    if (codeSize <= funcSize) {
                        DWORD funcOffset = (DWORD)(func.entryAddress - baseAddr);
                        memcpy(secData + funcOffset, flatCode, codeSize);
                        if (codeSize < funcSize) {
                            memset(secData + funcOffset + codeSize, 0xCC, funcSize - codeSize);
                        }
                        flattenedCount++;
                    }
                    delete[] flatCode;
                }
            }
            std::cout << "    已平坦化 " << flattenedCount << " 个函数" << std::endl;
        }
    }

    // Phase D: 铏氬亣鎺у埗娴侊紙L3+锛岄渶鍦ㄥ姞瀵嗗墠鍙嶆眹缂栨槑鏂囦唬鐮侊級
    if (buildCtx.bogusFlow.enabled) {
        std::cout << "  搴旂敤铏氬亣鎺у埗娴?.." << std::endl;

        CipherShell::BogusFlowInjector bogusInjector;
        CipherShell::BogusFlowConfig bogusConfig;
        bogusConfig.bogusBlocksPerReal = 2;
        bogusConfig.duplicateCode = true;
        bogusConfig.duplicateRatio = 0.3f;
        bogusConfig.insertDeadCode = true;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        disasm.Initialize(is64, is64 ? image->ntHeaders64->OptionalHeader.ImageBase
                                     : image->ntHeaders32->OptionalHeader.ImageBase);

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            auto functions = disasm.AnalyzeCode(
                image->rawData + secOffset, secSize,
                sec.VirtualAddress, is64);
            if (disasm.HasError()) {
                std::cerr << "CFG_BOGUS_FAIL module=ZydisDecoder reason="
                          << disasm.GetLastError() << std::endl;
                PrintFeatureStatus("control_flow.bogus", "failed", disasm.GetLastError());
                return 1;
            }

            uint32_t injectedCount = 0;
            for (const auto& func : functions) {
                if (func.blocks.size() < 2) continue;

                auto bogusResult = bogusInjector.InjectIntoFunction(func, bogusConfig);

                DWORD codeSize = 0;
                BYTE* bogusCode = bogusInjector.GenerateBogusCode(bogusResult, is64, &codeSize);
                if (bogusCode && codeSize > 0) {
                    DWORD funcSize = static_cast<DWORD>(func.size);
                    DWORD funcOffset = static_cast<DWORD>(func.entryAddress - sec.VirtualAddress);
                    if (codeSize <= funcSize && funcOffset + funcSize <= secSize) {
                        memcpy(image->rawData + secOffset + funcOffset, bogusCode, codeSize);
                        if (codeSize < funcSize) {
                            memset(image->rawData + secOffset + funcOffset + codeSize, 0x90, funcSize - codeSize);
                        }
                        injectedCount++;
                    } else {
                        std::cerr << "CFG_BOGUS_SKIP module=BogusFlow function_rva=0x" << std::hex
                                  << func.entryAddress << std::dec
                                  << " reason=generated_code_does_not_fit_original_function" << std::endl;
                    }
                    delete[] bogusCode;
                }
                bogusInjector.Cleanup(bogusResult);
            }
            std::cout << "    已向 " << injectedCount << " 个函数写入虚假控制流" << std::endl;
        }
    }

    bool vmApplied = false;
    uint32_t vmRegisterCount = 0;
    std::vector<uint8_t> vmBytecodeBlob;
    std::vector<CipherShell::VMFunctionRecord> vmRecords;
    std::vector<CipherShell::Function> protectedFunctions;
    CipherShell::VMInstructionBridgeBuildResult bridgeResult{};
    CipherShell::VMEmitResult emitResult{};
    CipherShell::VMRuntimeBuildResult runtimeResult{};
    std::vector<CipherShell::FunctionPatchResult> patchResults;

    // Phase E: 鍑芥暟绾?VM 淇濇姢銆傝繖閲屽彧鍏佽瀹屾暣钀界洏鐨勬暟鎹繘鍏ヤ笅涓€姝ワ紝澶辫触蹇呴』鏄庣‘璇婃柇銆?
    if (buildCtx.vm.enabled) {
        std::cout << "  搴旂敤浠ｇ爜铏氭嫙鍖?(Mirage VM)..." << std::endl;

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
        mutConfig.randomizeOpcodeMap = config.vm.opcodeRandomization;
        mutConfig.randomizeRegisterMap = true;
        mutConfig.registerCount = static_cast<uint32_t>(config.vm.registerCount);
        mutConfig.seed = buildCtx.isaSeed;
        mutConfig.mutateHandlers = config.vm.handlerMutation;
        mutConfig.embedJunkHandlers = config.vm.embedJunkHandlers;
        mutConfig.requestedJunkHandlerCount = config.vm.embedJunkHandlers ? 16u : 0u;
        for (const auto& descriptor : CipherShell::VMSchema::Opcodes()) {
            mutConfig.validOpcodes.push_back(descriptor.opcode);
        }
        if (!mutEngine.Initialize(mutConfig)) {
            std::cerr << "VM_INIT_FAIL module=MutationEngine reason=register_count_must_be_16_to_32" << std::endl;
            PrintFeatureStatus("vm", "failed", "invalid_register_count");
            return 1;
        }

        CipherShell::MutatedISA mutatedISA = mutEngine.GenerateMutatedISA();
        buildCtx.opcodeMap = mutatedISA.opcodeMap;
        buildCtx.registerMap = mutatedISA.registerMap;
        std::string registerMapReason;
        if (!ValidateVMRegisterMap(buildCtx.registerMap, mutConfig.registerCount, registerMapReason)) {
            std::cerr << "VM_INIT_FAIL module=MutationEngine reason=" << registerMapReason << std::endl;
            PrintFeatureStatus("vm", "failed", registerMapReason);
            return 1;
        }
        std::cout << "    ISA seed fingerprint: 0x" << std::hex
                  << mutEngine.GetSeedFingerprint() << std::dec << std::endl;
        std::cout << "VM_HANDLER_LAYOUT mutated="
                  << (mutatedISA.handlerMutationEnabled ? "true" : "false")
                  << " junk_handlers=" << mutatedISA.junkHandlerCount
                  << " variant_count=" << VM_HANDLER_VARIANT_COUNT << std::endl;

        CipherShell::Translator translator;
        CipherShell::TranslationConfig transConfig;
        transConfig.virtualRegisterCount = mutConfig.registerCount;
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

                auto transResult = translator.TranslateFunction(func);
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

                std::string interpreterRejectReason;
                if (!IsRuntimeInterpreterProgram(transResult.instructions, is64, interpreterRejectReason)) {
                    std::cerr << "VM_REJECT module=VMRuntimeBuilder function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " reason=" << interpreterRejectReason << std::endl;
                    rejectedCount++;
                    continue;
                }

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
            CipherShell::VMSectionEmitter vmEmitter;
            emitResult = vmEmitter.Emit(image.get(), vmBytecodeBlob, vmRecords,
                buildCtx.opcodeMap, buildCtx.registerMap,
                mutatedISA.handlerSemanticToSlot, mutatedISA.handlerSlotToSemantic,
                mutatedISA.handlerVariants, mutatedISA.junkHandlerCount,
                mutatedISA.handlerMutationEnabled, mutatedISA.junkHandlersEnabled,
                0, buildCtx.vmSectionName);
            if (!emitResult.success) {
                std::cerr << "VM_EMIT_FAIL module=VMSectionEmitter reason=" << emitResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", emitResult.error);
                return 1;
            }
            vmRecords = emitResult.records;

            CipherShell::VMRuntimeBuilder runtimeBuilder;
            runtimeResult = runtimeBuilder.Build(image.get(), vmRecords,
                emitResult.metadataRVA, emitResult.runtimeKeyShare,
                buildCtx.vmRuntimeSectionName,
                buildCtx.vmUnwindSectionName,
                buildCtx.vmRelocSectionName);
            if (!runtimeResult.success) {
                std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder reason=" << runtimeResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", runtimeResult.error);
                return 1;
            }

            std::string patchError;
            const uint32_t runtimeVerifiedFlags = runtimeResult.unwindVerified
                ? static_cast<uint32_t>(VM_METADATA_FLAG_UNWIND_VERIFIED) : 0u;
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
                      << " native_call_bridge=true simd_x87_bridge=true"
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

        std::cout << "    VM bytecode 鍐欏叆鍑芥暟鏁? " << virtualizedCount
                  << "锛屾嫆缁濆嚱鏁版暟: " << rejectedCount << std::endl;

    }
    // Phase F: Section 鍔犲瘑锛圠1+锛屾渶鍚庢墽琛屸€斺€斿姞瀵嗘墍鏈夊彉鎹㈠悗鐨勪唬鐮侊級
    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedSections;
    CipherShell::StubEmbedResult loaderResult{};
    bool loaderApplied = false;
    if (buildCtx.sectionEncryption.enabled) {
        std::cout << "  搴旂敤 Section 鍔犲瘑..." << std::endl;

        CipherShell::SectionEncryptor encryptor;
        CipherShell::CS_ENCRYPT_CONFIG encConfig;
        encConfig.encryptCodeSections = true;
        encConfig.encryptDataSections = false;
        encConfig.encryptResources = config.global.resourceEncryption;
        encConfig.excludeSectionsAtOrAfter = originalSectionCount;
        encConfig.excludeRelocationTargets = TRUE;
        CipherShell::CS_ENCRYPTION_KEY masterKey{};
        if (!encryptor.GenerateRandomKey(masterKey)) {
            std::cerr << "SECTION_ENCRYPTION_FAIL module=SectionEncryptor reason=secure_random_failed" << std::endl;
            PrintFeatureStatus("section_encryption", "failed", "secure_random_failed");
            return 1;
        }

        encryptedSections = encryptor.EncryptSections(image.get(), encConfig, masterKey);
        std::cout << "    宸插姞瀵?" << encryptedSections.size() << " 涓?Section" << std::endl;
            PrintFeatureStatus("section_encryption", encryptedSections.empty() ? "skipped" : "applied", encryptedSections.empty() ? "no_encryptable_sections" : "mode=" + buildCtx.sectionEncryption.mode);
    } else {
        PrintFeatureStatus("section_encryption", "skipped", "disabled");
    }

    if (!encryptedStringRegions.empty()) {
        encryptedSections.insert(encryptedSections.end(),
            encryptedStringRegions.begin(), encryptedStringRegions.end());
        std::cout << "    已追加 " << encryptedStringRegions.size()
                  << " 个字符串运行时解密任务" << std::endl;
    }

    // ============================================================================
    // Step 3: 绛惧悕娑堥櫎
    // ============================================================================

    std::cout << "\n[3/5] 娑堥櫎澹崇鍚?.." << std::endl;

    {
        CipherShell::SignatureEliminator sigEliminator;

        auto sigMatches = sigEliminator.DetectSignatures(image.get());
        if (!sigMatches.empty()) {
            std::cout << "  鍙戠幇 " << sigMatches.size() << " 涓鍚嶅尮閰?" << std::endl;
            for (const auto& match : sigMatches) {
                std::cout << "    - " << match.signatureName << " (" << match.detector << ")" << std::endl;
            }
        }

        CipherShell::EliminationConfig elimConfig;
        sigEliminator.EliminateSignatures(image.get(), elimConfig);

        if (sigEliminator.VerifyElimination(image.get())) {
            std::cout << "  绛惧悕娑堥櫎鎴愬姛" << std::endl;
        } else {
            std::cout << "  璀﹀憡: 浠嶆湁绛惧悕娈嬬暀" << std::endl;
        }
    }

    // ============================================================================
    // Step 4: 宓屽叆 Stub
    // ============================================================================

    std::cout << "\n[4/6] 宓屽叆瑙ｅ瘑 Stub..." << std::endl;

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
    // Step 5: 閲嶅缓 PE
    // ============================================================================

    std::cout << "\n[5/6] 鍐欏叆杈撳嚭鏂囦欢..." << std::endl;

    CipherShell::PERebuilder rebuilder;
    CipherShell::CS_REBUILD_CONFIG rebuildConfig;

    rebuildConfig.randomizeSectionNames = config.global.randomizeSections;
    rebuildConfig.zeroTimestamps = config.global.stripTimestamps;
    rebuildConfig.preserveRichHeader = !config.global.stripRichHeader;
    rebuildConfig.preserveDebugInfo = !config.global.stripDebugInfo;

    DWORD outputSize = 0;
    std::unique_ptr<BYTE[]> outputData(rebuilder.RebuildImage(image.get(), rebuildConfig, &outputSize));

    if (!outputData || outputSize == 0) {
        std::cerr << "閿欒: PE 閲嶅缓澶辫触" << std::endl;
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

    std::cout << "  PE 閲嶅缓鎴愬姛" << std::endl;
    std::cout << "  杈撳嚭澶у皬: " << outputSize << " 瀛楄妭" << std::endl;

    // 鍐欏叆杈撳嚭鏂囦欢
    FILE* outFile = fopen(outputFile.c_str(), "wb");
    if (!outFile) {
        std::cerr << "閿欒: 鏃犳硶鍒涘缓杈撳嚭鏂囦欢: " << outputFile << std::endl;
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

    std::cout << "  杈撳嚭鏂囦欢宸蹭繚瀛? " << outputFile << std::endl;
    std::cout << "  鏂囦欢澶у皬: " << outputSize << " 瀛楄妭" << std::endl;

    // ============================================================================
    // Step 6: 楠岃瘉杈撳嚭
    // ============================================================================

    std::cout << "\n[6/6] 楠岃瘉杈撳嚭鏂囦欢..." << std::endl;

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
    std::cout << "CipherShell 澶勭悊瀹屾垚!" << std::endl;
    std::cout << "杈撳嚭鏂囦欢: " << outputFile << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}


