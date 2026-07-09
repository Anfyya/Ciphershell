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
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif

#include "pe_parser/pe_parser.h"
#include "pe_parser/pe_rebuilder.h"
#include "pe_parser/pe_emitter.h"
#include "transforms/section_encryptor.h"
#include "transforms/string_encryptor.h"
#include "transforms/import_obfuscator.h"
#include "transforms/reloc_fixer.h"
#include "config/config_parser.h"
#include "signature/signature_eliminator.h"
#include "analysis/disassembler.h"
#include "analysis/cfg_builder.h"
#include "transforms/cfg_flattener.h"
#include "transforms/opaque_predicates.h"
#include "transforms/bogus_flow.h"
#include "transforms/stub_builder.h"
#include "transforms/translator.h"
#include "transforms/vm_section_emitter.h"
#include "transforms/vm_nester.h"
#include "mutation/mutation_engine.h"
#include "gui/console_gui.h"
#include "transforms/function_trampoline_patcher.h"
#include "transforms/vm_runtime_builder.h"
#include "analysis/capability_checker.h"
#include "config/protection_build_context.h"

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


static bool IsMinimalVMInterpreterOpcode(uint8_t opcode) {
    switch (opcode) {
        case VM_NOP:
        case VM_MOV_RR:
        case VM_MOV_RC:
        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
        case VM_PUSH_R:
        case VM_PUSH_C:
        case VM_POP_R:
        case VM_CALL_NATIVE:
        case VM_ADD_RR:
        case VM_ADD_RC:
        case VM_SUB_RR:
        case VM_SUB_RC:
        case VM_AND_RR:
        case VM_AND_RC:
        case VM_OR_RR:
        case VM_OR_RC:
        case VM_XOR_RR:
        case VM_XOR_RC:
        case VM_CMP_RR:
        case VM_CMP_RC:
        case VM_TEST_RR:
        case VM_TEST_RC:
        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JAE:
        case VM_JB:
        case VM_JBE:
        case VM_JG:
        case VM_JGE:
        case VM_JL:
        case VM_JLE:
        case VM_RET_VM:
            return true;
        default:
            return false;
    }
}

static bool IsMinimalVMInterpreterProgram(
    const std::vector<CipherShell::BytecodeInstr>& instructions,
    std::string& reason)
{
    for (const auto& instr : instructions) {
        if (!IsMinimalVMInterpreterOpcode(instr.opcode)) {
            reason = "unsupported_minimal_interpreter_opcode_" +
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

static uint32_t ReadLe32(const std::vector<uint8_t>& data, size_t pos) {
    return static_cast<uint32_t>(data[pos]) |
        (static_cast<uint32_t>(data[pos + 1]) << 8) |
        (static_cast<uint32_t>(data[pos + 2]) << 16) |
        (static_cast<uint32_t>(data[pos + 3]) << 24);
}

static uint64_t ReadLe64(const std::vector<uint8_t>& data, size_t pos) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= static_cast<uint64_t>(data[pos + i]) << (i * 8);
    }
    return value;
}

static std::string HexValue(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

static bool IsValidVMRegisterId(uint8_t reg, uint32_t registerCount) {
    return reg == CipherShell::VM_REG_INVALID || reg < registerCount;
}

static bool IsVmJumpOpcode(uint8_t opcode) {
    switch (opcode) {
        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JAE:
        case VM_JB:
        case VM_JBE:
        case VM_JG:
        case VM_JGE:
        case VM_JL:
        case VM_JLE:
            return true;
        default:
            return false;
    }
}

static bool IsVmConditionalJumpOpcode(uint8_t opcode) {
    return IsVmJumpOpcode(opcode) && opcode != VM_JMP;
}

struct VMStaticDecodedInstr {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint8_t opcode = 0;
    bool hasTarget = false;
    uint32_t target = 0;
    bool terminal = false;
};

static bool DecodeAndValidateVMRecordBytecode(
    const CipherShell::VMFunctionRecord& record,
    const std::vector<uint8_t>& bytecode,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint32_t registerCount,
    uint32_t& opcodeCount,
    std::string& reason)
{
    opcodeCount = 0;
    if (registerCount == 0 || registerCount > 32) {
        reason = "invalid_register_count";
        return false;
    }
    if (record.bytecodeOffset > bytecode.size() ||
        record.bytecodeSize > bytecode.size() - record.bytecodeOffset) {
        reason = "record_bytecode_range_outside_blob";
        return false;
    }

    uint8_t reverseOpcode[256];
    for (uint32_t i = 0; i < 256; i++) reverseOpcode[i] = static_cast<uint8_t>(i);
    for (const auto& kv : opcodeMap) reverseOpcode[kv.second] = kv.first;

    const size_t begin = record.bytecodeOffset;
    const size_t end = begin + record.bytecodeSize;
    size_t ip = begin;
    bool hasRet = false;
    std::vector<VMStaticDecodedInstr> decoded;

    auto failAt = [&](const std::string& what, size_t at) {
        reason = what + " function_rva=" + HexValue(record.functionRVA) +
            " bytecode_offset=" + HexValue(static_cast<uint64_t>(at - begin));
        return false;
    };
    auto requireBytes = [&](size_t count, size_t at, const std::string& what) {
        if (at + count > end) {
            reason = what + " function_rva=" + HexValue(record.functionRVA) +
                " bytecode_offset=" + HexValue(static_cast<uint64_t>(at - begin));
            return false;
        }
        return true;
    };

    while (ip < end) {
        VMStaticDecodedInstr instr{};
        instr.offset = static_cast<uint32_t>(ip - begin);
        uint8_t encodedOpcode = bytecode[ip++];
        instr.opcode = reverseOpcode[encodedOpcode];

        if (!IsMinimalVMInterpreterOpcode(instr.opcode)) {
            reason = "unsupported_runtime_opcode function_rva=" + HexValue(record.functionRVA) +
                " bytecode_offset=" + HexValue(instr.offset) +
                " encoded=" + HexValue(encodedOpcode) +
                " opcode=" + HexValue(instr.opcode);
            return false;
        }

        switch (instr.opcode) {
            case VM_NOP:
                break;

            case VM_RET_VM:
                instr.terminal = true;
                hasRet = true;
                break;

            case VM_MOV_RR:
            case VM_ADD_RR:
            case VM_SUB_RR:
            case VM_AND_RR:
            case VM_OR_RR:
            case VM_XOR_RR:
            case VM_CMP_RR:
            case VM_TEST_RR: {
                if (!requireBytes(3, ip, "rr_operand_oob")) return false;
                uint8_t dst = bytecode[ip++];
                uint8_t src = bytecode[ip++];
                uint8_t width = bytecode[ip++];
                if (!IsValidVMRegisterId(dst, registerCount) || !IsValidVMRegisterId(src, registerCount)) {
                    return failAt("invalid_register_id", ip - 3);
                }
                if (!(width == 1 || width == 2 || width == 4 || width == 8)) return failAt("invalid_operand_width", ip - 1);
                break;
            }

            case VM_MOV_RC:
            case VM_ADD_RC:
            case VM_SUB_RC:
            case VM_AND_RC:
            case VM_OR_RC:
            case VM_XOR_RC:
            case VM_CMP_RC:
            case VM_TEST_RC:
            case VM_PUSH_C: {
                if (!requireBytes(10, ip, "rc_operand_oob")) return false;
                uint8_t dst = bytecode[ip++];
                if (!IsValidVMRegisterId(dst, registerCount)) return failAt("invalid_register_id", ip - 1);
                ip += 8;
                uint8_t width = bytecode[ip++];
                if (!(width == 1 || width == 2 || width == 4 || width == 8)) return failAt("invalid_operand_width", ip - 1);
                break;
            }

            case VM_PUSH_R:
            case VM_POP_R: {
                if (!requireBytes(2, ip, "single_reg_operand_oob")) return false;
                uint8_t reg = bytecode[ip++];
                uint8_t width = bytecode[ip++];
                if (!IsValidVMRegisterId(reg, registerCount)) return failAt("invalid_register_id", ip - 2);
                if (!(width == 1 || width == 2 || width == 4 || width == 8)) return failAt("invalid_operand_width", ip - 1);
                break;
            }

            case VM_MOV_RM:
            case VM_MOV_MR:
            case VM_LEA: {
                if (!requireBytes(15, ip, "memory_operand_oob")) return false;
                uint8_t dst = bytecode[ip++];
                uint8_t src = bytecode[ip++];
                uint8_t base = bytecode[ip++];
                uint8_t index = bytecode[ip++];
                uint8_t scale = bytecode[ip++];
                uint8_t width = bytecode[ip++];
                uint8_t kind = bytecode[ip++];
                (void)ReadLe64(bytecode, ip);
                ip += 8;
                if (!IsValidVMRegisterId(dst, registerCount) ||
                    !IsValidVMRegisterId(src, registerCount) ||
                    !IsValidVMRegisterId(base, registerCount) ||
                    !IsValidVMRegisterId(index, registerCount)) {
                    return failAt("invalid_register_id", ip - 15);
                }
                if (!(scale == 1 || scale == 2 || scale == 4 || scale == 8)) {
                    return failAt("invalid_memory_scale", ip - 11);
                }
                if (!(width == 1 || width == 2 || width == 4 || width == 8)) {
                    return failAt("invalid_memory_width", ip - 10);
                }
                if (kind > 1) return failAt("invalid_memory_kind", ip - 9);
                break;
            }

            case VM_JMP:
            case VM_JZ:
            case VM_JNZ:
            case VM_JA:
            case VM_JAE:
            case VM_JB:
            case VM_JBE:
            case VM_JG:
            case VM_JGE:
            case VM_JL:
            case VM_JLE: {
                if (!requireBytes(4, ip, "jump_operand_oob")) return false;
                instr.hasTarget = true;
                instr.target = ReadLe32(bytecode, ip);
                ip += 4;
                if (instr.target >= record.bytecodeSize) {
                    return failAt("jump_target_outside_record", begin + instr.target);
                }
                break;
            }

            case VM_CALL_NATIVE: {
                if (!requireBytes(4, ip, "native_call_operand_oob")) return false;
                ip += 4;
                break;
            }

            default:
                return failAt("unsupported_static_decoder_opcode", ip - 1);
        }

        instr.size = static_cast<uint32_t>((ip - begin) - instr.offset);
        decoded.push_back(instr);
        opcodeCount++;
    }

    if (decoded.empty()) {
        reason = "empty_decoded_bytecode function_rva=" + HexValue(record.functionRVA);
        return false;
    }
    if (!hasRet) {
        reason = "ret_missing function_rva=" + HexValue(record.functionRVA);
        return false;
    }

    auto findIndexByOffset = [&](uint32_t offset, size_t& index) {
        for (size_t i = 0; i < decoded.size(); i++) {
            if (decoded[i].offset == offset) {
                index = i;
                return true;
            }
        }
        return false;
    };

    std::vector<uint8_t> visited(decoded.size(), 0);
    std::vector<size_t> stack;
    stack.push_back(0);
    bool reachableRet = false;

    auto pushOffset = [&](uint32_t offset, const std::string& edgeName) {
        size_t idx = 0;
        if (!findIndexByOffset(offset, idx)) {
            reason = edgeName + "_not_instruction_boundary function_rva=" + HexValue(record.functionRVA) +
                " target=" + HexValue(offset);
            return false;
        }
        if (!visited[idx]) stack.push_back(idx);
        return true;
    };

    while (!stack.empty()) {
        size_t idx = stack.back();
        stack.pop_back();
        if (idx >= decoded.size() || visited[idx]) continue;
        visited[idx] = 1;
        const auto& instr = decoded[idx];
        uint32_t next = instr.offset + instr.size;

        if (instr.terminal) {
            reachableRet = true;
            continue;
        }
        if (instr.hasTarget) {
            if (!pushOffset(instr.target, "jump_target")) return false;
            if (IsVmConditionalJumpOpcode(instr.opcode) && next < record.bytecodeSize) {
                if (!pushOffset(next, "fallthrough")) return false;
            }
            continue;
        }
        if (next < record.bytecodeSize) {
            if (!pushOffset(next, "fallthrough")) return false;
        } else {
            reason = "control_flow_falls_off_without_ret function_rva=" + HexValue(record.functionRVA);
            return false;
        }
    }

    if (!reachableRet) {
        reason = "ret_not_reachable function_rva=" + HexValue(record.functionRVA);
        return false;
    }
    return true;
}

static const char* PatchKindName(CipherShell::FunctionPatchKind kind) {
    switch (kind) {
        case CipherShell::FunctionPatchKind::NearRel32: return "rel32";
        case CipherShell::FunctionPatchKind::X64AbsoluteR11: return "abs64";
        default: return "none";
    }
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
    const std::vector<CipherShell::VMFunctionRecord>& records,
    const std::vector<uint8_t>& bytecode,
    const CipherShell::VMEmitResult& emitResult,
    const CipherShell::VMRuntimeBuildResult& runtimeResult,
    const std::vector<CipherShell::FunctionPatchResult>& patchResults,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint32_t registerCount,
    std::unordered_map<uint32_t, uint32_t>& opcodeCounts,
    std::string& reason)
{
    opcodeCounts.clear();
    if (!runtimeResult.executionReady) { reason = "runtime_not_execution_ready"; return false; }
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
    if (records.empty() || bytecode.empty()) { reason = "records_or_bytecode_empty"; return false; }
    if (opcodeMap.empty() || registerMap.empty()) { reason = "opcode_or_register_map_missing"; return false; }
    if (runtimeResult.trampolines.size() != records.size()) { reason = "trampoline_count_mismatch"; return false; }
    if (patchResults.size() != records.size()) { reason = "patch_result_count_mismatch"; return false; }

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
            if (patch.functionRVA == record.functionRVA && patch.success && patch.verified && patch.trampolineRVA != 0) {
                hasVerifiedPatch = true;
                break;
            }
        }
        if (!hasVerifiedPatch) {
            reason = "record_without_verified_function_patch";
            return false;
        }

        uint32_t opcodeCount = 0;
        std::string decodeReason;
        if (!DecodeAndValidateVMRecordBytecode(record, bytecode, opcodeMap, registerCount, opcodeCount, decodeReason)) {
            reason = "bytecode_decoder_check_failed: " + decodeReason;
            return false;
        }
        opcodeCounts[record.functionRVA] = opcodeCount;
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
                std::cerr << "閿欒: -o 閫夐」闇€瑕佹寚瀹氳緭鍑烘枃浠惰矾寰? << std::endl;
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
                std::cerr << "閿欒: -l 閫夐」闇€瑕佹寚瀹氫繚鎶ょ瓑绾? << std::endl;
                return 1;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                configFile = argv[++i];
            } else {
                std::cerr << "閿欒: -c 閫夐」闇€瑕佹寚瀹氶厤缃枃浠惰矾寰? << std::endl;
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
        std::cerr << "閿欒: 鏈寚瀹氳緭鍏ユ枃浠? << std::endl;
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
        std::cout << "    鍙戠幇 " << strings.size() << " 涓瓧绗︿覆" << std::endl;

        if (!strings.empty()) {
            strEncryptor.EncryptStrings(image.get(), strings);
            encryptedStringRegions.reserve(encryptedStringRegions.size() + strings.size());
            for (const auto& s : strings) {
                CipherShell::CS_ENCRYPTED_SECTION region{};
                region.sectionIndex = 0xFFFF;
                region.originalRVA = s.rva;
                region.originalSize = s.length;
                region.encryptedSize = s.length;
                memcpy(region.sectionKey.key, s.key, 32);
                memcpy(region.sectionKey.nonce, s.nonce, 12);
                region.sectionKey.counter = 0;
                encryptedStringRegions.push_back(region);
            }
            std::cout << "    宸插姞瀵嗘墍鏈夊瓧绗︿覆锛屽苟鐧昏杩愯鏃惰В瀵嗕换鍔? << std::endl;
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
        obfConfig.strategy = CipherShell::ImportObfuscationStrategy::StrategyC;

        CipherShell::APIResolver resolver;
        resolver.Initialize();

        auto obfImports = obfuscator.ObfuscateImports(image.get(), obfConfig, &resolver);
        std::cout << "    娣锋穯浜?" << obfImports.size() << " 涓鍏ュ嚱鏁? << std::endl;
            PrintFeatureStatus("import_protection", "partial", "runtime_resolver_callsite_rewrite_not_closed");
    } else {
        PrintFeatureStatus("import_protection", "skipped", "disabled");
    }

    // Phase C: 鎺у埗娴佸钩鍧﹀寲锛圠3+锛屾殏绂佺敤鈥斺€擥enerateFlattenedCode 闇€瑕佷紭鍖栵級
    if (buildCtx.flattening.enabled) {  // FIXME: 鏆傛椂绂佺敤锛屽緟浼樺寲
        std::cout << "  搴旂敤鎺у埗娴佸钩鍧﹀寲..." << std::endl;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            BYTE* secData = image->rawData + secOffset;
            uint64_t baseAddr = sec.VirtualAddress;

            auto functions = disasm.AnalyzeCode(secData, secSize, baseAddr, is64);
            if (functions.empty()) {
                std::cout << "    浠ｇ爜娈礫" << si << "]: 鏈瘑鍒埌鍑芥暟锛堝彲鑳芥棤杩斿洖鎸囦护锛? << std::endl;
                continue;
            }
            std::cout << "    浠ｇ爜娈礫" << si << "]: 璇嗗埆鍒?" << functions.size() << " 涓嚱鏁? << std::endl;

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
            std::cout << "    骞冲潶鍖栦簡 " << flattenedCount << " 涓嚱鏁? << std::endl;
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

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            auto functions = disasm.AnalyzeCode(
                image->rawData + secOffset, secSize,
                sec.VirtualAddress, is64);

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
            std::cout << "    娉ㄥ叆浜?" << injectedCount << " 涓嚱鏁扮殑铏氬亣鎺у埗娴? << std::endl;
        }
    }

    // Phase E: 鍑芥暟绾?VM 淇濇姢銆傝繖閲屽彧鍏佽瀹屾暣钀界洏鐨勬暟鎹繘鍏ヤ笅涓€姝ワ紝澶辫触蹇呴』鏄庣‘璇婃柇銆?
    if (buildCtx.vm.enabled) {
        std::cout << "  搴旂敤浠ｇ爜铏氭嫙鍖?(Mirage VM)..." << std::endl;

        CipherShell::MutationEngine mutEngine;
        CipherShell::MutationConfig mutConfig;
        mutConfig.randomizeOpcodeMap = true;
        mutConfig.randomizeRegisterMap = true;
        mutConfig.mutateHandlers = true;
        mutConfig.insertJunkHandlers = true;
        mutConfig.junkHandlerCount = 20;
        mutConfig.seed = buildCtx.isaSeed;
        mutEngine.Initialize(mutConfig);

        CipherShell::MutatedISA mutatedISA = mutEngine.GenerateMutatedISA();
        buildCtx.opcodeMap = mutatedISA.opcodeMap;
        buildCtx.registerMap = mutatedISA.registerMap;
        std::cout << "    ISA 鍙樺紓绉嶅瓙: 0x" << std::hex << mutEngine.GetSeed() << std::dec << std::endl;

        CipherShell::Translator translator;
        CipherShell::TranslationConfig transConfig;
        transConfig.virtualRegisterCount = mutConfig.registerCount;
        transConfig.enableOpcodeRandomization = true;
        transConfig.enableJunkInsertion = true;
        transConfig.junkRatio = 10;
        if (!translator.Initialize(transConfig)) {
            std::cerr << "VM_INIT_FAIL module=Translator reason=initialize_failed" << std::endl;
            return 1;
        }
        translator.SetOpcodeMap(buildCtx.opcodeMap);
        translator.SetRegisterMap(buildCtx.registerMap);
        PrintVMRegisterMapReport(buildCtx.registerMap);
        std::cout << "VM_MEMORY_SUPPORT load_store=MOV_RM,MOV_MR address_calc=LEA memory_arithmetic=false addressing=base_disp,index_scale,rip_relative_image_rva widths=1,2,4,8 stack_policy=rsp_mutation_rejected" << std::endl;
        std::cout << "VM_CALL_STACK_POLICY call=reject push=reject pop=reject native_bridge=not_implemented" << std::endl;


        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        uint32_t virtualizedCount = 0;
        uint32_t rejectedCount = 0;
        std::vector<uint8_t> vmBytecodeBlob;
        std::vector<CipherShell::VMFunctionRecord> vmRecords;

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            BYTE* secData = image->rawData + secOffset;
            uint64_t baseAddr = sec.VirtualAddress;
            auto functions = disasm.AnalyzeCode(secData, secSize, baseAddr, is64);

            for (const auto& func : functions) {
                if (func.blocks.size() < 2 || func.size < 5) continue;
                if (func.entryAddress > 0xFFFFFFFFULL || func.size > 0xFFFFFFFFULL) {
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
                if (!IsMinimalVMInterpreterProgram(transResult.instructions, interpreterRejectReason)) {
                    std::cerr << "VM_REJECT module=VMRuntimeBuilder function_rva=0x" << std::hex
                              << func.entryAddress << std::dec
                              << " reason=" << interpreterRejectReason << std::endl;
                    rejectedCount++;
                    continue;
                }

                auto vmBytecode = translator.GenerateBytecode(transResult, nullptr, nullptr);
                if (vmBytecode.empty()) {
                    std::cerr << "VM_BYTECODE_FAIL module=TranslatorBytecode function_rva=0x" << std::hex
                              << func.entryAddress << std::dec << " reason=empty_bytecode" << std::endl;
                    rejectedCount++;
                    continue;
                }

                CipherShell::VMFunctionRecord record{};
                record.functionRVA = static_cast<uint32_t>(func.entryAddress);
                record.functionSize = static_cast<uint32_t>(func.size);
                record.bytecodeOffset = static_cast<uint32_t>(vmBytecodeBlob.size());
                record.bytecodeSize = static_cast<uint32_t>(vmBytecode.size());
                record.opcodeMapOffset = 0;
                record.registerMapOffset = 0;
                record.flags = is64 ? 1u : 0u;
                vmRecords.push_back(record);
                vmBytecodeBlob.insert(vmBytecodeBlob.end(), vmBytecode.begin(), vmBytecode.end());
                virtualizedCount++;
            }
        }

        if (!vmRecords.empty()) {
            CipherShell::VMSectionEmitter vmEmitter;
            auto emitResult = vmEmitter.Emit(image.get(), vmBytecodeBlob, vmRecords,
                buildCtx.opcodeMap, buildCtx.registerMap, 0, buildCtx.vmSectionName);
            if (!emitResult.success) {
                std::cerr << "VM_EMIT_FAIL module=VMSectionEmitter reason=" << emitResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", emitResult.error);
                return 1;
            }

            CipherShell::VMRuntimeBuilder runtimeBuilder;
            auto runtimeResult = runtimeBuilder.Build(image.get(), vmRecords,
                emitResult.metadataRVA, buildCtx.vmRuntimeSectionName);
            if (!runtimeResult.success) {
                std::cerr << "VM_RUNTIME_FAIL module=VMRuntimeBuilder reason=" << runtimeResult.error << std::endl;
                                PrintFeatureStatus("vm", "failed", runtimeResult.error);
                return 1;
            }

            std::string patchError;
            if (!vmEmitter.PatchRuntimeEntry(image.get(), emitResult.metadataRVA,
                    runtimeResult.runtimeEntryRVA, &patchError)) {
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
            auto patchResults = patcher.PatchFunctions(image.get(), runtimeResult.trampolines, vmRecords, true);
            for (const auto& patch : patchResults) {
                if (!patch.success) {
                    std::cerr << "VM_PATCH_FAIL module=FunctionTrampolinePatcher function_rva=0x"
                              << std::hex << patch.functionRVA << std::dec
                              << " reason=" << patch.error << std::endl;
                                        PrintFeatureStatus("vm", "failed", patch.error);
                    return 1;
                }
            }

            std::string staticCheckReason;
            std::unordered_map<uint32_t, uint32_t> vmOpcodeCounts;
            if (!ValidateVMStaticLink(vmRecords, vmBytecodeBlob, emitResult, runtimeResult,
                    patchResults, buildCtx.opcodeMap, buildCtx.registerMap,
                    transConfig.virtualRegisterCount, vmOpcodeCounts, staticCheckReason)) {
                std::cerr << "VM_STATIC_CHECK_FAIL module=VMStaticLinkChecker reason="
                          << staticCheckReason << std::endl;
                PrintFeatureStatus("vm", "failed", staticCheckReason);
                return 1;
            }
            std::cout << "VM_STATIC_CHECK_PASS module=VMStaticLinkChecker records="
                      << vmRecords.size() << std::endl;
            std::cout << "VM_RUNTIME_SECTION rva=0x" << std::hex << runtimeResult.sectionRVA
                      << " raw=0x" << runtimeResult.sectionRawOffset
                      << " size=0x" << runtimeResult.sectionSize
                      << " entry=0x" << runtimeResult.runtimeEntryRVA << std::dec << std::endl;
            std::cout << "VM_METADATA_SECTION rva=0x" << std::hex << emitResult.sectionRVA
                      << " raw=0x" << emitResult.sectionRawOffset
                      << " size=0x" << emitResult.sectionSize
                      << " metadata=0x" << emitResult.metadataRVA
                      << " bytecode=0x" << emitResult.bytecodeRVA << std::dec << std::endl;
            std::cout << "VM_DEBUG_TRACE_LAYOUT runtime_version_off=32 runtime_flags_off=36 enter_count_off=40"
                      << " last_function_rva_off=44 last_opcode_off=48 last_error_code_off=52"
                      << " last_bytecode_offset_off=56 last_ret_value_low32_off=60 fail_policy=int3_ud2" << std::endl;
            std::cout << "VM_MEMORY_SUPPORT load_store=MOV_RM,MOV_MR address_calc=LEA memory_arithmetic=false widths=1,2,4,8" << std::endl;

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
                          << " opcode_count=" << std::dec << opcodeCount
                          << " patched_first16=" << FormatImageBytesAtRva(image.get(), record.functionRVA, 16)
                          << " trampoline_first16=" << FormatImageBytesAtRva(image.get(), trampoline ? trampoline->trampolineRVA : 0, 16)
                          << std::endl;
            }
            std::cout << "VM_MANUAL_TEST_COMMAND compile=\"D:\\vs2022\\vs2022.exe\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx86\\x86\\cl.exe /nologo /EHsc /O2 /Fe:tests\\samples\\vm_manual_x64_sample.exe tests\\samples\\vm_manual_x64_sample.cpp\"" << std::endl;
            std::cout << "VM_MANUAL_TEST_COMMAND pack=\"ciphershell tests\\samples\\vm_manual_x64_sample.exe -o tests\\samples\\vm_manual_x64_sample.vm.exe -l 4 -v\"" << std::endl;
            std::cout << "VM_MANUAL_DEBUG_HINT first_check=metadata_trace_slots,last_error_code,runtime_section,trampoline_patch,bytecode_offset" << std::endl;
            PrintFeatureStatus("vm", "applied", "functions=" + std::to_string(vmRecords.size()));
        } else {
            PrintFeatureStatus("vm", "skipped", "no_supported_functions");
        }

        std::cout << "    VM bytecode 鍐欏叆鍑芥暟鏁? " << virtualizedCount
                  << "锛屾嫆缁濆嚱鏁版暟: " << rejectedCount << std::endl;

        if (buildCtx.quickLevel >= 5) {
            std::cout << "  宓屽 VM 绛夊緟涓€绾?VM runtime 鎵ц鍣?ready 鍚庡惎鐢? << std::endl;
        }
    }
    // Phase F: Section 鍔犲瘑锛圠1+锛屾渶鍚庢墽琛屸€斺€斿姞瀵嗘墍鏈夊彉鎹㈠悗鐨勪唬鐮侊級
    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedSections;
    if (buildCtx.sectionEncryption.enabled) {
        std::cout << "  搴旂敤 Section 鍔犲瘑..." << std::endl;

        CipherShell::SectionEncryptor encryptor;
        CipherShell::CS_ENCRYPT_CONFIG encConfig;
        encConfig.encryptCodeSections = true;
        encConfig.encryptDataSections = false;
        encConfig.encryptResources = config.global.resourceEncryption;
        CipherShell::CS_ENCRYPTION_KEY masterKey = encryptor.GenerateRandomKey();

        encryptedSections = encryptor.EncryptSections(image.get(), encConfig, masterKey);
        std::cout << "    宸插姞瀵?" << encryptedSections.size() << " 涓?Section" << std::endl;
            PrintFeatureStatus("section_encryption", encryptedSections.empty() ? "skipped" : "applied", encryptedSections.empty() ? "no_encryptable_sections" : "mode=" + buildCtx.sectionEncryption.mode);
    } else {
        PrintFeatureStatus("section_encryption", "skipped", "disabled");
    }

    if (!encryptedStringRegions.empty()) {
        encryptedSections.insert(encryptedSections.end(),
            encryptedStringRegions.begin(), encryptedStringRegions.end());
        std::cout << "    宸茶拷鍔?" << encryptedStringRegions.size()
                  << " 涓瓧绗︿覆杩愯鏃惰В瀵嗕换鍔? << std::endl;
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
        if (!stubBuilder.EmbedStub(image.get(), encryptedSections, originalOEP)) {
            std::cerr << "  閿欒: Stub 宓屽叆澶辫触" << std::endl;
            return 1;
        }
    } else {
        std::cout << "  璺宠繃锛堟棤鍔犲瘑 section锛? << std::endl;
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

    std::cout << "  PE 閲嶅缓鎴愬姛" << std::endl;
    std::cout << "  杈撳嚭澶у皬: " << outputSize << " 瀛楄妭" << std::endl;

    // 鍐欏叆杈撳嚭鏂囦欢
    FILE* outFile = fopen(outputFile.c_str(), "wb");
    if (!outFile) {
        std::cerr << "閿欒: 鏃犳硶鍒涘缓杈撳嚭鏂囦欢: " << outputFile << std::endl;
        return 1;
    }
    fwrite(outputData.get(), 1, outputSize, outFile);
    fclose(outFile);

    std::cout << "  杈撳嚭鏂囦欢宸蹭繚瀛? " << outputFile << std::endl;
    std::cout << "  鏂囦欢澶у皬: " << outputSize << " 瀛楄妭" << std::endl;

    // ============================================================================
    // Step 6: 楠岃瘉杈撳嚭
    // ============================================================================

    std::cout << "\n[6/6] 楠岃瘉杈撳嚭鏂囦欢..." << std::endl;

    CipherShell::CS_PE_IMAGE* verifyImage = parser.LoadFromFile(outputFile);
    if (verifyImage && verifyImage->isValid) {
        std::cout << "  楠岃瘉鎴愬姛: 杈撳嚭鏂囦欢鏄湁鏁堢殑 PE" << std::endl;
        parser.FreeImage(verifyImage);
    } else {
        std::cerr << "  璀﹀憡: 杈撳嚭鏂囦欢鍙兘涓嶆槸鏈夋晥鐨?PE" << std::endl;
    }

    std::cout << "\n======================================" << std::endl;
    std::cout << "CipherShell 澶勭悊瀹屾垚!" << std::endl;
    std::cout << "杈撳嚭鏂囦欢: " << outputFile << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}


