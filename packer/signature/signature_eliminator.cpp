/**
 * CipherShell 签名消除器 - 实现
 */

#include "signature_eliminator.h"
#include "../config/config_parser.h"
#include "../pe_parser/pe_utils.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <limits>
#include <sstream>
// 与 protection_build_context.cpp / section_encryptor.cpp / string_encryptor.cpp /
// vm_section_emitter.cpp 统一：BCryptGenRandom 是 Windows-only API，非 Windows
// 平台改用 std::random_device，不能无条件 #include <bcrypt.h>（该头文件在非
// Windows 平台根本不存在，会导致整个目标编译失败）。
#ifdef _WIN32
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <random>
#endif

namespace CipherShell {

namespace {

bool IsExactPreservedSectionName(const BYTE name[IMAGE_SIZEOF_SHORT_NAME]) {
    static constexpr BYTE kResourceName[IMAGE_SIZEOF_SHORT_NAME] = {
        '.', 'r', 's', 'r', 'c', 0, 0, 0};
    static constexpr BYTE kRelocationName[IMAGE_SIZEOF_SHORT_NAME] = {
        '.', 'r', 'e', 'l', 'o', 'c', 0, 0};
    return std::memcmp(name, kResourceName, sizeof(kResourceName)) == 0 ||
        std::memcmp(name, kRelocationName, sizeof(kRelocationName)) == 0;
}

} // namespace

// ============================================================================
// 已知壳的特征模式
// ============================================================================

// VMProtect 特征：.vmp0, .vmp1 section
const BYTE SignatureEliminator::s_vmpPattern[] = {0x2E, 0x76, 0x6D, 0x70, 0x30};  // ".vmp0"

// Themida 特征
const BYTE SignatureEliminator::s_themidaPattern[] = {0x2E, 0x74, 0x68, 0x65, 0x6D, 0x69, 0x64, 0x61};  // ".themida"

// UPX 特征
const BYTE SignatureEliminator::s_upxPattern[] = {0x55, 0x50, 0x58, 0x30};  // "UPX0"

// ASPack 特征
const BYTE SignatureEliminator::s_aspackPattern[] = {0x2E, 0x41, 0x53, 0x50, 0x61, 0x63, 0x6B};  // ".ASPack"

// ============================================================================
// 构造/析构
// ============================================================================

SignatureEliminator::SignatureEliminator() {
    srand((unsigned int)time(nullptr));
}

SignatureEliminator::~SignatureEliminator() {}

EliminationConfig BuildEliminationConfig(const GlobalConfig& global) {
    EliminationConfig config;
    config.randomizeSectionNames = global.randomizeSections;
    config.randomizeTimestamps = global.stripTimestamps;
    config.clearRichHeader = global.stripRichHeader;
    config.clearDebugDirectory = global.stripDebugInfo;

    // Checksum 没有独立 UI 项；维持既有的强制输出卫生策略。其余历史字段
    // 没有生产实现，必须显式关闭，不能借默认值伪装成已应用。
    config.clearChecksum = true;
    config.randomizeFileAlignment = false;
    config.randomizeSectionAlignment = false;
    config.addFakeImports = false;
    config.addFakeResources = false;
    return config;
}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<SignatureMatch> SignatureEliminator::DetectSignatures(CS_PE_IMAGE* image) {
    std::vector<SignatureMatch> matches;

    if (!image || !image->isValid) {
        return matches;
    }

    // 检测各种壳的签名
    CheckVMProtectSignature(image, matches);
    CheckThemidaSignature(image, matches);
    CheckUPXSignature(image, matches);
    CheckASPackSignature(image, matches);
    CheckPEiDSignatures(image, matches);

    return matches;
}

bool SignatureEliminator::EliminateSignatures(CS_PE_IMAGE* image, const EliminationConfig& config,
        std::string& reason) {
    reason.clear();
    if (!image || !image->isValid) {
        reason = "invalid_pe_image";
        return false;
    }

    // 这些历史字段没有对应的生产实现，也未暴露为 global/UI 控件。显式传入
    // true 时必须 fail-closed，不能把一个未执行的隐藏选项算进四个全局开关。
    if (config.randomizeFileAlignment || config.randomizeSectionAlignment ||
        config.addFakeImports || config.addFakeResources) {
        reason = "unsupported_elimination_option_enabled";
        return false;
    }

    // 每个子步骤的返回值都必须传播：吞掉失败会让调用方把一次不完整的签名
    // 消除当作"成功产物"报告出去，与项目 fail-closed 原则冲突。

    // 随机化 section 名称
    if (config.randomizeSectionNames && !RandomizeSectionNames(image)) {
        reason = "randomize_section_names_failed";
        return false;
    }

    // 清除 Rich Header
    if (config.clearRichHeader && !ClearRichHeader(image)) {
        reason = "clear_rich_header_failed";
        return false;
    }

    // 清除调试目录
    if (config.clearDebugDirectory && !ClearDebugDirectory(image)) {
        reason = "clear_debug_directory_failed";
        return false;
    }

    // 清除时间戳
    if (config.randomizeTimestamps && !ClearTimestamps(image)) {
        reason = "clear_timestamps_failed";
        return false;
    }

    // 清除校验和
    if (config.clearChecksum && !ClearChecksum(image)) {
        reason = "clear_checksum_failed";
        return false;
    }

    // 注意：不得在此统一重写 section 权限。VM metadata/bytecode/只读数据段的
    // 原始权限必须保持不变；任何权限规范化都会破坏后续流程已设置的 W^X 布局。

    return true;
}

bool SignatureEliminator::VerifyElimination(CS_PE_IMAGE* image) {
    if (!image || !image->isValid) {
        return false;
    }

    // 重新检测
    auto matches = DetectSignatures(image);
    return matches.empty();
}

bool SignatureEliminator::VerifyElimination(CS_PE_IMAGE* image,
        const EliminationConfig& config, std::string& reason) {
    reason.clear();
    if (!image || !image->isValid) {
        reason = "invalid_pe_image";
        return false;
    }

    if (config.randomizeFileAlignment || config.randomizeSectionAlignment ||
        config.addFakeImports || config.addFakeResources) {
        reason = "unsupported_elimination_option_enabled";
        return false;
    }

    if (config.randomizeSectionNames) {
        if (!image->sections || image->numSections == 0) {
            reason = "section_table_missing";
            return false;
        }
        for (WORD i = 0; i < image->numSections; i++) {
            if (IsExactPreservedSectionName(image->sections[i].Name)) {
                continue;
            }

            // GenerateRandomName 的生产后置条件是恰好 8 个小写字母；这也让
            // verifier 能拒绝仍为 .text/UPX0 等原始名称的伪 applied 状态。
            for (size_t j = 0; j < 8; j++) {
                const BYTE value = image->sections[i].Name[j];
                if (value < static_cast<BYTE>('a') ||
                    value > static_cast<BYTE>('z')) {
                    reason = "section_name_not_randomized index=" +
                        std::to_string(i);
                    return false;
                }
            }
            if (!VerifyNoSignatureMatch(image->sections[i].Name, 8)) {
                reason = "randomized_section_name_matches_signature index=" +
                    std::to_string(i);
                return false;
            }
        }
    }

    if (config.clearRichHeader) {
        if (image->hasRichHeader) {
            reason = "rich_header_present";
            return false;
        }
        if (!image->rawData || !image->dosHeader ||
            image->dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            static_cast<uint64_t>(image->dosHeader->e_lfanew) > image->rawSize) {
            reason = "rich_header_bounds_invalid";
            return false;
        }

        constexpr DWORD kRichSignature = 0x68636952u;  // "Rich"
        const DWORD end = static_cast<DWORD>(image->dosHeader->e_lfanew);
        for (DWORD offset = static_cast<DWORD>(sizeof(IMAGE_DOS_HEADER));
             offset <= end - sizeof(DWORD); offset += sizeof(DWORD)) {
            DWORD value = 0;
            std::memcpy(&value, image->rawData + offset, sizeof(value));
            if (value == kRichSignature) {
                reason = "rich_header_marker_present";
                return false;
            }
        }
    }

    if (config.clearDebugDirectory) {
        const IMAGE_DATA_DIRECTORY* debugDirectory = nullptr;
        if (image->is64Bit && image->ntHeaders64) {
            debugDirectory = &image->ntHeaders64->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        } else if (!image->is64Bit && image->ntHeaders32) {
            debugDirectory = &image->ntHeaders32->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
        if (!debugDirectory) {
            reason = "debug_directory_header_missing";
            return false;
        }
        if (debugDirectory->VirtualAddress != 0 || debugDirectory->Size != 0) {
            reason = "debug_directory_present";
            return false;
        }
    }

    if (config.randomizeTimestamps) {
        DWORD timestamp = 0;
        if (image->is64Bit && image->ntHeaders64) {
            timestamp = image->ntHeaders64->FileHeader.TimeDateStamp;
        } else if (!image->is64Bit && image->ntHeaders32) {
            timestamp = image->ntHeaders32->FileHeader.TimeDateStamp;
        } else {
            reason = "timestamp_header_missing";
            return false;
        }
        if (timestamp != 0) {
            reason = "timestamp_not_cleared";
            return false;
        }
    }

    if (config.clearChecksum) {
        DWORD checksum = 0;
        if (image->is64Bit && image->ntHeaders64) {
            checksum = image->ntHeaders64->OptionalHeader.CheckSum;
        } else if (!image->is64Bit && image->ntHeaders32) {
            checksum = image->ntHeaders32->OptionalHeader.CheckSum;
        } else {
            reason = "checksum_header_missing";
            return false;
        }
        if (checksum != 0) {
            reason = "checksum_not_cleared";
            return false;
        }
    }

    // 有意不调用 DetectSignatures：例如用户只请求清时间戳时，输入原本存在
    // 的 UPX section 名或通用入口特征不属于本次请求，不能导致误判失败。
    return true;
}

bool SignatureEliminator::CaptureState(CS_PE_IMAGE* image,
        EliminationState& state, std::string& reason) {
    state = EliminationState{};
    reason.clear();
    if (!image || !image->isValid || !image->rawData || !image->dosHeader) {
        reason = "state_invalid_pe_image";
        return false;
    }
    if (image->dosHeader->e_lfanew <
            static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        static_cast<uint64_t>(image->dosHeader->e_lfanew) > image->rawSize) {
        reason = "state_pe_header_bounds_invalid";
        return false;
    }
    if (image->numSections != 0 && !image->sections) {
        reason = "state_section_table_missing";
        return false;
    }

    const IMAGE_DATA_DIRECTORY* debugDirectory = nullptr;
    if (image->is64Bit && image->ntHeaders64) {
        debugDirectory = &image->ntHeaders64->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        state.machine = image->ntHeaders64->FileHeader.Machine;
        state.optionalHeaderMagic =
            image->ntHeaders64->OptionalHeader.Magic;
        state.sizeOfOptionalHeader =
            image->ntHeaders64->FileHeader.SizeOfOptionalHeader;
        state.numberOfRvaAndSizes =
            image->ntHeaders64->OptionalHeader.NumberOfRvaAndSizes;
        state.coffTimestamp =
            image->ntHeaders64->FileHeader.TimeDateStamp;
        state.checksum = image->ntHeaders64->OptionalHeader.CheckSum;
    } else if (!image->is64Bit && image->ntHeaders32) {
        debugDirectory = &image->ntHeaders32->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        state.machine = image->ntHeaders32->FileHeader.Machine;
        state.optionalHeaderMagic =
            image->ntHeaders32->OptionalHeader.Magic;
        state.sizeOfOptionalHeader =
            image->ntHeaders32->FileHeader.SizeOfOptionalHeader;
        state.numberOfRvaAndSizes =
            image->ntHeaders32->OptionalHeader.NumberOfRvaAndSizes;
        state.coffTimestamp =
            image->ntHeaders32->FileHeader.TimeDateStamp;
        state.checksum = image->ntHeaders32->OptionalHeader.CheckSum;
    } else {
        reason = "state_nt_headers_missing";
        return false;
    }

    state.is64Bit = image->is64Bit != FALSE;
    state.numberOfSections = image->numSections;
    state.peHeaderOffset = static_cast<DWORD>(image->dosHeader->e_lfanew);
    state.hasRichHeader = image->hasRichHeader != FALSE;
    state.debugDirectoryRVA = debugDirectory->VirtualAddress;
    state.debugDirectorySize = debugDirectory->Size;

    try {
        state.sectionNames.resize(image->numSections);
        for (WORD i = 0; i < image->numSections; ++i) {
            std::memcpy(state.sectionNames[i].data(),
                image->sections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        }
        const BYTE* stubBegin =
            image->rawData + sizeof(IMAGE_DOS_HEADER);
        const BYTE* stubEnd = image->rawData + state.peHeaderOffset;
        state.dosStubBytes.assign(stubBegin, stubEnd);
    } catch (...) {
        state = EliminationState{};
        reason = "state_capture_allocation_failed";
        return false;
    }
    return true;
}

bool SignatureEliminator::VerifyTransition(const EliminationState& before,
        CS_PE_IMAGE* image, const EliminationConfig& config,
        EliminationState& after, std::string& reason) {
    if (!VerifyElimination(image, config, reason)) {
        return false;
    }
    if (!CaptureState(image, after, reason)) {
        return false;
    }
    if (before.is64Bit != after.is64Bit ||
        before.machine != after.machine ||
        before.optionalHeaderMagic != after.optionalHeaderMagic ||
        before.sizeOfOptionalHeader != after.sizeOfOptionalHeader ||
        before.numberOfSections != after.numberOfSections ||
        before.numberOfRvaAndSizes != after.numberOfRvaAndSizes ||
        before.peHeaderOffset != after.peHeaderOffset ||
        before.sectionNames.size() != after.sectionNames.size()) {
        reason = "state_layout_changed";
        return false;
    }

    for (size_t i = 0; i < before.sectionNames.size(); ++i) {
        const auto& oldName = before.sectionNames[i];
        const auto& newName = after.sectionNames[i];
        if (!config.randomizeSectionNames) {
            if (oldName != newName) {
                reason = "disabled_section_name_changed index=" +
                    std::to_string(i);
                return false;
            }
            continue;
        }
        if (IsExactPreservedSectionName(oldName.data())) {
            if (oldName != newName) {
                reason = "preserved_section_name_changed index=" +
                    std::to_string(i);
                return false;
            }
            continue;
        }
        if (oldName == newName) {
            reason = "section_name_not_changed index=" +
                std::to_string(i);
            return false;
        }
        for (BYTE value : newName) {
            if (value < static_cast<BYTE>('a') ||
                value > static_cast<BYTE>('z')) {
                reason = "section_name_not_randomized index=" +
                    std::to_string(i);
                return false;
            }
        }
        if (!VerifyNoSignatureMatch(newName.data(),
                static_cast<DWORD>(newName.size()))) {
            reason = "randomized_section_name_matches_signature index=" +
                std::to_string(i);
            return false;
        }
    }

    if (config.clearRichHeader) {
        if (after.hasRichHeader) {
            reason = "rich_header_present";
            return false;
        }
        if (before.hasRichHeader) {
            for (BYTE value : after.dosStubBytes) {
                if (value != 0) {
                    reason = "rich_header_region_not_zero";
                    return false;
                }
            }
        } else if (before.dosStubBytes != after.dosStubBytes) {
            reason = "absent_rich_region_changed";
            return false;
        }
    } else if (before.hasRichHeader != after.hasRichHeader ||
            before.dosStubBytes != after.dosStubBytes) {
        reason = "disabled_rich_header_changed";
        return false;
    }

    if (config.clearDebugDirectory) {
        if (after.debugDirectoryRVA != 0 ||
            after.debugDirectorySize != 0) {
            reason = "debug_directory_present";
            return false;
        }
    } else if (before.debugDirectoryRVA != after.debugDirectoryRVA ||
            before.debugDirectorySize != after.debugDirectorySize) {
        reason = "disabled_debug_directory_changed";
        return false;
    }

    if (config.randomizeTimestamps) {
        if (after.coffTimestamp != 0) {
            reason = "timestamp_not_cleared";
            return false;
        }
    } else if (before.coffTimestamp != after.coffTimestamp) {
        reason = "disabled_timestamp_changed";
        return false;
    }

    if (config.clearChecksum) {
        if (after.checksum != 0) {
            reason = "checksum_not_cleared";
            return false;
        }
    } else if (before.checksum != after.checksum) {
        reason = "disabled_checksum_changed";
        return false;
    }
    return true;
}

bool SignatureEliminator::VerifyExactState(CS_PE_IMAGE* image,
        const EliminationState& expected, std::string& reason) {
    EliminationState actual;
    if (!CaptureState(image, actual, reason)) {
        return false;
    }
    if (actual.is64Bit != expected.is64Bit ||
        actual.machine != expected.machine ||
        actual.optionalHeaderMagic != expected.optionalHeaderMagic ||
        actual.sizeOfOptionalHeader != expected.sizeOfOptionalHeader ||
        actual.numberOfSections != expected.numberOfSections ||
        actual.numberOfRvaAndSizes != expected.numberOfRvaAndSizes ||
        actual.peHeaderOffset != expected.peHeaderOffset) {
        reason = "final_layout_changed";
        return false;
    }
    if (actual.sectionNames != expected.sectionNames) {
        reason = "final_section_names_changed";
        return false;
    }
    if (actual.hasRichHeader != expected.hasRichHeader ||
        actual.dosStubBytes != expected.dosStubBytes) {
        reason = "final_rich_region_changed";
        return false;
    }
    if (actual.debugDirectoryRVA != expected.debugDirectoryRVA ||
        actual.debugDirectorySize != expected.debugDirectorySize) {
        reason = "final_debug_directory_changed";
        return false;
    }
    if (actual.coffTimestamp != expected.coffTimestamp) {
        reason = "final_timestamp_changed";
        return false;
    }
    if (actual.checksum != expected.checksum) {
        reason = "final_checksum_changed";
        return false;
    }
    reason.clear();
    return true;
}

// ============================================================================
// 签名检测实现
// ============================================================================

bool SignatureEliminator::CheckVMProtectSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".vmp", 4) == 0) {
            SignatureMatch match;
            match.signatureName = "VMProtect";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "VMProtect section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckThemidaSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".themida", 8) == 0 || strncmp(name, ".winlice", 8) == 0) {
            SignatureMatch match;
            match.signatureName = "Themida/WinLicense";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "Themida section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckUPXSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, "UPX", 3) == 0) {
            SignatureMatch match;
            match.signatureName = "UPX";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "UPX section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckASPackSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".ASPack", 7) == 0 || strncmp(name, ".adata", 6) == 0) {
            SignatureMatch match;
            match.signatureName = "ASPack";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "ASPack section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckPEiDSignatures(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查入口点模式
    DWORD entryRVA = 0;
    if (image->is64Bit) {
        entryRVA = image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        entryRVA = image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }

    constexpr uint32_t kPatternSize = 3;
    if (entryRVA > (std::numeric_limits<uint32_t>::max)() -
            kPatternSize ||
        !PEUtils::IsExecutableFileBackedRange(
            image, entryRVA, entryRVA + kPatternSize)) {
        return false;
    }
    const DWORD offset = PEUtils::RvaToOffset(image, entryRVA);
    if (offset == 0 ||
        !PEUtils::CheckRawBounds(image, offset, kPatternSize)) {
        return false;
    }

    const BYTE* entryCode = image->rawData + offset;
    // 检查常见的壳入口模式：pushad / mov ebp, esp / ...
    if (entryCode[0] == 0x60 && entryCode[1] == 0x89 &&
        entryCode[2] == 0xE5) {
        SignatureMatch match;
        match.signatureName = "Generic Packer Entry";
        match.detector = "Heuristic";
        match.matchOffset = offset;
        match.matchLength = kPatternSize;
        match.description = "Common packer entry pattern detected";
        matches.push_back(match);
    }

    return !matches.empty();
}

// ============================================================================
// 消除操作实现
// ============================================================================

bool SignatureEliminator::RandomizeSectionNames(CS_PE_IMAGE* image) {
    for (WORD i = 0; i < image->numSections; i++) {
        // 仅保留严格的零填充 .rsrc/.reloc 名称；“.rsrcX”等前缀相似
        // 名称不属于保留集合，不能借前缀比较绕过随机化及后置验证。
        if (IsExactPreservedSectionName(image->sections[i].Name)) {
            continue;
        }

        // 生成一个与输入精确不同的名称；这样过渡验证能证明该 section
        // 确实被处理，而不是仅凭输入碰巧已有 8 个小写字母就判为成功。
        char newName[IMAGE_SIZEOF_SHORT_NAME];
        bool generated = false;
        for (int attempt = 0; attempt < 10; ++attempt) {
            if (!GenerateRandomName(newName, IMAGE_SIZEOF_SHORT_NAME)) {
                return false;
            }
            if (std::memcmp(newName, image->sections[i].Name,
                    IMAGE_SIZEOF_SHORT_NAME) != 0) {
                generated = true;
                break;
            }
        }
        if (!generated) {
            return false;
        }
        memcpy(image->sections[i].Name, newName, IMAGE_SIZEOF_SHORT_NAME);
    }

    return true;
}

bool SignatureEliminator::ClearRichHeader(CS_PE_IMAGE* image) {
    if (!image->hasRichHeader) {
        return true;
    }

    if (!image->rawData || !image->dosHeader) {
        return false;
    }

    // 与 PEParser::DetectRichHeader 使用同一范围：DOS Header 末尾到 PE
    // 签名之前。固定从 0x80 开始会遗漏合法位于 0x40..0x7f 的早期 Rich。
    const DWORD start = static_cast<DWORD>(sizeof(IMAGE_DOS_HEADER));
    DWORD end = image->dosHeader->e_lfanew;

    if (start >= end || end > image->rawSize) {
        return false;
    }

    memset(image->rawData + start, 0, end - start);
    image->hasRichHeader = FALSE;
    image->richHeaderOffset = 0;
    return true;
}

bool SignatureEliminator::ClearDebugDirectory(CS_PE_IMAGE* image) {
    // 清除调试目录
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    } else {
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    }

    return true;
}

bool SignatureEliminator::ClearTimestamps(CS_PE_IMAGE* image) {
    // 清除时间戳
    if (image->is64Bit) {
        image->ntHeaders64->FileHeader.TimeDateStamp = 0;
    } else {
        image->ntHeaders32->FileHeader.TimeDateStamp = 0;
    }

    return true;
}

bool SignatureEliminator::ClearChecksum(CS_PE_IMAGE* image) {
    // 清除校验和
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.CheckSum = 0;
    } else {
        image->ntHeaders32->OptionalHeader.CheckSum = 0;
    }

    return true;
}

// ============================================================================
// 辅助函数
// ============================================================================

bool SignatureEliminator::PatternMatch(const BYTE* data, DWORD size, const BYTE* pattern, DWORD patternSize) {
    if (size < patternSize) return false;

    for (DWORD i = 0; i <= size - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return true;
        }
    }

    return false;
}

DWORD SignatureEliminator::GenerateRandomDWORD() {
    return ((DWORD)rand() << 16) | (DWORD)rand();
}

bool SignatureEliminator::GenerateRandomName(char* name, DWORD length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = sizeof(charset) - 1;

    // 原实现用 libc rand()（构造函数里 time(nullptr) 播种，state 空间小、
    // 按秒计时可被大致推算）生成 section 名。section 名不是保密边界，但
    // protection_build_context.cpp 里已经确立"随机性来自 BCryptGenRandom，
    // 熵源不可用就 fail-closed"的方针，这里改用同一个 API 保持一致。
    std::vector<BYTE> entropy(length);
    // BUG 18 修复：生成随机名称后自检，确保不匹配已知签名
    const int maxRetries = 10;
    for (int retry = 0; retry < maxRetries; retry++) {
#ifdef _WIN32
        if (BCryptGenRandom(nullptr, entropy.data(), static_cast<ULONG>(length),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            return false;
        }
#else
        try {
            std::random_device source;
            for (DWORD i = 0; i < length; i++) {
                entropy[i] = static_cast<BYTE>(source());
            }
        } catch (...) {
            return false;
        }
#endif
        for (DWORD i = 0; i < length; i++) {
            name[i] = charset[entropy[i] % charsetSize];
        }

        // 自检：确保生成的名称不匹配已知壳的 section 名
        if (VerifyNoSignatureMatch((const BYTE*)name, length)) {
            return true;  // 通过自检，可以使用
        }
        // 未通过自检，重新生成
    }
    // 外部签名库可能覆盖所有候选结果；不能在自检连续失败后继续使用。
    return false;
}

// BUG 17 修复：从外部文件加载签名数据库
uint32_t SignatureEliminator::LoadSignatureDatabase(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return 0;
    }

    uint32_t loadedCount = 0;
    std::string line;

    while (std::getline(file, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') continue;

        // 格式: "名称:十六进制字节串"
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) continue;

        ExternalSignature sig;
        sig.name = line.substr(0, colonPos);
        std::string hexStr = line.substr(colonPos + 1);

        // 解析十六进制字节
        for (size_t i = 0; i + 1 < hexStr.size(); i += 2) {
            std::string byteStr = hexStr.substr(i, 2);
            try {
                uint8_t byte = (uint8_t)std::stoul(byteStr, nullptr, 16);
                sig.pattern.push_back(byte);
            } catch (...) {
                break;
            }
        }

        if (!sig.pattern.empty()) {
            m_externalSignatures.push_back(sig);
            loadedCount++;
        }
    }

    return loadedCount;
}

// BUG 18 修复：验证数据不匹配已知签名
bool SignatureEliminator::VerifyNoSignatureMatch(const BYTE* data, DWORD size) {
    // 检查内置签名
    if (PatternMatch(data, size, s_vmpPattern, sizeof(s_vmpPattern))) return false;
    if (PatternMatch(data, size, s_themidaPattern, sizeof(s_themidaPattern))) return false;
    if (PatternMatch(data, size, s_upxPattern, sizeof(s_upxPattern))) return false;
    if (PatternMatch(data, size, s_aspackPattern, sizeof(s_aspackPattern))) return false;

    // 检查外部加载的签名
    for (const auto& sig : m_externalSignatures) {
        if (!sig.pattern.empty() &&
            PatternMatch(data, size, sig.pattern.data(), (DWORD)sig.pattern.size())) {
            return false;
        }
    }

    return true;
}

} // namespace CipherShell
