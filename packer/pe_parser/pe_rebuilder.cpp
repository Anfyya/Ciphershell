/**
 * CipherShell PE Rebuilder - 实现
 */

#include "pe_rebuilder.h"
#include "pe_utils.h"
#include <cstring>
#include <algorithm>
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

struct RebuildLayout {
    DWORD ntOffset = 0;
    DWORD sectionTableOffset = 0;
    WORD sectionCount = 0;
    bool is64Bit = false;
};

bool ValidateRebuildInput(const CS_PE_IMAGE* image, RebuildLayout& layout) {
    layout = RebuildLayout{};
    if (!image || !image->isValid || !image->rawData ||
        image->rawSize < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(image->rawData);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) {
        return false;
    }
    const uint64_t ntOffset =
        static_cast<uint64_t>(dosHeader->e_lfanew);
    const uint64_t fileHeaderOffset = ntOffset + sizeof(DWORD);
    const uint64_t optionalHeaderOffset =
        fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeaderOffset > image->rawSize ||
        image->rawSize - optionalHeaderOffset <
            sizeof(IMAGE_OPTIONAL_HEADER32)) {
        return false;
    }

    DWORD signature = 0;
    std::memcpy(&signature, image->rawData + ntOffset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const auto* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(
            image->rawData + fileHeaderOffset);
    if (fileHeader->NumberOfSections == 0 ||
        fileHeader->NumberOfSections > 96) {
        return false;
    }

    size_t requiredOptionalSize = 0;
    WORD expectedMagic = 0;
    bool is64Bit = false;
    if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        requiredOptionalSize = sizeof(IMAGE_OPTIONAL_HEADER64);
        expectedMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        is64Bit = true;
    } else if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        requiredOptionalSize = sizeof(IMAGE_OPTIONAL_HEADER32);
        expectedMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    } else {
        return false;
    }
    if (fileHeader->SizeOfOptionalHeader < requiredOptionalSize ||
        optionalHeaderOffset + fileHeader->SizeOfOptionalHeader >
            image->rawSize ||
        (image->is64Bit != FALSE) != is64Bit ||
        image->numSections != fileHeader->NumberOfSections) {
        return false;
    }

    WORD actualMagic = 0;
    std::memcpy(&actualMagic, image->rawData + optionalHeaderOffset,
        sizeof(actualMagic));
    if (actualMagic != expectedMagic) {
        return false;
    }

    const uint64_t sectionTableOffset =
        optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    const uint64_t sectionTableSize =
        static_cast<uint64_t>(fileHeader->NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset > image->rawSize ||
        sectionTableSize > image->rawSize - sectionTableOffset) {
        return false;
    }

    layout.ntOffset = static_cast<DWORD>(ntOffset);
    layout.sectionTableOffset = static_cast<DWORD>(sectionTableOffset);
    layout.sectionCount = fileHeader->NumberOfSections;
    layout.is64Bit = is64Bit;
    return true;
}

} // namespace

// ============================================================================
// 构造/析构
// ============================================================================

PERebuilder::PERebuilder() {
    // 初始化随机数生成器
}

PERebuilder::~PERebuilder() {}

// ============================================================================
// 公共接口
// ============================================================================

BYTE* PERebuilder::RebuildImage(CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config, DWORD* outputSize) {
    if (!outputSize) {
        return nullptr;
    }
    *outputSize = 0;

    // 当前 Rebuilder 是“受控复制 + 已实现元数据变换”，不是通用 PE 重排器。
    // 对没有实现的公开策略必须 fail-closed，不能静默返回看似成功的原样输出。
    const bool preserveTimestamp =
        config.preserveTimestamps != FALSE;
    const bool zeroTimestamp =
        config.zeroTimestamps != FALSE;
    if (config.randomizeTimestamps ||
        !config.preserveSignature ||
        !config.preserveOverlay ||
        preserveTimestamp == zeroTimestamp) {
        return nullptr;
    }

    RebuildLayout layout;
    if (!ValidateRebuildInput(image, layout)) {
        return nullptr;
    }

    DWORD totalSize = image->rawSize;

    BYTE* output = new(std::nothrow) BYTE[totalSize];
    if (!output) {
        return nullptr;
    }
    memset(output, 0, totalSize);

    // 复制原始数据
    memcpy(output, image->rawData, image->rawSize);

    // 上述布局已在复制前完整验证；这里不再存在“非法 e_lfanew 也返回
    // 原样成功”的 fail-open 路径。
    PIMAGE_DOS_HEADER dosHeader =
        reinterpret_cast<PIMAGE_DOS_HEADER>(output);
    PIMAGE_NT_HEADERS ntHeaders =
        reinterpret_cast<PIMAGE_NT_HEADERS>(output + layout.ntOffset);

    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    }

    // 仅移除 Debug DataDirectory 引用；该选项不承诺擦除文件中已失去引用的
    // CodeView/PDB 原始载荷。对外 UI/模板使用相同的精确措辞。
    if (!config.preserveDebugInfo) {
        if (layout.is64Bit) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    if (!config.preserveRichHeader && image->hasRichHeader) {
        constexpr DWORD kRichStart =
            static_cast<DWORD>(sizeof(IMAGE_DOS_HEADER));
        const DWORD richEnd = static_cast<DWORD>(dosHeader->e_lfanew);
        if (kRichStart >= richEnd || richEnd > totalSize) {
            delete[] output;
            *outputSize = 0;
            return nullptr;
        }
        std::memset(output + kRichStart, 0, richEnd - kRichStart);
    }

    if (!config.preserveChecksum) {
        if (layout.is64Bit) {
            ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.CheckSum = 0;
        } else {
            ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.CheckSum = 0;
        }
    }

    // 随机化 section 名称
    if (config.randomizeSectionNames) {
        PIMAGE_SECTION_HEADER sections =
            reinterpret_cast<PIMAGE_SECTION_HEADER>(
                output + layout.sectionTableOffset);
        for (WORD i = 0; i < layout.sectionCount; i++) {
            if (!IsExactPreservedSectionName(sections[i].Name)) {
                BYTE originalName[IMAGE_SIZEOF_SHORT_NAME] = {};
                std::memcpy(originalName, sections[i].Name,
                    sizeof(originalName));
                bool changed = false;
                for (int attempt = 0; attempt < 10; ++attempt) {
                    if (!GenerateRandomName(
                            reinterpret_cast<char*>(sections[i].Name),
                            IMAGE_SIZEOF_SHORT_NAME)) {
                        delete[] output;
                        *outputSize = 0;
                        return nullptr;
                    }
                    if (std::memcmp(originalName, sections[i].Name,
                            sizeof(originalName)) != 0) {
                        changed = true;
                        break;
                    }
                }
                if (!changed) {
                    delete[] output;
                    *outputSize = 0;
                    return nullptr;
                }
            }
        }
    }

    *outputSize = image->rawSize;
    return output;
}

void PERebuilder::AddSection(std::vector<CS_SECTION_CONFIG>& sections, const CS_SECTION_CONFIG& section) {
    CS_SECTION_CONFIG fixedSection = section;

    // 至少应等于 SizeOfRawData（即 dataSize），确保数据能完整映射到内存
    if (fixedSection.virtualSize == 0 && fixedSection.dataSize > 0) {
        DWORD align = fixedSection.alignment > 0 ? fixedSection.alignment : 0x1000;
        // 按 SectionAlignment 对齐
        fixedSection.virtualSize = (fixedSection.dataSize + align - 1) & ~(align - 1);
    }

    sections.push_back(fixedSection);
}

char* PERebuilder::GenerateRandomSectionName() {
    static char name[8];
    if (!GenerateRandomName(name, sizeof(name))) {
        return nullptr;
    }
    return name;
}

bool PERebuilder::ModifySectionCharacteristics(CS_PE_IMAGE* image, WORD sectionIndex, DWORD newCharacteristics) {
    if (!image || sectionIndex >= image->numSections) {
        return false;
    }

    image->sections[sectionIndex].Characteristics = newCharacteristics;
    return true;
}

bool PERebuilder::SetEntryPoint(CS_PE_IMAGE* image, DWORD newEntryPoint) {
    if (!image) {
        return false;
    }

    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    } else {
        image->ntHeaders32->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    }

    return true;
}

// ============================================================================
// 辅助函数
// ============================================================================

bool PERebuilder::GenerateRandomName(char* name, DWORD length) {
    if (!name || length == 0) {
        return false;
    }

    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    BYTE entropy[IMAGE_SIZEOF_SHORT_NAME] = {};
    if (length > sizeof(entropy)) {
        return false;
    }

#ifdef _WIN32
    if (BCryptGenRandom(nullptr, entropy, static_cast<ULONG>(length),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return false;
    }
#else
    try {
        std::random_device source;
        for (DWORD i = 0; i < length; ++i) {
            entropy[i] = static_cast<BYTE>(source());
        }
    } catch (...) {
        return false;
    }
#endif

    for (DWORD i = 0; i < length; ++i) {
        name[i] = charset[entropy[i] % (sizeof(charset) - 1)];
    }
    return true;
}

} // namespace CipherShell
