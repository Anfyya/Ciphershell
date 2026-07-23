/**
 * CipherShell PE Rebuilder - 实现
 */

#include "pe_rebuilder.h"
#include "pe_utils.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace CipherShell {

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
    if (!image || !image->isValid || !outputSize) {
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

    // 获取 NT Headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew <= 0 || static_cast<DWORD>(dosHeader->e_lfanew) >= image->rawSize) {
        *outputSize = image->rawSize;
        return output;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + static_cast<DWORD>(dosHeader->e_lfanew));

    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    }

    // 清除调试信息
    if (!config.preserveDebugInfo) {
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    if (!config.preserveChecksum) {
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.CheckSum = 0;
        } else {
            ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.CheckSum = 0;
        }
    }

    // 随机化 section 名称
    if (config.randomizeSectionNames) {
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            char name[9] = {0};
            memcpy(name, sections[i].Name, 8);
            if (strncmp(name, ".rsrc", 5) != 0 && strncmp(name, ".reloc", 6) != 0) {
                GenerateRandomName((char*)sections[i].Name, 8);
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
    GenerateRandomName(name, 8);
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

void PERebuilder::GenerateRandomName(char* name, DWORD length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    for (DWORD i = 0; i < length - 1; i++) {
        name[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    name[length - 1] = '\0';
}

} // namespace CipherShell

