/**
 * CipherShell PE Rebuilder - 实现
 */

#include "pe_rebuilder.h"
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
    srand((unsigned int)time(nullptr));
}

PERebuilder::~PERebuilder() {}

// ============================================================================
// 公共接口
// ============================================================================

BYTE* PERebuilder::RebuildImage(CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config, DWORD* outputSize) {
    if (!image || !image->isValid || !outputSize) {
        return nullptr;
    }

    // 计算输出大小
    // 头大小 + 所有 section 大小 + overlay
    DWORD headerSize = image->sections[0].PointerToRawData;
    DWORD sectionsSize = 0;

    for (WORD i = 0; i < image->numSections; i++) {
        sectionsSize += AlignValue(image->sections[i].SizeOfRawData, config.fileAlignment);
    }

    DWORD overlaySize = 0;
    if (config.preserveOverlay && image->hasOverlay) {
        overlaySize = image->rawSize - image->overlayOffset;
    }

    DWORD totalSize = AlignValue(headerSize, config.fileAlignment) + sectionsSize + overlaySize;
    totalSize = AlignValue(totalSize, config.fileAlignment) + 0x1000;  // 额外空间

    // 分配输出缓冲区
    BYTE* output = new(std::nothrow) BYTE[totalSize];
    if (!output) {
        return nullptr;
    }
    memset(output, 0, totalSize);

    // 重建头部
    if (!RebuildHeaders(output, image, config)) {
        delete[] output;
        return nullptr;
    }

    // 重建 sections
    if (!RebuildSections(output, image, config)) {
        delete[] output;
        return nullptr;
    }

    // 重建 overlay
    if (!RebuildOverlay(output, image, config)) {
        delete[] output;
        return nullptr;
    }

    // 更新校验和
    if (!config.preserveChecksum) {
        UpdateChecksum(output);
    }

    *outputSize = totalSize;
    return output;
}

void PERebuilder::AddSection(std::vector<CS_SECTION_CONFIG>& sections, const CS_SECTION_CONFIG& section) {
    sections.push_back(section);
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
// 重建实现
// ============================================================================

bool PERebuilder::RebuildHeaders(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 复制原始头部
    DWORD headerSize = image->sections[0].PointerToRawData;
    memcpy(output, image->rawData, headerSize);

    // 获取 NT Headers 指针
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + dosHeader->e_lfanew);

    // 处理 Rich Header
    if (!config.preserveRichHeader && image->hasRichHeader) {
        // 清除 Rich Header
        memset(output + sizeof(IMAGE_DOS_HEADER),
               0,
               image->richHeaderOffset - sizeof(IMAGE_DOS_HEADER));
    }

    // 处理时间戳
    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    } else if (config.randomizeTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = GenerateRandomDWORD();
    }

    // 处理调试信息
    if (!config.preserveDebugInfo) {
        if (image->is64Bit) {
            image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    // 处理校验和
    if (!config.preserveChecksum) {
        if (image->is64Bit) {
            image->ntHeaders64->OptionalHeader.CheckSum = 0;
        } else {
            image->ntHeaders32->OptionalHeader.CheckSum = 0;
        }
    }

    return true;
}

bool PERebuilder::RebuildSections(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 获取 NT Headers 信息
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + dosHeader->e_lfanew);

    DWORD currentOffset = AlignValue(image->sections[0].PointerToRawData, config.fileAlignment);

    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 复制 section 数据
        if (section->SizeOfRawData > 0 && section->PointerToRawData > 0) {
            DWORD copySize = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);
            memcpy(output + currentOffset,
                   image->rawData + section->PointerToRawData,
                   copySize);
        }

        // 更新 section 头中的偏移
        PIMAGE_SECTION_HEADER outputSection = (PIMAGE_SECTION_HEADER)(
            output + dosHeader->e_lfanew +
            sizeof(DWORD) +  // PE signature
            sizeof(IMAGE_FILE_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader +
            i * sizeof(IMAGE_SECTION_HEADER)
        );

        outputSection->PointerToRawData = currentOffset;
        outputSection->SizeOfRawData = AlignValue(section->SizeOfRawData, config.fileAlignment);

        // 随机化 section 名称
        if (config.randomizeSectionNames) {
            // 保留 .rsrc 和 .reloc 名称以兼容 Windows loader
            if (strncmp((char*)section->Name, ".rsrc", 5) != 0 &&
                strncmp((char*)section->Name, ".reloc", 6) != 0) {
                GenerateRandomName((char*)outputSection->Name, 8);
            }
        }

        currentOffset += AlignValue(section->SizeOfRawData, config.fileAlignment);
    }

    return true;
}

bool PERebuilder::RebuildOverlay(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    if (!config.preserveOverlay || !image->hasOverlay) {
        return true;
    }

    // 找到最后一个 section 的结束位置
    DWORD lastSectionEnd = 0;
    for (WORD i = 0; i < image->numSections; i++) {
        DWORD sectionEnd = image->sections[i].PointerToRawData + image->sections[i].SizeOfRawData;
        if (sectionEnd > lastSectionEnd) {
            lastSectionEnd = sectionEnd;
        }
    }

    // 复制 overlay 数据
    DWORD overlaySize = image->rawSize - image->overlayOffset;
    memcpy(output + lastSectionEnd,
           image->rawData + image->overlayOffset,
           overlaySize);

    return true;
}

// ============================================================================
// 辅助函数
// ============================================================================

DWORD PERebuilder::AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void PERebuilder::GenerateRandomName(char* name, DWORD length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    for (DWORD i = 0; i < length - 1; i++) {
        name[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    name[length - 1] = '\0';
}

DWORD PERebuilder::CalculateChecksum(BYTE* data, DWORD size) {
    DWORD checksum = 0;
    DWORD remainder = size % 4;
    DWORD longs = size / 4;

    // 对每个 DWORD 求和
    for (DWORD i = 0; i < longs; i++) {
        DWORD value = *(DWORD*)(data + i * 4);
        checksum += value;
        if (checksum < value) {
            checksum++;
        }
    }

    // 处理剩余字节
    if (remainder > 0) {
        DWORD value = 0;
        memcpy(&value, data + longs * 4, remainder);
        checksum += value;
        if (checksum < value) {
            checksum++;
        }
    }

    // 高低16位相加
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += (checksum >> 16);
    checksum &= 0xFFFF;

    return checksum + size;
}

bool PERebuilder::UpdateChecksum(BYTE* peData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);

    // 计算新校验和
    DWORD fileSize = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD checksum = CalculateChecksum(peData, fileSize);

    // 更新校验和
    if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.CheckSum = checksum;
    } else {
        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.CheckSum = checksum;
    }

    return true;
}

DWORD PERebuilder::GenerateRandomDWORD() {
    return ((DWORD)rand() << 16) | (DWORD)rand();
}

BYTE PERebuilder::GenerateRandomBYTE() {
    return (BYTE)(rand() % 256);
}

} // namespace CipherShell
