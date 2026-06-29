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

    // 简单方法：复制整个原始文件，然后修改
    DWORD totalSize = image->rawSize + 0x10000;  // 额外空间

    // 分配输出缓冲区
    BYTE* output = new(std::nothrow) BYTE[totalSize];
    if (!output) {
        return nullptr;
    }
    memset(output, 0, totalSize);

    // 复制原始数据
    memcpy(output, image->rawData, image->rawSize);

    // 获取 NT Headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew == 0 || dosHeader->e_lfanew >= image->rawSize) {
        *outputSize = image->rawSize;
        return output;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + dosHeader->e_lfanew);

    // 清除时间戳
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

    // 清除校验和
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

    // BUG4修复：VirtualSize=0 会导致节区在内存中被映射为零大小，节区数据丢失
    // Windows PE 加载器在 VirtualSize=0 时可能不分配内存页，导致运行时访问违例
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
// 重建实现
// ============================================================================

bool PERebuilder::RebuildHeaders(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 复制原始头部
    DWORD headerSize = image->sections[0].PointerToRawData;
    if (headerSize == 0 || headerSize > image->rawSize) headerSize = 0x400;
    if (headerSize > image->rawSize) headerSize = image->rawSize;
    
    memcpy(output, image->rawData, headerSize);

    // 获取输出缓冲区中的 NT Headers 指针
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew == 0 || dosHeader->e_lfanew > headerSize) return true;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + dosHeader->e_lfanew);

    // 处理 Rich Header
    if (!config.preserveRichHeader && image->hasRichHeader && image->richHeaderOffset > sizeof(IMAGE_DOS_HEADER)) {
        DWORD richClearSize = image->richHeaderOffset - sizeof(IMAGE_DOS_HEADER);
        if (richClearSize < headerSize) {
            memset(output + sizeof(IMAGE_DOS_HEADER), 0, richClearSize);
        }
    }

    // 处理时间戳（修改输出缓冲区，不是原始镜像）
    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    } else if (config.randomizeTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = GenerateRandomDWORD();
    }

    // 处理调试信息（修改输出缓冲区）
    if (!config.preserveDebugInfo) {
        if (image->is64Bit && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    // 处理校验和
    if (!config.preserveChecksum) {
        if (image->is64Bit && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            ntHeaders64->OptionalHeader.CheckSum = 0;
        } else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            ntHeaders32->OptionalHeader.CheckSum = 0;
        }
    }

    return true;
}

bool PERebuilder::RebuildSections(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 获取 NT Headers 信息
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew == 0 || dosHeader->e_lfanew > 0x1000) return false;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + dosHeader->e_lfanew);

    DWORD headerSize = image->sections[0].PointerToRawData;
    if (headerSize == 0 || headerSize > image->rawSize) headerSize = 0x200;
    
    DWORD currentOffset = AlignValue(headerSize, config.fileAlignment);

    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 安全检查
        if (section->SizeOfRawData == 0) continue;
        if (section->PointerToRawData == 0) continue;
        if (section->PointerToRawData + section->SizeOfRawData > image->rawSize) continue;

        // 复制 section 数据
        DWORD copySize = (std::min)(section->SizeOfRawData, section->Misc.VirtualSize);
        if (copySize > 0 && currentOffset + copySize <= config.fileAlignment * 1000) {
            memcpy(output + currentOffset,
                   image->rawData + section->PointerToRawData,
                   copySize);
        }

        // 更新 section 头中的偏移
        DWORD sectionHeaderOffset = dosHeader->e_lfanew +
            sizeof(DWORD) +  // PE signature
            sizeof(IMAGE_FILE_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader +
            i * sizeof(IMAGE_SECTION_HEADER);
        
        if (sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER) <= headerSize) {
            PIMAGE_SECTION_HEADER outputSection = (PIMAGE_SECTION_HEADER)(output + sectionHeaderOffset);
            outputSection->PointerToRawData = currentOffset;
            outputSection->SizeOfRawData = AlignValue(section->SizeOfRawData, config.fileAlignment);

            // 随机化 section 名称
            if (config.randomizeSectionNames) {
                char name[9] = {0};
                memcpy(name, outputSection->Name, 8);
                if (strncmp(name, ".rsrc", 5) != 0 && strncmp(name, ".reloc", 6) != 0) {
                    GenerateRandomName((char*)outputSection->Name, 8);
                }
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

bool PERebuilder::UpdateChecksum(BYTE* peData, DWORD actualFileSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);

    // BUG3修复：使用实际文件缓冲区大小而非 SizeOfImage（内存映像大小）
    // SizeOfImage 是 PE 映射到内存后的大小（按 SectionAlignment 对齐），通常远大于文件大小
    // 用 SizeOfImage 计算校验和会读取超出文件数据范围的内存，导致校验和错误
    DWORD checksum = CalculateChecksum(peData, actualFileSize);

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
