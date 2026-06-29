/**
 * CipherShell 重定位修复器 - 实现
 */

#include "reloc_fixer.h"
#include <cstring>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// RVA 到文件偏移转换
// ============================================================================

// RVA（相对虚拟地址）是 PE 映射到内存后的偏移，与文件中的偏移不同
// 节区在文件中按 FileAlignment 对齐，内存中按 SectionAlignment 对齐
static DWORD RvaToFileOffset(BYTE* fileBase, DWORD64 rva) {
    if (rva == 0) return 0;

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(fileBase + dosHdr->e_lfanew);

    PIMAGE_SECTION_HEADER sections;
    WORD numSections = ntHdr->FileHeader.NumberOfSections;
    if (ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        sections = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS64)ntHdr);
    } else {
        sections = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS32)ntHdr);
    }

    for (WORD i = 0; i < numSections; i++) {
        DWORD64 secStart = sections[i].VirtualAddress;
        DWORD64 secEnd = secStart + sections[i].SizeOfRawData;
        if (rva >= secStart && rva < secEnd) {
            return static_cast<DWORD>(rva - secStart + sections[i].PointerToRawData);
        }
    }

    if (numSections > 0 && rva < sections[0].VirtualAddress && rva <= 0xFFFFFFFFULL) {
        return static_cast<DWORD>(rva);
    }

    return 0;
}

// ============================================================================
// 构造/析构
// ============================================================================

RelocFixer::RelocFixer() {}

RelocFixer::~RelocFixer() {}

// ============================================================================
// 公共接口
// ============================================================================

bool RelocFixer::FixRelocations(
    CS_PE_IMAGE* image,
    DWORD64 newImageBase,
    const CS_RELOC_CONFIG& config)
{
    if (!image || !image->isValid) {
        return false;
    }

    DWORD64 originalBase = 0;
    if (image->is64Bit) {
        originalBase = image->ntHeaders64->OptionalHeader.ImageBase;
    } else {
        originalBase = image->ntHeaders32->OptionalHeader.ImageBase;
        if (newImageBase > 0xFFFFFFFFULL) {
            return false;
        }
    }

    int64_t delta = (newImageBase >= originalBase)
        ? static_cast<int64_t>(newImageBase - originalBase)
        : -static_cast<int64_t>(originalBase - newImageBase);

    if (delta == 0) {
        return true;
    }

    if (!ApplyRelocations(image->rawData, image->relocs.entries, delta)) {
        return false;
    }

    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.ImageBase = newImageBase;
    } else {
        image->ntHeaders32->OptionalHeader.ImageBase = static_cast<DWORD>(newImageBase);
    }

    return true;
}
bool RelocFixer::RebuildRelocations(
    CS_PE_IMAGE* image,
    const std::vector<CS_RELOC_ENTRY>& newRelocs)
{
    if (!image || !image->isValid) {
        return false;
    }

    // 获取重定位表目录
    IMAGE_DATA_DIRECTORY relocDir;
    if (image->is64Bit) {
        relocDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        relocDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    // 按页 RVA 分组重定位条目
    std::vector<std::vector<CS_RELOC_ENTRY>> pageGroups;

    // 先按 RVA 排序
    std::vector<CS_RELOC_ENTRY> sortedRelocs = newRelocs;
    std::sort(sortedRelocs.begin(), sortedRelocs.end(),
        [](const CS_RELOC_ENTRY& a, const CS_RELOC_ENTRY& b) {
            return a.pageRVA < b.pageRVA;
        });

    // 分组
    DWORD currentPageRVA = 0;
    for (const auto& reloc : sortedRelocs) {
        if (reloc.pageRVA != currentPageRVA || pageGroups.empty()) {
            pageGroups.push_back(std::vector<CS_RELOC_ENTRY>());
            currentPageRVA = reloc.pageRVA;
        }
        pageGroups.back().push_back(reloc);
    }

    // 计算新的重定位表大小
    DWORD newSize = 0;
    for (const auto& group : pageGroups) {
        newSize += sizeof(IMAGE_BASE_RELOCATION) + (DWORD)group.size() * sizeof(WORD);
        // 添加对齐填充
        if (group.size() % 2 != 0) {
            newSize += sizeof(WORD);
        }
    }

    // 更新重定位表目录
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = newSize;
    } else {
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = newSize;
    }

    return true;
}

bool RelocFixer::ApplyRelocations(
    BYTE* imageBase,
    const std::vector<CS_RELOC_ENTRY>& relocs,
    int64_t delta)
{
    if (!imageBase || relocs.empty()) {
        return true;
    }

    for (const auto& reloc : relocs) {
        // BUG11修复：将 RVA 转换为文件偏移后再访问数据
        // fullRVA 是内存中的相对虚拟地址，不能直接作为文件缓冲区的偏移
        DWORD fileOffset = RvaToFileOffset(imageBase, reloc.fullRVA);
        if (fileOffset == 0 && reloc.fullRVA != 0) {
            // RVA 转换失败，跳过此条目
            continue;
        }
        BYTE* address = imageBase + fileOffset;

        // 根据重定位类型应用修复
        switch (reloc.type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                // 填充项，跳过
                break;

            case IMAGE_REL_BASED_HIGH:
                // 高 16 位
                *(uint16_t*)address += (uint16_t)(delta >> 16);
                break;

            case IMAGE_REL_BASED_LOW:
                // 低 16 位
                *(uint16_t*)address += (uint16_t)delta;
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // 32 位
                *(int32_t*)address += (int32_t)delta;
                break;

            case IMAGE_REL_BASED_HIGHADJ:
                // 高 16 位 + 调整（需要两个条目）
                // 这里简化处理
                *(uint16_t*)address += (uint16_t)(delta >> 16);
                break;

            case IMAGE_REL_BASED_DIR64:
                // 64 位
                *(int64_t*)address += delta;
                break;

            default:
                // 不支持的重定位类型
                return false;
        }
    }

    return true;
}

std::vector<CS_RELOC_ENTRY> RelocFixer::ExtractRelocations(
    BYTE* imageBase,
    DWORD imageSize,
    DWORD64 originalBase)
{
    std::vector<CS_RELOC_ENTRY> relocs;

    if (!imageBase || imageSize == 0) {
        return relocs;
    }

    // 获取 PE 头
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return relocs;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return relocs;
    }

    // 获取重定位表
    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) {
        return relocs;
    }

    // BUG11修复：将重定位表 RVA 转换为文件偏移
    DWORD relocFileOffset = RvaToFileOffset(imageBase, relocRVA);
    if (relocFileOffset == 0) {
        return relocs;
    }

    // 遍历重定位块
    DWORD offset = 0;
    while (offset < relocSize) {
        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(imageBase + relocFileOffset + offset);

        if (block->VirtualAddress == 0 || block->SizeOfBlock == 0) {
            break;
        }

        // 遍历块中的条目
        DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)block + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entryCount; i++) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD relocOffset = entry & 0xFFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;  // 填充项
            }

            CS_RELOC_ENTRY reloc;
            reloc.pageRVA = block->VirtualAddress;
            reloc.type = type;
            reloc.offset = relocOffset;
            reloc.fullRVA = block->VirtualAddress + relocOffset;

            relocs.push_back(reloc);
        }

        offset += block->SizeOfBlock;
    }

    return relocs;
}

// ============================================================================
// 内部实现
// ============================================================================

bool RelocFixer::ProcessRelocType(BYTE* address, WORD type, int64_t delta) {
    switch (type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            return true;

        case IMAGE_REL_BASED_HIGH:
            *(uint16_t*)address += (uint16_t)(delta >> 16);
            return true;

        case IMAGE_REL_BASED_LOW:
            *(uint16_t*)address += (uint16_t)delta;
            return true;

        case IMAGE_REL_BASED_HIGHLOW:
            *(int32_t*)address += (int32_t)delta;
            return true;

        case IMAGE_REL_BASED_HIGHADJ:
            *(uint16_t*)address += (uint16_t)(delta >> 16);
            return true;

        case IMAGE_REL_BASED_DIR64:
            *(int64_t*)address += delta;
            return true;

        default:
            return false;
    }
}

DWORD RelocFixer::AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

bool RelocFixer::IsValidRelocType(WORD type, bool is64Bit) {
    switch (type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            return true;
        case IMAGE_REL_BASED_HIGH:
            return true;
        case IMAGE_REL_BASED_LOW:
            return true;
        case IMAGE_REL_BASED_HIGHLOW:
            return true;
        case IMAGE_REL_BASED_HIGHADJ:
            return true;
        case IMAGE_REL_BASED_DIR64:
            return is64Bit;
        default:
            return false;
    }
}

} // namespace CipherShell
