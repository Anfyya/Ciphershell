#ifndef CS_PE_UTILS_H
#define CS_PE_UTILS_H

#include "pe_parser.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>

namespace CipherShell {
namespace PEUtils {

inline uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

inline bool CheckRawBounds(const CS_PE_IMAGE* image, uint32_t offset, uint32_t size) {
    return image && image->rawData && offset <= image->rawSize && size <= image->rawSize - offset;
}

inline uint32_t SizeOfHeaders(const CS_PE_IMAGE* image) {
    if (!image) return 0;
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.SizeOfHeaders
                          : image->ntHeaders32->OptionalHeader.SizeOfHeaders;
}

inline uint32_t FileAlignment(const CS_PE_IMAGE* image) {
    if (!image) return 0x200;
    uint32_t align = image->is64Bit ? image->ntHeaders64->OptionalHeader.FileAlignment
                                    : image->ntHeaders32->OptionalHeader.FileAlignment;
    return align < 0x200 ? 0x200 : align;
}

inline uint32_t SectionAlignment(const CS_PE_IMAGE* image) {
    if (!image) return 0x1000;
    uint32_t align = image->is64Bit ? image->ntHeaders64->OptionalHeader.SectionAlignment
                                    : image->ntHeaders32->OptionalHeader.SectionAlignment;
    return align < 0x1000 ? 0x1000 : align;
}

inline uint64_t ImageBase(const CS_PE_IMAGE* image) {
    if (!image) return 0;
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.ImageBase
                          : image->ntHeaders32->OptionalHeader.ImageBase;
}

inline IMAGE_DATA_DIRECTORY GetDataDirectory(const CS_PE_IMAGE* image, uint32_t index) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!image || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return dir;
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.DataDirectory[index]
                          : image->ntHeaders32->OptionalHeader.DataDirectory[index];
}

inline void SetDataDirectory(CS_PE_IMAGE* image, uint32_t index, uint32_t rva, uint32_t size) {
    if (!image || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return;
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.DataDirectory[index].VirtualAddress = rva;
        image->ntHeaders64->OptionalHeader.DataDirectory[index].Size = size;
    } else {
        image->ntHeaders32->OptionalHeader.DataDirectory[index].VirtualAddress = rva;
        image->ntHeaders32->OptionalHeader.DataDirectory[index].Size = size;
    }
}

inline uint32_t SectionMappedSpan(const IMAGE_SECTION_HEADER& section) {
    uint32_t virtualSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
    return (std::max)(virtualSize, static_cast<uint32_t>(section.SizeOfRawData));
}

inline bool RvaInSection(const IMAGE_SECTION_HEADER& section, uint32_t rva) {
    const uint32_t start = section.VirtualAddress;
    const uint32_t span = SectionMappedSpan(section);
    return span != 0 && rva >= start && rva - start < span;
}

inline uint32_t RvaToOffset(const CS_PE_IMAGE* image, uint32_t rva) {
    if (!image || !image->sections || image->numSections == 0) return 0;

    const uint32_t headerSize = SizeOfHeaders(image);
    if (rva < headerSize && CheckRawBounds(image, rva, 1)) {
        return rva;
    }

    for (WORD i = 0; i < image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = image->sections[i];
        if (!RvaInSection(sec, rva)) continue;

        const uint32_t delta = rva - sec.VirtualAddress;
        if (delta >= sec.SizeOfRawData) {
            return 0;
        }

        const uint32_t offset = sec.PointerToRawData + delta;
        if (CheckRawBounds(image, offset, 1)) {
            return offset;
        }
        return 0;
    }

    return 0;
}

// 单点校验：rva 必须落在某个可执行且 file-backed 的 section 内（能映射到文件字节）。
// 供 SafeSEH handler、TLS callback 等“单地址”场景复用。
inline bool IsExecutableFileBackedAddress(const CS_PE_IMAGE* image, uint32_t rva) {
    if (!image || !image->sections) return false;
    for (WORD i = 0; i < image->numSections; ++i) {
        const IMAGE_SECTION_HEADER& s = image->sections[i];
        const uint32_t span = SectionMappedSpan(s);
        if (span == 0 || rva < s.VirtualAddress || rva - s.VirtualAddress >= span) continue;
        if ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) return false;
        return RvaToOffset(image, rva) != 0;
    }
    return false;
}

namespace detail {
// 定位 [begin, end) 整体落入的唯一 section：要求二者都在同一个 section 的映射范围内、
// 该 section 是 file-backed（越过 SizeOfRawData 视为仅虚存，拒绝），且首尾字节都能
// 映射到文件数据。只检查两个端点分别可映射是不够的——不同端点可能落在不同 section，
// 中间跨越空洞或另一段数据，因此必须先确认整个区间都属于同一个 section。
inline const IMAGE_SECTION_HEADER* FindContainingFileBackedSection(
    const CS_PE_IMAGE* image, uint32_t begin, uint32_t end) {
    if (!image || !image->sections || begin >= end) return nullptr;
    for (WORD i = 0; i < image->numSections; ++i) {
        const IMAGE_SECTION_HEADER& s = image->sections[i];
        const uint32_t span = SectionMappedSpan(s);
        if (span == 0) continue;
        if (begin < s.VirtualAddress || end > s.VirtualAddress + span) continue;
        const uint32_t endDelta = end - s.VirtualAddress;
        if (endDelta > s.SizeOfRawData) return nullptr;  // 越过 raw 边界 → 仅虚存
        if (RvaToOffset(image, begin) == 0 || RvaToOffset(image, end - 1) == 0) return nullptr;
        return &s;
    }
    return nullptr;
}
} // namespace detail

// 范围校验（不要求可执行）：[begin, end) 必须整体落在同一个 file-backed 的 section 内。
// 供 TLS Start/End 模板数据范围等“地址区间但无需可执行”场景复用。
inline bool IsFileBackedRange(const CS_PE_IMAGE* image, uint32_t begin, uint32_t end) {
    return detail::FindContainingFileBackedSection(image, begin, end) != nullptr;
}

// 大小校验（不要求可执行）：[rva, rva+size) 必须整体落在同一个 file-backed 的 section 内；
// 内部处理 rva+size 的 32 位加法溢出。供 AddressOfIndex 等“地址 + 固定宽度字段”场景复用。
inline bool IsFileBackedSpan(const CS_PE_IMAGE* image, uint32_t rva, uint32_t size) {
    if (size == 0 || rva > std::numeric_limits<uint32_t>::max() - size) return false;
    return IsFileBackedRange(image, rva, rva + size);
}

// 范围校验：[begin, end) 必须整体落在同一个可执行且 file-backed 的 section 内，
// 供异常表 BeginAddress/EndAddress 等“地址区间”场景复用。
inline bool IsExecutableFileBackedRange(const CS_PE_IMAGE* image, uint32_t begin, uint32_t end) {
    const IMAGE_SECTION_HEADER* s = detail::FindContainingFileBackedSection(image, begin, end);
    return s != nullptr && (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

#pragma pack(push, 1)
// x64 UNWIND_INFO 固定头部（不含变长 UnwindCode 数组）。自行定义而非依赖 SDK 头文件，
// 避免不同编译环境下该结构是否公开暴露的差异。
struct CS_UNWIND_INFO_HEADER {
    uint8_t versionAndFlags;         // bits 0-2: Version, bits 3-7: Flags
    uint8_t sizeOfProlog;
    uint8_t countOfCodes;
    uint8_t frameRegisterAndOffset;  // bits 0-3: FrameRegister, bits 4-7: FrameOffset
};
#pragma pack(pop)
static_assert(sizeof(CS_UNWIND_INFO_HEADER) == 4, "UNWIND_INFO header must be 4 bytes");

// x64 UNWIND_INFO 最小校验：unwindRVA 必须可映射，且至少能完整读取 4 字节固定头部
// （不校验变长 UnwindCode 数组），并且 Version 字段（低 3 位）必须等于当前唯一定义的
// 版本号 1，否则视为不是一个合法的 UNWIND_INFO。
inline bool IsValidUnwindInfoHeader(const CS_PE_IMAGE* image, uint32_t unwindRVA) {
    const uint32_t offset = RvaToOffset(image, unwindRVA);
    if (offset == 0 || !CheckRawBounds(image, offset, sizeof(CS_UNWIND_INFO_HEADER))) return false;
    CS_UNWIND_INFO_HEADER header;
    std::memcpy(&header, image->rawData + offset, sizeof(header));
    constexpr uint8_t kUnwindInfoVersion = 1;
    return (header.versionAndFlags & 0x07u) == kUnwindInfoVersion;
}

inline uint32_t RecomputeSizeOfImage(const CS_PE_IMAGE* image) {
    if (!image || !image->sections) return 0;
    const uint32_t align = SectionAlignment(image);
    uint32_t size = AlignUp(SizeOfHeaders(image), align);
    for (WORD i = 0; i < image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = image->sections[i];
        const uint32_t span = SectionMappedSpan(sec);
        if (span == 0) continue;
        const uint32_t sectionEnd = static_cast<uint32_t>(sec.VirtualAddress) + AlignUp(span, align);
        size = (std::max)(size, sectionEnd);
    }
    return size;
}

} // namespace PEUtils
} // namespace CipherShell

#endif // CS_PE_UTILS_H
