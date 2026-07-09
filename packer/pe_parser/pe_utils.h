#ifndef CS_PE_UTILS_H
#define CS_PE_UTILS_H

#include "pe_parser.h"
#include <algorithm>
#include <cstdint>

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

inline uint32_t RecomputeSizeOfImage(const CS_PE_IMAGE* image) {
    if (!image || !image->sections) return 0;
    const uint32_t align = SectionAlignment(image);
    uint32_t size = AlignUp(SizeOfHeaders(image), align);
    for (WORD i = 0; i < image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = image->sections[i];
        const uint32_t span = SectionMappedSpan(sec);
        if (span == 0) continue;
        size = (std::max)(size, sec.VirtualAddress + AlignUp(span, align));
    }
    return size;
}

} // namespace PEUtils
} // namespace CipherShell

#endif // CS_PE_UTILS_H
