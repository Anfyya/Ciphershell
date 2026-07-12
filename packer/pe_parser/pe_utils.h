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

// 64 位对齐：调用方在自己的 64 位计算中使用，随后自行与 UINT32_MAX 比较判定是否
// 能安全转回 uint32_t。避免像 AlignUp 那样在 32 位域内相加可能静默回绕。
inline uint64_t AlignUp64(uint64_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~static_cast<uint64_t>(alignment - 1);
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

        // 64 位预计算，避免 PointerToRawData+delta 在 32 位域内回绕后意外落入合法范围。
        const uint64_t offset64 = static_cast<uint64_t>(sec.PointerToRawData) + delta;
        if (offset64 > std::numeric_limits<uint32_t>::max()) {
            return 0;
        }
        const uint32_t offset = static_cast<uint32_t>(offset64);
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
        // 64 位预计算 section 的虚拟结束地址，避免 VirtualAddress+span 在 32 位域内回绕
        // 后让本不该匹配的 [begin,end) 意外通过范围检查。
        const uint64_t sectionVirtualEnd64 = static_cast<uint64_t>(s.VirtualAddress) + span;
        if (begin < s.VirtualAddress || end > sectionVirtualEnd64) continue;
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

// x64 UNWIND_INFO 支持的 Version 范围（低 3 位字段）。标准 x64 ABI 只定义 Version 1；
// 本项目的 CapabilityChecker::IsFunctionVmSafe 额外接受 Version 2，因此这里作为唯一的
// 权威定义，解析器与 CapabilityChecker 都必须引用这两个常量，不得各自硬编码不同范围。
constexpr uint8_t kUnwindInfoMinVersion = 1;
constexpr uint8_t kUnwindInfoMaxVersion = 2;

inline bool IsSupportedUnwindVersion(uint8_t version) {
    return version >= kUnwindInfoMinVersion && version <= kUnwindInfoMaxVersion;
}

// UNWIND_INFO.Flags 位定义（Flags 字段的低 3 位为已定义标志，高 2 位保留）。
constexpr uint8_t kUnwindFlagEHandler = 0x1;   // 有语言相关异常处理函数
constexpr uint8_t kUnwindFlagUHandler = 0x2;   // 有终止处理函数
constexpr uint8_t kUnwindFlagChainInfo = 0x4;  // 本记录是链式 UNWIND_INFO 的延续

// x64 UNWIND_INFO 完整结构校验：
//   1. 4 字节固定头部可读，Version 落在 [kUnwindInfoMinVersion, kUnwindInfoMaxVersion]。
//   2. CountOfCodes 个 UNWIND_CODE（每个 2 字节）数组完整落在文件范围内；规范要求
//      奇数个时补齐 1 个 slot 到偶数以保持后续数据 DWORD 对齐，这里同样按偶数计入。
//   3. 按 Flags 校验紧随其后的尾部结构（互斥）：
//        - UNW_FLAG_CHAININFO：尾部是一个链接的 IMAGE_RUNTIME_FUNCTION_ENTRY（12 字节），
//          要求完整可读且 BeginAddress < EndAddress；不递归校验其自身 UnwindData，
//          避免恶意构造的链条造成无界递归。
//        - UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER：尾部是 4 字节异常处理函数 RVA，
//          要求可读且落在可执行且 file-backed 的 section 内。
//        - 均未设置：无需尾部结构。
//   全部范围计算使用 64 位中间值，避免 32 位加法回绕。
inline bool IsValidUnwindInfo(const CS_PE_IMAGE* image, uint32_t unwindRVA) {
    const uint32_t offset = RvaToOffset(image, unwindRVA);
    if (offset == 0 || !CheckRawBounds(image, offset, sizeof(CS_UNWIND_INFO_HEADER))) return false;

    CS_UNWIND_INFO_HEADER header;
    std::memcpy(&header, image->rawData + offset, sizeof(header));
    const uint8_t version = header.versionAndFlags & 0x07u;
    const uint8_t flags = static_cast<uint8_t>(header.versionAndFlags >> 3);
    if (!IsSupportedUnwindVersion(version)) return false;

    // UnwindCode 数组：CountOfCodes 个 2 字节 slot，奇数时向上补齐到偶数。
    const uint32_t codeSlots = (static_cast<uint32_t>(header.countOfCodes) + 1u) & ~1u;
    const uint64_t codesBytes64 = static_cast<uint64_t>(codeSlots) * 2u;
    const uint64_t afterCodesOffset64 =
        static_cast<uint64_t>(offset) + sizeof(CS_UNWIND_INFO_HEADER) + codesBytes64;
    if (afterCodesOffset64 > image->rawSize) return false;
    const uint32_t afterCodesOffset = static_cast<uint32_t>(afterCodesOffset64);

    if (flags & kUnwindFlagChainInfo) {
        constexpr uint32_t kChainedEntrySize = 12;  // BeginAddress+EndAddress+UnwindData
        if (!CheckRawBounds(image, afterCodesOffset, kChainedEntrySize)) return false;
        DWORD chainedBegin = 0, chainedEnd = 0;
        std::memcpy(&chainedBegin, image->rawData + afterCodesOffset, sizeof(DWORD));
        std::memcpy(&chainedEnd, image->rawData + afterCodesOffset + sizeof(DWORD), sizeof(DWORD));
        if (chainedBegin >= chainedEnd) return false;
    } else if (flags & (kUnwindFlagEHandler | kUnwindFlagUHandler)) {
        if (!CheckRawBounds(image, afterCodesOffset, sizeof(DWORD))) return false;
        DWORD handlerRVA = 0;
        std::memcpy(&handlerRVA, image->rawData + afterCodesOffset, sizeof(DWORD));
        if (handlerRVA == 0 || !IsExecutableFileBackedAddress(image, handlerRVA)) return false;
    }

    return true;
}

// 失败（结果无法用 uint32_t 表示）时返回 0，与本文件其余函数“0 表示无效”的约定一致。
inline uint32_t RecomputeSizeOfImage(const CS_PE_IMAGE* image) {
    if (!image || !image->sections) return 0;
    const uint32_t align = SectionAlignment(image);
    // 全程用 64 位累加，最后统一与 UINT32_MAX 比较后再转回 uint32_t，避免
    // VirtualAddress+AlignUp(span,align) 在 32 位域内回绕成一个偏小的错误结果。
    uint64_t size64 = AlignUp64(SizeOfHeaders(image), align);
    for (WORD i = 0; i < image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = image->sections[i];
        const uint32_t span = SectionMappedSpan(sec);
        if (span == 0) continue;
        const uint64_t sectionEnd64 = static_cast<uint64_t>(sec.VirtualAddress) + AlignUp64(span, align);
        size64 = (std::max)(size64, sectionEnd64);
    }
    if (size64 > std::numeric_limits<uint32_t>::max()) return 0;
    return static_cast<uint32_t>(size64);
}

} // namespace PEUtils
} // namespace CipherShell

#endif // CS_PE_UTILS_H
