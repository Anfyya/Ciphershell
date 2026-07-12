#ifndef CS_PE_UTILS_H
#define CS_PE_UTILS_H

#include "pe_parser.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

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

// Parser 能完整识别的 UNWIND_INFO 版本。VM 的能力范围不得复用这个上限：Parser 接受
// 只表示输入格式合法，不代表 VM runtime/重建器已经能保持该版本的运行时语义。
constexpr uint8_t kParserUnwindInfoMinVersion = 1;
constexpr uint8_t kParserUnwindInfoMaxVersion = 2;
constexpr uint8_t kVmUnwindInfoMaxVersion = 1;

inline bool IsParserSupportedUnwindVersion(uint8_t version) {
    return version >= kParserUnwindInfoMinVersion && version <= kParserUnwindInfoMaxVersion;
}

// UNWIND_INFO.Flags 位定义（Flags 字段的低 3 位为已定义标志，高 2 位保留）。
constexpr uint8_t kUnwindFlagEHandler = 0x1;   // 有语言相关异常处理函数
constexpr uint8_t kUnwindFlagUHandler = 0x2;   // 有终止处理函数
constexpr uint8_t kUnwindFlagChainInfo = 0x4;  // 本记录是链式 UNWIND_INFO 的延续
constexpr uint8_t kUnwindKnownFlags =
    kUnwindFlagEHandler | kUnwindFlagUHandler | kUnwindFlagChainInfo;

// AMD64 V1/V2 UNWIND_CODE 操作码。
constexpr uint8_t kUwopPushNonvol = 0;
constexpr uint8_t kUwopAllocLarge = 1;
constexpr uint8_t kUwopAllocSmall = 2;
constexpr uint8_t kUwopSetFpReg = 3;
constexpr uint8_t kUwopSaveNonvol = 4;
constexpr uint8_t kUwopSaveNonvolFar = 5;
constexpr uint8_t kUwopEpilog = 6;       // 仅 V2
constexpr uint8_t kUwopSpareCode = 7;    // 保留，必须拒绝
constexpr uint8_t kUwopSaveXmm128 = 8;
constexpr uint8_t kUwopSaveXmm128Far = 9;
constexpr uint8_t kUwopPushMachFrame = 10;
constexpr uint32_t kMaxUnwindChainDepth = 32;

inline bool IsNonvolatileGpr(uint8_t reg) {
    return reg == 3 || reg == 5 || reg == 6 || reg == 7 || reg >= 12;
}

inline bool IsNonvolatileXmm(uint8_t reg) {
    return reg >= 6 && reg <= 15;
}

inline bool ReadUnwindInfoVersion(
    const CS_PE_IMAGE* image, uint32_t unwindRVA, uint8_t& version, uint8_t& flags) {
    const uint32_t offset = RvaToOffset(image, unwindRVA);
    if (offset == 0 || !CheckRawBounds(image, offset, sizeof(CS_UNWIND_INFO_HEADER))) return false;
    version = image->rawData[offset] & 0x07u;
    flags = static_cast<uint8_t>(image->rawData[offset] >> 3);
    return true;
}

namespace detail {

inline bool ValidateRuntimeFunctionInternal(
    const CS_PE_IMAGE* image,
    const CS_RUNTIME_FUNCTION& runtimeFunction,
    std::vector<uint32_t>& visited,
    uint32_t depth);

inline bool ValidateUnwindCodes(
    const CS_PE_IMAGE* image,
    const CS_RUNTIME_FUNCTION& runtimeFunction,
    uint32_t unwindOffset,
    const CS_UNWIND_INFO_HEADER& header,
    uint8_t version) {
    const uint32_t count = header.countOfCodes;
    const uint8_t frameRegister = header.frameRegisterAndOffset & 0x0Fu;
    const uint8_t frameOffset = header.frameRegisterAndOffset >> 4;
    if ((frameRegister == 0 && frameOffset != 0) ||
        (frameRegister != 0 && !IsNonvolatileGpr(frameRegister))) {
        return false;
    }
    if (header.sizeOfProlog > runtimeFunction.endAddress - runtimeFunction.beginAddress) return false;

    uint32_t index = 0;
    bool sawNormalCode = false;
    bool sawFirstEpilog = false;
    bool sawExplicitEpilog = false;
    bool sawEpilogPadding = false;
    bool epilogAtEnd = false;
    uint32_t epilogSlotCount = 0;
    uint32_t epilogSize = 0;
    uint32_t previousEpilogOffset = 0;
    uint8_t previousCodeOffset = 0xFF;
    bool sawSetFpReg = false;

    while (index < count) {
        const uint32_t slotOffset = unwindOffset + sizeof(CS_UNWIND_INFO_HEADER) + index * 2u;
        const uint8_t codeOffset = image->rawData[slotOffset];
        const uint8_t opAndInfo = image->rawData[slotOffset + 1u];
        const uint8_t op = opAndInfo & 0x0Fu;
        const uint8_t opInfo = opAndInfo >> 4;

        if (op == kUwopEpilog) {
            if (version != 2 || sawNormalCode) return false;
            ++epilogSlotCount;
            if (!sawFirstEpilog) {
                // 第一条 EPILOG 槽存放统一 epilog 长度；OpInfo 仅 bit0 表示函数尾部
                // 存在隐式 epilog，其余位保留。
                if (codeOffset == 0 || (opInfo & ~0x01u) != 0) return false;
                sawFirstEpilog = true;
                epilogAtEnd = (opInfo & 0x01u) != 0;
                epilogSize = codeOffset;
                if (epilogSize > runtimeFunction.endAddress - runtimeFunction.beginAddress) return false;
            } else {
                const uint32_t epilogOffset =
                    static_cast<uint32_t>(codeOffset) | (static_cast<uint32_t>(opInfo) << 8);
                if (epilogOffset == 0) {
                    // V2 用全零 EPILOG 槽把 epilog 描述符数量补成偶数。它必须是
                    // epilog 前缀的最后一槽；其后仍可跟普通 prolog unwind codes。
                    if (sawEpilogPadding) return false;
                    sawEpilogPadding = true;
                } else {
                    if (sawEpilogPadding) return false;
                    const uint32_t functionSize =
                        runtimeFunction.endAddress - runtimeFunction.beginAddress;
                    if ((sawExplicitEpilog && epilogOffset <= previousEpilogOffset) ||
                        epilogOffset >= functionSize || epilogSize > functionSize - epilogOffset) {
                        return false;
                    }
                    if (epilogAtEnd && epilogOffset >= functionSize - epilogSize) return false;
                    previousEpilogOffset = epilogOffset;
                    sawExplicitEpilog = true;
                }
            }
            ++index;
            continue;
        }

        sawNormalCode = true;
        if (sawFirstEpilog && (epilogSlotCount & 1u) != 0) return false;

        // PUSH_MACHFRAME 是唯一合法使用 CodeOffset==0 的普通 unwind operation，且必须
        // 位于逻辑代码数组末尾。它仍参与降序状态更新；其他 UWOP 继续要求非零 offset。
        const bool isPushMachFrame = op == kUwopPushMachFrame;
        if (isPushMachFrame) {
            if (codeOffset != 0 || opInfo > 1 || index + 1u != count ||
                codeOffset > previousCodeOffset) {
                return false;
            }
        } else if (codeOffset == 0 || codeOffset > header.sizeOfProlog ||
                   codeOffset > previousCodeOffset) {
            return false;
        }
        previousCodeOffset = codeOffset;

        uint32_t consumed = 1;
        switch (op) {
        case kUwopPushNonvol:
            if (!IsNonvolatileGpr(opInfo)) return false;
            break;
        case kUwopAllocLarge:
            if (opInfo == 0) consumed = 2;
            else if (opInfo == 1) consumed = 3;
            else return false;
            break;
        case kUwopAllocSmall:
            break;
        case kUwopSetFpReg:
            if (opInfo != 0 || frameRegister == 0 || sawSetFpReg) return false;
            sawSetFpReg = true;
            break;
        case kUwopSaveNonvol:
            if (!IsNonvolatileGpr(opInfo)) return false;
            consumed = 2;
            break;
        case kUwopSaveNonvolFar:
            if (!IsNonvolatileGpr(opInfo)) return false;
            consumed = 3;
            break;
        case kUwopSpareCode:
            return false;
        case kUwopSaveXmm128:
            if (!IsNonvolatileXmm(opInfo)) return false;
            consumed = 2;
            break;
        case kUwopSaveXmm128Far:
            if (!IsNonvolatileXmm(opInfo)) return false;
            consumed = 3;
            break;
        case kUwopPushMachFrame:
            // CodeOffset、OpInfo 与逻辑末尾约束已在通用降序检查前单独验证。
            break;
        default:
            return false;
        }
        if (consumed > count - index) return false;
        index += consumed;
    }

    if (sawFirstEpilog && ((epilogSlotCount & 1u) != 0 ||
        (!epilogAtEnd && !sawExplicitEpilog))) return false;
    return frameRegister == 0 || sawSetFpReg;
}

inline bool ValidateRuntimeFunctionInternal(
    const CS_PE_IMAGE* image,
    const CS_RUNTIME_FUNCTION& runtimeFunction,
    std::vector<uint32_t>& visited,
    uint32_t depth) {
    if (!image || runtimeFunction.beginAddress >= runtimeFunction.endAddress ||
        runtimeFunction.unwindData == 0 || depth >= kMaxUnwindChainDepth ||
        !IsExecutableFileBackedRange(image, runtimeFunction.beginAddress, runtimeFunction.endAddress) ||
        std::find(visited.begin(), visited.end(), runtimeFunction.unwindData) != visited.end()) {
        return false;
    }
    visited.push_back(runtimeFunction.unwindData);

    const uint32_t offset = RvaToOffset(image, runtimeFunction.unwindData);
    if (offset == 0 || !CheckRawBounds(image, offset, sizeof(CS_UNWIND_INFO_HEADER))) return false;

    CS_UNWIND_INFO_HEADER header{};
    std::memcpy(&header, image->rawData + offset, sizeof(header));
    const uint8_t version = header.versionAndFlags & 0x07u;
    const uint8_t flags = static_cast<uint8_t>(header.versionAndFlags >> 3);
    if (!IsParserSupportedUnwindVersion(version) || (flags & ~kUnwindKnownFlags) != 0 ||
        ((flags & kUnwindFlagChainInfo) != 0 &&
         (flags & (kUnwindFlagEHandler | kUnwindFlagUHandler)) != 0)) {
        return false;
    }

    const uint32_t paddedCodeSlots = (static_cast<uint32_t>(header.countOfCodes) + 1u) & ~1u;
    const uint64_t baseSize64 = sizeof(CS_UNWIND_INFO_HEADER) +
        static_cast<uint64_t>(paddedCodeSlots) * 2u;
    const uint32_t tailSize = (flags & kUnwindFlagChainInfo) != 0
        ? static_cast<uint32_t>(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
        : ((flags & (kUnwindFlagEHandler | kUnwindFlagUHandler)) != 0
            ? static_cast<uint32_t>(sizeof(DWORD)) : 0u);
    const uint64_t totalSize64 = baseSize64 + tailSize;
    if (totalSize64 > std::numeric_limits<uint32_t>::max() ||
        !IsFileBackedSpan(image, runtimeFunction.unwindData, static_cast<uint32_t>(totalSize64))) {
        return false;
    }
    if (!ValidateUnwindCodes(image, runtimeFunction, offset, header, version)) return false;

    const uint32_t tailOffset = offset + static_cast<uint32_t>(baseSize64);
    if ((flags & kUnwindFlagChainInfo) != 0) {
        IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
        std::memcpy(&chained, image->rawData + tailOffset, sizeof(chained));
        CS_RUNTIME_FUNCTION chainedEntry{};
        chainedEntry.beginAddress = chained.BeginAddress;
        chainedEntry.endAddress = chained.EndAddress;
        chainedEntry.unwindData = chained.UnwindData;
        return ValidateRuntimeFunctionInternal(image, chainedEntry, visited, depth + 1u);
    }
    if ((flags & (kUnwindFlagEHandler | kUnwindFlagUHandler)) != 0) {
        DWORD handlerRVA = 0;
        std::memcpy(&handlerRVA, image->rawData + tailOffset, sizeof(handlerRVA));
        if (handlerRVA == 0 || !IsExecutableFileBackedAddress(image, handlerRVA)) return false;
    }
    return true;
}

} // namespace detail

// 从根 RUNTIME_FUNCTION 开始完整验证 UNWIND_INFO。链式记录递归验证其代码范围、
// UnwindData 和下一层元数据；visited 拒绝循环，固定深度上限拒绝恶意超长链。
inline bool IsValidRuntimeFunction(
    const CS_PE_IMAGE* image, const CS_RUNTIME_FUNCTION& runtimeFunction) {
    std::vector<uint32_t> visited;
    visited.reserve(kMaxUnwindChainDepth);
    return detail::ValidateRuntimeFunctionInternal(image, runtimeFunction, visited, 0);
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
