#include "pe_emitter.h"
#include "pe_utils.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <new>

namespace CipherShell {

namespace {
bool CheckedAdd(uint32_t left, uint32_t right, uint32_t& result) {
    const uint64_t sum = static_cast<uint64_t>(left) + right;
    if (sum > std::numeric_limits<uint32_t>::max()) return false;
    result = static_cast<uint32_t>(sum);
    return true;
}
} // namespace

PEEmitter::PEEmitter(CS_PE_IMAGE* image) : m_image(image) {}

bool PEEmitter::IsValid() const {
    return m_image && m_image->isValid && m_image->rawData && m_image->sections && m_image->numSections > 0;
}

uint32_t PEEmitter::AlignUp(uint32_t value, uint32_t alignment) const {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

uint32_t PEEmitter::GetFileAlignment() const {
    if (!IsValid()) return 0x200;
    return PEUtils::FileAlignment(m_image);
}

uint32_t PEEmitter::GetSectionAlignment() const {
    if (!IsValid()) return 0x1000;
    return PEUtils::SectionAlignment(m_image);
}

uint32_t PEEmitter::GetSizeOfHeaders() const {
    if (!IsValid()) return 0;
    return PEUtils::SizeOfHeaders(m_image);
}

void PEEmitter::SetSizeOfHeaders(uint32_t value) {
    if (!IsValid()) return;
    if (m_image->is64Bit) m_image->ntHeaders64->OptionalHeader.SizeOfHeaders = value;
    else m_image->ntHeaders32->OptionalHeader.SizeOfHeaders = value;
}

void PEEmitter::SetSizeOfImage(uint32_t value) {
    if (!IsValid()) return;
    if (m_image->is64Bit) m_image->ntHeaders64->OptionalHeader.SizeOfImage = value;
    else m_image->ntHeaders32->OptionalHeader.SizeOfImage = value;
}

uint32_t PEEmitter::GetEntryPoint() const {
    if (!IsValid()) return 0;
    return m_image->is64Bit ? m_image->ntHeaders64->OptionalHeader.AddressOfEntryPoint
                            : m_image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
}

void PEEmitter::SetEntryPoint(uint32_t rva) {
    if (!IsValid()) return;
    if (m_image->is64Bit) m_image->ntHeaders64->OptionalHeader.AddressOfEntryPoint = rva;
    else m_image->ntHeaders32->OptionalHeader.AddressOfEntryPoint = rva;
}

void PEEmitter::RefreshPointers(uint32_t ntOffset) {
    m_image->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image->rawData);
    if (m_image->is64Bit) {
        m_image->ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_image->rawData + ntOffset);
        m_image->sections = IMAGE_FIRST_SECTION(m_image->ntHeaders64);
    } else {
        m_image->ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_image->rawData + ntOffset);
        m_image->sections = IMAGE_FIRST_SECTION(m_image->ntHeaders32);
    }
}

uint32_t PEEmitter::RvaToOffset(uint32_t rva) const {
    return PEUtils::RvaToOffset(m_image, rva);
}

PEAppendSectionResult PEEmitter::AppendSection(
    const char name[8],
    const std::vector<uint8_t>& data,
    uint32_t characteristics)
{
    PEAppendSectionResult result{};
    if (!IsValid()) {
        result.error = "invalid PE image";
        return result;
    }
    if (!name || data.empty()) {
        result.error = "empty section name or data";
        return result;
    }
    if (data.size() > std::numeric_limits<uint32_t>::max()) {
        result.error = "section data exceeds PE size limits";
        return result;
    }

    const uint32_t fileAlign = GetFileAlignment();
    const uint32_t sectionAlign = GetSectionAlignment();
    const uint32_t ntOffset = static_cast<uint32_t>(m_image->dosHeader->e_lfanew);

    // ========================================================================
    // 统一 relocation plan：把“header 扩容”与“追加 section”合并为一个完整计划。
    // 所有 32 位算术检查与 buffer 分配在提交 image 之前完成；任何失败都直接返回，
    // image 的 rawData/rawSize/headers/sections/overlay/目录字段完全不变。
    // ========================================================================

    // 收集现有 section 的边界（带溢出检查）。
    uint32_t firstRaw = 0xFFFFFFFFu;
    uint32_t lastFileEnd = 0;
    uint32_t lastVirtualEnd = 0;
    for (WORD i = 0; i < m_image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = m_image->sections[i];
        if (sec.PointerToRawData != 0 && sec.PointerToRawData < firstRaw) {
            firstRaw = sec.PointerToRawData;
        }
        uint32_t fileEnd = 0;
        if (!CheckedAdd(sec.PointerToRawData, sec.SizeOfRawData, fileEnd)) {
            result.error = "existing section raw end overflows";
            return result;
        }
        lastFileEnd = (std::max)(lastFileEnd, fileEnd);
        const uint32_t vspan = PEUtils::SectionMappedSpan(sec);
        const uint32_t alignedV = AlignUp(vspan, sectionAlign);
        uint32_t vEnd = 0;
        if (!CheckedAdd(sec.VirtualAddress, alignedV, vEnd)) {
            result.error = "existing section virtual end overflows";
            return result;
        }
        lastVirtualEnd = (std::max)(lastVirtualEnd, vEnd);
    }
    if (firstRaw == 0xFFFFFFFFu) firstRaw = GetSizeOfHeaders();

    // requiredHeaderEnd = 增加 1 条 section header 后的 section table 末尾。
    // 用整数偏移 + 64 位乘加计算，避免指针运算结果直接截断到 32 位可能吞掉的溢出。
    const uint64_t sectionTableOffset = static_cast<uint64_t>(
        reinterpret_cast<BYTE*>(m_image->sections) - m_image->rawData);
    const uint64_t requiredHeaderEnd64 = sectionTableOffset +
        (static_cast<uint64_t>(m_image->numSections) + 1ull) * sizeof(IMAGE_SECTION_HEADER);
    if (requiredHeaderEnd64 > std::numeric_limits<uint32_t>::max()) {
        result.error = "section table would exceed PE header limits";
        return result;
    }
    const uint32_t requiredHeaderEnd = static_cast<uint32_t>(requiredHeaderEnd64);

    // headerDelta：仅当现有头部放不下 +1 条 section header 时才需要扩容。
    // 此处只计算 delta，不提交。
    // 关键：新 SizeOfHeaders 必须 fileAlign 对齐，且 firstRaw + headerDelta 必须严格
    // 等于新 SizeOfHeaders（section data 紧跟对齐后的头部），否则布局不一致。
    uint32_t headerDelta = 0;
    uint32_t newSizeOfHeaders = GetSizeOfHeaders();
    if (requiredHeaderEnd > firstRaw) {
        newSizeOfHeaders = AlignUp(requiredHeaderEnd, fileAlign);
        if (newSizeOfHeaders < requiredHeaderEnd) {  // AlignUp 回绕
            result.error = "new SizeOfHeaders alignment overflow";
            return result;
        }
        // firstRaw + headerDelta == newSizeOfHeaders（严格）。
        if (newSizeOfHeaders < firstRaw) {
            result.error = "header relocation would shrink first raw offset";
            return result;
        }
        headerDelta = newSizeOfHeaders - firstRaw;
    }

    // 平移后的 section 数据末尾 = lastFileEnd + headerDelta。
    uint32_t shiftedLastFileEnd = 0;
    if (!CheckedAdd(lastFileEnd, headerDelta, shiftedLastFileEnd)) {
        result.error = "shifted section raw end overflows";
        return result;
    }

    // 新 section 布局（全部带溢出检查，在分配 buffer 前完成）。
    const uint32_t rawOffset = AlignUp(shiftedLastFileEnd, fileAlign);
    if (rawOffset < shiftedLastFileEnd) {
        result.error = "raw offset alignment overflow";
        return result;
    }
    const uint32_t rawSize = AlignUp(static_cast<uint32_t>(data.size()), fileAlign);
    const uint32_t virtualAddress = AlignUp(lastVirtualEnd, sectionAlign);
    if (virtualAddress < lastVirtualEnd) {
        result.error = "virtual address alignment overflow";
        return result;
    }
    const uint32_t virtualSize = AlignUp(static_cast<uint32_t>(data.size()), sectionAlign);

    const uint32_t overlaySize = m_image->rawSize > lastFileEnd
        ? m_image->rawSize - lastFileEnd : 0;
    // newRawSize = rawOffset + rawSize + overlaySize
    uint32_t newRawSize = 0;
    uint32_t overlayDestBase = 0;
    if (!CheckedAdd(rawOffset, rawSize, overlayDestBase) ||
        !CheckedAdd(overlayDestBase, overlaySize, newRawSize)) {
        result.error = "appended section raw size overflows";
        return result;
    }
    // SizeOfImage = virtualAddress + virtualSize
    uint32_t newSizeOfImage = 0;
    if (!CheckedAdd(virtualAddress, virtualSize, newSizeOfImage)) {
        result.error = "SizeOfImage overflows";
        return result;
    }

    // 拷贝区域合法性（防止越界读源 buffer）。
    //   头部 [0, firstRaw)；section 数据 [firstRaw, lastFileEnd)；
    //   overlay [lastFileEnd, lastFileEnd+overlaySize)。
    if (lastFileEnd < firstRaw || lastFileEnd > m_image->rawSize) {
        result.error = "existing section bounds are inconsistent";
        return result;
    }

    // 统一偏移映射必须先在旧 buffer 状态下验证成功，任何一项映射溢出都必须在
    // 分配/提交新 buffer 之前中止，否则会在提交后才发现失败,留下半成品 image。
    RemapPlan remapPlan;
    if (!BuildRemapPlan(firstRaw, lastFileEnd, headerDelta, overlayDestBase, remapPlan)) {
        result.error = "file offset remap would overflow";
        return result;
    }

    // 至此所有计算与验证完成。分配唯一的新 buffer；失败时 image 完全不变。
    BYTE* newData = new(std::nothrow) BYTE[newRawSize];
    if (!newData) {
        result.error = "no memory while appending section";
        return result;
    }

    // 一次性填充新 buffer：
    //   [0, firstRaw)                       ← 原头部
    //   [firstRaw, firstRaw+headerDelta)    ← 零（头部间隙，仅扩容时存在）
    //   [firstRaw+headerDelta, shiftedLastFileEnd) ← 原 section 数据
    //   [rawOffset, rawOffset+rawSize)      ← 新 section 数据
    //   [overlayDestBase, +overlaySize)     ← 原 overlay
    memset(newData, 0, newRawSize);
    memcpy(newData, m_image->rawData, firstRaw);
    memcpy(newData + firstRaw + headerDelta, m_image->rawData + firstRaw,
           lastFileEnd - firstRaw);
    memcpy(newData + rawOffset, data.data(), data.size());
    if (overlaySize) {
        memcpy(newData + overlayDestBase, m_image->rawData + lastFileEnd, overlaySize);
    }

    // 所有可能失败的操作已完成，提交新 buffer。
    delete[] m_image->rawData;
    m_image->rawData = newData;
    m_image->rawSize = newRawSize;
    RefreshPointers(ntOffset);

    // 用预先算好且已验证成功的映射写入所有文件偏移型引用（section/overlay/security/debug）。
    // 必须在写入新 section header 之前调用：此时 numSections 仍是旧值，
    // 新槽尚未写入，不会被映射误伤。
    ApplyRemapPlan(remapPlan);

    // 写入新 section header。
    PIMAGE_SECTION_HEADER newSection = &m_image->sections[m_image->numSections];
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSection->Name, name, 8);
    newSection->Misc.VirtualSize = static_cast<DWORD>(data.size());
    newSection->VirtualAddress = virtualAddress;
    newSection->SizeOfRawData = rawSize;
    newSection->PointerToRawData = rawOffset;
    newSection->Characteristics = characteristics;

    result.sectionIndex = m_image->numSections;
    m_image->numSections++;
    if (m_image->is64Bit) {
        m_image->ntHeaders64->FileHeader.NumberOfSections = m_image->numSections;
    } else {
        m_image->ntHeaders32->FileHeader.NumberOfSections = m_image->numSections;
    }
    SetSizeOfHeaders(newSizeOfHeaders);
    SetSizeOfImage(newSizeOfImage);

    result.success = true;
    result.rva = virtualAddress;
    result.rawOffset = rawOffset;
    result.rawSize = rawSize;
    result.virtualSize = static_cast<uint32_t>(data.size());
    return result;
}

bool PEEmitter::BuildRemapPlan(uint32_t firstRaw, uint32_t lastFileEnd, uint32_t headerDelta,
                               uint32_t overlayDestBase, RemapPlan& plan) const {
    // 统一偏移映射（两种区域不同 delta）：
    //   off < firstRaw            → off
    //   firstRaw <= off < lastFileEnd → off + headerDelta
    //   off >= lastFileEnd        → overlayDestBase + (off - lastFileEnd)
    // 任何一项映射加法溢出都视为整体失败，调用方必须在提交新 buffer 之前中止。
    auto mapOffset = [&](uint32_t off, uint32_t& mapped) -> bool {
        if (off == 0) { mapped = 0; return true; }
        if (off < firstRaw) { mapped = off; return true; }
        if (off < lastFileEnd) {
            return CheckedAdd(off, headerDelta, mapped);
        }
        // overlay 区域：overlayDestBase + (off - lastFileEnd)
        uint32_t tail = off - lastFileEnd;
        return CheckedAdd(overlayDestBase, tail, mapped);
    };

    // 1. section.PointerToRawData（BSS 的 0 保持 0）。此时仍是旧 buffer/旧 sections。
    plan.sectionRaw.resize(m_image->numSections);
    for (WORD i = 0; i < m_image->numSections; i++) {
        if (!mapOffset(m_image->sections[i].PointerToRawData, plan.sectionRaw[i])) return false;
    }

    // 2. overlayOffset。
    if (m_image->hasOverlay) {
        plan.hasOverlay = true;
        if (!mapOffset(m_image->overlayOffset, plan.overlayOffset)) return false;
    }

    // 3. Security Directory.VirtualAddress 是文件偏移（绝不做 RVA 转换）。
    const IMAGE_DATA_DIRECTORY secDir = PEUtils::GetDataDirectory(m_image, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (secDir.VirtualAddress != 0) {
        plan.hasSecurity = true;
        if (!mapOffset(secDir.VirtualAddress, plan.securityOffset)) return false;
    }

    // 4. Debug Directory 每个 IMAGE_DEBUG_DIRECTORY.PointerToRawData（含同步副本）。
    //    目录自身的位置也要重映射，才能在新 buffer 中定位到同一批结构体。
    const IMAGE_DATA_DIRECTORY dbgDir = PEUtils::GetDataDirectory(m_image, IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (dbgDir.VirtualAddress != 0 && dbgDir.Size != 0) {
        if (dbgDir.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0) return false;
        const DWORD dbgOff = PEUtils::RvaToOffset(m_image, dbgDir.VirtualAddress);
        if (dbgOff == 0 || !PEUtils::CheckRawBounds(m_image, dbgOff, dbgDir.Size)) return false;
        if (!mapOffset(dbgOff, plan.debugDirNewOffset)) return false;
        const PIMAGE_DEBUG_DIRECTORY dbgEntries = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
            m_image->rawData + dbgOff);
        const DWORD count = dbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        plan.hasDebug = true;
        plan.debugPointers.resize(count);
        for (DWORD i = 0; i < count; ++i) {
            if (!mapOffset(dbgEntries[i].PointerToRawData, plan.debugPointers[i])) return false;
        }
    }

    return true;
}

void PEEmitter::ApplyRemapPlan(const RemapPlan& plan) {
    // 纯写入：全部目标值已由 BuildRemapPlan 验证成功，这里不会失败。
    for (WORD i = 0; i < m_image->numSections && i < plan.sectionRaw.size(); i++) {
        m_image->sections[i].PointerToRawData = plan.sectionRaw[i];
    }

    if (plan.hasOverlay) {
        m_image->overlayOffset = plan.overlayOffset;
    }

    if (plan.hasSecurity) {
        if (m_image->is64Bit) {
            m_image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = plan.securityOffset;
        } else {
            m_image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = plan.securityOffset;
        }
    }

    if (plan.hasDebug) {
        PIMAGE_DEBUG_DIRECTORY dbgEntries = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
            m_image->rawData + plan.debugDirNewOffset);
        for (size_t i = 0; i < plan.debugPointers.size(); ++i) {
            dbgEntries[i].PointerToRawData = plan.debugPointers[i];
            if (i < m_image->debugDir.entries.size()) {
                m_image->debugDir.entries[i].pointerToRawData = plan.debugPointers[i];
            }
        }
    }
}

bool PEEmitter::PatchBytes(uint32_t rva, const std::vector<uint8_t>& bytes, std::string* error) {
    if (!IsValid() || bytes.empty()) {
        if (error) *error = "invalid PE image or empty patch";
        return false;
    }
    if (bytes.size() > std::numeric_limits<uint32_t>::max()) {
        if (error) *error = "patch size exceeds PE limits";
        return false;
    }
    uint32_t offset = RvaToOffset(rva);
    uint32_t patchEnd = 0;
    if (offset == 0 || !CheckedAdd(offset, static_cast<uint32_t>(bytes.size()), patchEnd) ||
        patchEnd > m_image->rawSize) {
        if (error) *error = "patch RVA is outside file data";
        return false;
    }
    memcpy(m_image->rawData + offset, bytes.data(), bytes.size());
    return true;
}

bool PEEmitter::FillBytes(uint32_t rva, uint32_t size, uint8_t value, std::string* error) {
    if (!IsValid() || size == 0) {
        if (error) *error = "invalid PE image or empty fill";
        return false;
    }
    uint32_t offset = RvaToOffset(rva);
    uint32_t fillEnd = 0;
    if (offset == 0 || !CheckedAdd(offset, size, fillEnd) || fillEnd > m_image->rawSize) {
        if (error) *error = "fill RVA is outside file data";
        return false;
    }
    memset(m_image->rawData + offset, value, size);
    return true;
}

bool PEEmitter::SetSectionCharacteristics(uint32_t sectionIndex, uint32_t characteristics, std::string* error) {
    if (!IsValid() || sectionIndex >= m_image->numSections) {
        if (error) *error = "invalid section index";
        return false;
    }
    m_image->sections[sectionIndex].Characteristics = characteristics;
    return true;
}

bool PEEmitter::RebuildExceptionDirectory(
    const std::vector<CS_RUNTIME_FUNCTION>& additionalEntries,
    const char sectionName[8],
    PEAppendSectionResult* sectionResult,
    std::string* error)
{
    if (!IsValid() || !m_image->is64Bit || !sectionName || additionalEntries.empty()) {
        if (error) *error = "exception directory rebuild requires a valid x64 image and entries";
        return false;
    }

    std::vector<CS_RUNTIME_FUNCTION> entries = m_image->exceptions.entries;
    entries.insert(entries.end(), additionalEntries.begin(), additionalEntries.end());
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        if (left.beginAddress != right.beginAddress) return left.beginAddress < right.beginAddress;
        if (left.endAddress != right.endAddress) return left.endAddress < right.endAddress;
        return left.unwindData < right.unwindData;
    });
    entries.erase(std::unique(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        return left.beginAddress == right.beginAddress &&
            left.endAddress == right.endAddress && left.unwindData == right.unwindData;
    }), entries.end());

    uint32_t previousEnd = 0;
    for (const auto& entry : entries) {
        // UnwindData 必须至少能读取合法的 UNWIND_INFO 最小固定头部（4 字节、Version==1），
        // 而不是仅首字节可映射。
        if (entry.beginAddress >= entry.endAddress || entry.unwindData == 0 ||
            !PEUtils::IsValidUnwindInfoHeader(m_image, entry.unwindData)) {
            if (error) *error = "exception directory contains an invalid runtime-function range";
            return false;
        }
        // 代码范围必须整体位于可执行且 file-backed section。
        if (!PEUtils::IsExecutableFileBackedRange(m_image, entry.beginAddress, entry.endAddress)) {
            if (error) *error = "exception directory range is not executable/file-backed";
            return false;
        }
        if (previousEnd != 0 && entry.beginAddress < previousEnd) {
            if (error) *error = "exception directory contains overlapping runtime-function ranges";
            return false;
        }
        previousEnd = entry.endAddress;
    }

    std::vector<uint8_t> table(entries.size() * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 0);
    auto* nativeEntries = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(table.data());
    for (size_t i = 0; i < entries.size(); ++i) {
        nativeEntries[i].BeginAddress = entries[i].beginAddress;
        nativeEntries[i].EndAddress = entries[i].endAddress;
        nativeEntries[i].UnwindData = entries[i].unwindData;
    }

    PEAppendSectionResult appended = AppendSection(
        sectionName, table, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        if (error) *error = appended.error;
        return false;
    }
    m_image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = appended.rva;
    m_image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
        static_cast<DWORD>(table.size());
    m_image->exceptions.entries = std::move(entries);
    if (sectionResult) *sectionResult = appended;
    return true;
}

bool PEEmitter::RebuildGuardCFFunctionTable(
    const std::vector<uint32_t>& additionalFunctionRVAs,
    const char sectionName[8],
    PEAppendSectionResult* sectionResult,
    std::string* error)
{
    if (!IsValid() || !sectionName || additionalFunctionRVAs.empty()) {
        if (error) *error = "Guard CF table rebuild requires a valid image and target list";
        return false;
    }
    if (!m_image->loadConfig.hasCFG) {
        if (sectionResult) *sectionResult = {};
        return true;
    }
    constexpr uint32_t kGuardTableSizeMask = 0xF0000000u;
    constexpr uint32_t kGuardTableSizeShift = 28u;
    const size_t entrySize = sizeof(uint32_t) +
        ((m_image->loadConfig.guardFlags & kGuardTableSizeMask) >> kGuardTableSizeShift);
    if (!m_image->loadConfig.valid || entrySize < sizeof(uint32_t) || entrySize > 19u ||
        ((m_image->loadConfig.guardCFFunctionTable == 0) !=
         (m_image->loadConfig.guardCFFunctionCount == 0))) {
        if (error) *error = "existing Guard CF function table is incomplete or unsupported";
        return false;
    }

    const uint64_t imageBase = m_image->is64Bit
        ? m_image->ntHeaders64->OptionalHeader.ImageBase
        : m_image->ntHeaders32->OptionalHeader.ImageBase;
    if ((m_image->loadConfig.guardCFFunctionTable != 0 &&
         (m_image->loadConfig.guardCFFunctionTable < imageBase ||
          m_image->loadConfig.guardCFFunctionTable - imageBase > std::numeric_limits<uint32_t>::max())) ||
        (m_image->loadConfig.guardCFFunctionCount != 0 &&
         m_image->loadConfig.guardCFFunctionCount > std::numeric_limits<size_t>::max() /
            entrySize)) {
        if (error) *error = "existing Guard CF table address or size is invalid";
        return false;
    }
    const uint32_t oldTableRVA = m_image->loadConfig.guardCFFunctionTable
        ? static_cast<uint32_t>(m_image->loadConfig.guardCFFunctionTable - imageBase) : 0;
    const uint32_t oldTableOffset = oldTableRVA ? RvaToOffset(oldTableRVA) : 0;
    const size_t oldTableSize = static_cast<size_t>(
        m_image->loadConfig.guardCFFunctionCount) * entrySize;
    if (oldTableSize != 0 && (oldTableOffset == 0 || oldTableOffset > m_image->rawSize ||
        oldTableSize > m_image->rawSize - oldTableOffset)) {
        if (error) *error = "existing Guard CF table is outside the PE file";
        return false;
    }

    std::map<uint32_t, std::vector<uint8_t>> entries;
    for (size_t i = 0; i < m_image->loadConfig.guardCFFunctionCount; ++i) {
        const uint8_t* source = m_image->rawData + oldTableOffset + i * entrySize;
        uint32_t rva = 0;
        std::memcpy(&rva, source, sizeof(rva));
        if (rva == 0) {
            if (error) *error = "existing Guard CF table contains a null target";
            return false;
        }
        entries.emplace(rva, std::vector<uint8_t>(source, source + entrySize));
    }
    for (uint32_t rva : additionalFunctionRVAs) {
        if (rva == 0 || RvaToOffset(rva) == 0) {
            if (error) *error = "new Guard CF target is outside the file-backed image";
            return false;
        }
        auto inserted = entries.emplace(rva, std::vector<uint8_t>(entrySize, 0));
        if (inserted.second) std::memcpy(inserted.first->second.data(), &rva, sizeof(rva));
    }
    if (entries.size() > std::numeric_limits<uint32_t>::max() / entrySize) {
        if (error) *error = "rebuilt Guard CF table exceeds PE limits";
        return false;
    }
    std::vector<uint8_t> table;
    table.reserve(entries.size() * entrySize);
    for (const auto& entry : entries) table.insert(
        table.end(), entry.second.begin(), entry.second.end());

    // Load Config 里 GuardCFFunctionTable/GuardCFFunctionCount 两个字段的位置在
    // AppendSection 之前就已确定；必须先确认它们可写（RvaToOffset 成功且在文件范围内），
    // 否则一旦 AppendSection 提交新 section 之后再发现不可写，就会留下半成品 image。
    const uint32_t fieldWidth = m_image->is64Bit ? 8u : 4u;
    const uint32_t tableFieldRVA = m_image->loadConfig.directoryRVA + static_cast<uint32_t>(
        m_image->is64Bit ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable)
                         : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionTable));
    const uint32_t countFieldRVA = m_image->loadConfig.directoryRVA + static_cast<uint32_t>(
        m_image->is64Bit ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount)
                         : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount));
    auto rvaIsPatchable = [&](uint32_t rva) -> bool {
        const uint32_t off = RvaToOffset(rva);
        uint32_t end = 0;
        return off != 0 && CheckedAdd(off, fieldWidth, end) && end <= m_image->rawSize;
    };
    if (!rvaIsPatchable(tableFieldRVA) || !rvaIsPatchable(countFieldRVA)) {
        if (error) *error = "Guard CF directory fields are not patchable";
        return false;
    }

    PEAppendSectionResult appended = AppendSection(sectionName, table,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        if (error) *error = appended.error;
        return false;
    }
    const uint64_t tableVA = imageBase + appended.rva;
    const uint64_t count = entries.size();
    std::vector<uint8_t> tableField(fieldWidth, 0);
    std::vector<uint8_t> countField(fieldWidth, 0);
    std::memcpy(tableField.data(), &tableVA, tableField.size());
    std::memcpy(countField.data(), &count, countField.size());
    if (!PatchBytes(tableFieldRVA, tableField, error) ||
        !PatchBytes(countFieldRVA, countField, error)) return false;

    m_image->loadConfig.guardCFFunctionTable = tableVA;
    m_image->loadConfig.guardCFFunctionCount = count;
    m_image->loadConfig.guardTableEntrySize = static_cast<uint32_t>(entrySize);
    m_image->loadConfig.guardFunctionRVAs.clear();
    m_image->loadConfig.guardFunctionRVAs.reserve(entries.size());
    for (const auto& entry : entries) m_image->loadConfig.guardFunctionRVAs.push_back(entry.first);
    if (sectionResult) *sectionResult = appended;
    return true;
}

bool PEEmitter::RebuildBaseRelocationDirectory(
    const std::vector<CS_RELOC_ENTRY>& additionalEntries,
    const char sectionName[8],
    PEAppendSectionResult* sectionResult,
    std::string* error)
{
    if (!IsValid() || !sectionName || additionalEntries.empty()) {
        if (error) *error = "base relocation rebuild requires a valid image and fixup list";
        return false;
    }
    std::vector<CS_RELOC_ENTRY> entries = m_image->relocs.entries;
    entries.insert(entries.end(), additionalEntries.begin(), additionalEntries.end());
    for (auto& entry : entries) {
        if (entry.fullRVA > std::numeric_limits<uint32_t>::max()) {
            if (error) *error = "base relocation target exceeds PE RVA range";
            return false;
        }
        const uint32_t rva = static_cast<uint32_t>(entry.fullRVA);
        entry.pageRVA = rva & ~0xFFFu;
        entry.offset = static_cast<uint16_t>(rva & 0x0FFFu);
        const bool typeValid = m_image->is64Bit
            ? entry.type == IMAGE_REL_BASED_DIR64
            : entry.type == IMAGE_REL_BASED_HIGHLOW;
        if (!typeValid || RvaToOffset(rva) == 0) {
            if (error) *error = "base relocation contains an unsupported type or unmapped target";
            return false;
        }
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        if (left.fullRVA != right.fullRVA) return left.fullRVA < right.fullRVA;
        return left.type < right.type;
    });
    entries.erase(std::unique(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        return left.fullRVA == right.fullRVA && left.type == right.type;
    }), entries.end());

    std::vector<uint8_t> table;
    size_t index = 0;
    while (index < entries.size()) {
        const uint32_t page = entries[index].pageRVA;
        size_t end = index;
        while (end < entries.size() && entries[end].pageRVA == page) ++end;
        const size_t realCount = end - index;
        const size_t encodedCount = realCount + (realCount & 1u);
        const size_t blockSize = sizeof(IMAGE_BASE_RELOCATION) + encodedCount * sizeof(uint16_t);
        if (blockSize > std::numeric_limits<uint32_t>::max() ||
            table.size() > std::numeric_limits<uint32_t>::max() - blockSize) {
            if (error) *error = "base relocation table exceeds PE limits";
            return false;
        }
        const size_t blockOffset = table.size();
        table.resize(blockOffset + blockSize, 0);
        IMAGE_BASE_RELOCATION block{};
        block.VirtualAddress = page;
        block.SizeOfBlock = static_cast<uint32_t>(blockSize);
        std::memcpy(table.data() + blockOffset, &block, sizeof(block));
        for (size_t item = index; item < end; ++item) {
            const uint16_t encoded = static_cast<uint16_t>(
                (entries[item].type << 12u) | entries[item].offset);
            std::memcpy(table.data() + blockOffset + sizeof(block) +
                (item - index) * sizeof(encoded), &encoded, sizeof(encoded));
        }
        index = end;
    }

    PEAppendSectionResult appended = AppendSection(sectionName, table,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE);
    if (!appended.success) {
        if (error) *error = appended.error;
        return false;
    }
    PEUtils::SetDataDirectory(m_image, IMAGE_DIRECTORY_ENTRY_BASERELOC,
        appended.rva, static_cast<uint32_t>(table.size()));
    if (m_image->is64Bit) {
        m_image->ntHeaders64->FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;
    } else {
        m_image->ntHeaders32->FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;
    }
    m_image->relocs.entries = std::move(entries);
    if (sectionResult) *sectionResult = appended;
    return true;
}

} // namespace CipherShell



