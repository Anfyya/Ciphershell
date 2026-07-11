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

bool PEEmitter::RelocateHeaders(uint32_t requiredHeaderEnd, uint32_t firstRaw, std::string& error) {
    // 预计算并验证：所有可能失败的算术检查在分配新 buffer 与提交 image 之前完成。
    if (requiredHeaderEnd <= firstRaw) {
        error = "header relocation requested but required header end does not exceed first raw offset";
        return false;
    }
    const uint32_t fileAlign = GetFileAlignment();
    const uint32_t ntOffset = static_cast<uint32_t>(m_image->dosHeader->e_lfanew);
    const uint32_t gap = requiredHeaderEnd - firstRaw;  // 已证 requiredHeaderEnd > firstRaw
    const uint32_t headerDelta = AlignUp(gap, fileAlign);  // requiredHeaderEnd - firstRaw
    uint32_t newRawSize = 0;
    if (!CheckedAdd(m_image->rawSize, headerDelta, newRawSize)) {
        error = "header relocation would overflow raw size";
        return false;
    }
    // 校验对齐后的 headerDelta 不回绕。
    if (headerDelta < gap) {
        error = "header relocation alignment overflow";
        return false;
    }

    // 分配新 buffer；分配失败时 image 完全不变。
    BYTE* moved = new(std::nothrow) BYTE[newRawSize];
    if (!moved) {
        error = "no memory while relocating PE headers";
        return false;
    }

    memset(moved, 0, newRawSize);
    memcpy(moved, m_image->rawData, firstRaw);
    memcpy(moved + firstRaw + headerDelta, m_image->rawData + firstRaw, m_image->rawSize - firstRaw);

    // 所有可能失败的操作已完成，提交新 buffer。
    delete[] m_image->rawData;
    m_image->rawData = moved;
    m_image->rawSize = newRawSize;
    RefreshPointers(ntOffset);

    // 平移所有文件偏移型引用（section/overlay/security/debug）。
    ShiftFileOffsetReferences(firstRaw, headerDelta);
    SetSizeOfHeaders(AlignUp(requiredHeaderEnd, fileAlign));
    return true;
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

    const uint32_t fileAlign = GetFileAlignment();
    const uint32_t sectionAlign = GetSectionAlignment();
    const uint32_t ntOffset = static_cast<uint32_t>(m_image->dosHeader->e_lfanew);

    // 预计算并验证：所有 32 位溢出检查在分配新 buffer 与提交 image 之前完成。
    auto gatherSectionBounds = [&](uint32_t& firstRawOut, uint32_t& lastFileEndOut,
                                   uint32_t& lastVirtualEndOut) -> bool {
        uint32_t firstRaw = 0xFFFFFFFFu;
        uint32_t lastFileEnd = 0;
        uint32_t lastVirtualEnd = 0;
        for (WORD i = 0; i < m_image->numSections; i++) {
            const IMAGE_SECTION_HEADER& sec = m_image->sections[i];
            if (sec.PointerToRawData != 0 && sec.PointerToRawData < firstRaw) {
                firstRaw = sec.PointerToRawData;
            }
            // PointerToRawData + SizeOfRawData 溢出检查
            uint32_t fileEnd = 0;
            if (!CheckedAdd(sec.PointerToRawData, sec.SizeOfRawData, fileEnd)) return false;
            lastFileEnd = (std::max)(lastFileEnd, fileEnd);
            // VirtualAddress + AlignUp(virtualSize, sectionAlign) 溢出检查
            const uint32_t vspan = PEUtils::SectionMappedSpan(sec);
            const uint32_t alignedV = AlignUp(vspan, sectionAlign);
            uint32_t vEnd = 0;
            if (!CheckedAdd(sec.VirtualAddress, alignedV, vEnd)) return false;
            lastVirtualEnd = (std::max)(lastVirtualEnd, vEnd);
        }
        firstRawOut = firstRaw;
        lastFileEndOut = lastFileEnd;
        lastVirtualEndOut = lastVirtualEnd;
        return true;
    };

    uint32_t firstRaw = 0, lastFileEnd = 0, lastVirtualEnd = 0;
    if (!gatherSectionBounds(firstRaw, lastFileEnd, lastVirtualEnd)) {
        result.error = "existing section raw/virtual bounds overflow";
        return result;
    }
    if (firstRaw == 0xFFFFFFFFu) firstRaw = GetSizeOfHeaders();

    // requiredHeaderEnd = section table 末尾（再增加一条）。
    uint32_t requiredHeaderEnd = static_cast<uint32_t>(
        reinterpret_cast<BYTE*>(&m_image->sections[m_image->numSections + 1]) - m_image->rawData);
    if (requiredHeaderEnd > firstRaw) {
        if (!RelocateHeaders(requiredHeaderEnd, firstRaw, result.error)) {
            return result;
        }
        // 重定位后 section PointerToRawData 已平移，重新收集边界（同样带溢出检查）。
        if (!gatherSectionBounds(firstRaw, lastFileEnd, lastVirtualEnd)) {
            result.error = "post-relocation section raw/virtual bounds overflow";
            return result;
        }
        if (firstRaw == 0xFFFFFFFFu) firstRaw = GetSizeOfHeaders();
    }

    // 新 section 布局算术，全部带溢出检查。
    const uint32_t rawOffset = AlignUp(lastFileEnd, fileAlign);
    if (rawOffset < lastFileEnd) {  // AlignUp 回绕
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

    const uint32_t overlaySize = m_image->rawSize > lastFileEnd ? m_image->rawSize - lastFileEnd : 0;
    // rawOffset + rawSize + overlaySize
    uint32_t newRawSize = 0;
    if (!CheckedAdd(rawOffset, rawSize, newRawSize) ||
        !CheckedAdd(newRawSize, overlaySize, newRawSize)) {
        result.error = "appended section raw size overflows";
        return result;
    }
    // overlay 目标基址 = rawOffset + rawSize，并用作 shift delta。
    uint32_t overlayDestBase = 0;
    if (!CheckedAdd(rawOffset, rawSize, overlayDestBase)) {
        result.error = "overlay destination offset overflows";
        return result;
    }
    const uint32_t shiftDelta = overlayDestBase - lastFileEnd;  // overlayDestBase >= lastFileEnd
    // SizeOfImage = virtualAddress + virtualSize
    uint32_t newSizeOfImage = 0;
    if (!CheckedAdd(virtualAddress, virtualSize, newSizeOfImage)) {
        result.error = "SizeOfImage overflows";
        return result;
    }

    // 分配新 buffer；失败时 image 完全不变。
    BYTE* newData = new(std::nothrow) BYTE[newRawSize];
    if (!newData) {
        result.error = "no memory while appending section";
        return result;
    }

    memset(newData, 0, newRawSize);
    const uint32_t copyPrefix = (m_image->rawSize < lastFileEnd) ? m_image->rawSize : lastFileEnd;
    memcpy(newData, m_image->rawData, copyPrefix);
    memcpy(newData + rawOffset, data.data(), data.size());
    if (overlaySize) {
        memcpy(newData + overlayDestBase, m_image->rawData + lastFileEnd, overlaySize);
    }

    // 所有可能失败的操作已完成，提交新 buffer。
    delete[] m_image->rawData;
    m_image->rawData = newData;
    m_image->rawSize = newRawSize;
    RefreshPointers(ntOffset);

    // 平移 overlay/security/debug 的文件偏移引用。无 section 落在 lastFileEnd 之后，
    // 故 section PointerToRawData 不会被错误平移。
    ShiftFileOffsetReferences(lastFileEnd, shiftDelta);

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
    SetSizeOfImage(newSizeOfImage);

    result.success = true;
    result.rva = virtualAddress;
    result.rawOffset = rawOffset;
    result.rawSize = rawSize;
    result.virtualSize = static_cast<uint32_t>(data.size());
    return result;
}

void PEEmitter::ShiftFileOffsetReferences(uint32_t shiftPoint, uint32_t delta) {
    if (delta == 0) return;
    // section.PointerToRawData
    for (WORD i = 0; i < m_image->numSections; i++) {
        if (m_image->sections[i].PointerToRawData >= shiftPoint) {
            m_image->sections[i].PointerToRawData += delta;
        }
    }
    // overlayOffset
    if (m_image->hasOverlay && m_image->overlayOffset >= shiftPoint) {
        m_image->overlayOffset += delta;
    }
    // Security Directory.VirtualAddress 是文件偏移（绝不做 RVA 转换）。
    if (m_image->is64Bit) {
        IMAGE_DATA_DIRECTORY& secDir =
            m_image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (secDir.VirtualAddress != 0 && secDir.VirtualAddress >= shiftPoint) {
            secDir.VirtualAddress += delta;
        }
    } else {
        IMAGE_DATA_DIRECTORY& secDir =
            m_image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (secDir.VirtualAddress != 0 && secDir.VirtualAddress >= shiftPoint) {
            secDir.VirtualAddress += delta;
        }
    }
    // Debug Directory 每个 IMAGE_DEBUG_DIRECTORY.PointerToRawData（含 image->debugDir.entries 同步副本）。
    // 必须在 section PointerToRawData 平移之后计算 debug 目录文件偏移，使 RvaToOffset 指向新位置。
    const IMAGE_DATA_DIRECTORY dbgDir = PEUtils::GetDataDirectory(m_image, IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (dbgDir.VirtualAddress == 0 || dbgDir.Size == 0) return;
    if (dbgDir.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0) return;
    const DWORD dbgOff = PEUtils::RvaToOffset(m_image, dbgDir.VirtualAddress);
    if (dbgOff == 0 || !PEUtils::CheckRawBounds(m_image, dbgOff, dbgDir.Size)) return;
    PIMAGE_DEBUG_DIRECTORY dbgEntries = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
        m_image->rawData + dbgOff);
    const DWORD count = dbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (DWORD i = 0; i < count; ++i) {
        if (dbgEntries[i].PointerToRawData >= shiftPoint) {
            dbgEntries[i].PointerToRawData += delta;
        }
        if (i < m_image->debugDir.entries.size() &&
            m_image->debugDir.entries[i].pointerToRawData >= shiftPoint) {
            m_image->debugDir.entries[i].pointerToRawData += delta;
        }
    }
}

bool PEEmitter::PatchBytes(uint32_t rva, const std::vector<uint8_t>& bytes, std::string* error) {
    if (!IsValid() || bytes.empty()) {
        if (error) *error = "invalid PE image or empty patch";
        return false;
    }
    uint32_t offset = RvaToOffset(rva);
    if (offset == 0 || offset + bytes.size() > m_image->rawSize) {
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
    if (offset == 0 || offset + size > m_image->rawSize) {
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
        if (entry.beginAddress >= entry.endAddress || entry.unwindData == 0 ||
            RvaToOffset(entry.beginAddress) == 0 ||
            RvaToOffset(entry.endAddress - 1) == 0 ||
            RvaToOffset(entry.unwindData) == 0) {
            if (error) *error = "exception directory contains an invalid runtime-function range";
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

    PEAppendSectionResult appended = AppendSection(sectionName, table,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        if (error) *error = appended.error;
        return false;
    }
    const uint64_t tableVA = imageBase + appended.rva;
    const uint64_t count = entries.size();
    const uint32_t tableFieldRVA = m_image->loadConfig.directoryRVA + static_cast<uint32_t>(
        m_image->is64Bit ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable)
                         : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionTable));
    const uint32_t countFieldRVA = m_image->loadConfig.directoryRVA + static_cast<uint32_t>(
        m_image->is64Bit ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount)
                         : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount));
    std::vector<uint8_t> tableField(m_image->is64Bit ? 8u : 4u, 0);
    std::vector<uint8_t> countField(m_image->is64Bit ? 8u : 4u, 0);
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



