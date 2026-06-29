#include "pe_emitter.h"
#include <algorithm>
#include <cstring>
#include <new>

namespace CipherShell {

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
    uint32_t align = m_image->is64Bit ? m_image->ntHeaders64->OptionalHeader.FileAlignment
                                      : m_image->ntHeaders32->OptionalHeader.FileAlignment;
    return align < 0x200 ? 0x200 : align;
}

uint32_t PEEmitter::GetSectionAlignment() const {
    if (!IsValid()) return 0x1000;
    uint32_t align = m_image->is64Bit ? m_image->ntHeaders64->OptionalHeader.SectionAlignment
                                      : m_image->ntHeaders32->OptionalHeader.SectionAlignment;
    return align < 0x1000 ? 0x1000 : align;
}

uint32_t PEEmitter::GetSizeOfHeaders() const {
    if (!IsValid()) return 0;
    return m_image->is64Bit ? m_image->ntHeaders64->OptionalHeader.SizeOfHeaders
                            : m_image->ntHeaders32->OptionalHeader.SizeOfHeaders;
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
    if (!IsValid()) return 0;
    const uint32_t sizeOfHeaders = GetSizeOfHeaders();
    if (rva < sizeOfHeaders) return rva;

    for (WORD i = 0; i < m_image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = m_image->sections[i];
        uint32_t virtualSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        uint32_t span = (std::max)(virtualSize, static_cast<uint32_t>(sec.SizeOfRawData));
        if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + span) {
            return sec.PointerToRawData + (rva - sec.VirtualAddress);
        }
    }
    return 0;
}

bool PEEmitter::RelocateHeaders(uint32_t requiredHeaderEnd, uint32_t firstRaw, std::string& error) {
    const uint32_t fileAlign = GetFileAlignment();
    const uint32_t ntOffset = static_cast<uint32_t>(m_image->dosHeader->e_lfanew);
    const uint32_t headerDelta = AlignUp(requiredHeaderEnd - firstRaw, fileAlign);
    const uint32_t newRawSize = m_image->rawSize + headerDelta;

    BYTE* moved = new(std::nothrow) BYTE[newRawSize];
    if (!moved) {
        error = "no memory while relocating PE headers";
        return false;
    }

    memset(moved, 0, newRawSize);
    memcpy(moved, m_image->rawData, firstRaw);
    memcpy(moved + firstRaw + headerDelta, m_image->rawData + firstRaw, m_image->rawSize - firstRaw);

    delete[] m_image->rawData;
    m_image->rawData = moved;
    m_image->rawSize = newRawSize;
    RefreshPointers(ntOffset);

    for (WORD i = 0; i < m_image->numSections; i++) {
        if (m_image->sections[i].PointerToRawData >= firstRaw) {
            m_image->sections[i].PointerToRawData += headerDelta;
        }
    }

    if (m_image->hasOverlay && m_image->overlayOffset >= firstRaw) {
        m_image->overlayOffset += headerDelta;
    }
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

    uint32_t firstRaw = 0xFFFFFFFFu;
    uint32_t lastFileEnd = 0;
    uint32_t lastVirtualEnd = 0;

    for (WORD i = 0; i < m_image->numSections; i++) {
        const IMAGE_SECTION_HEADER& sec = m_image->sections[i];
        if (sec.PointerToRawData != 0 && sec.PointerToRawData < firstRaw) {
            firstRaw = sec.PointerToRawData;
        }
        lastFileEnd = (std::max)(lastFileEnd, static_cast<uint32_t>(sec.PointerToRawData + sec.SizeOfRawData));

        uint32_t virtualSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        lastVirtualEnd = (std::max)(lastVirtualEnd,
            static_cast<uint32_t>(sec.VirtualAddress + AlignUp(virtualSize, sectionAlign)));
    }

    if (firstRaw == 0xFFFFFFFFu) {
        firstRaw = GetSizeOfHeaders();
    }

    uint32_t requiredHeaderEnd = static_cast<uint32_t>(
        reinterpret_cast<BYTE*>(&m_image->sections[m_image->numSections + 1]) - m_image->rawData);
    if (requiredHeaderEnd > firstRaw) {
        if (!RelocateHeaders(requiredHeaderEnd, firstRaw, result.error)) {
            return result;
        }

        firstRaw = 0xFFFFFFFFu;
        lastFileEnd = 0;
        lastVirtualEnd = 0;
        for (WORD i = 0; i < m_image->numSections; i++) {
            const IMAGE_SECTION_HEADER& sec = m_image->sections[i];
            if (sec.PointerToRawData != 0 && sec.PointerToRawData < firstRaw) {
                firstRaw = sec.PointerToRawData;
            }
            lastFileEnd = (std::max)(lastFileEnd, static_cast<uint32_t>(sec.PointerToRawData + sec.SizeOfRawData));
            uint32_t virtualSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            lastVirtualEnd = (std::max)(lastVirtualEnd,
                static_cast<uint32_t>(sec.VirtualAddress + AlignUp(virtualSize, sectionAlign)));
        }
    }

    const uint32_t rawOffset = AlignUp(lastFileEnd, fileAlign);
    const uint32_t rawSize = AlignUp(static_cast<uint32_t>(data.size()), fileAlign);
    const uint32_t virtualAddress = AlignUp(lastVirtualEnd, sectionAlign);
    const uint32_t virtualSize = AlignUp(static_cast<uint32_t>(data.size()), sectionAlign);
    const uint32_t overlaySize = m_image->rawSize > lastFileEnd ? m_image->rawSize - lastFileEnd : 0;
    const uint32_t newRawSize = rawOffset + rawSize + overlaySize;

    BYTE* newData = new(std::nothrow) BYTE[newRawSize];
    if (!newData) {
        result.error = "no memory while appending section";
        return result;
    }

    memset(newData, 0, newRawSize);
    uint32_t copyPrefix = (m_image->rawSize < lastFileEnd) ? m_image->rawSize : lastFileEnd;
    memcpy(newData, m_image->rawData, copyPrefix);
    memcpy(newData + rawOffset, data.data(), data.size());
    if (overlaySize) {
        memcpy(newData + rawOffset + rawSize, m_image->rawData + lastFileEnd, overlaySize);
        if (m_image->hasOverlay && m_image->overlayOffset >= lastFileEnd) {
            m_image->overlayOffset = rawOffset + rawSize + (m_image->overlayOffset - lastFileEnd);
        }
    }

    delete[] m_image->rawData;
    m_image->rawData = newData;
    m_image->rawSize = newRawSize;
    RefreshPointers(ntOffset);

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
    SetSizeOfImage(virtualAddress + virtualSize);

    result.success = true;
    result.rva = virtualAddress;
    result.rawOffset = rawOffset;
    result.rawSize = rawSize;
    result.virtualSize = static_cast<uint32_t>(data.size());
    return result;
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

} // namespace CipherShell
