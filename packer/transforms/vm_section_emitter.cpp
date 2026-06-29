#include "vm_section_emitter.h"
#include <algorithm>
#include <cstring>
#include <ctime>
#include <new>

namespace CipherShell {

namespace {
uint32_t RotL32(uint32_t v, unsigned c) {
    c &= 31;
    return (v << c) | (v >> ((32 - c) & 31));
}

uint32_t GetFileAlignment(CS_PE_IMAGE* image) {
    uint32_t align = image->is64Bit ? image->ntHeaders64->OptionalHeader.FileAlignment
                                    : image->ntHeaders32->OptionalHeader.FileAlignment;
    return align < 0x200 ? 0x200 : align;
}

uint32_t GetSectionAlignment(CS_PE_IMAGE* image) {
    uint32_t align = image->is64Bit ? image->ntHeaders64->OptionalHeader.SectionAlignment
                                    : image->ntHeaders32->OptionalHeader.SectionAlignment;
    return align < 0x1000 ? 0x1000 : align;
}

uint32_t GetSizeOfHeaders(CS_PE_IMAGE* image) {
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.SizeOfHeaders
                          : image->ntHeaders32->OptionalHeader.SizeOfHeaders;
}

void SetSizeOfHeaders(CS_PE_IMAGE* image, uint32_t value) {
    if (image->is64Bit) image->ntHeaders64->OptionalHeader.SizeOfHeaders = value;
    else image->ntHeaders32->OptionalHeader.SizeOfHeaders = value;
}
}

uint32_t VMSectionEmitter::AlignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void VMSectionEmitter::AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

VMEmitResult VMSectionEmitter::Emit(
    CS_PE_IMAGE* image,
    const std::vector<uint8_t>& bytecode,
    const std::vector<VMFunctionRecord>& records,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap)
{
    VMEmitResult result{};
    if (!image || !image->isValid) {
        result.error = "VM_EMIT: invalid PE image";
        return result;
    }
    if (bytecode.empty() || records.empty()) {
        result.error = "VM_EMIT: empty bytecode or function record table";
        return result;
    }

    uint32_t cookie = static_cast<uint32_t>(time(nullptr)) ^ static_cast<uint32_t>(bytecode.size() * 0x45D9F3Bu);
    cookie ^= static_cast<uint32_t>(records.size() * 0x9E3779B9u);
    if (cookie == 0) cookie = 0xA5C35A3Cu;

    std::vector<uint8_t> section;
    section.reserve(0x100 + records.size() * 32 + bytecode.size());

    const uint32_t headerSize = 32;
    const uint32_t recordOffset = headerSize;
    const uint32_t recordSize = 28;
    const uint32_t opcodeMapOffset = recordOffset + static_cast<uint32_t>(records.size() * recordSize);
    const uint32_t opcodeMapSize = 256;
    const uint32_t registerMapOffset = opcodeMapOffset + opcodeMapSize;
    const uint32_t registerMapSize = 32;
    const uint32_t bytecodeOffset = registerMapOffset + registerMapSize;

    AppendU32(section, cookie);
    AppendU32(section, static_cast<uint32_t>(records.size()) ^ cookie);
    AppendU32(section, recordOffset ^ RotL32(cookie, 3));
    AppendU32(section, opcodeMapOffset ^ RotL32(cookie, 7));
    AppendU32(section, registerMapOffset ^ RotL32(cookie, 11));
    AppendU32(section, bytecodeOffset ^ RotL32(cookie, 17));
    AppendU32(section, static_cast<uint32_t>(bytecode.size()) ^ RotL32(cookie, 19));
    AppendU32(section, 0u ^ RotL32(cookie, 23));

    for (const auto& record : records) {
        AppendU32(section, record.functionRVA ^ cookie);
        AppendU32(section, record.functionSize ^ RotL32(cookie, 1));
        AppendU32(section, record.bytecodeOffset ^ RotL32(cookie, 5));
        AppendU32(section, record.bytecodeSize ^ RotL32(cookie, 9));
        AppendU32(section, record.opcodeMapOffset ^ RotL32(cookie, 13));
        AppendU32(section, record.registerMapOffset ^ RotL32(cookie, 15));
        AppendU32(section, record.flags ^ RotL32(cookie, 21));
    }

    uint8_t reverseOpcode[256];
    for (uint32_t i = 0; i < 256; i++) reverseOpcode[i] = static_cast<uint8_t>(i);
    for (const auto& kv : opcodeMap) {
        reverseOpcode[kv.second] = kv.first;
    }
    section.insert(section.end(), reverseOpcode, reverseOpcode + 256);

    uint8_t regMap[32] = {0};
    for (uint32_t i = 0; i < 32; i++) regMap[i] = static_cast<uint8_t>(i);
    for (const auto& kv : registerMap) {
        if (kv.first < 32) regMap[kv.first] = kv.second;
    }
    section.insert(section.end(), regMap, regMap + 32);
    section.insert(section.end(), bytecode.begin(), bytecode.end());

    char name[8] = {'.','c','s','v','m',0,0,0};
    if (!AppendSection(image, name, section,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, result)) {
        return result;
    }

    result.metadataRVA = result.sectionRVA;
    result.bytecodeRVA = result.sectionRVA + bytecodeOffset;
    result.trampolineRVA = 0;
    result.success = true;
    return result;
}

bool VMSectionEmitter::AppendSection(
    CS_PE_IMAGE* image,
    const char name[8],
    const std::vector<uint8_t>& data,
    uint32_t characteristics,
    VMEmitResult& result)
{
    const uint32_t fileAlign = GetFileAlignment(image);
    const uint32_t sectionAlign = GetSectionAlignment(image);
    uint32_t ntOffset = static_cast<uint32_t>(image->dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER sections = image->sections;
    uint32_t firstRaw = 0xFFFFFFFFu;
    uint32_t lastFileEnd = 0;
    uint32_t lastVirtualEnd = 0;

    for (WORD i = 0; i < image->numSections; i++) {
        if (sections[i].PointerToRawData != 0 && sections[i].PointerToRawData < firstRaw) {
            firstRaw = sections[i].PointerToRawData;
        }
        uint32_t fileEnd = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        uint32_t virtualSize = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        uint32_t virtualEnd = sections[i].VirtualAddress + AlignUp(virtualSize, sectionAlign);
        lastFileEnd = (std::max)(lastFileEnd, fileEnd);
        lastVirtualEnd = (std::max)(lastVirtualEnd, virtualEnd);
    }
    if (firstRaw == 0xFFFFFFFFu) firstRaw = GetSizeOfHeaders(image);

    uint32_t newHeaderEnd = static_cast<uint32_t>(
        reinterpret_cast<BYTE*>(&sections[image->numSections + 1]) - image->rawData);

    if (newHeaderEnd > firstRaw) {
        uint32_t headerDelta = AlignUp(newHeaderEnd - firstRaw, fileAlign);
        uint32_t newRawSize = image->rawSize + headerDelta;
        BYTE* moved = new(std::nothrow) BYTE[newRawSize];
        if (!moved) {
            result.error = "VM_EMIT: no memory while relocating PE headers";
            return false;
        }
        memset(moved, 0, newRawSize);
        memcpy(moved, image->rawData, firstRaw);
        memcpy(moved + firstRaw + headerDelta,
               image->rawData + firstRaw,
               image->rawSize - firstRaw);

        delete[] image->rawData;
        image->rawData = moved;
        image->rawSize = newRawSize;
        image->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moved);
        if (image->is64Bit) image->ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(moved + ntOffset);
        else image->ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(moved + ntOffset);
        image->sections = image->is64Bit ? IMAGE_FIRST_SECTION(image->ntHeaders64)
                                         : IMAGE_FIRST_SECTION(image->ntHeaders32);
        sections = image->sections;

        for (WORD i = 0; i < image->numSections; i++) {
            if (sections[i].PointerToRawData >= firstRaw) {
                sections[i].PointerToRawData += headerDelta;
            }
        }
        if (image->hasOverlay && image->overlayOffset >= firstRaw) {
            image->overlayOffset += headerDelta;
        }
        SetSizeOfHeaders(image, AlignUp(newHeaderEnd, fileAlign));
        lastFileEnd += headerDelta;
    }

    uint32_t rawOffset = AlignUp(lastFileEnd, fileAlign);
    uint32_t rawSize = AlignUp(static_cast<uint32_t>(data.size()), fileAlign);
    uint32_t virtualAddress = AlignUp(lastVirtualEnd, sectionAlign);
    uint32_t virtualSize = AlignUp(static_cast<uint32_t>(data.size()), sectionAlign);
    uint32_t overlaySize = image->rawSize > lastFileEnd ? image->rawSize - lastFileEnd : 0;
    uint32_t newRawSize = rawOffset + rawSize + overlaySize;

    BYTE* newData = new(std::nothrow) BYTE[newRawSize];
    if (!newData) {
        result.error = "VM_EMIT: no memory while appending VM section";
        return false;
    }
    memset(newData, 0, newRawSize);
    uint32_t copyPrefix = (image->rawSize < lastFileEnd) ? image->rawSize : lastFileEnd;
    memcpy(newData, image->rawData, copyPrefix);
    memcpy(newData + rawOffset, data.data(), data.size());
    if (overlaySize) {
        memcpy(newData + rawOffset + rawSize, image->rawData + lastFileEnd, overlaySize);
        if (image->hasOverlay && image->overlayOffset >= lastFileEnd) {
            image->overlayOffset = rawOffset + rawSize + (image->overlayOffset - lastFileEnd);
        }
    }

    delete[] image->rawData;
    image->rawData = newData;
    image->rawSize = newRawSize;
    image->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(newData);
    if (image->is64Bit) image->ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(newData + ntOffset);
    else image->ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(newData + ntOffset);
    image->sections = image->is64Bit ? IMAGE_FIRST_SECTION(image->ntHeaders64)
                                     : IMAGE_FIRST_SECTION(image->ntHeaders32);
    sections = image->sections;

    PIMAGE_SECTION_HEADER newSection = &sections[image->numSections];
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSection->Name, name, 8);
    newSection->Misc.VirtualSize = static_cast<DWORD>(data.size());
    newSection->VirtualAddress = virtualAddress;
    newSection->SizeOfRawData = rawSize;
    newSection->PointerToRawData = rawOffset;
    newSection->Characteristics = characteristics;

    image->numSections++;
    if (image->is64Bit) {
        image->ntHeaders64->FileHeader.NumberOfSections = image->numSections;
        image->ntHeaders64->OptionalHeader.SizeOfImage = virtualAddress + virtualSize;
    } else {
        image->ntHeaders32->FileHeader.NumberOfSections = image->numSections;
        image->ntHeaders32->OptionalHeader.SizeOfImage = virtualAddress + virtualSize;
    }

    result.sectionRVA = virtualAddress;
    result.sectionRawOffset = rawOffset;
    return true;
}

} // namespace CipherShell
