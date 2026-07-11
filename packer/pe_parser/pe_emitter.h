#ifndef CS_PE_EMITTER_H
#define CS_PE_EMITTER_H

#include "pe_parser.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct PEAppendSectionResult {
    bool success = false;
    uint32_t sectionIndex = 0;
    uint32_t rva = 0;
    uint32_t rawOffset = 0;
    uint32_t rawSize = 0;
    uint32_t virtualSize = 0;
    std::string error;
};

class PEEmitter {
public:
    explicit PEEmitter(CS_PE_IMAGE* image);

    bool IsValid() const;
    uint32_t GetFileAlignment() const;
    uint32_t GetSectionAlignment() const;
    uint32_t GetSizeOfHeaders() const;
    uint32_t GetEntryPoint() const;
    void SetEntryPoint(uint32_t rva);
    uint32_t RvaToOffset(uint32_t rva) const;

    PEAppendSectionResult AppendSection(
        const char name[8],
        const std::vector<uint8_t>& data,
        uint32_t characteristics);

    bool PatchBytes(uint32_t rva, const std::vector<uint8_t>& bytes, std::string* error = nullptr);
    bool FillBytes(uint32_t rva, uint32_t size, uint8_t value, std::string* error = nullptr);
    bool SetSectionCharacteristics(uint32_t sectionIndex, uint32_t characteristics, std::string* error = nullptr);
    bool RebuildExceptionDirectory(
        const std::vector<CS_RUNTIME_FUNCTION>& additionalEntries,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);
    bool RebuildGuardCFFunctionTable(
        const std::vector<uint32_t>& additionalFunctionRVAs,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);
    bool RebuildBaseRelocationDirectory(
        const std::vector<CS_RELOC_ENTRY>& additionalEntries,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);

private:
    uint32_t AlignUp(uint32_t value, uint32_t alignment) const;
    void RefreshPointers(uint32_t ntOffset);
    void SetSizeOfHeaders(uint32_t value);
    void SetSizeOfImage(uint32_t value);
    bool RelocateHeaders(uint32_t requiredHeaderEnd, uint32_t firstRaw, std::string& error);

    CS_PE_IMAGE* m_image;
};

} // namespace CipherShell

#endif // CS_PE_EMITTER_H
