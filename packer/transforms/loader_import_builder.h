#ifndef CS_LOADER_IMPORT_BUILDER_H
#define CS_LOADER_IMPORT_BUILDER_H

#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>

namespace CipherShell {

struct LoaderImportBuildResult {
    bool success = false;
    uint32_t sectionRVA = 0;
    uint32_t sectionRawOffset = 0;
    uint32_t sectionSize = 0;
    uint32_t virtualProtectIatRVA = 0;
    uint32_t flushInstructionCacheIatRVA = 0;
    std::string error;
};

class LoaderImportBuilder {
public:
    LoaderImportBuildResult Build(CS_PE_IMAGE* image, const char sectionName[8]);
};

} // namespace CipherShell

#endif // CS_LOADER_IMPORT_BUILDER_H
