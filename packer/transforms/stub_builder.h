#ifndef CS_STUB_BUILDER_H
#define CS_STUB_BUILDER_H

#include "../pe_parser/pe_parser.h"
#include "section_encryptor.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct StubEmbedResult {
    bool success = false;
    bool installedAsTlsCallback = false;
    bool wxVerified = false;
    uint32_t stubRVA = 0;
    uint32_t stubSize = 0;
    uint32_t virtualProtectIatRVA = 0;
    uint32_t flushInstructionCacheIatRVA = 0;
    uint32_t tlsCallbackArrayRVA = 0;
    std::string error;
};

class StubBuilder {
public:
    StubEmbedResult EmbedStub(
        CS_PE_IMAGE* image,
        const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections,
        uint32_t originalEntryPointRVA,
        bool preservePEHeaders = false);

private:
    static bool VerifyNoWritableExecutableSections(
        const CS_PE_IMAGE* image, std::string& error);
};

} // namespace CipherShell

#endif // CS_STUB_BUILDER_H
