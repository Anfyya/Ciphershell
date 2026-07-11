#include "packer/analysis/capability_checker.h"
#include "packer/signature/signature_eliminator.h"

#include <iostream>

namespace {

bool IsRejected(const CipherShell::CS_PE_IMAGE& image,
                const CipherShell::ProtectionBuildContext& context) {
    return !CipherShell::CapabilityChecker().CheckImage(&image, context).ok;
}

bool Expect(bool condition, const char* name) {
    std::cout << '[' << (condition ? "PASS" : "FAIL") << "] " << name << '\n';
    return condition;
}

} // namespace

int main() {
    IMAGE_NT_HEADERS64 headers{};
    headers.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NO_SEH;
    IMAGE_SECTION_HEADER section{};
    section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    BYTE rawData[512]{};

    CipherShell::CS_PE_IMAGE image{};
    image.rawData = rawData;
    image.rawSize = sizeof(rawData);
    image.ntHeaders64 = &headers;
    image.sections = &section;
    image.numSections = 1;
    image.is64Bit = TRUE;
    image.isValid = TRUE;

    int failures = 0;
    CipherShell::ProtectionBuildContext context{};
    context.flattening.enabled = true;
    failures += !Expect(IsRejected(image, context), "unsafe CFG flattening rejected");

    context = {};
    context.bogusFlow.enabled = true;
    failures += !Expect(IsRejected(image, context), "unsafe bogus flow rejected");

    context = {};
    context.importProtection.enabled = true;
    failures += !Expect(IsRejected(image, context), "fake import protection rejected");

    context = {};
    context.sectionEncryption.enabled = true;
    failures += !Expect(IsRejected(image, context), "weak section encryption rejected");

    context = {};
    context.stringEncryption.enabled = true;
    failures += !Expect(IsRejected(image, context), "weak string encryption rejected");

    CipherShell::EliminationConfig elimination{};
    elimination.randomizeSectionNames = false;
    elimination.randomizeTimestamps = false;
    elimination.clearRichHeader = false;
    elimination.clearDebugDirectory = false;
    elimination.clearChecksum = false;
    elimination.randomizeFileAlignment = false;
    elimination.randomizeSectionAlignment = false;
    elimination.addFakeImports = false;
    elimination.addFakeResources = false;
    const DWORD originalPermissions = section.Characteristics;
    failures += !Expect(
        CipherShell::SignatureEliminator().EliminateSignatures(&image, elimination) &&
            section.Characteristics == originalPermissions,
        "signature elimination preserves VM/data section permissions");

    return failures == 0 ? 0 : 1;
}
