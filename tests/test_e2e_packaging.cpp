#include "packer/analysis/capability_checker.h"
#include "packer/config/protection_build_context.h"
#include "packer/pe_parser/pe_parser.h"
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: test_e2e_packaging <pe-file>\n";
        return 2;
    }

    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromFile(argv[1]);
    if (!image || !image->isValid) {
        std::cerr << "E2E_PARSE_FAIL\n";
        if (image) parser.FreeImage(image);
        return 1;
    }

    CipherShell::CipherShellConfig config;
    config.global.protectionLevel = 4;
    CipherShell::ProtectionBuildContext ctx =
        CipherShell::ProtectionBuildContext::FromConfig(config, 4, false);
    CipherShell::CapabilityChecker checker;
    auto report = checker.CheckImage(image, ctx);

    std::cout << "E2E_CAPABILITY_OK=" << (report.ok ? 1 : 0)
              << " issues=" << report.issues.size() << "\n";
    parser.FreeImage(image);
    return report.ok ? 0 : 3;
}
