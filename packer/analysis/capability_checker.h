#ifndef CS_CAPABILITY_CHECKER_H
#define CS_CAPABILITY_CHECKER_H

#include "../config/protection_build_context.h"
#include "../pe_parser/pe_parser.h"
#include "../analysis/disassembler.h"
#include <string>
#include <vector>

namespace CipherShell {

struct CapabilityIssue {
    std::string module;
    uint32_t rva = 0;
    std::string reason;
    bool fatal = false;
};

struct CapabilityReport {
    bool ok = true;
    std::vector<CapabilityIssue> issues;
};

class CapabilityChecker {
public:
    CapabilityReport CheckImage(const CS_PE_IMAGE* image, const ProtectionBuildContext& ctx) const;
    bool IsFunctionCfgSafe(const CS_PE_IMAGE* image, const Function& func, std::string& reason) const;
    bool IsFunctionVmSafe(const CS_PE_IMAGE* image, const Function& func, std::string& reason) const;
};

} // namespace CipherShell

#endif // CS_CAPABILITY_CHECKER_H
