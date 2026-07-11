#ifndef CS_FUNCTION_DISCOVERY_H
#define CS_FUNCTION_DISCOVERY_H

#include "disassembler.h"
#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct FunctionDiscoveryIssue {
    uint32_t rva = 0;
    std::string reason;
};

struct FunctionDiscoveryResult {
    bool success = false;
    std::vector<Function> functions;
    std::vector<FunctionDiscoveryIssue> issues;
    std::string error;
};

class FunctionDiscovery {
public:
    FunctionDiscoveryResult Discover(CS_PE_IMAGE* image, Disassembler& disassembler) const;
};

} // namespace CipherShell

#endif // CS_FUNCTION_DISCOVERY_H
